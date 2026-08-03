package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.core.enr.Enr;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv4.KademliaTable;
import com.jaeckel.ethp2p.networking.discv5.DiscV5Service;
import com.jaeckel.ethp2p.networking.dns.DnsEnrResolver;
import com.jaeckel.ethp2p.networking.eth.ServeStats;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import io.myotis.api.LifecycleState;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static io.myotis.api.LifecycleState.PAUSED;
import static io.myotis.api.LifecycleState.RUNNING;
import static io.myotis.api.LifecycleState.STOPPED;

/**
 * One Ethereum network's full node stack — RLPx (EL) + discv4 + discv5 (CL discovery)
 * + the beacon light client + the verified JSON-RPC server — on its own ports and with
 * its own identity and per-stack dial bookkeeping. Several {@code ChainStack}s run side
 * by side in one process (see {@code NodeRegistry}) without colliding.
 *
 * <p>Hosted identically by the {@code :app} daemon and {@code :android-app}; everything
 * platform-specific (peer caches, the node key file location, the snapshot file, the
 * CCIP gateway) is injected, so this per-network lifecycle lives once instead of being
 * duplicated across the two hosts.
 *
 * <p>{@link #start()} is fault-isolated: any failure closes only this stack's resources
 * and returns {@code false}; it never affects sibling stacks or the host process.
 */
public final class ChainStack {

    private static final Logger log = LoggerFactory.getLogger(ChainStack.class);

    private static final long BACKOFF_INCOMPATIBLE_MS = 10 * 60 * 1000L; // 10 min, wrong-chain peers
    private static final long BACKOFF_TRANSIENT_MS = 30 * 1000L;         // 30s, transient failures
    /** Cap on DNS-resolved (EIP-1459) EL enodes RLPx-dialed directly at startup, bypassing discv4. */
    private static final int DNS_DIRECT_DIAL_LIMIT = 50;
    // Snap-peer maintainer tunables (ported from the Android NodeService).
    private static final int MAX_ATTEMPTED = 200;
    private static final int DNS_MAINTAIN_DIAL_BATCH = 15;   // per-cycle dial budget from the DNS pool
    private static final int DNS_DIALS_PER_MIN = 60;         // rolling-minute rate cap
    private static final int DNS_POOL_MAX = 600;             // candidate-pool size cap
    private static final long DNS_REFRESH_INTERVAL_MS = 4 * 60 * 1000L;
    /** EL hunt: the snap SERVING pool has been empty this long → emergency mode.
     *  Deliberately zero-based, not target-based — on snap-scarce chains (gnosis)
     *  the target is unreachable and a below-target trigger would hunt forever;
     *  zero serving is the state where verified reads are actually impossible.
     *  The hunt bypasses transient backoffs for cache-CONFIRMED snap servers
     *  (they served chain-verified snap data — wrong-chain impossible), doubles
     *  the DNS dial budget, and shortens the DNS re-walk interval. The Rust
     *  engine's pool maintainer applies the same trigger (EL_HUNT_STALL). */
    static final long EL_HUNT_STALL_MS = 60_000L;

    /** Backoff for peers that rejected us with TooManyPeers (0x04): alive, just
     *  full. Longer than transient (halves the dial burn on saturated networks)
     *  but short enough to keep farming freed slots. While the EL hunt is
     *  engaged the transient window applies instead — see {@link #busyBackoffMs}. */
    static final long BACKOFF_BUSY_MS = 60_000L;

    /** Distinct peers that rejected us with TooManyPeers recently (rolling
     *  window) — hunt diagnostics: distinguishes "the network is full" from
     *  "the network is dead" when the serving pool is empty. */
    private final Map<String, Long> busySeen = new ConcurrentHashMap<>();
    private static final long BUSY_SEEN_WINDOW_MS = 10 * 60 * 1000L;
    /** DNS ENR re-walk interval while the EL hunt is engaged (vs 4 min normally). */
    private static final long DNS_REFRESH_HUNT_INTERVAL_MS = 60_000L;

    /** How recent a successful DNS ENR-tree resolve still counts as an
     *  online signal for {@link #reportConnectFailure}. Deliberately short: a
     *  device that drops offline right after a resolve must stop counting
     *  failures before it can demote healthy cached peers (at the ~40s re-dial
     *  cadence a 2-min window allows ~3 counts — under the demote threshold).
     *  Undercounting while online merely slows demotion, which is fine. */
    private static final long ONLINE_SIGNAL_MAX_AGE_MS = 2 * 60 * 1000L;

    /** Max time a verified read arriving on a paused stack is held while the wake completes. */
    public static final long WAKE_WAIT_CAP_MS = 90_000L;
    /** Wake-wait poll interval. */
    private static final long WAKE_POLL_MS = 250L;

    // -- injected configuration ------------------------------------------------
    private final NetworkConfig network;
    private final ChainPorts ports;
    private final NodeKey nodeKey;
    private final PeerCachePort peerCache;
    private final ClPeerCachePort clPeerCache;
    private final io.myotis.evm.ccipread.CcipGateway ccipGateway;
    private final Path syncSnapshotFile;
    private final boolean gossipsubEnabled;

    // -- per-stack mutable state (formerly Main/NodeService singletons) ---------
    private final Set<String> attempted = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> backoff = new ConcurrentHashMap<>();
    private final Set<String> blacklistedNodeIds = ConcurrentHashMap.newKeySet();
    private final AtomicReference<LifecycleState> phase = new AtomicReference<>(STOPPED);
    /** Wake-on-request: activity stamping + single-flight resume + bounded request hold. */
    private final WakeGate wakeGate;
    /** The stable VerifiedReads the RPC server holds across pause/resume cycles. */
    private final GatedVerifiedReads gatedReads;
    /** Idle-sleep bookkeeping (pause count / total paused / last wake) for the status screens. */
    private final SleepMetrics sleepMetrics = new SleepMetrics();

    // -- snap-peer maintainer (optional; enabled via configureSnapMaintainer) --
    private volatile boolean maintainerEnabled = false;
    private volatile int targetSnapPeers = 32;
    private DnsServerProvider dnsServerProvider;            // null → resolver's default DNS
    private volatile List<Enr> dnsElPool = List.of();
    private final AtomicBoolean dnsResolving = new AtomicBoolean(false);
    private volatile long lastDnsResolveMs = 0L;
    /** Last DNS ENR-tree walk that returned at least one ENR. Distinct from
     *  {@link #lastDnsResolveMs}: the resolver swallows per-tree failures and
     *  returns an empty list offline, and the walk itself is throttled by
     *  {@code lastDnsResolveMs} — so a FAILED walk must still count for the
     *  refresh cadence but must NOT count as an online signal, or an offline
     *  hunting machine (60s re-walks < the 2-min window) would keep the
     *  connect-failure gate permanently open and decimate its own cache. */
    private volatile long lastDnsSuccessMs = 0L;
    private volatile long dnsDialWindowStartMs = 0L;
    private final AtomicInteger dnsDialsInWindow = new AtomicInteger(0);
    private volatile ScheduledExecutorService peerMaintainer;
    /** Monotonic ms (nanoTime-derived) when the snap serving pool went empty. Only
     *  meaningful while {@link #snapZeroActive}; nanoTime's origin is arbitrary (can
     *  be ≤ 0), so an explicit flag marks validity instead of a 0 sentinel. Written
     *  by the maintainer tick, read by {@link #elHunting()} / the status snapshot. */
    private volatile long snapZeroSinceMs = 0L;
    /** True while the serving pool is empty and {@link #snapZeroSinceMs} is valid. */
    private volatile boolean snapZeroActive = false;
    /** EL hunt engaged (see EL_HUNT_STALL_MS). Maintainer-tick-updated. */
    private volatile boolean elHunting = false;

    // -- live components (built in start()) ------------------------------------
    /** Inbound-serve counters (peers asking US for headers/bodies). Stack-owned so the
     *  numbers survive pause/resume connector rebuilds; see ServeStats. */
    private final ServeStats serveStats = new ServeStats();
    private volatile RLPxConnector connector;
    private volatile DiscV4Service discV4;
    private volatile DiscV5Service discV5;
    private volatile BeaconSyncState beaconSyncState;
    private volatile BeaconLightClient beaconLightClient;
    private volatile io.myotis.rpc.VerifiedRpcBackend rpcBackend;
    private volatile io.myotis.jsonrpc.MyotisRpcServer rpcServer;
    /** The port startRpc() was configured with (recorded even when the bind fails,
     *  so the status row can show the failure); 0 until startRpc runs. */
    private volatile int rpcListenPort;

    /** Status source for the JSON-RPC myotis_status / myotis_beaconStatus methods; the
     *  wrapping handle late-binds it (see {@link #setStatusReads}) before start(). */
    private volatile io.myotis.api.NodeStatusReads statusReads;
    /** Monotonic start time (ns) of the first start; drives {@link #uptimeSeconds()}. Paired
     *  with {@link #started} because nanoTime()'s origin is arbitrary (0 is a valid reading). */
    private volatile long startedAtNs;
    private volatile boolean started;

    public ChainStack(NetworkConfig network,
                      ChainPorts ports,
                      NodeKey nodeKey,
                      PeerCachePort peerCache,
                      ClPeerCachePort clPeerCache,
                      io.myotis.evm.ccipread.CcipGateway ccipGateway,
                      Path syncSnapshotFile,
                      boolean gossipsubEnabled) {
        this.network = network;
        this.ports = ports;
        this.nodeKey = nodeKey;
        this.peerCache = peerCache;
        this.clPeerCache = clPeerCache;
        this.ccipGateway = ccipGateway;
        this.syncSnapshotFile = syncSnapshotFile;
        this.gossipsubEnabled = gossipsubEnabled;
        this.wakeGate = new WakeGate(phase::get, this::readyForReads,
                () -> resume(io.myotis.api.WakeReason.REQUEST),
                System::currentTimeMillis, WAKE_POLL_MS, "wake-resume-" + network.name());
        this.gatedReads = new GatedVerifiedReads(this);
    }

    /**
     * Enable the snap-peer maintainer for this stack — a background loop that keeps
     * {@code connector.activeSnapHandlers() >= targetSnapPeers} by re-dialing cached snap
     * peers and a refreshing EIP-1459 DNS-resolved ENR pool (the discv4-independent path
     * NAT'd mobile hosts rely on, where discv4 can't bootstrap). Must be called before
     * {@link #start()}. {@code dnsServers} may be null → the resolver uses its default DNS.
     *
     * <p>Off by default: a bare daemon relies on continuous discv4 discovery; mobile (and
     * any host wanting aggressive snap-peer retention) turns it on.
     */
    public void configureSnapMaintainer(int targetSnapPeers, DnsServerProvider dnsServers) {
        if (phase.get() != STOPPED) {
            throw new IllegalStateException("configureSnapMaintainer must be called before start()");
        }
        this.maintainerEnabled = true;
        this.targetSnapPeers = targetSnapPeers;
        this.dnsServerProvider = dnsServers;
    }

    /** Live-update the snap-peer target (no restart). */
    public void setTargetSnapPeers(int target) {
        this.targetSnapPeers = target;
    }

    /** eth/69 served-block window size; applied to the connector's shared
     *  ServedHeaderWindow when it is built and live via {@link #setServedBlockWindow}. */
    private volatile int servedBlockWindow =
            com.jaeckel.ethp2p.networking.eth.EthHandler.DEFAULT_SERVED_BLOCK_WINDOW;

    /** Live-update the eth/69 served-block window (no restart). Clamped to [1, 4096]:
     *  0/negative would kill header serving entirely, and an unbounded window is an
     *  archive-node promise a light client can't keep (also a memory knob, ~500 B/header). */
    public void setServedBlockWindow(int blocks) {
        int clamped = Math.max(1, Math.min(blocks, 4096));
        this.servedBlockWindow = clamped;
        RLPxConnector conn = connector;
        if (conn != null) conn.servedWindow().setMaxWindow(clamped);
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /**
     * Build and start this network's stack. Returns {@code true} on success. On any
     * failure, closes whatever was constructed and returns {@code false} without
     * affecting sibling stacks (fault isolation).
     *
     * <p>{@code synchronized} on the same monitor as {@link #shutdown()} so the two
     * never interleave: a {@code shutdown()} that races an in-progress {@code start()}
     * waits until startup finishes, then tears the fully-built stack down — rather than
     * flipping {@code running} mid-build and leaking the components started afterward.
     */
    public synchronized boolean start() {
        if (!phase.compareAndSet(STOPPED, RUNNING)) return true; // already started
        try {
            log.info("[{}] Node ID: {}", network.name(), nodeKey.nodeId().toHexString());

            // 1. EIP-1459 DNS discovery (EL + CL trees), concurrent + best-effort.
            DnsEnrResolver dnsResolver = new DnsEnrResolver();
            // Apply the host's DNS servers (Android: dnsjava has no system resolver config,
            // so without these the initial EL/CL resolve — and the maintainer's pool seed —
            // come back empty). Null/empty → resolver uses its default/public-DNS fallback.
            if (dnsServerProvider != null) {
                List<String> servers = dnsServerProvider.get();
                if (servers != null && !servers.isEmpty()) dnsResolver.setDnsServerIps(servers);
            }
            Duration dnsDeadline = Duration.ofSeconds(10);
            CompletableFuture<List<Enr>> elFuture = CompletableFuture.supplyAsync(
                    () -> dnsResolver.resolveAllFromStrings(network.elEnrTreeUrls(), dnsDeadline));
            CompletableFuture<List<Enr>> clFuture = CompletableFuture.supplyAsync(
                    () -> dnsResolver.resolveAllFromStrings(network.clEnrTreeUrls(), dnsDeadline));
            List<Enr> dnsElEnrs = elFuture.join();
            List<Enr> dnsClEnrs = clFuture.join();
            this.dnsElPool = dnsElEnrs;  // seed the maintainer's candidate pool

            // 2. RLPx connector + immediate cached / DNS-direct dials.
            this.connector = buildConnector();
            // Re-apply after publish: a Save racing this build can read connector==null in
            // setServedBlockWindow (skipping the live apply) after buildConnector already read
            // the old field value — without this, the new size would sit unapplied until the
            // next Save. Idempotent when there was no race.
            this.connector.servedWindow().setMaxWindow(Math.max(1, Math.min(servedBlockWindow, 4096)));
            dialInitialPeers(dnsElEnrs);

            // 3. discv4.
            startDiscV4(dnsElEnrs);

            // 4. Beacon: sync-state + discv5 (CL discovery) + light client.
            this.beaconSyncState = new BeaconSyncState();
            startDiscV5();
            buildAndStartBeacon(dnsClEnrs);

            // 5. Verified JSON-RPC (best-effort; a bind failure here does not fail the stack).
            startRpc();

            // 6. Snap-peer maintainer (optional): keep snap peers topped up from cache +
            //    the refreshing DNS pool. The discv4-independent path NAT'd hosts need.
            if (maintainerEnabled) startPeerMaintainer();

            // Anchor uptime only after a fully successful start (a failed start below tears
            // the stack down via shutdown(), which clears `started` so a later start re-anchors).
            // The serve counters share the same epoch: reset here (first start and any
            // start-after-shutdown), never on pause/resume — matching uptime exactly.
            if (!started) { startedAtNs = System.nanoTime(); started = true; serveStats.reset(); }
            return true;
        } catch (Throwable t) {
            log.error("[{}] stack failed to start: {}", network.name(), t.toString());
            shutdown();
            return false;
        }
    }

    /**
     * Suspend all networking — every socket and every periodic timer — while keeping
     * the stack instance and its warm verified state in memory: the beacon light
     * client's store, {@code beaconSyncState}'s roots window, the peer caches (NOT
     * closed, unlike {@link #shutdown()}), the DNS candidate pool, and the dial
     * backoff/blacklist. The JSON-RPC server keeps LISTENING (an idle loopback
     * socket holds no radio); a verified read arriving while paused goes through
     * {@link #awaitReadyForReads}, which triggers {@link #resume()} and holds the
     * request until the node can answer.
     *
     * @return {@code true} when the stack is {@code PAUSED} on return
     */
    public synchronized boolean pause() {
        if (!phase.compareAndSet(RUNNING, PAUSED)) return phase.get() == PAUSED;
        sleepMetrics.onPause(System.currentTimeMillis(), System.nanoTime());
        log.info("[{}] pausing: quiescing networking (RPC keeps listening)", network.name());
        closeNetworkingComponents();
        log.info("[{}] paused", network.name());
        return true;
    }

    /**
     * Rebuild networking after {@link #pause()}. Skips the cold-start DNS tree walk
     * (the retained {@code dnsElPool} seeds the dials) and re-anchors the beacon
     * light client from its warm in-memory store. Fault-isolated like
     * {@link #start()}: on failure whatever was rebuilt is closed again and the
     * stack stays {@code PAUSED} (retryable).
     */
    public synchronized boolean resume() {
        return resume(io.myotis.api.WakeReason.MANUAL);
    }

    /**
     * As {@link #resume()}, recording {@code reason} as the wake cause for the status
     * screens. {@link io.myotis.api.WakeReason#FOREGROUND} is an observation wake: it
     * still counts toward the pause total but does not overwrite the last-wake reason.
     */
    public synchronized boolean resume(String reason) {
        LifecycleState p = phase.get();
        if (p == RUNNING) return true;
        if (p != PAUSED) return false; // STOPPED is terminal
        log.info("[{}] resuming from pause ({})", network.name(), reason);
        try {
            this.connector = buildConnector();
            // Re-apply after publish: a Save racing this build can read connector==null in
            // setServedBlockWindow (skipping the live apply) after buildConnector already read
            // the old field value — without this, the new size would sit unapplied until the
            // next Save. Idempotent when there was no race.
            this.connector.servedWindow().setMaxWindow(Math.max(1, Math.min(servedBlockWindow, 4096)));
            dialInitialPeers(dnsElPool);
            startDiscV4(dnsElPool);          // essential — throws on bind failure
            startDiscV5();                   // non-essential, warn-and-continue
            BeaconLightClient blc = beaconLightClient;
            if (blc != null) blc.resume();
            io.myotis.jsonrpc.MyotisRpcServer liveServer = rpcServer;
            if (liveServer != null && liveServer.isServing()) {
                // The listener survived the pause; swap a fresh backend in behind
                // the gate (the old one died with the previous connector).
                io.myotis.rpc.VerifiedRpcBackend backend = buildAndStartBackend();
                this.rpcBackend = backend;
            } else {
                // Absent (first bind failed) OR dead (crashGuard latched a fatal
                // failure — previously unrecoverable, the row stayed red forever):
                // tear down any corpse and retry the full start best-effort.
                if (liveServer != null) {
                    try { liveServer.stop(); } catch (Throwable ignored) {}
                    rpcServer = null;
                }
                startRpc();
            }
            if (maintainerEnabled) startPeerMaintainer();
            phase.set(RUNNING);
            // Foreground (observation) wakes count toward the total but must not overwrite
            // the last-wake reason — see WakeReason / SleepMetrics.
            sleepMetrics.onResume(System.currentTimeMillis(), System.nanoTime(), reason,
                    !io.myotis.api.WakeReason.FOREGROUND.equals(reason));
            log.info("[{}] resumed ({})", network.name(), reason);
            return true;
        } catch (Throwable t) {
            log.error("[{}] resume failed (staying paused): {}", network.name(), t.toString());
            closeNetworkingComponents();
            return false;
        }
    }

    /**
     * The teardown shared by {@link #pause()} and a failed {@link #resume()}'s
     * cleanup: stop every timer and socket, keep the RPC listener and all warm
     * state. {@code attempted} is cleared because its entries are normally freed
     * by connect-future listeners that die with the connector — leaving them
     * would block re-dials on resume.
     */
    private void closeNetworkingComponents() {
        // EL hunt state must not leak across a pause: the wall time spent
        // paused would otherwise count toward the stall window and the first
        // maintainer tick after resume would trip emergency mode instantly
        // (the Rust engine rebuilds its pool with fresh state on resume —
        // keep the engines' behavior aligned).
        snapZeroSinceMs = 0L;
        snapZeroActive = false;
        elHunting = false;
        ScheduledExecutorService pm = peerMaintainer;
        if (pm != null) { pm.shutdownNow(); peerMaintainer = null; }
        io.myotis.rpc.VerifiedRpcBackend backend = rpcBackend;
        if (backend != null) {
            rpcBackend = null; // gate re-reads this; null → requests hold instead of hitting a closed backend
            try { backend.close(); } catch (Throwable ignored) {}
        }
        BeaconLightClient blc = beaconLightClient;
        if (blc != null) {
            try { blc.pause(); } catch (Throwable e) {
                log.warn("[{}] beacon pause: {}", network.name(), e.toString());
            }
        }
        RLPxConnector conn = connector;
        if (conn != null) { connector = null; try { conn.close(); } catch (Throwable ignored) {} }
        DiscV5Service d5 = discV5;
        if (d5 != null) { discV5 = null; try { d5.close(); } catch (Throwable ignored) {} }
        DiscV4Service d4 = discV4;
        if (d4 != null) { discV4 = null; try { d4.close(); } catch (Throwable ignored) {} }
        attempted.clear();
    }

    /**
     * Tear down this stack's components (reverse order) and release its caches.
     * Valid from any phase — a paused stack's components are already null and the
     * closes are null-guarded; {@code BeaconLightClient.close()} after a pause is
     * safe. Setting the phase to {@code STOPPED} first also releases any request
     * threads parked in {@link #awaitReadyForReads} (they observe STOPPED on
     * their next poll and return null).
     */
    public synchronized void shutdown() {
        phase.set(STOPPED);
        started = false;   // a fresh start() after shutdown re-anchors uptime to that run
        ScheduledExecutorService pm = peerMaintainer;
        if (pm != null) { pm.shutdownNow(); peerMaintainer = null; }
        if (rpcServer != null) { try { rpcServer.stop(); } catch (Throwable ignored) {} }
        // A stopped stack has no listener EXPECTATION either — zero the recorded
        // port so the status row hides instead of misreporting a normal stop as
        // a red bind failure.
        rpcListenPort = 0;
        if (rpcBackend != null) { try { rpcBackend.close(); } catch (Throwable ignored) {} }
        if (beaconLightClient != null) { try { beaconLightClient.close(); } catch (Throwable ignored) {} }
        if (connector != null) { try { connector.close(); } catch (Throwable ignored) {} }
        if (discV5 != null) { try { discV5.close(); } catch (Throwable ignored) {} }
        if (discV4 != null) { try { discV4.close(); } catch (Throwable ignored) {} }
        try { peerCache.close(); } catch (Throwable ignored) {}
        try { clPeerCache.close(); } catch (Throwable ignored) {}
        attempted.clear();
        backoff.clear();
        busySeen.clear();
        blacklistedNodeIds.clear();
    }

    // -------------------------------------------------------------------------
    // Wake-on-request gate
    // -------------------------------------------------------------------------

    /**
     * The wake-on-request choke point every verified read goes through: notes
     * host-visible activity, triggers a single-flight async {@link #resume()}
     * when paused, and blocks until reads are answerable or {@code capMs}
     * elapses.
     *
     * @return the live backend to query, or {@code null} when no verified answer
     *         is possible (stack stopped, RPC never started / failed to bind, or
     *         still paused at the deadline). A stack that is RUNNING but still cold
     *         at the deadline returns the backend anyway — it produces its own
     *         precise bounded errors.
     */
    public io.myotis.rpc.VerifiedRpcBackend awaitReadyForReads(long capMs) {
        // RUNNING with no backend means the JSON-RPC bind failed at start (the failure
        // is swallowed and the phase stays RUNNING). No amount of waiting will produce a
        // backend without a pause→resume, so fast-fail instead of holding the full cap —
        // otherwise ENS / operator queries would hang ~90s and still fail. (PAUSED with a
        // null backend is the normal sleep state and falls through to await(), which
        // triggers the wake.)
        if (phase.get() == RUNNING && rpcBackend == null) return null;
        return wakeGate.await(capMs) ? rpcBackend : null;
    }

    /** Note activity and kick a wake if paused, without blocking (status probes). */
    public void noteActivityAndWake() {
        wakeGate.poke();
    }

    /**
     * Requests currently being served (gated JSON-RPC reads + operator queries). While
     * non-zero, {@link #lastActivityMs()} reports "now" so the host idle timer never
     * pauses the stack mid-request — pausing would close the backend/connector under a
     * slow in-flight call (e.g. a multi-second confirm-screen sweep). Balanced with
     * {@link #beginRequest()}/{@link #endRequest()}.
     */
    private final AtomicInteger inFlight = new AtomicInteger();

    public void beginRequest() { inFlight.incrementAndGet(); }
    public void endRequest() { inFlight.decrementAndGet(); }

    /** Epoch millis of the last gated verified read / operator query; 0 if none. While a
     *  request is in flight this returns the current time, so the idle timer holds off. */
    public long lastActivityMs() {
        return inFlight.get() > 0 ? System.currentTimeMillis() : wakeGate.lastActivityMs();
    }

    // -- idle-sleep metrics (for status snapshots) --
    /** Late-bind the JSON-RPC status source (the wrapping handle), before {@link #start()}. */
    public void setStatusReads(io.myotis.api.NodeStatusReads statusReads) { this.statusReads = statusReads; }

    /** Node uptime in seconds since the first start; 0 before then. Monotonic (nanoTime),
     *  so it's immune to wall-clock/NTP adjustments. */
    public long uptimeSeconds() {
        return !started ? 0L : (System.nanoTime() - startedAtNs) / 1_000_000_000L;
    }

    public int pauseCount() { return sleepMetrics.pauseCount(); }
    public long totalPausedMs() { return sleepMetrics.totalPausedMs(); }
    public long lastPauseEpochMs() { return sleepMetrics.lastPauseEpochMs(); }
    public long lastResumeEpochMs() { return sleepMetrics.lastResumeEpochMs(); }
    public String lastWakeReason() { return sleepMetrics.lastWakeReason(); }

    /** Readiness for verified reads: beacon SYNCED and the head warmer has an anchored head. */
    private boolean readyForReads() {
        if (phase.get() != RUNNING) return false;
        BeaconSyncState bss = beaconSyncState;
        io.myotis.rpc.VerifiedRpcBackend b = rpcBackend;
        return bss != null && b != null
                && bss.getSyncState(network.clGenesisTime(), network.secondsPerSlot())
                        == BeaconSyncState.State.SYNCED
                && b.verifiedHeadAgeMs() != Long.MAX_VALUE;
    }

    // -------------------------------------------------------------------------
    // Accessors (for the host's IPC / UI layer)
    // -------------------------------------------------------------------------

    public NetworkConfig network() { return network; }
    public ChainPorts ports() { return ports; }
    public boolean isRunning() { return phase.get() == RUNNING; }

    /** LC hunt engaged on the beacon light client (starved of LC servers). */
    public boolean lcHunting() {
        BeaconLightClient b = beaconLightClient;
        return b != null && b.isHunting();
    }

    /** EL hunt engaged: snap serving pool empty past the stall window. */
    /** The JSON-RPC port the listener was configured with (0 = none configured yet). */
    public int rpcListenPort() {
        return rpcListenPort;
    }

    /** Live listener state: bound AND its supervisor hasn't recorded a fatal
     *  failure. Consults the server (not just the start outcome) so an
     *  asynchronously-died listener reads false, iOS-controller parity. */
    public boolean rpcServing() {
        io.myotis.jsonrpc.MyotisRpcServer s = rpcServer;
        return s != null && s.isServing();
    }

    public boolean elHunting() {
        return elHunting;
    }

    /** Pure trigger for the EL hunt (unit-tested; the Rust pool's el_hunt_due twin):
     *  serving pool empty AND it has been empty past the stall window. The explicit
     *  {@code zeroActive} flag (not a timestamp sentinel) keeps this correct on
     *  platforms where nanoTime readings are zero or negative. */
    static boolean elHuntDue(int servingPeers, boolean zeroActive, long zeroSinceMs, long nowMs) {
        return servingPeers == 0 && zeroActive && nowMs - zeroSinceMs >= EL_HUNT_STALL_MS;
    }
    public LifecycleState lifecycle() { return phase.get(); }
    public RLPxConnector connector() { return connector; }

    /** Inbound-serve counters for the status surfaces. */
    public ServeStats serveStats() { return serveStats; }
    public DiscV4Service discV4() { return discV4; }
    public DiscV5Service discV5() { return discV5; }
    public BeaconSyncState beaconSyncState() { return beaconSyncState; }
    public BeaconLightClient beaconLightClient() { return beaconLightClient; }
    /** The verified backend (for ENS resolution / verified reads), or null if RPC didn't start. */
    public io.myotis.rpc.VerifiedRpcBackend rpcBackend() { return rpcBackend; }

    /**
     * The pause-stable verified read surface hosts should hold: routes every read
     * through the wake gate, so it stays valid across pause/resume cycles while
     * the backend underneath is rebuilt. Null when the RPC pipeline never came up
     * (bind failure at start and no successful resume since) and the stack has no
     * backend — matching the old "reads unavailable" contract.
     */
    public io.myotis.api.VerifiedReads verifiedReads() {
        return (rpcServer != null || rpcBackend != null) ? gatedReads : null;
    }
    public Map<String, Long> backoff() { return backoff; }
    public Set<String> blacklistedNodeIds() { return blacklistedNodeIds; }
    /** Count of in-flight / recently-attempted dials (for host status snapshots). */
    public int attemptedCount() { return attempted.size(); }

    /**
     * Active (non-expired) dial-backoff entries, pruning expired ones as a side effect.
     * The per-peer dial paths only drop a backoff entry when that peer is re-encountered, so a
     * peer never seen again would leak its entry forever — over long uptimes the map would grow
     * without bound and inflate the reported count. Hosts that surface this stat (e.g. a UI
     * polling {@code snapshot()}) call this so the map is swept on the same cadence. {@code backoff}
     * stores each entry's expiry timestamp, so an entry is active iff its expiry is still in the future.
     */
    public int pruneAndCountActiveBackoff() {
        long now = System.currentTimeMillis();
        backoff.values().removeIf(expiry -> expiry <= now);
        return backoff.size();
    }

    // -------------------------------------------------------------------------
    // Construction helpers (faithful ports of Main.runDaemon)
    // -------------------------------------------------------------------------

    private List<InetSocketAddress> mergeBootnodes(List<Enr> dnsElEnrs) {
        List<InetSocketAddress> merged = new ArrayList<>(network.bootnodes());
        Set<String> seen = new HashSet<>();
        for (InetSocketAddress sa : merged) {
            seen.add(sa.getAddress().getHostAddress() + ":" + sa.getPort());
        }
        int before = merged.size();
        for (Enr enr : dnsElEnrs) {
            enr.udpAddress().or(enr::tcpAddress).ifPresent(sa -> {
                String key = sa.getAddress().getHostAddress() + ":" + sa.getPort();
                if (seen.add(key)) merged.add(sa);
            });
        }
        // Also seed discv4 from the static EL enodes (chains without an enrtree, e.g. Gnosis):
        // their ip:port widen the ping set; their pubkeys feed the direct-dial path separately.
        for (ParsedEnode pe : parseStaticEnodes()) {
            // getHostString() (not getAddress().getHostAddress()) — NPE-safe if the address is
            // unresolved, and consistent with directDialStaticEnodes; Gnosis enodes are IP
            // literals, so the key still matches the resolved bootnode keys above.
            String key = pe.address().getHostString() + ":" + pe.address().getPort();
            if (seen.add(key)) merged.add(pe.address());
        }
        if (merged.size() > before) {
            log.info("[{}] discovery seeds added {} EL bootnode(s) (total: {})",
                    network.name(), merged.size() - before, merged.size());
        }
        return merged;
    }

    /** A parsed {@code enode://<pubkey>@<host>:<port>} — address + secp256k1 pubkey. */
    private record ParsedEnode(InetSocketAddress address, SECP256K1.PublicKey pubkey) {}

    /** Parse {@link NetworkConfig#elBootEnodes()} into dialable (address, pubkey) pairs,
     *  skipping any malformed entry. */
    private List<ParsedEnode> parseStaticEnodes() {
        List<ParsedEnode> out = new ArrayList<>();
        for (String enode : network.elBootEnodes()) {
            try {
                String b = enode.substring(enode.indexOf("//") + 2);
                int at = b.indexOf('@');
                SECP256K1.PublicKey pub = SECP256K1.PublicKey.fromBytes(Bytes.fromHexString(b.substring(0, at)));
                String hostPort = b.substring(at + 1);
                int colon = hostPort.lastIndexOf(':');
                out.add(new ParsedEnode(
                        new InetSocketAddress(hostPort.substring(0, colon),
                                Integer.parseInt(hostPort.substring(colon + 1))),
                        pub));
            } catch (Exception e) {
                log.warn("[{}] skipping malformed static EL enode '{}': {}",
                        network.name(), enode, e.getMessage());
            }
        }
        return out;
    }

    /** Direct-RLPx-dial the network's static EL enodes — the discv4-independent discovery seed
     *  for chains with no EL enrtree (Gnosis): a NAT'd/mobile host reaches these known peers
     *  over RLPx without bootstrapping discv4 UDP. Mirrors {@link #directDialDnsEnodes}'s
     *  attempted/backoff bookkeeping; peers that connect are cached, so the snap-peer maintainer
     *  keeps re-dialing them from the cache on later cycles. */
    private void directDialStaticEnodes() {
        int dialed = 0;
        for (ParsedEnode pe : parseStaticEnodes()) {
            if (dialed >= DNS_DIRECT_DIAL_LIMIT) break;
            String peerKey = pe.address().getHostString() + ":" + pe.address().getPort();
            if (!attempted.add(peerKey)) continue;
            dialed++;
            final String key = peerKey;
            try {
                connector.connect(pe.address(), pe.pubkey(), (incompatible, busy, nodeIdHex) -> {
                            if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                            if (busy) noteBusy(key);
                            backoff.putIfAbsent(key, System.currentTimeMillis()
                                    + (incompatible ? BACKOFF_INCOMPATIBLE_MS
                                       : busy ? busyBackoffMs() : BACKOFF_TRANSIENT_MS));
                            attempted.remove(key);
                        })
                        .addListener(future -> { if (!future.isSuccess()) attempted.remove(key); });
            } catch (Exception e) {
                log.warn("[{}] direct dial of static EL enode {} failed: {}",
                        network.name(), key, e.getMessage());
                attempted.remove(key);
            }
        }
        if (dialed > 0) {
            log.info("[{}] Direct-dialed {} static EL enode(s)", network.name(), dialed);
        }
    }

    /** The immediate dial burst after a connector is (re)built: cached peers first,
     *  then DNS-resolved enodes, then the static enode list (Gnosis's enrtree substitute). */
    private void dialInitialPeers(List<Enr> dnsElEnrs) {
        dialCachedPeers();
        directDialDnsEnodes(dnsElEnrs);
        directDialStaticEnodes();
    }

    /** Build and bind discv4 (EL discovery). Essential: a bind failure throws and
     *  fails the start/resume that called this. */
    private void startDiscV4(List<Enr> dnsElEnrs) throws Exception {
        List<InetSocketAddress> mergedBootnodes = mergeBootnodes(dnsElEnrs);
        this.discV4 = buildDiscV4(mergedBootnodes);
        try {
            discV4.start(ports.elPort());
        } catch (Exception e) {
            log.error("[{}] discv4 failed to bind UDP {}: {}", network.name(), ports.elPort(), e.toString());
            throw e; // EL is essential — fail this stack
        }
        log.info("[{}] discv4 started on UDP port {}", network.name(), ports.elPort());
    }

    private RLPxConnector buildConnector() {
        RLPxConnector conn = new RLPxConnector(nodeKey, ports.elPort(), network, headers -> {
            if (!headers.isEmpty()) {
                log.debug("[{}] {} block header(s) received", network.name(), headers.size());
            }
        }, (address, publicKeyHex, snap) -> {
            peerCache.add(address, publicKeyHex, snap);
            // Nudge discovery toward this PROVEN peer's neighbourhood: peers
            // reached via the DNS pool or cache may never enter the discv4
            // table on their own, so the random walk would never ask them for
            // neighbours. UDP port is a guess (= TCP port, the devp2p default);
            // a wrong guess just means no pong, which is harmless.
            DiscV4Service d4 = discV4;
            if (d4 != null) {
                try {
                    // Pass the dial address through as-is (same host:port) —
                    // constructing a fresh InetSocketAddress from a host string
                    // could do a blocking DNS lookup on this Netty event-loop
                    // thread if a dial source ever supplies hostnames.
                    d4.probeEndpoint(address);
                } catch (Throwable ignored) {
                    // discovery nudge must never break the READY path
                }
            }
        }, serveStats);
        // Apply a window size set before start(): setServedBlockWindow may have run while
        // connector was still null (hosts read Settings before booting the stack).
        conn.servedWindow().setMaxWindow(servedBlockWindow);
        return conn;
    }

    private void dialCachedPeers() {
        List<CachedPeer> cached = new ArrayList<>(peerCache.load());
        cached.sort(Comparator.comparingInt(ChainStack::snapDialRank));
        for (CachedPeer peer : cached) {
            // getHostString() (not getAddress().getHostAddress()) — the latter NPEs on
            // an unresolved address; getHostString() returns the literal IP/host directly.
            String peerKey = peer.address().getHostString() + ":" + peer.address().getPort();
            attempted.add(peerKey);
            try {
                SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(
                        Bytes.fromHexString(peer.publicKeyHex()));
                connector.connect(peer.address(), pubKey, (incompatible, busy, nodeIdHex) -> {
                            if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                            if (busy) noteBusy(peerKey);
                            long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS
                                    : busy ? busyBackoffMs() : BACKOFF_TRANSIENT_MS;
                            backoff.putIfAbsent(peerKey, System.currentTimeMillis() + backoffMs);
                            attempted.remove(peerKey);
                        })
                        .addListener(future -> { if (!future.isSuccess()) attempted.remove(peerKey); });
            } catch (Exception e) {
                log.warn("[{}] Failed to connect to cached peer {}: {}", network.name(), peer.address(), e.getMessage());
                attempted.remove(peerKey);
            }
        }
    }

    private void directDialDnsEnodes(List<Enr> dnsElEnrs) {
        int directDialed = 0;
        for (Enr enr : dnsElEnrs) {
            if (directDialed >= DNS_DIRECT_DIAL_LIMIT) break;
            String peerKey = null;
            try {
                Optional<InetSocketAddress> tcp = enr.tcpAddress();
                Optional<SECP256K1.PublicKey> pub = enr.publicKey();
                if (tcp.isEmpty() || pub.isEmpty()) continue;
                InetSocketAddress peerTcp = tcp.get();
                peerKey = peerTcp.getHostString() + ":" + peerTcp.getPort();
                if (!attempted.add(peerKey)) continue;
                directDialed++;
                final String key = peerKey;
                connector.connect(peerTcp, pub.get(), (incompatible, busy, nodeIdHex) -> {
                            if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                            if (busy) noteBusy(key);
                            long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS
                                    : busy ? busyBackoffMs() : BACKOFF_TRANSIENT_MS;
                            backoff.putIfAbsent(key, System.currentTimeMillis() + backoffMs);
                            attempted.remove(key);
                        })
                        .addListener(future -> { if (!future.isSuccess()) attempted.remove(key); });
            } catch (Exception e) {
                log.warn("[{}] Failed direct dial of DNS EL enode: {}", network.name(), e.getMessage());
                if (peerKey != null) attempted.remove(peerKey);
            }
        }
        if (directDialed > 0) {
            log.info("[{}] Direct-dialed {} DNS EL enode(s)", network.name(), directDialed);
        }
    }

    private DiscV4Service buildDiscV4(List<InetSocketAddress> mergedBootnodes) {
        return new DiscV4Service(nodeKey, mergedBootnodes, entry -> {
            if (connector.isSnapHeavy()) return;
            if (entry.tcpPort() > 0 && attempted.size() < 2000) {
                String nodeIdHex = entry.nodeId().toHexString();
                if (blacklistedNodeIds.contains(nodeIdHex)) return;
                String peerKey = entry.udpAddr().getAddress().getHostAddress() + ":" + entry.tcpPort();
                Long expiry = backoff.get(peerKey);
                if (expiry != null) {
                    if (System.currentTimeMillis() < expiry) return;
                    backoff.remove(peerKey);
                }
                if (attempted.add(peerKey)) {
                    InetSocketAddress peerTcp = new InetSocketAddress(entry.udpAddr().getAddress(), entry.tcpPort());
                    tryConnectWithKnownKey(entry, peerTcp, peerKey);
                }
            }
        });
    }

    /** Build and bind discv5 (CL discovery). Non-essential: a failure is logged and
     *  swallowed — EL keeps working and CL falls back to cache + seed list. The
     *  found-peer callback reads the volatile {@code beaconLightClient} field: null
     *  during the first start's brief pre-BLC window (peers land in the cache and
     *  are picked up moments later), already-set on resume. */
    private void startDiscV5() {
        List<byte[]> acceptedForkDigests = network.acceptedForkDigests();
        AtomicInteger mismatchesLogged = new AtomicInteger();

        this.discV5 = new DiscV5Service(nodeKey, network.clDiscv5Bootnodes(), enr -> {
            var eth2 = enr.eth2();
            if (eth2.isEmpty()) return;
            byte[] peerDigest = eth2.get().forkDigest();
            int matchIdx = -1;
            for (int i = 0; i < acceptedForkDigests.size(); i++) {
                if (java.util.Arrays.equals(peerDigest, acceptedForkDigests.get(i))) { matchIdx = i; break; }
            }
            if (matchIdx < 0) {
                int n = mismatchesLogged.incrementAndGet();
                if (n <= 5) {
                    log.info("[{}][discv5] eth2 fork_digest=0x{} not accepted — rejected{}",
                            network.name(), java.util.HexFormat.of().formatHex(peerDigest),
                            n == 5 ? " [further mismatch logs suppressed]" : "");
                }
                return;
            }
            final int mi = matchIdx;
            enr.toLibp2pMultiaddr().ifPresent(ma -> {
                clPeerCache.add(ma);
                BeaconLightClient blc = beaconLightClient;
                boolean liveAdded = blc != null && blc.addPeer(ma);
                log.info("[{}][discv5] CL peer {} ({} match){}", network.name(), ma,
                        mi == 0 ? "current" : "prior", liveAdded ? " → live pool" : "");
            });
        });
        try {
            discV5.start(ports.discv5Port());
        } catch (Throwable t) {
            // discv5 is non-essential: EL keeps working and CL falls back to cache + seed list.
            log.warn("[{}][discv5] failed to start on UDP {}, continuing without CL discovery: {}",
                    network.name(), ports.discv5Port(), t.toString());
        }
    }

    /** Construct and start the beacon light client (first start only — a resume
     *  reuses the retained instance via {@code BeaconLightClient.resume()}). */
    private void buildAndStartBeacon(List<Enr> dnsClEnrs) {
        List<String> clPeers = new ArrayList<>(clPeerCache.load());
        for (String peer : network.clPeerMultiaddrs()) {
            if (!clPeers.contains(peer)) clPeers.add(peer);
        }
        for (Enr enr : dnsClEnrs) {
            enr.toLibp2pMultiaddr().ifPresent(ma -> { if (!clPeers.contains(ma)) clPeers.add(ma); });
        }
        BeaconLightClient blc = new BeaconLightClient(
                clPeers, network.checkpointRoot(), network.checkpointSlot(),
                network.currentForkVersion(), network.genesisValidatorsRoot(),
                beaconSyncState, network.beaconApiUrl(),
                clPeerCache::add, clPeerCache::markFailure, network.clGenesisTime());
        blc.setBlobParameters(network.activeBlobParamsEpoch(), network.activeBlobParamsMaxBlobs());
        blc.setBeaconPreset(network.secondsPerSlot(), network.slotsPerEpoch());
        blc.setProvenCatchUpServers(clPeerCache.servedRanges());
        blc.setOnCatchUpServed(clPeerCache::recordServed);
        blc.setProvenBootstrapPeers(clPeerCache.bootstrapPeers());
        blc.setOnBootstrapServed(clPeerCache::recordBootstrap);
        blc.setProvenLightClient(clPeerCache.lightClientConfirmed());
        blc.setProvenNonLightClient(clPeerCache.lightClientDenied());
        blc.setOnLightClientVerdict(clPeerCache::markLightClientBatch);
        blc.setSnapshotFile(syncSnapshotFile);
        blc.setGossipsubEnabled(gossipsubEnabled);
        // LC hunt: when the light client is starved of servers it flips this
        // and the CL discv5 service runs extra lookup rounds per tick. Read
        // the field at call time — discv5 (re)starts independently of the
        // beacon client, so an early registration must not pin a dead ref.
        blc.setHuntBoostListener(on -> {
            DiscV5Service d5 = discV5;
            if (d5 != null) d5.setHuntBoost(on);
        });
        blc.start();
        this.beaconLightClient = blc;
        log.info("[{}] Beacon light client started with {} CL peer(s)", network.name(), clPeers.size());
    }

    /** Build and start a fresh verified backend over the CURRENT connector/light
     *  client. One-shot like the components it binds to — pause closes it and
     *  resume calls this again. */
    private io.myotis.rpc.VerifiedRpcBackend buildAndStartBackend() {
        io.myotis.rpc.SnapQualitySink snapQualitySink = new io.myotis.rpc.SnapQualitySink() {
            @Override public void recordSnapServed(InetSocketAddress address) { peerCache.recordSnapServed(address); }
            @Override public void recordSnapFailure(InetSocketAddress address) { peerCache.recordSnapFailure(address); }
        };
        io.myotis.rpc.RpcLogger rpcLogger = new io.myotis.rpc.RpcLogger() {
            @Override public void info(String message) { log.info(message); }
            @Override public void warn(String message) { log.warn(message); }
        };
        io.myotis.rpc.VerifiedRpcBackend backend = new io.myotis.rpc.VerifiedRpcBackend(
                connector, beaconLightClient, beaconSyncState, ccipGateway,
                rpcLogger, io.myotis.rpc.RpcClock.monotonic(), snapQualitySink);
        backend.start();
        return backend;
    }

    private void startRpc() {
        int rpcPort = ports.rpcPort();
        try {
            // Deterministic up-front bind probe: Ktor's CIO engine surfaces bind
            // failures asynchronously, which a try/catch around start() can miss.
            try (java.net.ServerSocket probe = new java.net.ServerSocket()) {
                probe.setReuseAddress(true);
                probe.bind(new InetSocketAddress("127.0.0.1", rpcPort));
            }
            io.myotis.rpc.VerifiedRpcBackend backend = buildAndStartBackend();
            try {
                // The server is constructed over the GATE, never the raw backend:
                // it survives pause() (keeps listening) while the backend underneath
                // is torn down and rebuilt, and a request on a paused stack wakes it.
                io.myotis.jsonrpc.MyotisRpcServer server =
                        io.myotis.jsonrpc.MyotisRpc.server(rpcPort, null, "127.0.0.1", gatedReads, statusReads);
                server.start();
                this.rpcServer = server;
                this.rpcBackend = backend;
                rpcListenPort = rpcPort; // publish AFTER the server: no red flash mid-boot
                log.info("[{}] JSON-RPC listening on http://127.0.0.1:{} (verified, strict)",
                        network.name(), rpcPort);
            } catch (Throwable serverEx) {
                backend.close();
                throw serverEx;
            }
        } catch (java.io.IOException bindEx) {
            rpcListenPort = rpcPort; // recorded so the status row shows the failure
            log.warn("[{}][rpc] port {} unavailable ({}); continuing without JSON-RPC",
                    network.name(), rpcPort, bindEx.getMessage());
        } catch (Throwable t) {
            rpcListenPort = rpcPort;
            log.warn("[{}][rpc] failed to start JSON-RPC; continuing without it: {}",
                    network.name(), t.toString());
        }
    }

    private void tryConnectWithKnownKey(KademliaTable.Entry entry, InetSocketAddress peerTcp, String peerKey) {
        try {
            Bytes nodeId = entry.nodeId();
            if (nodeId.size() != 64) { attempted.remove(peerKey); return; }
            SECP256K1.PublicKey peerPubkey = SECP256K1.PublicKey.fromBytes(nodeId);
            connector.connect(peerTcp, peerPubkey, (incompatible, busy, nodeIdHex) -> {
                        if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                        if (busy) noteBusy(peerKey);
                        long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS
                                    : busy ? busyBackoffMs() : BACKOFF_TRANSIENT_MS;
                        backoff.putIfAbsent(peerKey, System.currentTimeMillis() + backoffMs);
                        attempted.remove(peerKey);
                    })
                    .addListener(future -> {
                        if (!future.isSuccess()) {
                            backoff.putIfAbsent(peerKey, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
                            attempted.remove(peerKey);
                        }
                    });
        } catch (Exception e) {
            backoff.putIfAbsent(peerKey, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
            attempted.remove(peerKey);
        }
    }

    /** Dial-priority rank (lower = dialed first): proven snap-servers, then snap-capable
     *  unproven, then known snap hangers, then plain-eth peers. */
    private static int snapDialRank(CachedPeer p) {
        if (!p.snap()) return 3;
        return switch (p.snapQuality()) {
            case CONFIRMED -> 0;
            case UNKNOWN -> 1;
            case DENIED -> 2;
        };
    }

    // -------------------------------------------------------------------------
    // Snap-peer maintainer (ported from NodeService; optional per-stack)
    // -------------------------------------------------------------------------

    /** Max headers requested per backfill tick — twin of the Rust
     *  {@code pool::BACKFILL_BATCH}. */
    private static final int BACKFILL_BATCH = 192;

    /** What a backfill batch must anchor its TOP header's hash against (twin of
     *  the Rust {@code BatchAnchor}): the beacon-anchored head hash, or — for a
     *  downward fill — the held run's earliest header's parent hash. */
    record BatchAnchor(org.apache.tuweni.bytes.Bytes32 topHash) {}

    /** A planned backfill request: {@code [from, from+count)} anchored by {@code anchor}. */
    record BackfillPlan(long from, int count, BatchAnchor anchor) {}

    /**
     * Keep the served-header window topped up toward the BEACON-anchored head, so
     * the eth/69 advertised range (and actual serving) reflects a real contiguous
     * recent run. Every batch is fetched RAW (no side-channel admission), then
     * verified — exact numbering, internal parent-hash chain, top anchored to the
     * beacon head hash or the held run's earliest parent hash — before any of it
     * enters the window. Only content cryptographically linked to the verified
     * head is ever served. One bounded request per tick; failures drop the batch
     * and the next tick retries.
     */
    private void backfillServedHeaders() {
        try {
            RLPxConnector conn = connector;
            BeaconSyncState bss = beaconSyncState;
            if (conn == null || bss == null) return;
            long head = bss.getOptimisticBlockNumber();
            byte[] headHashBytes = bss.getOptimisticBlockHash();
            if (head <= 0 || headHashBytes == null || headHashBytes.length != 32) return;
            org.apache.tuweni.bytes.Bytes32 headHash =
                    org.apache.tuweni.bytes.Bytes32.wrap(headHashBytes);
            com.jaeckel.ethp2p.networking.eth.ServedHeaderWindow window = conn.servedWindow();
            com.jaeckel.ethp2p.networking.eth.ServedHeaderWindow.Range r =
                    window.advertise(head, headHash);
            // advertise()'s empty-window shape is the genesis-only [0, 0]: treat as no run.
            boolean empty = r.latest() == 0;
            BackfillPlan plan = backfillPlan(head, headHash, window.maxWindow(),
                    empty ? -1 : r.earliest(), empty ? -1 : r.latest(),
                    empty ? null : r.latestHash(),
                    empty ? null : window.parentHashOf(r.earliest()));
            if (plan == null) return;
            var future = conn.backfillHeaders(plan.from(), plan.count());
            if (future == null) return; // no ready peer this tick
            future.orTimeout(10, TimeUnit.SECONDS).whenComplete((headers, ex) -> {
                if (ex != null || headers == null) {
                    log.debug("[{}] header backfill fetch failed: {}", network.name(),
                            ex != null ? ex.toString() : "null");
                    return;
                }
                if (!batchAnchored(headers, plan.from(), plan.count(), plan.anchor())) {
                    log.debug("[{}] header backfill: batch [{}..{}) failed anchoring — dropped",
                            network.name(), plan.from(), plan.from() + plan.count());
                    return;
                }
                // Reorg splice repair: if the held entry just below this verified
                // batch isn't the batch's parent, everything below is a stale
                // fork — evict it so the window never serves a spliced non-chain.
                org.apache.tuweni.bytes.Bytes32 below = window.hashOf(plan.from() - 1);
                if (below != null && !headers.get(0).header().parentHash.equals(below)) {
                    window.evictBelow(plan.from());
                }
                for (var vh : headers) {
                    window.put(vh.header().number, vh.hash(), vh.header().parentHash,
                            vh.rawRlp().toArrayUnsafe());
                }
            });
        } catch (Throwable t) {
            log.debug("[{}] header backfill tick failed: {}", network.name(), t.toString());
        }
    }

    /**
     * The pure per-tick backfill plan (twin of the Rust {@code backfill_plan};
     * kept case-identical with its tests). {@code runEarliest/runLatest} are -1
     * for an empty window; {@code earliestParent} is the held run's earliest
     * header's stored parent hash (null when unknown → no downward plan).
     */
    static BackfillPlan backfillPlan(long head, org.apache.tuweni.bytes.Bytes32 headHash,
            long cap, long runEarliest, long runLatest,
            org.apache.tuweni.bytes.Bytes32 runTopHash,
            org.apache.tuweni.bytes.Bytes32 earliestParent) {
        if (head <= 0) return null;
        long floor = Math.max(1, head - Math.max(0, cap - 1));
        if (runLatest == head && headHash.equals(runTopHash)) {
            // Run reaches the anchored head AND its top is the beacon-verified
            // hash: fill DOWN below it. The hash equality is load-bearing —
            // without it, one spoofed organic entry at the head number would
            // become the down-fill anchor and "verify" fabricated batches
            // against itself. A mismatched (or head-passing) top falls through
            // to the head-anchored restart, which overwrites the junk.
            if (runEarliest <= floor) return null; // window full
            long from = Math.max(floor, runEarliest - BACKFILL_BATCH);
            if (earliestParent == null) return null;
            return new BackfillPlan(from, (int) (runEarliest - from), new BatchAnchor(earliestParent));
        }
        if (runLatest >= 0 && runLatest < head && head - runLatest <= BACKFILL_BATCH) {
            // Extend UP to and including the head (one anchored batch).
            long from = Math.max(floor, runLatest + 1);
            return new BackfillPlan(from, (int) (head - from + 1), new BatchAnchor(headHash));
        }
        // Too far behind (or empty): restart at the head window.
        long from = Math.max(floor, head - (BACKFILL_BATCH - 1));
        return new BackfillPlan(from, (int) (head - from + 1), new BatchAnchor(headHash));
    }

    /** Validate an ascending backfill batch before admission (twin of the Rust
     *  {@code batch_anchored}): exact numbering, internal parent-hash chain, top
     *  anchored. Any failure rejects the WHOLE batch. */
    static boolean batchAnchored(
            java.util.List<com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage.VerifiedHeader> headers,
            long from, int count, BatchAnchor anchor) {
        if (headers.size() != count || headers.isEmpty()) return false;
        for (int i = 0; i < headers.size(); i++) {
            var h = headers.get(i);
            if (h.header().number != from + i) return false;
            if (i > 0 && !h.header().parentHash.equals(headers.get(i - 1).hash())) return false;
        }
        return headers.get(headers.size() - 1).hash().equals(anchor.topHash());
    }

    private void startPeerMaintainer() {
        if (peerMaintainer != null) return;
        peerMaintainer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "snap-peer-maintainer-" + network.name());
            t.setDaemon(true);
            return t;
        });
        peerMaintainer.scheduleWithFixedDelay(this::maintainSnapPeers, 5, 10, TimeUnit.SECONDS);
        // Header backfill rides the same executor: serving is only real if we HOLD
        // the recent headers peers ask for, and a light client fetches almost none
        // organically (a couple of probes + query walks). Top the served window up
        // toward the announced head, bounded per tick.
        peerMaintainer.scheduleWithFixedDelay(this::backfillServedHeaders, 7, 15, TimeUnit.SECONDS);
    }

    /** Keep {@code activeSnapHandlers() >= targetSnapPeers}: re-dial cached snap peers,
     *  then top up from the DNS ENR pool (rate-capped), then refresh the pool if still low. */
    private void maintainSnapPeers() {
        if (phase.get() != RUNNING) return;
        // Guard the whole body: an uncaught throw would make scheduleWithFixedDelay
        // silently stop all future runs.
        try {
            RLPxConnector conn = connector;
            if (conn == null) return;
            // target <= 0 = maintainer deliberately idle: an empty pool is the
            // EXPECTED state, not starvation — never engage (or advertise) the
            // hunt, and clear any state left from a previous target.
            if (targetSnapPeers <= 0) {
                snapZeroActive = false;
                if (elHunting) {
                    elHunting = false;
                    log.info("[{}][peers] EL hunt disengaged — snap target set to 0", network.name());
                }
                return;
            }
            int snapPeers = conn.activeSnapHandlers().size();
            long now = System.currentTimeMillis();
            // EL hunt bookkeeping: stall clock while the SERVING pool is empty,
            // trigger + transition logs (Rust maintainer_loop twin).
            long monotonicNowMs = System.nanoTime() / 1_000_000L;
            if (snapPeers > 0) {
                snapZeroActive = false;
                if (elHunting) {
                    elHunting = false;
                    log.info("[{}][peers] EL hunt disengaged — snap peer serving again", network.name());
                }
            } else if (!snapZeroActive) {
                snapZeroActive = true;
                snapZeroSinceMs = monotonicNowMs;
            }
            // Monotonic clock: an NTP jump during a momentary outage must not
            // fake a 60s stall (same rule as verifiedHeadAgeMs).
            boolean hunting = elHuntDue(snapPeers, snapZeroActive, snapZeroSinceMs, monotonicNowMs);
            if (hunting && !elHunting) {
                elHunting = true;
                log.info("[{}][peers] EL hunt engaged — snap serving pool empty {}s "
                        + "(bypassing transient backoffs for confirmed snap servers, "
                        + "boosted DNS budget; {} distinct busy peer(s) in the last {} min "
                        + "— busy means full-not-dead)", network.name(), EL_HUNT_STALL_MS / 1000,
                        busySeenCount(), BUSY_SEEN_WINDOW_MS / 60_000);
            }
            if (snapPeers >= targetSnapPeers) return;
            log.info("[{}][peers] {} snap peer(s) < target {}; re-dialing cached + DNS pool",
                    network.name(), snapPeers, targetSnapPeers);
            // 1) Re-dial known snap peers from the cache, proven snap-servers first.
            List<CachedPeer> snapCached = new ArrayList<>();
            for (CachedPeer p : peerCache.load()) {
                if (p.snap()) snapCached.add(p);
            }
            snapCached.sort(Comparator.comparingInt(ChainStack::snapDialRank));
            for (CachedPeer p : snapCached) {
                if (conn.activeSnapHandlers().size() >= targetSnapPeers) break;
                try {
                    // Hunting: free a CONFIRMED snap server's TRANSIENT backoff so
                    // this pass dials it NOW. Confirmed = it served chain-verified
                    // snap data. The backoff map holds transient (30s), busy (60s),
                    // and incompatible (10min) entries under the same key, so only
                    // clear entries within the transient window — a peer re-marked
                    // incompatible after its confirm (post-fork lag) keeps its
                    // 10-min timer instead of being re-dialed every 10s tick.
                    // Busy entries: outside the hunt they're 60s and enter the
                    // clearable window once ≤30s remain; DURING the hunt they're
                    // written at 30s (busyBackoffMs) and are therefore clearable
                    // immediately — a CONFIRMED-but-busy server gets re-dialed
                    // roughly every maintainer tick (~10s) while the pool is
                    // empty. Intentional, eyes open: it's bounded to the few
                    // confirmed servers, only runs in emergency mode, and each
                    // extra attempt is a cheap fast-refusal (geth-class nodes
                    // throttle repeat inbound within ~30s anyway) — maximal
                    // slot-farming pressure exactly when a freed slot is the
                    // only way back to verified reads.
                    if (hunting && p.snapQuality() == SnapQuality.CONFIRMED) {
                        String key = p.address().getHostString() + ":" + p.address().getPort();
                        backoff.computeIfPresent(key,
                                (k, exp) -> exp - now > BACKOFF_TRANSIENT_MS ? exp : null);
                    }
                    dialCachedSnapPeer(conn, p, now);
                } catch (Exception e) {
                    log.warn("[{}][peers] skipping cached peer: {}", network.name(), e.getMessage());
                }
            }
            // 2) Top up from the DNS-resolved ENR pool (discv4 substitute on NAT'd hosts),
            //    bounded by a per-cycle batch and a rolling-minute rate cap.
            List<Enr> pool = dnsElPool;
            if (!pool.isEmpty() && conn.activeSnapHandlers().size() < targetSnapPeers) {
                // Hunting doubles both the per-cycle batch and the rolling-minute cap.
                int batchCap = hunting ? DNS_MAINTAIN_DIAL_BATCH * 2 : DNS_MAINTAIN_DIAL_BATCH;
                int budget = Math.min(batchCap, dnsDialBudget(hunting));
                int dialed = 0;
                for (Enr enr : pool) {
                    if (dialed >= budget || attempted.size() >= MAX_ATTEMPTED) break;
                    if (dialEnr(conn, enr, now)) {
                        dialed++;
                        dnsDialsInWindow.incrementAndGet();
                    }
                }
                if (dialed > 0) {
                    log.info("[{}][peers] topped up {} dial(s) from DNS ENR pool ({} known)",
                            network.name(), dialed, pool.size());
                }
            }
            // 3) Grow/refresh the candidate pool — only while still below target and no
            //    more often than DNS_REFRESH_INTERVAL_MS.
            long refreshInterval = hunting ? DNS_REFRESH_HUNT_INTERVAL_MS : DNS_REFRESH_INTERVAL_MS;
            if (conn.activeSnapHandlers().size() < targetSnapPeers
                    && !dnsResolving.get()
                    && System.currentTimeMillis() - lastDnsResolveMs > refreshInterval) {
                Thread t = new Thread(this::refreshDnsPool, "dns-el-refresh-" + network.name());
                t.setDaemon(true);
                t.start();
            }
        } catch (Throwable t) {
            log.warn("[{}][peers] maintenance loop error: {}", network.name(), t.toString());
        }
    }

    /** Re-walk the EL ENR trees, fork-filter, and merge into the rolling candidate pool
     *  (dedup by enode address, capped at {@link #DNS_POOL_MAX}). Guarded to one walk at a time. */
    private void refreshDnsPool() {
        if (!dnsResolving.compareAndSet(false, true)) return;
        try {
            DnsEnrResolver resolver = new DnsEnrResolver();
            // On Android dnsjava has no system resolver config, so the host supplies DNS
            // server IPs; on the daemon dnsServerProvider is null and the resolver uses
            // its own default/public-DNS fallback.
            if (dnsServerProvider != null) {
                List<String> servers = dnsServerProvider.get();
                if (servers != null && !servers.isEmpty()) resolver.setDnsServerIps(servers);
            }
            List<Enr> resolved = resolver.resolveAllFromStrings(
                    network.elEnrTreeUrls(), Duration.ofSeconds(25));
            // The resolve can take ~25s; if the stack was shut down or paused meanwhile,
            // drop the result instead of merging into / writing the pool of a dead stack.
            if (phase.get() != RUNNING) return;
            lastDnsResolveMs = System.currentTimeMillis();
            if (!resolved.isEmpty()) lastDnsSuccessMs = lastDnsResolveMs;

            byte[] ourFork = network.forkIdHash();
            LinkedHashMap<String, Enr> merged = new LinkedHashMap<>();
            for (Enr e : dnsElPool) {
                e.tcpAddress().ifPresent(a -> merged.put(a.getHostString() + ":" + a.getPort(), e));
            }
            int added = 0, dropped = 0;
            for (Enr e : resolved) {
                if (merged.size() >= DNS_POOL_MAX) break;
                try {
                    Optional<InetSocketAddress> tcp = e.tcpAddress();
                    if (tcp.isEmpty() || e.publicKey().isEmpty()) continue;
                    Optional<byte[]> fork = e.ethForkIdHash();
                    if (fork.isPresent() && !Arrays.equals(fork.get(), ourFork)) { dropped++; continue; }
                    String key = tcp.get().getHostString() + ":" + tcp.get().getPort();
                    if (merged.putIfAbsent(key, e) == null) added++;
                } catch (Exception ex) {
                    dropped++; // malformed ENR — skip, don't abort the refresh
                }
            }
            // Stable partition: fork-id-verified entries dial before entries with
            // no eth forkid at all. The latter can't be pre-filtered (wrong-chain
            // ones only reveal themselves at the Status handshake), so they must
            // not compete equally for the per-cycle dial budget.
            List<Enr> ranked = new ArrayList<>(merged.values());
            ranked.sort(Comparator.comparingInt(ChainStack::enrForkRank));
            dnsElPool = ranked;
            log.info("[{}] DNS EL pool: +{} new, {} dropped (off-fork/malformed), {} total "
                    + "({} forkid-verified ranked first)",
                    network.name(), added, dropped, ranked.size(),
                    ranked.stream().filter(e -> enrForkRank(e) == 0).count());
        } catch (Exception e) {
            log.warn("[{}] DNS EL pool refresh failed: {}", network.name(), e.getMessage());
        } finally {
            dnsResolving.set(false);
        }
    }

    /** Dial rank for a DNS-pool ENR: 0 = carries an eth forkid (fork-verified on
     *  merge — mismatches never enter the pool), 1 = no forkid (unverifiable until
     *  the Status handshake). A malformed entry shares rank 1 — both are
     *  "unverifiable until dialed", so they compete equally behind verified ones. */
    private static int enrForkRank(Enr e) {
        try {
            return e.ethForkIdHash().isPresent() ? 0 : 1;
        } catch (Exception ex) {
            return 1;
        }
    }

    /** Remaining DNS-pool dials allowed in the current rolling minute (see DNS_DIALS_PER_MIN). */
    private int dnsDialBudget(boolean hunting) {
        int cap = hunting ? DNS_DIALS_PER_MIN * 2 : DNS_DIALS_PER_MIN;
        return Math.max(0, cap - dnsDialsInWindowCount());
    }

    private int dnsDialsInWindowCount() {
        long now = System.currentTimeMillis();
        if (now - dnsDialWindowStartMs >= 60_000L) {
            dnsDialWindowStartMs = now;
            dnsDialsInWindow.set(0);
        }
        return dnsDialsInWindow.get();
    }

    /** Dial one DNS-resolved (EIP-1459) EL enode over RLPx — same attempted/backoff/blacklist
     *  bookkeeping as the other dial paths; returns true if a connect was started. */
    private boolean dialEnr(RLPxConnector conn, Enr enr, long now) {
        String peerKey = null;
        try {
            Optional<InetSocketAddress> tcp = enr.tcpAddress();
            Optional<SECP256K1.PublicKey> pub = enr.publicKey();
            if (tcp.isEmpty() || pub.isEmpty()) return false;
            InetSocketAddress peerTcp = tcp.get();
            peerKey = peerTcp.getHostString() + ":" + peerTcp.getPort();
            Long expiry = backoff.get(peerKey);
            if (expiry != null) {
                if (now < expiry) return false;
                backoff.remove(peerKey);
            }
            if (attempted.size() >= MAX_ATTEMPTED || !attempted.add(peerKey)) return false;
            final String key = peerKey;
            conn.connect(peerTcp, pub.get(), (incompatible, busy, idHex) -> {
                if (incompatible) blacklistedNodeIds.add(idHex);
                if (busy) noteBusy(key);
                long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS
                        : busy ? busyBackoffMs() : BACKOFF_TRANSIENT_MS;
                backoff.putIfAbsent(key, System.currentTimeMillis() + ms);
                attempted.remove(key);
            }).addListener(future -> {
                if (!future.isSuccess()) {
                    backoff.putIfAbsent(key, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
                    attempted.remove(key);
                    reportConnectFailure(peerTcp);
                }
            });
            return true;
        } catch (Exception e) {
            log.warn("[{}] DNS EL dial failed: {}", network.name(), e.getMessage());
            if (peerKey != null) attempted.remove(peerKey);
            return false;
        }
    }

    /** Dial a cached snap peer with the same backoff/blacklist/attempted bookkeeping. */
    private void dialCachedSnapPeer(RLPxConnector conn, CachedPeer p, long now) {
        String peerKey = p.address().getHostString() + ":" + p.address().getPort();
        Long expiry = backoff.get(peerKey);
        if (expiry != null) {
            if (now < expiry) return;
            backoff.remove(peerKey);
        }
        if (attempted.size() >= MAX_ATTEMPTED || !attempted.add(peerKey)) return;
        try {
            SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(Bytes.fromHexString(p.publicKeyHex()));
            conn.connect(p.address(), pubKey, (incompatible, busy, idHex) -> {
                if (incompatible) blacklistedNodeIds.add(idHex);
                if (busy) noteBusy(peerKey);
                long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS
                        : busy ? busyBackoffMs() : BACKOFF_TRANSIENT_MS;
                backoff.putIfAbsent(peerKey, System.currentTimeMillis() + ms);
                attempted.remove(peerKey);
            }).addListener(future -> {
                // TCP-level failure (refused/timeout) fires here, not the handshake
                // callback above — free the slot and back off so a dead peer can't pin
                // `attempted` and eventually starve the pool at MAX_ATTEMPTED.
                if (!future.isSuccess()) {
                    backoff.putIfAbsent(peerKey, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
                    attempted.remove(peerKey);
                    reportConnectFailure(p.address());
                }
            });
        } catch (Exception e) {
            attempted.remove(peerKey);
        }
    }

    /** Busy peers wait {@link #BACKOFF_BUSY_MS} normally — but while the EL
     *  hunt is engaged they retry on the transient cadence instead: when the
     *  serving pool is empty, proven-alive-but-full nodes are the only
     *  realistic source of a freed slot, and slots are won by fast retries. */
    private long busyBackoffMs() {
        return elHunting ? BACKOFF_TRANSIENT_MS : BACKOFF_BUSY_MS;
    }

    /** Note a TooManyPeers rejection for hunt diagnostics (bounded, rolling). */
    private void noteBusy(String peerKey) {
        long now = System.currentTimeMillis();
        busySeen.put(peerKey, now);
        if (busySeen.size() > 256) {
            busySeen.values().removeIf(t -> now - t > BUSY_SEEN_WINDOW_MS);
            // Hard bound even when >256 are genuinely inside the window: drop
            // oldest first — the counter is diagnostics, not bookkeeping.
            while (busySeen.size() > 256) {
                String oldest = null;
                long oldestTs = Long.MAX_VALUE;
                for (Map.Entry<String, Long> e : busySeen.entrySet()) {
                    if (e.getValue() < oldestTs) { oldestTs = e.getValue(); oldest = e.getKey(); }
                }
                if (oldest == null) break;
                busySeen.remove(oldest);
            }
        }
    }

    /** Distinct busy peers seen inside the rolling window (prunes as it counts). */
    private int busySeenCount() {
        long now = System.currentTimeMillis();
        busySeen.values().removeIf(t -> now - t > BUSY_SEEN_WINDOW_MS);
        return busySeen.size();
    }

    /** Report a TCP-level dial failure to the peer cache (streaks demote and
     *  eventually evict long-dead peers) — but only while demonstrably online:
     *  a recent successful DNS ENR-tree resolve or any live RLPx connection.
     *  Without the guard, a machine that lost its network would count a failure
     *  against every cached peer each maintainer cycle and decimate the cache.
     *  Known divergence from the Rust twin: Rust also counts ECIES handshake
     *  failures (a cached entry with a rotated node key can never handshake
     *  again), while here the Netty connect future only surfaces pre-handshake
     *  TCP failures — post-TCP failures land in the close callback, which can't
     *  distinguish a stale-key peer from a healthy one disconnecting, so they
     *  are deliberately not counted. */
    private void reportConnectFailure(InetSocketAddress address) {
        try {
            RLPxConnector conn = connector;
            boolean online = System.currentTimeMillis() - lastDnsSuccessMs < ONLINE_SIGNAL_MAX_AGE_MS
                    || (conn != null && !conn.getActivePeers().isEmpty());
            if (online) peerCache.recordConnectFailure(address);
        } catch (Throwable t) {
            // Cache bookkeeping must never break the dial path.
        }
    }
}
