package io.myotis.engines;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import io.myotis.api.AccountProofResult;
import io.myotis.api.BeaconState;
import io.myotis.api.BeaconStatus;
import io.myotis.api.BlockResult;
import io.myotis.api.ChainHandle;
import io.myotis.api.ClPeerInfo;
import io.myotis.api.ConnectedPeer;
import io.myotis.api.DialResult;
import io.myotis.api.DiscoveredPeer;
import io.myotis.api.EngineException;
import io.myotis.api.EnsApi;
import io.myotis.api.EnsResolutionResult;
import io.myotis.api.HeadersResult;
import io.myotis.api.LifecycleState;
import io.myotis.api.NodeStatusReads;
import io.myotis.api.PeerInfo;
import io.myotis.api.StatusSnapshot;
import io.myotis.api.StorageProofResult;
import io.myotis.api.VerifiedReads;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * The Rust engine's {@link ChainHandle}: one hosted mainnet network backed by a
 * {@code myotis_net::SyncHandle} (the light-client sync loop) running on the tokio
 * runtime the native engine owns. Lifecycle + status cross the JNI boundary via
 * {@link RustEngineNative}; compound status is a JSON object (the hand-JNI + JSON
 * decision, pinned by golden tests on both sides).
 *
 * <p>Mainnet-only. The beacon fields of the status snapshot are real (finalized
 * slot, sync period, peer count, beacon state); some EL-side status fields
 * (snap-peer counts, RPC head age) are still zero. The verified-read
 * {@link #requestAccount}/{@link #getStorageProof} queries ARE live — they cross
 * to the Rust {@code ElReader} (discovery + peer pool + the CL-fed execution
 * anchor) and return the same proof/verdict records as the Java engine. The
 * remaining EL queries ({@link #getHeaders}/{@link #getBlockVerified}/
 * {@link #dialPeer}) throw {@link EngineException} until those surfaces land.
 *
 * <p>{@link #reads()} now serves the verified JSON-RPC endpoint (EL-B): on
 * {@link #start()} this handle self-starts the shared {@code jsonrpc-server} on
 * {@code 127.0.0.1:rpcPort} backed by {@link RustVerifiedReads}, mirroring how the
 * Java engine self-starts it inside {@code ChainStack}.
 *
 * <p>Idle sleep is REAL on this engine (the Java engine's behaviour, mirrored for
 * Android): {@link #pause()} tears the native networking down while the handle and
 * the JSON-RPC listener stay, {@link #resume(String)} warm-starts from the
 * persisted snapshot/peer caches, and every verified read below crosses the same
 * {@code WakeGate} the Java engine uses — a request on a paused stack wakes it and
 * is held (bounded, ~90 s) until the node can answer.
 */
final class RustChainHandle implements ChainHandle, NodeStatusReads {

    private static final Logger log = LoggerFactory.getLogger(RustChainHandle.class);

    /** Message for the queries the CL-only R1 engine can't answer yet. */
    private static final String NOT_AVAILABLE = "not available on the R1 Rust engine (CL-only)";

    private final long handle;
    private final String networkName;
    private final long chainId;
    /** Loopback JSON-RPC port; {@code <= 0} disables the server (e.g. the JSON test seams). */
    private final int rpcPort;
    /** The verified read surface the JSON-RPC server serves; never null. */
    private final RustVerifiedReads verifiedReads = new RustVerifiedReads(this);
    /** The running JSON-RPC server, or null when disabled / not started. */
    private volatile io.myotis.jsonrpc.MyotisRpcServer rpcServer;

    /** Monotonic start time (ns) of the current run; drives {@link #uptimeSeconds()}. Paired
     *  with {@link #started} because nanoTime()'s origin is arbitrary (0 is a valid reading). */
    private volatile long startedAtNs;
    private volatile boolean started;

    /** Head-freshness tracking for verifiedHeadAgeMs: the last optimistic-head block
     *  number seen, and the monotonic time it was first seen. The reported age is the
     *  elapsed time since the head last ADVANCED — a real age (0 → ~12 s per block,
     *  growing if the head stalls), not a constant. Guarded by {@link #headAgeLock}
     *  so the paired check-and-update is atomic across concurrent status() callers
     *  (UI poll + health thread) — a torn read would yield a spurious huge age.
     *  A DEDICATED lock (not {@code this}) so it never contends with start()/stop(). */
    private final Object headAgeLock = new Object();
    private long lastHeadBlock = -1L;
    private long lastHeadAdvanceNanos;

    /** CCIP-Read HTTP transport from EnginePorts; null = offchain names error. */
    private final io.myotis.api.ports.HttpGateway httpGateway;

    RustChainHandle(long handle, String networkName, long chainId, int rpcPort, boolean hasEns) {
        this(handle, networkName, chainId, rpcPort, hasEns, null);
    }

    RustChainHandle(long handle, String networkName, long chainId, int rpcPort, boolean hasEns,
            io.myotis.api.ports.HttpGateway httpGateway) {
        this.handle = handle;
        this.networkName = networkName;
        this.chainId = chainId;
        this.rpcPort = rpcPort;
        this.httpGateway = httpGateway;
        // Networks without ENS (e.g. gnosis) get no EnsApi — ens() returns null.
        this.ensApi = hasEns ? new RustEnsApi(this) : null;
        // Wake-on-request over the NATIVE lifecycle: the same primitive ChainStack
        // wires, so the two engines share the hold/single-flight semantics.
        this.wakeGate = new io.myotis.node.WakeGate(this::lifecycle, this::readyForReads,
                () -> resume(io.myotis.api.WakeReason.REQUEST),
                System::currentTimeMillis, WAKE_POLL_MS, "wake-resume-" + networkName);
    }

    io.myotis.api.ports.HttpGateway httpGateway() {
        return httpGateway;
    }

    @Override public String networkName() { return networkName; }

    @Override public long chainId() { return chainId; }

    @Override
    public synchronized boolean start() {
        boolean ok = RustEngineNative.nativeStart(handle);
        // Only expose the verified JSON-RPC endpoint once the native stack is up.
        if (ok) {
            // Anchor uptime to this successful start (cleared in stop() so a restart re-anchors).
            if (!started) { startedAtNs = System.nanoTime(); started = true; }
            startRpc();
        }
        return ok;
    }

    @Override
    public synchronized void stop() {
        // Stop serving before tearing down the native stack the reads depend on.
        io.myotis.jsonrpc.MyotisRpcServer server = this.rpcServer;
        if (server != null) {
            try { server.stop(); } catch (Throwable ignored) {}
            this.rpcServer = null;
        }
        started = false;   // a fresh start() after stop re-anchors uptime to that run
        RustEngineNative.nativeStop(handle);
    }

    // ---- idle-sleep lifecycle (mirrors ChainStack.pause/resume) ----
    //
    // pause() tears the native networking down (zero sockets, zero timers — the
    // radio can sleep) while the handle, its persisted warm state, and the
    // JSON-RPC LISTENER stay: a verified read arriving while paused goes through
    // the wake gate below, which triggers a single-flight resume(REQUEST) and
    // holds the request (bounded) until the node can answer. resume() re-runs
    // the native start path, which warm-starts from the persisted snapshot /
    // peer caches (no checkpoint re-bootstrap, no cold discovery). The
    // pause/resume accounting reuses the Java engine's SleepMetrics — including
    // the FOREGROUND observer-effect rule — so the two engines' status screens
    // can't drift.

    /** Max time a verified read arriving on a paused stack is held while the wake
     *  completes (mirrors ChainStack.WAKE_WAIT_CAP_MS). */
    static final long WAKE_WAIT_CAP_MS = 90_000L;
    /** Wake-wait poll interval (mirrors ChainStack.WAKE_POLL_MS). */
    private static final long WAKE_POLL_MS = 250L;

    /** Wake-on-request: activity stamping + single-flight resume + bounded request
     *  hold — the same primitive ChainStack wires (assigned in the constructor). */
    private final io.myotis.node.WakeGate wakeGate;
    /** Idle-sleep bookkeeping (pause count / total paused / last wake) for the
     *  status screens. Mutated only under this handle's lifecycle monitor
     *  (pause/resume are synchronized), like ChainStack. */
    private final io.myotis.node.SleepMetrics sleepMetrics = new io.myotis.node.SleepMetrics();
    /** Requests currently being served; while non-zero lastActivityEpochMillis
     *  reports "now" so the host idle timer never pauses the stack mid-query. */
    private final java.util.concurrent.atomic.AtomicInteger inFlight =
            new java.util.concurrent.atomic.AtomicInteger();

    @Override
    public synchronized boolean pause() {
        if (RustEngineNative.nativePause(handle)) {
            sleepMetrics.onPause(System.currentTimeMillis(), System.nanoTime());
            log.info("[{}] paused (networking torn down; RPC keeps listening)", networkName);
            return true;
        }
        // No transition — idempotent success only when already PAUSED (a
        // created/stopped handle reports false, per the ChainHandle contract).
        return lifecycle() == LifecycleState.PAUSED;
    }

    @Override
    public boolean resume() {
        return resume(io.myotis.api.WakeReason.MANUAL);
    }

    @Override
    public synchronized boolean resume(String reason) {
        if (isRunning()) return true; // no-op success, no accounting (mirrors ChainStack)
        if (RustEngineNative.nativeResume(handle)) {
            // Foreground (observation) wakes count toward the total but must not
            // overwrite the last-wake reason — see WakeReason / SleepMetrics.
            sleepMetrics.onResume(System.currentTimeMillis(), System.nanoTime(), reason,
                    !io.myotis.api.WakeReason.FOREGROUND.equals(reason));
            // The listener normally survived the pause; if the FIRST start's bind
            // failed this retries it best-effort (mirrors ChainStack.resume).
            startRpc();
            log.info("[{}] resumed ({})", networkName, reason);
            return true;
        }
        // Not paused (stopped), or the rebuild failed and the native side stayed
        // PAUSED (retryable) — either way, not RUNNING now.
        log.warn("[{}] resume ({}) did not start the stack (stayed {})",
                networkName, reason, lifecycle());
        return false;
    }

    @Override
    public LifecycleState lifecycle() {
        ParsedStatus s = readStatus();
        if (s.running()) return LifecycleState.RUNNING;
        return s.paused() ? LifecycleState.PAUSED : LifecycleState.STOPPED;
    }

    @Override
    public long lastActivityEpochMillis() {
        // Epoch millis of the last gated verified read / operator query; 0 if none.
        // While a request is in flight this reports "now" so the host idle timer
        // holds off (mirrors ChainStack.lastActivityMs).
        return inFlight.get() > 0 ? System.currentTimeMillis() : wakeGate.lastActivityMs();
    }

    /**
     * Wake-and-wait shared by every verified read / operator query below: a query
     * on a paused stack triggers the (single-flight) resume and waits up to the cap
     * for readiness. A RUNNING-but-cold stack proceeds at the deadline — the native
     * query produces its own precise bounded errors. Only PAUSED-at-deadline
     * (resume kept failing) throws; a STOPPED stack falls through to the native's
     * "handle not started"/"unknown handle" error (mirrors JavaChainHandle.awaitWake).
     */
    private void awaitWake() {
        // Fast-fail the unrecoverable-while-RUNNING state (the twin of
        // ChainStack.awaitReadyForReads' "RUNNING with no backend" fast-fail):
        // RUNNING with no EL reader means the reader failed at start (the CL-only
        // degraded mode). No amount of waiting produces one without a pause→resume,
        // so let the native's precise "EL reader unavailable" error surface
        // immediately instead of holding every query the full ~90 s cap.
        ParsedStatus probe = readStatus();
        if (probe.running() && !probe.elReaderAvailable()) return;
        wakeGate.await(WAKE_WAIT_CAP_MS);
        if (lifecycle() == LifecycleState.PAUSED) {
            throw new EngineException("node did not become ready within "
                    + (WAKE_WAIT_CAP_MS / 1000) + "s (paused; resume failing)");
        }
    }

    /** Adapter seam ({@link RustVerifiedReads#headBlockNumber}): wake-and-hold;
     *  false when no verified answer is possible right now. */
    boolean awaitReadyForReads() {
        try {
            awaitWake();
            return true;
        } catch (EngineException e) {
            return false;
        }
    }

    /** Adapter seam: note activity and kick a wake if paused, without blocking
     *  (status probes — {@link RustVerifiedReads#syncState}). */
    void noteActivityAndWake() {
        wakeGate.poke();
    }

    /**
     * The wake-on-request choke point every verified read crosses before its JNI
     * call (the Rust-engine twin of ChainStack.awaitReadyForReads + the
     * begin/endRequest in-flight guard): stamps activity, wakes a paused stack,
     * holds bounded until reads are answerable, and marks the request in flight so
     * the host idle timer can't pause the stack mid-query.
     */
    private <T> T gated(java.util.function.Supplier<T> nativeCall) {
        awaitWake();
        inFlight.incrementAndGet();
        try {
            return nativeCall.get();
        } finally {
            inFlight.decrementAndGet();
        }
    }

    /** Readiness for verified reads — the serveable predicate status() ages the
     *  head by: SYNCED, an anchored optimistic head, and snap peers to query
     *  (the Rust twin of ChainStack.readyForReads). */
    private boolean readyForReads() {
        try {
            ParsedStatus s = readStatus();
            // RUNNING with no EL reader is terminal-until-pause/resume (the CL-only
            // degraded mode): more waiting cannot help, so report "attempt the read
            // now" and let the native surface its precise "EL reader unavailable"
            // error. The pre-gate probe in awaitWake covers the already-RUNNING
            // case without stamping activity; this covers a wake whose resume
            // lands in the degraded mode MID-HOLD, which would otherwise park the
            // request for the full cap.
            if (s.running() && !s.elReaderAvailable()) return true;
            return s.running() && s.beaconState() == BeaconState.SYNCED
                    && s.optimisticBlockNumber() > 0 && s.snapPeers() > 0;
        } catch (RuntimeException e) {
            return false; // an unreadable status is "not ready", never a wake-loop crash
        }
    }

    /** {@link NodeStatusReads}: node uptime for the JSON-RPC myotis_status result. Monotonic
     *  (nanoTime), so it's immune to wall-clock/NTP adjustments; 0 before the first start. */
    @Override
    public long uptimeSeconds() {
        return !started ? 0L : (System.nanoTime() - startedAtNs) / 1_000_000_000L;
    }

    /**
     * Start the shared {@code jsonrpc-server} on {@code 127.0.0.1:rpcPort}, backed by
     * {@link RustVerifiedReads} — the Rust-engine counterpart to
     * {@code ChainStack.startRpc()}. Loopback only, strict (no upstream proxy). A
     * bind failure is logged and the stack continues without JSON-RPC (mirrors the
     * Java engine): the IPC socket still serves the same verified primitives.
     */
    /** Live listener state (bound AND no fatal supervisor failure) — ChainStack parity. */
    private boolean rpcServing() {
        io.myotis.jsonrpc.MyotisRpcServer s = rpcServer;
        return s != null && s.isServing();
    }

    private void startRpc() {
        if (rpcPort <= 0) return;        // RPC disabled (test seam / explicit opt-out)
        if (rpcServer != null) return;   // already started — avoid a re-bind / server leak
        try {
            // Deterministic up-front bind probe: Ktor's CIO engine surfaces bind
            // failures asynchronously, which a try/catch around start() can miss.
            try (java.net.ServerSocket probe = new java.net.ServerSocket()) {
                probe.setReuseAddress(true);
                probe.bind(new java.net.InetSocketAddress("127.0.0.1", rpcPort));
            }
            io.myotis.jsonrpc.MyotisRpcServer server =
                    io.myotis.jsonrpc.MyotisRpc.server(rpcPort, null, "127.0.0.1", verifiedReads, this);
            server.start();
            this.rpcServer = server;
            log.info("[{}] JSON-RPC listening on http://127.0.0.1:{} (verified, strict)",
                    networkName, rpcPort);
        } catch (java.io.IOException bindEx) {
            log.warn("[{}][rpc] port {} unavailable ({}); continuing without JSON-RPC",
                    networkName, rpcPort, bindEx.getMessage());
        } catch (Throwable t) {
            log.warn("[{}][rpc] failed to start JSON-RPC; continuing without it: {}",
                    networkName, t.toString());
        }
    }

    @Override public boolean isRunning() { return readStatus().running(); }

    // ---- status ----

    /** Parse the native status JSON; a null/empty payload → an unknown/dead handle. */
    private ParsedStatus readStatus() {
        String json = RustEngineNative.nativeStatusJson(handle);
        return ParsedStatus.parse(json);
    }

    /** The parsed native status object — CL fields plus the EL pool/discovery
     *  counts. Older natives omit the EL keys → they default to 0 (and the
     *  paused key → false, so an older .so can only ever look RUNNING/STOPPED). */
    private record ParsedStatus(
            boolean running,
            boolean paused,
            boolean elReaderAvailable,
            BeaconState beaconState,
            boolean bootstrapped,
            long finalizedSlot,
            long optimisticSlot,
            long currentPeriod,
            long targetPeriod,
            long peerCount,
            int servedPeersLastMinute,
            int discv5TableSize,
            long syncStartPeriod,
            int snapPeers,
            int discoveredPeers,
            int attemptedDials,
            int backedOffPeers,
            int blacklistedPeers,
            long optimisticBlockNumber,
            long finalizedBlockNumber,
            long peerHeaderRequests,
            long peerHeaderRequestsServed,
            long peerBodyRequests,
            long peerBodyRequestsServed,
            boolean lcHunting,
            boolean elHunting) {

        static ParsedStatus parse(String json) {
            if (json == null || json.isBlank()) return notRunning();
            try {
                JsonObject o = Json.parse(json).asObject();
                if (o.isEmpty()) return notRunning(); // "{}" == unknown handle
                return new ParsedStatus(
                        o.getBoolean("running", false),
                        o.getBoolean("paused", false),
                        o.getBoolean("elReaderAvailable", false),
                        BeaconState.valueOf(o.getString("beaconState", "STARTING")),
                        o.getBoolean("bootstrapped", false),
                        o.getLong("finalizedSlot", 0L),
                        o.getLong("optimisticSlot", 0L),
                        o.getLong("currentPeriod", 0L),
                        o.getLong("targetPeriod", 0L),
                        o.getLong("peerCount", 0L),
                        o.getInt("servedPeersLastMinute", 0),
                        o.getInt("discv5TableSize", 0),
                        o.getLong("syncStartPeriod", -1L),
                        o.getInt("snapPeers", 0),
                        o.getInt("discoveredPeers", 0),
                        o.getInt("attemptedDials", 0),
                        o.getInt("backedOffPeers", 0),
                        o.getInt("blacklistedPeers", 0),
                        o.getLong("optimisticBlockNumber", 0L),
                        o.getLong("finalizedBlockNumber", 0L),
                        o.getLong("peerHeaderRequests", 0L),
                        o.getLong("peerHeaderRequestsServed", 0L),
                        o.getLong("peerBodyRequests", 0L),
                        o.getLong("peerBodyRequestsServed", 0L),
                        o.getBoolean("lcHunting", false),
                        o.getBoolean("elHunting", false));
            } catch (RuntimeException e) {
                throw new EngineException(
                        "malformed status JSON from the Rust engine: " + e.getMessage(), e);
            }
        }

        static ParsedStatus notRunning() {
            return new ParsedStatus(false, false, false, BeaconState.STARTING, false, 0L, 0L, 0L,
                    0L, 0L, 0, 0, -1L, 0, 0, 0, 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, false, false);
        }
    }

    @Override
    public StatusSnapshot status() {
        return status(readStatus());
    }

    /**
     * Map a native status JSON payload to a {@link StatusSnapshot} for {@code network}.
     * Package-private test seam: exercises the JSON→snapshot mapping without JNI.
     */
    static StatusSnapshot statusFromJson(String network, String json) {
        return new RustChainHandle(0L, network, 1L, 0, false).status(ParsedStatus.parse(json));
    }

    /** Package-private test seam: JSON→{@link BeaconStatus} without JNI. */
    static BeaconStatus beaconStatusFromJson(String network, String json) {
        return new RustChainHandle(0L, network, 1L, 0, false).beaconStatus(ParsedStatus.parse(json));
    }

    /** Package-private test seam: map a status JSON on THIS handle (so head-age
     *  tracking persists across calls). Lets a test observe verifiedHeadAgeMs grow. */
    StatusSnapshot statusFromJsonOnThisHandle(String json) {
        return status(ParsedStatus.parse(json));
    }

    private StatusSnapshot status(ParsedStatus s) {
        int peers = (int) Math.min(s.peerCount(), Integer.MAX_VALUE);
        // Older natives don't emit "targetPeriod" (parsed as 0): fall back to
        // currentPeriod — the pre-targetPeriod mirror — so the target >= current
        // invariant holds against any .so vintage.
        long targetPeriod = Math.max(s.targetPeriod(), s.currentPeriod());
        // EL pool/discovery counts now come from the Rust status JSON. The pool
        // keeps only snap-capable READY peers, so readyPeers == snapPeers (and
        // snapServingPeers is approximated by the same). Execution block numbers
        // (optimistic head + finalized) come from the beacon anchor via the status.
        //
        // verifiedHeadAgeMs drives the host's readiness dot (< 45 s = ready/green).
        // The Rust reader anchors every query to the peer's fresh head; there's no
        // separate head context to age, so age it by how long since the optimistic
        // head last ADVANCED (a new block ~every 12 s resets it) — a REAL, changing
        // age, not a constant. Reported only when a verified read CAN be served
        // (SYNCED, an anchored head, snap peers); else the Long.MAX_VALUE "no
        // verified head yet" sentinel — and while NOT serveable we hold the advance
        // clock at "now" so the age starts fresh the instant we become serveable
        // (a not-serving stretch must not leak in as a stale age → amber flicker).
        // Monotonic nanoTime — a wall-clock/NTP jump must not distort the age.
        long optHead = s.optimisticBlockNumber();
        long nowNanos = System.nanoTime();
        boolean serveable = s.beaconState() == BeaconState.SYNCED
                && optHead > 0 && s.snapPeers() > 0;
        long verifiedHeadAgeMs;
        synchronized (headAgeLock) {
            if (!serveable) {
                // No verified head to age; keep the clock pinned to now so the first
                // serveable poll starts near 0 rather than carrying the outage gap.
                lastHeadBlock = optHead;
                lastHeadAdvanceNanos = nowNanos;
                verifiedHeadAgeMs = Long.MAX_VALUE;
            } else {
                if (optHead != lastHeadBlock) {
                    lastHeadBlock = optHead;
                    lastHeadAdvanceNanos = nowNanos;
                }
                verifiedHeadAgeMs = Math.max(0L, (nowNanos - lastHeadAdvanceNanos) / 1_000_000L);
            }
        }
        return new StatusSnapshot(
                s.running(),
                s.running() ? LifecycleState.RUNNING
                        : s.paused() ? LifecycleState.PAUSED : LifecycleState.STOPPED,
                networkName,
                s.beaconState(),
                peers,                 // connectedPeers (CL libp2p peers)
                s.snapPeers(),         // readyPeers (EL — pool holds only snap-ready)
                s.snapPeers(),         // snapPeers
                s.snapPeers(),         // snapServingPeers (approx)
                s.discoveredPeers(),   // discoveredPeers (discv4)
                s.backedOffPeers(),    // backedOffPeers
                s.blacklistedPeers(),  // blacklistedPeers
                s.attemptedDials(),    // attemptedDials
                s.discv5TableSize(),
                s.finalizedBlockNumber(),   // executionBlockNumber (== finalized payload's block)
                s.optimisticBlockNumber(),  // optimisticBlockNumber (the eth_blockNumber head)
                s.finalizedSlot(),
                s.finalizedBlockNumber(),   // finalizedBlockNumber
                s.syncStartPeriod(),
                s.currentPeriod(),
                targetPeriod,
                s.finalizedSlot() / 8192L, // finalizedPeriod (SLOTS_PER_SYNC_COMMITTEE_PERIOD)
                targetPeriod,   // wallClockPeriod == the catch-up target
                verifiedHeadAgeMs,
                List.<PeerInfo>of(),
                // Idle-sleep metrics, accounted Java-side across the native
                // pause/resume transitions (same SleepMetrics as the Java engine).
                sleepMetrics.pauseCount(),
                sleepMetrics.totalPausedMs(),
                sleepMetrics.lastPauseEpochMs(),
                sleepMetrics.lastResumeEpochMs(),
                sleepMetrics.lastWakeReason(),
                // Inbound-serve counters, parsed from the Rust engine's status JSON.
                s.peerHeaderRequests(),
                s.peerHeaderRequestsServed(),
                s.peerBodyRequests(),
                s.peerBodyRequestsServed(),
                s.lcHunting(),
                s.elHunting(),
                // Host-side listener truth (the JVM owns the server for Rust-hosted
                // networks): the configured port — while the handle runs OR is
                // idle-paused (the listener deliberately survives pause: a request
                // on 127.0.0.1:rpcPort is what WAKES the stack) — and whether the
                // server is live right now. Only a STOPPED handle reports 0, hiding
                // the row instead of faking a red bind failure.
                (s.running() || s.paused()) && rpcPort > 0 ? rpcPort : 0,
                rpcServing());
    }

    @Override
    public BeaconStatus beaconStatus() {
        return beaconStatus(readStatus());
    }

    private BeaconStatus beaconStatus(ParsedStatus s) {
        int peers = (int) Math.min(s.peerCount(), Integer.MAX_VALUE);
        return new BeaconStatus(
                s.beaconState(),
                s.bootstrapped(),
                s.currentPeriod(),
                // Same older-.so fallback as status(): missing key parses as 0.
                Math.max(s.targetPeriod(), s.currentPeriod()),
                s.discv5TableSize(),
                peers,                 // connectedPeers (CL)
                s.peerCount(),         // lightClientPeers
                s.servedPeersLastMinute(),
                s.finalizedSlot(),
                s.optimisticSlot(),
                s.finalizedSlot() / 8192L,  // finalizedPeriod = period OF the finalized
                                            // slot (SLOTS_PER_SYNC_COMMITTEE_PERIOD),
                                            // consistent with StatusSnapshot — not the
                                            // committee's currentPeriod.
                null,                  // executionStateRootHex (EL)
                null,                  // executionBlockHashHex (EL)
                0L,                    // executionBlockNumber
                0,                     // knownStateRoots
                0,                     // fillThreshold
                List.<ClPeerInfo>of());
    }

    // ---- verified-read surface (EL-B) ----
    //
    // reads() returns the RustVerifiedReads adapter — the JSON-RPC read surface the
    // shared jsonrpc-server serves on 127.0.0.1:rpcPort (started in startRpc()). It
    // answers the beacon-anchored reads a wallet needs to build a plain-ETH send
    // (chainId/getBalance/getTransactionCount/syncState) from the same proof-verified
    // account query as requestAccount below; the rest of VerifiedReads returns null
    // ("can't answer verified") until later EL-B / EL-C slices land.
    //
    // Per the ChainHandle contract, reads() is null "while the RPC backend isn't
    // started (e.g. the RPC port was unavailable at start())". The adapter is itself
    // transport-independent (it queries the native directly), but reads() gates on
    // rpcServer so it means the same thing on both engines: the Java engine's
    // rpcBackend is null until startRpc() succeeds, and hosts null-check reads()
    // to decide whether verified RPC is available. So: null before start(), when
    // rpcPort<=0, or on a bind failure; non-null once serving.
    //
    // ens() serves forward resolution via the native resolver (EL-C-5-1); the
    // Rust engine is mainnet-only and mainnet has ENS, so it is always non-null.
    // Unimplemented record types report a graceful error RESULT per the EnsApi
    // contract (see RustEnsApi). The EL QUERY methods further down
    // (getHeaders/getBlockVerified/dialPeer) still throw EngineException: the
    // contract reserves exceptions for malformed input / not running, and an
    // unimplemented EL surface is a capability error (no verification to report
    // a failReason for) — a failReason record would misrepresent "we can't" as
    // "we tried and failed".

    @Override public VerifiedReads reads() { return rpcServer != null ? verifiedReads : null; }

    // Non-null only for ENS-capable networks (gnosis has no ENS registry — the
    // ChainHandle contract returns null there). Assigned in the constructor since
    // it depends on hasEns.
    private final EnsApi ensApi;

    @Override public EnsApi ens() { return ensApi; }

    @Override
    public List<DiscoveredPeer> discoveredPeers() { return List.of(); }

    @Override
    public List<ConnectedPeer> connectedPeers() { return List.of(); }

    @Override
    public void setTargetSnapPeers(int target) {
        log.debug("[engines] setTargetSnapPeers({}) is a no-op on the R1 Rust engine (CL-only)",
                target);
    }

    @Override
    public void setServedBlockWindow(int blocks) {
        // Live-applied on a running EL handle; the native absorbs it as a no-op
        // when the handle isn't started or has no EL reader.
        RustEngineNative.nativeSetServedBlockWindow(handle, blocks);
    }

    @Override
    public void clearPeerState() {
        log.debug("[engines] clearPeerState is a no-op on the R1 Rust engine (CL-only)");
    }

    @Override
    public AccountProofResult requestAccount(String hexAddress) {
        JsonObject o = parseResultOrThrow(
                gated(() -> RustEngineNative.nativeRequestAccountJson(handle, hexAddress)),
                "account");
        return accountFromJson(hexAddress, o);
    }

    /** Package-private test seam: JSON → {@link AccountProofResult} without JNI. */
    static AccountProofResult accountFromJson(String hexAddress, String json) {
        return accountFromJson(hexAddress, parseResultOrThrow(json, "account"));
    }

    private static AccountProofResult accountFromJson(String hexAddress, JsonObject o) {
        try {
        return new AccountProofResult(
                o.getString("address", hexAddress),
                o.getBoolean("exists", false),
                o.getLong("nonce", -1L),
                stringOrNull(o, "balanceWei"),
                stringOrNull(o, "storageRootHex"),
                stringOrNull(o, "codeHashHex"),
                o.getLong("blockNumber", 0L),
                stringOrNull(o, "peerStateRootHex"),
                o.getBoolean("peerProofValid", false),
                o.getBoolean("beaconChainVerified", false),
                o.getBoolean("blsVerified", false),
                o.getLong("matchedBeaconSlot", -1L),
                stringOrNull(o, "verifyMethod"),
                stringOrNull(o, "failReason"),
                stringOrNull(o, "accountHashHex"),
                stringList(o, "proofNodesHex"),
                o.getBoolean("beaconSynced", false),
                o.getLong("finalizedPeriod", 0L),
                o.getLong("wallClockPeriod", 0L),
                o.getLong("finalizedBlockNumber", 0L),
                o.getLong("optimisticBlockNumber", 0L));
        } catch (RuntimeException e) {
            // A type-mismatched field (Rust-side shape drift) surfaces as an
            // EngineException, never a raw UnsupportedOperationException.
            throw new EngineException("malformed account JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    @Override
    public StorageProofResult getStorageProof(String hexAddress, long slot, String holderHexOrNull) {
        JsonObject o = parseResultOrThrow(
                gated(() -> RustEngineNative.nativeGetStorageProofJson(
                        handle, hexAddress, slot, holderHexOrNull)),
                "storage");
        return storageFromJson(hexAddress, slot, o);
    }

    /** Package-private test seam: JSON → {@link StorageProofResult} without JNI. */
    static StorageProofResult storageFromJson(String hexAddress, long slot, String json) {
        return storageFromJson(hexAddress, slot, parseResultOrThrow(json, "storage"));
    }

    // ---- VerifiedReads helpers (used by RustVerifiedReads; not ChainHandle API) ----

    /**
     * Verified contract bytecode for {@code hexAddress} (eth_getCode), or null when
     * the query produced no verdict (can't answer verified). A verified EOA /
     * empty-code account yields an empty array. Throws {@link EngineException} on a
     * transport / not-running failure (the adapter maps that to null).
     */
    byte[] codeVerified(String hexAddress) {
        return codeFromJson(gated(() -> RustEngineNative.nativeGetCodeJson(handle, hexAddress)));
    }

    /** Package-private test seam: code JSON → verified bytecode (or null) without JNI. */
    static byte[] codeFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "code");
        try {
            if (stringOrNull(o, "verifyMethod") == null) return null; // unverified → can't answer
            return hexToBytes(stringOrNull(o, "codeHex")); // 0x / empty → empty bytecode
        } catch (RuntimeException e) {
            throw new EngineException("malformed code JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * One verified {@code eth_call}: run it and return the result bytes, or null.
     * {@code from} is empty for an anonymous sender; {@code valueDecimal} is wei as
     * a decimal string. Throws {@link EngineException} on a transport / not-running
     * failure (the adapter maps that to null).
     */
    byte[] ethCallVerified(
            String fromHex, String toHex, String dataHex, String valueDecimal, String block) {
        return callResultFromJson(gated(() -> RustEngineNative.nativeEthCallJson(
                handle, fromHex, toHex, dataHex, valueDecimal, block)));
    }

    /** Package-private test seam: call JSON → result bytes (or null) without JNI. */
    static byte[] callResultFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "call");
        try {
            // Only "ok" carries a result. A revert or an unavailable/unverifiable
            // outcome is "no answer" → null, mirroring the reference engine (a
            // reverting or unverifiable eth_call returns a JSON-RPC null, not -32000).
            if ("ok".equals(stringOrNull(o, "status"))) {
                return hexToBytes(stringOrNull(o, "resultHex")); // 0x / empty → empty bytes
            }
            return null;
        } catch (RuntimeException e) {
            throw new EngineException("malformed call JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * One verified ENS forward resolution: {@code name} → its
     * {@link EnsResolutionResult}. Throws {@link EngineException} on a transport /
     * not-running failure (the RustEnsApi adapter maps that to an error result).
     */
    EnsResolutionResult resolveEnsVerified(String name) {
        return ensResolutionFromJson(name,
                gated(() -> RustEngineNative.nativeResolveEnsJson(handle, name)));
    }

    /**
     * One generic ENS record query (EL-C-5-2): raw params JSON in, raw record
     * JSON out. Parsing/typing lives in {@link RustEnsApi} (its per-record
     * fromJson seams are the golden-tested halves); this is only the native
     * transport hop.
     */
    String ensRecordJson(String paramsJson) {
        return gated(() -> RustEngineNative.nativeEnsRecordJson(handle, paramsJson));
    }

    /** Package-private test seam: ENS JSON → {@link EnsResolutionResult} without JNI. */
    static EnsResolutionResult ensResolutionFromJson(String name, String json) {
        JsonObject o = parseResultOrThrow(json, "resolve-ens");
        try {
            String status = stringOrNull(o, "status");
            // blockNumber is part of the pinned native shape for ALL statuses; a
            // missing one is shape drift -> fail closed (like ok-without-address).
            var bn = o.get("blockNumber");
            if (bn == null || bn.isNull()) {
                throw new EngineException("resolve-ens JSON: missing blockNumber");
            }
            long block = bn.asLong();
            // verified=false: the resolution IS proof-verified against the
            // beacon-anchored optimistic head, but "verified" in this API means a
            // beacon-FINALIZED root (see RustEnsApi) — don't overclaim.
            return switch (status == null ? "" : status) {
                // status=ok MUST carry an address; a missing one is native shape
                // drift -> fail closed (EngineException), NOT a silent result that
                // would read as the API's successful "no record" (same convention
                // as estimateGasFromJson's ok-without-gas).
                case "ok" -> {
                    String addressHex = stringOrNull(o, "addressHex");
                    if (addressHex == null || addressHex.isBlank()) {
                        throw new EngineException(
                                "resolve-ens JSON: status=ok without an addressHex");
                    }
                    yield new EnsResolutionResult(name, addressHex, block, false, null);
                }
                // API convention: addressHex==null && error==null is a SUCCESSFUL
                // "name has no record".
                case "noRecord" -> new EnsResolutionResult(name, null, block, false, null);
                case "offchain" -> new EnsResolutionResult(name, null, block, false,
                        "name resolves offchain (ERC-3668); CCIP-Read not yet supported"
                        + " on the rust engine");
                default -> throw new EngineException(
                        "resolve-ens JSON: unknown status '" + status + "'");
            };
        } catch (EngineException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new EngineException(
                    "malformed resolve-ens JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * One verified {@code eth_estimateGas}: the gas-limit estimate, or null. {@code
     * from} empty for an anonymous sender; {@code valueDecimal} is wei as a decimal
     * string. Throws {@link EngineException} on a transport / not-running failure.
     */
    Long estimateGasVerified(String fromHex, String toHex, String dataHex, String valueDecimal) {
        return estimateGasFromJson(gated(() -> RustEngineNative.nativeEstimateGasJson(
                handle, fromHex, toHex, dataHex, valueDecimal)));
    }

    /** Package-private test seam: estimateGas JSON → gas estimate (or null) without JNI. */
    static Long estimateGasFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "estimateGas");
        // A revert / unavailable run has no estimate → null.
        if (!"ok".equals(stringOrNull(o, "status"))) return null;
        // status == "ok" MUST carry a numeric gas; a missing/non-numeric one is native
        // shape drift → fail closed (EngineException), not a silent "unavailable".
        try {
            var gas = o.get("gas");
            if (gas == null || gas.isNull()) {
                throw new EngineException("estimateGas JSON: status=ok without a numeric 'gas' field");
            }
            return gas.asLong();
        } catch (EngineException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new EngineException(
                    "malformed estimateGas JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * One verified 32-byte storage word at a RAW position (eth_getStorageAt), or
     * null when unverified. The value is left-padded to a full 32-byte word (a
     * zero/unset slot → 32 zero bytes). {@code position32Hex} is the 0x-hex 32-byte
     * position. Throws {@link EngineException} on a transport / not-running failure.
     */
    byte[] storageAtVerified(String hexAddress, String position32Hex) {
        return storageValueFromJson(gated(() -> RustEngineNative.nativeGetStorageAtJson(
                handle, hexAddress, position32Hex)));
    }

    /**
     * Verified eth_getBlockByNumber: the block JSON object, the literal
     * {@code "null"} (a verified future/unknown block → eth null), or throws
     * {@link EngineException} when it can't verify (transport / not-running).
     * {@code blockTag} is an eth block selector ({@code "latest"} / 0x-hex number);
     * {@code fullTransactions} selects decoded tx objects over hashes.
     */
    String blockByNumberJson(String blockTag, boolean fullTransactions) {
        return blockJsonOrThrow(
                gated(() -> RustEngineNative.nativeGetBlockByNumberJson(
                        handle, blockTag, fullTransactions)));
    }

    /**
     * Verified eth_getTransactionReceipt: the receipt JSON object, the literal
     * {@code "null"} (a verified "not seen" — pending/unknown tx, the wallet keeps
     * polling), or throws {@link EngineException} when it can't verify (transport /
     * not-running). {@code txHashHex} is the 0x-hex 32-byte tx hash.
     */
    /**
     * The pending-tag nonce overlay: {@code max(minedNonce, our broadcast nonce + 1)}
     * while unmined+unexpired, identity otherwise. A negative native answer
     * (malformed input / not running) falls back to the plain mined nonce.
     */
    long pendingNonceOverlay(String addressHex, long minedNonce) {
        long overlaid = RustEngineNative.nativePendingNonceOverlay(handle, addressHex, minedNonce);
        return overlaid >= 0 ? overlaid : minedNonce;
    }

    String transactionReceiptJson(String txHashHex) {
        return receiptJsonOrThrow(
                gated(() -> RustEngineNative.nativeGetTransactionReceiptJson(handle, txHashHex)));
    }

    /**
     * Verified eth_getTransactionByHash: the tx JSON object, the literal
     * {@code "null"} (a verified "not seen" — unknown/pending tx), or throws
     * {@link EngineException} when it can't verify (transport / not-running /
     * an undecodable located tx). {@code txHashHex} is the 0x-hex 32-byte hash.
     */
    String transactionByHashJson(String txHashHex) {
        return transactionJsonOrThrow(
                gated(() -> RustEngineNative.nativeGetTransactionByHashJson(handle, txHashHex)));
    }

    /**
     * Verified eth_getBlockByHash: the block JSON object, the literal
     * {@code "null"} (a hash this engine never verified / reorged away — eth's
     * unknown-block null), or throws {@link EngineException} when it can't
     * verify. {@code blockHashHex} is the 0x-hex 32-byte hash;
     * {@code fullTransactions} selects decoded tx objects over hashes.
     */
    String blockByHashJson(String blockHashHex, boolean fullTransactions) {
        return blockJsonOrThrow(
                gated(() -> RustEngineNative.nativeGetBlockByHashJson(
                        handle, blockHashHex, fullTransactions)));
    }

    /**
     * Verified eth_feeHistory: the result JSON object, or throws
     * {@link EngineException} when it can't verify (transport / not-running /
     * bad selector) — this method has no {@code "null"} literal case, but the
     * shared tri-state parse tolerates one harmlessly. {@code percentilesJson}
     * is a JSON array of reward percentiles, or empty to omit the reward matrix.
     */
    String feeHistoryJson(long blockCount, String newestBlockTag, String percentilesJson) {
        return feeHistoryJsonOrThrow(gated(() -> RustEngineNative.nativeFeeHistoryJson(
                handle, blockCount, newestBlockTag, percentilesJson)));
    }

    /** Package-private test seam: native feeHistory payload → JSON | throw. */
    static String feeHistoryJsonOrThrow(String json) {
        return jsonObjectOrThrow(json, "feeHistory");
    }

    /**
     * eth_getLogs over the opt-in watch-list index. Returns the native payload
     * VERBATIM — the log ARRAY on success, or the {@code {"error": ...}}
     * envelope (coverage / config detail) for the router to surface at -32000.
     * Only the lifecycle gate throws (not running / paused).
     */
    String getLogsJson(String filterJson) {
        return gated(() -> RustEngineNative.nativeGetLogsJson(handle, filterJson));
    }

    /** Install the log-index config; false = invalid config or gate down. */
    @Override
    public boolean setLogIndexConfig(String configJson) {
        try {
            return gated(() -> RustEngineNative.nativeSetLogIndexConfig(handle, configJson));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Log-index status JSON ({"error":...} when the gate is down). */
    @Override
    public String logIndexStatusJson() {
        return gated(() -> RustEngineNative.nativeLogIndexStatusJson(handle));
    }

    /**
     * Verified eth_getBlockReceipts: the receipts ARRAY JSON, the literal
     * {@code "null"} (verified unknown/future block or a never-verified hash),
     * or throws {@link EngineException} when it can't verify. {@code selector}
     * is a tag, a 0x-hex block number, or a 0x-32-byte block hash.
     */
    String blockReceiptsJson(String selector) {
        return blockReceiptsJsonOrThrow(
                gated(() -> RustEngineNative.nativeGetBlockReceiptsJson(handle, selector)));
    }

    /**
     * Package-private test seam: native payload → receipts ARRAY | "null" | throw.
     * Unlike the object seams the SUCCESS shape is a JSON array; an object is
     * either the error envelope (→ its message) or native shape drift (→ throw).
     */
    static String blockReceiptsJsonOrThrow(String json) {
        if (json == null || json.isBlank()) {
            throw new EngineException(
                    "blank blockReceipts JSON from the Rust engine (native failure?)");
        }
        if (json.equals("null")) return "null";
        com.eclipsesource.json.JsonValue v;
        try {
            v = Json.parse(json);
        } catch (RuntimeException e) {
            throw new EngineException(
                    "malformed blockReceipts JSON from the Rust engine: " + e.getMessage(), e);
        }
        if (v.isArray()) return json; // the verified receipts array
        if (v.isObject()) {
            var error = v.asObject().get("error");
            if (error != null && !error.isNull()) {
                throw new EngineException(error.isString() ? error.asString() : error.toString());
            }
        }
        throw new EngineException("blockReceipts JSON is neither an array nor an error object");
    }

    /** Package-private test seam: native block payload → block JSON | "null" | throw. */
    static String blockJsonOrThrow(String json) {
        return jsonObjectOrThrow(json, "block");
    }

    /** Package-private test seam: native tx payload → tx JSON | "null" | throw. */
    static String transactionJsonOrThrow(String json) {
        return jsonObjectOrThrow(json, "transaction");
    }

    /** Package-private test seam: native receipt payload → receipt JSON | "null" | throw. */
    static String receiptJsonOrThrow(String json) {
        return jsonObjectOrThrow(json, "receipt");
    }

    /** The shared tri-state native payload parse: a JSON object passes through, the
     *  {@code "null"} literal (a VERIFIED eth-null) passes through, an {@code error}
     *  object / blank / malformed payload throws {@link EngineException}. */
    private static String jsonObjectOrThrow(String json, String what) {
        if (json == null || json.isBlank()) {
            throw new EngineException(
                    "blank " + what + " JSON from the Rust engine (native failure?)");
        }
        // The eth-null literal (a verified negative) is not a JSON object; return it
        // before parsing so the router can emit a JSON null result.
        if (json.equals("null")) return "null";
        JsonObject o;
        try {
            o = Json.parse(json).asObject();
        } catch (RuntimeException e) {
            throw new EngineException(
                    "malformed " + what + " JSON from the Rust engine: " + e.getMessage(), e);
        }
        var error = o.get("error");
        if (error != null && !error.isNull()) {
            throw new EngineException(error.isString() ? error.asString() : error.toString());
        }
        return json; // the verified object
    }

    /** A verified fee suggestion — both values decimal-wei strings. */
    record FeeEstimate(String gasPriceWei, String maxPriorityFeePerGasWei) {}

    /** How long a fee estimate is reused so a paired gasPrice+maxPriorityFee poll
     *  shares one native compute (each is a 3-block verified fetch). */
    private static final long FEE_CACHE_TTL_NANOS = 3_000_000_000L; // 3s
    /** Value+timestamp in one volatile so a reader can't pair a fresh estimate with
     *  a stale stamp (or vice versa). Monotonic nanoTime — immune to wall-clock/NTP
     *  jumps that could otherwise expire the cache early or serve it too long. */
    private record CachedFee(FeeEstimate est, long atNanos) {}
    private volatile CachedFee cachedFee;

    /**
     * Verified fee suggestion, cached for {@link #FEE_CACHE_TTL_NANOS}. Throws
     * {@link EngineException} when it can't verify (transport / not-running) — the
     * error is never cached, so the next call retries.
     */
    FeeEstimate feeEstimate() {
        CachedFee c = cachedFee;
        if (c != null && System.nanoTime() - c.atNanos() < FEE_CACHE_TTL_NANOS) {
            // Still a host-visible read: stamp activity (and kick a wake) even on a
            // cache hit, so a fee-polling wallet keeps the idle timer honest.
            noteActivityAndWake();
            return c.est();
        }
        FeeEstimate est = feeFromJson(gated(() -> RustEngineNative.nativeFeeEstimateJson(handle)));
        cachedFee = new CachedFee(est, System.nanoTime());
        return est;
    }

    /** Package-private test seam: fee JSON → {@link FeeEstimate} without JNI. */
    static FeeEstimate feeFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "fee");
        String gas;
        String tip;
        try {
            // Field extraction only — a type-mismatched value (asString on a non-
            // string) is Rust-side shape drift → "malformed".
            gas = stringOrNull(o, "gasPriceWei");
            tip = stringOrNull(o, "maxPriorityFeePerGasWei");
        } catch (RuntimeException e) {
            throw new EngineException("malformed fee JSON from the Rust engine: " + e.getMessage(), e);
        }
        // Missing-field check OUTSIDE the try so its message isn't re-wrapped as
        // "malformed" by the catch (EngineException is a RuntimeException).
        if (gas == null || tip == null) {
            throw new EngineException("fee JSON missing gasPriceWei/maxPriorityFeePerGasWei");
        }
        return new FeeEstimate(gas, tip);
    }

    /**
     * Gossip a signed raw transaction and return its 32-byte hash. Throws
     * {@link EngineException} when no peer could be reached / the input isn't a
     * plausible tx. {@code rawTxHex} is the 0x-hex raw transaction.
     */
    byte[] sendRawTransactionVerified(String rawTxHex) {
        return txHashFromJson(
                gated(() -> RustEngineNative.nativeSendRawTransactionJson(handle, rawTxHex)));
    }

    /** Package-private test seam: send-tx JSON → the 32-byte tx hash (throws on error). */
    static byte[] txHashFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "sendRawTransaction");
        String hex;
        try {
            hex = stringOrNull(o, "txHash");
        } catch (RuntimeException e) {
            throw new EngineException("malformed send-tx JSON from the Rust engine: " + e.getMessage(), e);
        }
        // Missing-field check OUTSIDE the try so its message isn't re-wrapped.
        if (hex == null) {
            throw new EngineException("send-tx JSON missing txHash");
        }
        byte[] hash;
        try {
            hash = hexToBytes(hex);
        } catch (RuntimeException e) {
            throw new EngineException("malformed send-tx txHash hex: " + e.getMessage(), e);
        }
        // A tx hash is exactly 32 bytes — fail closed rather than return a short/long
        // array the caller (router → hexData) would silently mis-encode.
        if (hash.length != 32) {
            throw new EngineException("send-tx txHash is not 32 bytes: " + hash.length);
        }
        return hash;
    }

    /** Package-private test seam: storage-at JSON → verified 32-byte word (or null). */
    static byte[] storageValueFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "storage");
        try {
            if (stringOrNull(o, "verifyMethod") == null) return null; // unverified → can't answer
            // valueHex is the big-endian value (leading zeros stripped) or null when the
            // slot is zero/unset; eth_getStorageAt returns a full 32-byte word.
            return leftPad32(hexToBytes(stringOrNull(o, "valueHex")));
        } catch (RuntimeException e) {
            throw new EngineException("malformed storage JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /** 0x-hex (or null/"0x"/empty) → bytes; null/empty → an empty array. */
    private static byte[] hexToBytes(String hexOrNull) {
        if (hexOrNull == null) return new byte[0];
        String h = (hexOrNull.startsWith("0x") || hexOrNull.startsWith("0X"))
                ? hexOrNull.substring(2) : hexOrNull;
        if (h.isEmpty()) return new byte[0];
        return java.util.HexFormat.of().parseHex(h);
    }

    /** Left-pad a big-endian value to a 32-byte word (a storage value is ≤ 32 bytes). */
    private static byte[] leftPad32(byte[] v) {
        if (v.length == 32) return v;
        if (v.length > 32) {
            throw new EngineException("storage value exceeds 32 bytes: " + v.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(v, 0, out, 32 - v.length, v.length);
        return out;
    }

    private static StorageProofResult storageFromJson(String hexAddress, long slot, JsonObject o) {
        try {
        return new StorageProofResult(
                o.getString("addressHex", hexAddress),
                o.getLong("slot", slot),
                stringOrNull(o, "holderHex"),
                stringOrNull(o, "storageKeyHex"),
                stringOrNull(o, "storageKeyHashHex"),
                o.getBoolean("exists", false),
                stringOrNull(o, "valueHex"),
                stringOrNull(o, "valueDecimal"),
                o.getInt("slotsReturned", 0),
                stringOrNull(o, "storageRootHex"),
                stringList(o, "proofNodesHex"),
                o.getBoolean("storageProofValid", false),
                o.getBoolean("beaconSynced", false),
                o.getBoolean("beaconChainVerified", false),
                o.getBoolean("blsVerified", false),
                o.getLong("matchedBeaconSlot", -1L),
                stringOrNull(o, "verifyMethod"),
                stringOrNull(o, "failReason"),
                o.getLong("peerBlockNumber", 0L),
                o.getLong("finalizedBlockNumber", 0L),
                o.getLong("optimisticBlockNumber", 0L),
                o.getLong("finalizedSlot", 0L),
                o.getLong("optimisticSlot", 0L),
                o.getInt("maxHeaderChainGap", 0));
        } catch (RuntimeException e) {
            throw new EngineException("malformed storage JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a native verified-read payload. A {@code {"error": "..."}} object (a
     * transport / not-running / bad-input failure) becomes an {@link EngineException};
     * a null/blank/malformed payload likewise. A verification FAILURE is NOT an error —
     * it is a full result whose {@code failReason} is set, and is returned normally.
     */
    private static JsonObject parseResultOrThrow(String json, String what) {
        if (json == null || json.isBlank()) {
            throw new EngineException((json == null ? "null" : "blank") + " " + what
                    + " JSON from the Rust engine (native failure?)");
        }
        JsonObject o;
        try {
            o = Json.parse(json).asObject();
        } catch (RuntimeException e) {
            throw new EngineException(
                    "malformed " + what + " JSON from the Rust engine: " + e.getMessage(), e);
        }
        var error = o.get("error");
        if (error != null && !error.isNull()) {
            // The Rust side always emits a string error, but tolerate a
            // structured value rather than throwing a raw library exception.
            throw new EngineException(error.isString() ? error.asString() : error.toString());
        }
        return o;
    }

    /** A JSON string field, or null when absent/JSON-null. */
    private static String stringOrNull(JsonObject o, String key) {
        var v = o.get(key);
        return (v == null || v.isNull()) ? null : v.asString();
    }

    /**
     * A JSON string-array field as an unmodifiable List. An ABSENT field yields
     * an empty list (forward-compat with an older native that omits it), but a
     * PRESENT field that isn't a string array throws (via {@code asArray()} /
     * {@code asString()}) — caught by the field-mapping try/catch as an
     * {@link EngineException}, failing closed on Rust-side shape drift.
     */
    private static List<String> stringList(JsonObject o, String key) {
        var v = o.get(key);
        if (v == null || v.isNull()) return List.of();
        List<String> out = new java.util.ArrayList<>();
        v.asArray().forEach(e -> out.add(e.asString()));
        // Unmodifiable: these lists live inside immutable result records.
        return java.util.Collections.unmodifiableList(out);
    }

    @Override
    public HeadersResult getHeaders(long startBlock, int count) {
        throw new EngineException(NOT_AVAILABLE);
    }

    @Override
    public BlockResult getBlockVerified(long blockNumber) {
        throw new EngineException(NOT_AVAILABLE);
    }

    @Override
    public DialResult dialPeer(String host, int port, String pubkeyHex) {
        throw new EngineException(NOT_AVAILABLE);
    }
}
