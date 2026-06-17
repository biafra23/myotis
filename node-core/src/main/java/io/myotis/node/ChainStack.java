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
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
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
    private final AtomicBoolean running = new AtomicBoolean(false);

    // -- snap-peer maintainer (optional; enabled via configureSnapMaintainer) --
    private volatile boolean maintainerEnabled = false;
    private volatile int targetSnapPeers = 32;
    private DnsServerProvider dnsServerProvider;            // null → resolver's default DNS
    private volatile List<Enr> dnsElPool = List.of();
    private final AtomicBoolean dnsResolving = new AtomicBoolean(false);
    private volatile long lastDnsResolveMs = 0L;
    private volatile long dnsDialWindowStartMs = 0L;
    private final AtomicInteger dnsDialsInWindow = new AtomicInteger(0);
    private volatile ScheduledExecutorService peerMaintainer;

    // -- live components (built in start()) ------------------------------------
    private volatile RLPxConnector connector;
    private volatile DiscV4Service discV4;
    private volatile DiscV5Service discV5;
    private volatile BeaconSyncState beaconSyncState;
    private volatile BeaconLightClient beaconLightClient;
    private volatile io.myotis.rpc.VerifiedRpcBackend rpcBackend;
    private volatile io.myotis.jsonrpc.MyotisRpcServer rpcServer;

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
        if (running.get()) {
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
        if (!running.compareAndSet(false, true)) return true; // already started
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

            List<InetSocketAddress> mergedBootnodes = mergeBootnodes(dnsElEnrs);

            // 2. RLPx connector + immediate cached / DNS-direct dials.
            this.connector = buildConnector();
            dialCachedPeers();
            directDialDnsEnodes(dnsElEnrs);
            directDialStaticEnodes();   // enrtree substitute for chains without one (Gnosis)

            // 3. discv4.
            this.discV4 = buildDiscV4(mergedBootnodes);
            try {
                discV4.start(ports.elPort());
            } catch (Exception e) {
                log.error("[{}] discv4 failed to bind UDP {}: {}", network.name(), ports.elPort(), e.toString());
                throw e; // EL is essential — fail this stack
            }
            log.info("[{}] discv4 started on UDP port {}", network.name(), ports.elPort());

            // 4. Beacon: sync-state + discv5 (CL discovery) + light client.
            this.beaconSyncState = new BeaconSyncState();
            startDiscV5AndBeacon(dnsClEnrs);

            // 5. Verified JSON-RPC (best-effort; a bind failure here does not fail the stack).
            startRpc();

            // 6. Snap-peer maintainer (optional): keep snap peers topped up from cache +
            //    the refreshing DNS pool. The discv4-independent path NAT'd hosts need.
            if (maintainerEnabled) startPeerMaintainer();

            return true;
        } catch (Throwable t) {
            log.error("[{}] stack failed to start: {}", network.name(), t.toString());
            shutdown();
            return false;
        }
    }

    /** Tear down this stack's components (reverse order) and release its caches. */
    public synchronized void shutdown() {
        running.set(false);
        ScheduledExecutorService pm = peerMaintainer;
        if (pm != null) { pm.shutdownNow(); peerMaintainer = null; }
        if (rpcServer != null) { try { rpcServer.stop(); } catch (Throwable ignored) {} }
        if (rpcBackend != null) { try { rpcBackend.close(); } catch (Throwable ignored) {} }
        if (beaconLightClient != null) { try { beaconLightClient.close(); } catch (Throwable ignored) {} }
        if (connector != null) { try { connector.close(); } catch (Throwable ignored) {} }
        if (discV5 != null) { try { discV5.close(); } catch (Throwable ignored) {} }
        if (discV4 != null) { try { discV4.close(); } catch (Throwable ignored) {} }
        try { peerCache.close(); } catch (Throwable ignored) {}
        try { clPeerCache.close(); } catch (Throwable ignored) {}
        attempted.clear();
        backoff.clear();
        blacklistedNodeIds.clear();
    }

    // -------------------------------------------------------------------------
    // Accessors (for the host's IPC / UI layer)
    // -------------------------------------------------------------------------

    public NetworkConfig network() { return network; }
    public ChainPorts ports() { return ports; }
    public boolean isRunning() { return running.get(); }
    public RLPxConnector connector() { return connector; }
    public DiscV4Service discV4() { return discV4; }
    public DiscV5Service discV5() { return discV5; }
    public BeaconSyncState beaconSyncState() { return beaconSyncState; }
    public BeaconLightClient beaconLightClient() { return beaconLightClient; }
    /** The verified backend (for ENS resolution / verified reads), or null if RPC didn't start. */
    public io.myotis.rpc.VerifiedRpcBackend rpcBackend() { return rpcBackend; }
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
                connector.connect(pe.address(), pe.pubkey(), (incompatible, nodeIdHex) -> {
                            if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                            backoff.putIfAbsent(key, System.currentTimeMillis()
                                    + (incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS));
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

    private RLPxConnector buildConnector() {
        return new RLPxConnector(nodeKey, ports.elPort(), network, headers -> {
            if (!headers.isEmpty()) {
                log.debug("[{}] {} block header(s) received", network.name(), headers.size());
            }
        }, (address, publicKeyHex, snap) -> peerCache.add(address, publicKeyHex, snap));
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
                connector.connect(peer.address(), pubKey, (incompatible, nodeIdHex) -> {
                            if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                            long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
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
                connector.connect(peerTcp, pub.get(), (incompatible, nodeIdHex) -> {
                            if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                            long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
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

    private void startDiscV5AndBeacon(List<Enr> dnsClEnrs) {
        List<byte[]> acceptedForkDigests = network.acceptedForkDigests();
        AtomicInteger mismatchesLogged = new AtomicInteger();
        AtomicReference<BeaconLightClient> blcRef = new AtomicReference<>();

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
                BeaconLightClient blc = blcRef.get();
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

        // Beacon light client.
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
        blcRef.set(blc);
        blc.start();
        this.beaconLightClient = blc;
        log.info("[{}] Beacon light client started with {} CL peer(s)", network.name(), clPeers.size());
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
            try {
                backend.start();
                io.myotis.jsonrpc.MyotisRpcServer server =
                        new io.myotis.jsonrpc.MyotisRpcServer(rpcPort, null, "127.0.0.1", backend);
                server.start();
                this.rpcServer = server;
                this.rpcBackend = backend;
                log.info("[{}] JSON-RPC listening on http://127.0.0.1:{} (verified, strict)",
                        network.name(), rpcPort);
            } catch (Throwable serverEx) {
                backend.close();
                throw serverEx;
            }
        } catch (java.io.IOException bindEx) {
            log.warn("[{}][rpc] port {} unavailable ({}); continuing without JSON-RPC",
                    network.name(), rpcPort, bindEx.getMessage());
        } catch (Throwable t) {
            log.warn("[{}][rpc] failed to start JSON-RPC; continuing without it: {}",
                    network.name(), t.toString());
        }
    }

    private void tryConnectWithKnownKey(KademliaTable.Entry entry, InetSocketAddress peerTcp, String peerKey) {
        try {
            Bytes nodeId = entry.nodeId();
            if (nodeId.size() != 64) { attempted.remove(peerKey); return; }
            SECP256K1.PublicKey peerPubkey = SECP256K1.PublicKey.fromBytes(nodeId);
            connector.connect(peerTcp, peerPubkey, (incompatible, nodeIdHex) -> {
                        if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                        long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
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

    private void startPeerMaintainer() {
        if (peerMaintainer != null) return;
        peerMaintainer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "snap-peer-maintainer-" + network.name());
            t.setDaemon(true);
            return t;
        });
        peerMaintainer.scheduleWithFixedDelay(this::maintainSnapPeers, 5, 10, TimeUnit.SECONDS);
    }

    /** Keep {@code activeSnapHandlers() >= targetSnapPeers}: re-dial cached snap peers,
     *  then top up from the DNS ENR pool (rate-capped), then refresh the pool if still low. */
    private void maintainSnapPeers() {
        if (!running.get()) return;
        // Guard the whole body: an uncaught throw would make scheduleWithFixedDelay
        // silently stop all future runs.
        try {
            RLPxConnector conn = connector;
            if (conn == null) return;
            int snapPeers = conn.activeSnapHandlers().size();
            if (snapPeers >= targetSnapPeers) return;
            long now = System.currentTimeMillis();
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
                    dialCachedSnapPeer(conn, p, now);
                } catch (Exception e) {
                    log.warn("[{}][peers] skipping cached peer: {}", network.name(), e.getMessage());
                }
            }
            // 2) Top up from the DNS-resolved ENR pool (discv4 substitute on NAT'd hosts),
            //    bounded by a per-cycle batch and a rolling-minute rate cap.
            List<Enr> pool = dnsElPool;
            if (!pool.isEmpty() && conn.activeSnapHandlers().size() < targetSnapPeers) {
                int budget = Math.min(DNS_MAINTAIN_DIAL_BATCH, dnsDialBudget());
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
            if (conn.activeSnapHandlers().size() < targetSnapPeers
                    && !dnsResolving.get()
                    && System.currentTimeMillis() - lastDnsResolveMs > DNS_REFRESH_INTERVAL_MS) {
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
            // The resolve can take ~25s; if the stack was shut down meanwhile, drop the
            // result instead of merging into / writing the pool of a dead stack.
            if (!running.get()) return;
            lastDnsResolveMs = System.currentTimeMillis();

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
            dnsElPool = new ArrayList<>(merged.values());
            log.info("[{}] DNS EL pool: +{} new, {} dropped (off-fork/malformed), {} total",
                    network.name(), added, dropped, dnsElPool.size());
        } catch (Exception e) {
            log.warn("[{}] DNS EL pool refresh failed: {}", network.name(), e.getMessage());
        } finally {
            dnsResolving.set(false);
        }
    }

    /** Remaining DNS-pool dials allowed in the current rolling minute (see DNS_DIALS_PER_MIN). */
    private int dnsDialBudget() {
        long now = System.currentTimeMillis();
        if (now - dnsDialWindowStartMs >= 60_000L) {
            dnsDialWindowStartMs = now;
            dnsDialsInWindow.set(0);
        }
        return Math.max(0, DNS_DIALS_PER_MIN - dnsDialsInWindow.get());
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
            conn.connect(peerTcp, pub.get(), (incompatible, idHex) -> {
                if (incompatible) blacklistedNodeIds.add(idHex);
                long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                backoff.putIfAbsent(key, System.currentTimeMillis() + ms);
                attempted.remove(key);
            }).addListener(future -> {
                if (!future.isSuccess()) {
                    backoff.putIfAbsent(key, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
                    attempted.remove(key);
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
            conn.connect(p.address(), pubKey, (incompatible, idHex) -> {
                if (incompatible) blacklistedNodeIds.add(idHex);
                long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                backoff.putIfAbsent(peerKey, System.currentTimeMillis() + ms);
                attempted.remove(peerKey);
            }).addListener(future -> {
                // TCP-level failure (refused/timeout) fires here, not the handshake
                // callback above — free the slot and back off so a dead peer can't pin
                // `attempted` and eventually starve the pool at MAX_ATTEMPTED.
                if (!future.isSuccess()) {
                    backoff.putIfAbsent(peerKey, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
                    attempted.remove(peerKey);
                }
            });
        } catch (Exception e) {
            attempted.remove(peerKey);
        }
    }
}
