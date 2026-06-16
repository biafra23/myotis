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
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
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
            Duration dnsDeadline = Duration.ofSeconds(10);
            CompletableFuture<List<Enr>> elFuture = CompletableFuture.supplyAsync(
                    () -> dnsResolver.resolveAllFromStrings(network.elEnrTreeUrls(), dnsDeadline));
            CompletableFuture<List<Enr>> clFuture = CompletableFuture.supplyAsync(
                    () -> dnsResolver.resolveAllFromStrings(network.clEnrTreeUrls(), dnsDeadline));
            List<Enr> dnsElEnrs = elFuture.join();
            List<Enr> dnsClEnrs = clFuture.join();

            List<InetSocketAddress> mergedBootnodes = mergeBootnodes(dnsElEnrs);

            // 2. RLPx connector + immediate cached / DNS-direct dials.
            this.connector = buildConnector();
            dialCachedPeers();
            directDialDnsEnodes(dnsElEnrs);

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
        if (merged.size() > before) {
            log.info("[{}] DNS discovery added {} EL bootnode(s) (total: {})",
                    network.name(), merged.size() - before, merged.size());
        }
        return merged;
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
}
