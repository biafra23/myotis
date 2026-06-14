package com.jaeckel.ethp2p.app;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.core.enr.Enr;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv4.KademliaTable;
import com.jaeckel.ethp2p.networking.discv5.DiscV5Service;
import com.jaeckel.ethp2p.networking.dns.DnsEnrResolver;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.BindException;
import java.net.InetSocketAddress;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Embeddable lifecycle for the ethp2p node — discovery (discv4/discv5), the RLPx
 * connector, the beacon light client, the Unix-domain IPC server, and the verified
 * loopback JSON-RPC endpoint.
 *
 * <p>Extracted from {@code Main.runDaemon} so the same daemon can be driven two ways:
 * <ul>
 *   <li>The CLI ({@link Main}) starts it, registers a JVM shutdown hook, and blocks on
 *       {@link #awaitStop()} until a {@code stop} command or signal arrives.</li>
 *   <li>A GUI / embedder (the desktop app) starts it on a background thread and observes
 *       live state through {@link #beaconSyncState()} / {@link #connector()} /
 *       {@link #commandHandler()}, then calls {@link #close()} to tear it down.</li>
 * </ul>
 *
 * <p>Unlike the old in-method bootstrap, {@code start()} never calls {@code System.exit}:
 * a fatal startup failure cleans up any partially-started components and throws
 * {@link DaemonStartException}, leaving exit-code policy to the caller. {@link #close()}
 * is idempotent and counts down the stop latch so any awaiter wakes.
 */
public final class DaemonRuntime implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(DaemonRuntime.class);

    private static final long BACKOFF_INCOMPATIBLE_MS = 10 * 60 * 1000L; // 10 min for wrong-chain peers
    private static final long BACKOFF_TRANSIENT_MS = 30 * 1000L; // 30s for transient failures (too many peers, etc.)
    // Cap on how many DNS-resolved (EIP-1459) EL enodes we RLPx-dial directly at startup,
    // bypassing discv4. Enough to land a snap peer on NAT'd hosts (Android emulator) without
    // a dial storm where discv4 already works.
    private static final int DNS_DIRECT_DIAL_LIMIT = 50;

    /**
     * Where the daemon keeps its socket, lock, keys and caches. The CLI maps these to its
     * historical {@code /tmp} + working-directory paths; an installed desktop app maps them
     * to per-user OS directories (see {@link AppPaths}).
     */
    public record Config(
            NetworkConfig network,
            int port,
            boolean gossipsubEnabled,
            Path socketPath,
            Path lockPath,
            Path nodeKeyFile,
            Path peerCacheFile,
            Path clPeerCacheFile,
            Path syncSnapshotFile) {
    }

    /** Thrown when the daemon cannot start (lock held, port in use, …). */
    public static final class DaemonStartException extends Exception {
        public DaemonStartException(String message) {
            super(message);
        }
    }

    private final Config config;
    private final CountDownLatch stopLatch = new CountDownLatch(1);
    private final AtomicBoolean closed = new AtomicBoolean(false);

    // Started components — written by start(), read by accessors / close(). All
    // null until start() reaches them, so close() and the accessors null-guard.
    private volatile FileChannel lockChannel;
    private volatile FileLock fileLock;
    private volatile PeerCache peerCache;
    private volatile RLPxConnector connector;
    private volatile DiscV4Service discV4;
    private volatile DiscV5Service discV5;
    private volatile BeaconSyncState beaconSyncState;
    private volatile BeaconLightClient beaconLightClient;
    private volatile CommandHandler commandHandler;
    private volatile DaemonServer server;
    private volatile io.myotis.rpc.VerifiedRpcBackend rpcBackend;
    private volatile io.myotis.jsonrpc.MyotisRpcServer rpcServer;

    public DaemonRuntime(Config config) {
        this.config = config;
    }

    // -------------------------------------------------------------------------
    // Accessors for embedders (GUI). Null until start() has progressed far enough.
    // -------------------------------------------------------------------------

    public BeaconSyncState beaconSyncState() {
        return beaconSyncState;
    }

    public RLPxConnector connector() {
        return connector;
    }

    public BeaconLightClient beaconLightClient() {
        return beaconLightClient;
    }

    public CommandHandler commandHandler() {
        return commandHandler;
    }

    public CountDownLatch stopLatch() {
        return stopLatch;
    }

    /** Block until {@link #close()} or a {@code stop} command fires the latch. */
    public void awaitStop() throws InterruptedException {
        stopLatch.await();
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public void start() throws Exception {
        final NetworkConfig network = config.network();
        final int port = config.port();
        final boolean gossipsubEnabled = config.gossipsubEnabled();
        final Path socketPath = config.socketPath();
        final Path lockPath = config.lockPath();

        log.info("=== ethp2p Daemon ({}) ===", network.name());
        log.info("IPC socket: {}", socketPath);

        // 0. Acquire exclusive lock file — auto-released on process death (even kill -9)
        lockChannel = FileChannel.open(lockPath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        fileLock = lockChannel.tryLock();
        if (fileLock == null) {
            lockChannel.close();
            lockChannel = null;
            throw new DaemonStartException("Daemon already running (lock held: " + lockPath + ")");
        }

        // 1. Load or generate node key
        NodeKey nodeKey = NodeKey.loadOrGenerate(config.nodeKeyFile());
        log.info("Node ID: {}", nodeKey.nodeId().toHexString());

        // 3. Peer cache
        peerCache = new PeerCache(config.peerCacheFile());

        // 3a. EIP-1459 DNS-based peer discovery. Best-effort: on any failure (timeout,
        // missing TXT, bad signature) the resolver returns an empty list and we fall
        // through to the hardcoded + cached peers. Run EL and CL resolution concurrently
        // on virtual threads so total startup cost is max(elTimeout, clTimeout), not
        // sum. Layers stay separated so EL-tree entries only feed discv4 bootnodes and
        // CL-tree entries only feed the libp2p peer list.
        DnsEnrResolver dnsResolver = new DnsEnrResolver();
        Duration dnsDeadline = Duration.ofSeconds(10);
        CompletableFuture<List<Enr>> elFuture = CompletableFuture.supplyAsync(
                () -> dnsResolver.resolveAllFromStrings(network.elEnrTreeUrls(), dnsDeadline));
        CompletableFuture<List<Enr>> clFuture = CompletableFuture.supplyAsync(
                () -> dnsResolver.resolveAllFromStrings(network.clEnrTreeUrls(), dnsDeadline));
        List<Enr> dnsElEnrs = elFuture.join();
        List<Enr> dnsClEnrs = clFuture.join();

        List<InetSocketAddress> mergedBootnodes = new ArrayList<>(network.bootnodes());
        // Dedupe by (host, port) so trees that overlap with the hardcoded list
        // (or contain internal duplicates) don't produce repeated dial attempts.
        Set<String> seenHostPort = new java.util.HashSet<>();
        for (InetSocketAddress sa : mergedBootnodes) {
            seenHostPort.add(sa.getAddress().getHostAddress() + ":" + sa.getPort());
        }
        int bootnodesBeforeDns = mergedBootnodes.size();
        for (Enr enr : dnsElEnrs) {
            // discv4 speaks UDP; fall back to the TCP endpoint only if UDP is missing.
            enr.udpAddress().or(enr::tcpAddress).ifPresent(sa -> {
                String key = sa.getAddress().getHostAddress() + ":" + sa.getPort();
                if (seenHostPort.add(key)) mergedBootnodes.add(sa);
            });
        }
        if (mergedBootnodes.size() > bootnodesBeforeDns) {
            log.info("[main] DNS discovery added {} EL bootnode(s) (total: {})",
                    mergedBootnodes.size() - bootnodesBeforeDns, mergedBootnodes.size());
        }

        // 4. RLPx connector
        Set<String> attempted = ConcurrentHashMap.newKeySet();
        Map<String, Long> backoff = new ConcurrentHashMap<>();
        Set<String> blacklistedNodeIds = ConcurrentHashMap.newKeySet();
        connector = new RLPxConnector(nodeKey, port, network, headers -> {
            if (!headers.isEmpty()) {
                log.info("\n=== BLOCK HEADERS RECEIVED ===");
                for (BlockHeadersMessage.VerifiedHeader vh : headers) {
                    BlockHeader h = vh.header();
                    log.info("  Block #{}", h.number);
                    log.info("  Hash:      {}", vh.hash().toHexString());
                    log.info("  StateRoot: {}", h.stateRoot.toHexString());
                    log.info("  TxRoot:    {}", h.transactionsRoot.toHexString());
                    if (h.baseFeePerGas != null) {
                        log.info("  BaseFee:   {} gwei",
                                h.baseFeePerGas.divide(java.math.BigInteger.valueOf(1_000_000_000L)));
                    }
                }
            }
        }, peerCache::add);
        final RLPxConnector connector = this.connector;

        // 5. Connect to cached peers immediately
        List<PeerCache.CachedPeer> cached = peerCache.load();
        // Reconnect snap/1-capable peers first so state queries (get-account,
        // get-storage) have a snap peer available sooner after a restart. Within
        // the snap set, peers proven to serve proofs (CONFIRMED) come ahead of
        // unproven ones, and known hangers (DENIED) come last — so a restart
        // converges on a working snap peer instead of re-timing-out the bad
        // ones first (mirrors NodeService's snapDialRank ordering).
        cached.sort(java.util.Comparator.comparingInt(DaemonRuntime::snapDialRank));
        for (PeerCache.CachedPeer peer : cached) {
            String peerKey = peer.address().getAddress().getHostAddress()
                    + ":" + peer.address().getPort();
            attempted.add(peerKey);
            try {
                SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(
                        Bytes.fromHexString(peer.publicKeyHex()));
                log.info("[main] Connecting to cached peer {}", peer.address());
                connector.connect(peer.address(), pubKey, (incompatible, nodeIdHex) -> {
                            if (incompatible) {
                                blacklistedNodeIds.add(nodeIdHex);
                                log.info("[main] Blacklisted node {} (incompatible network, cached peer)", nodeIdHex.substring(0, 16) + "...");
                            }
                            long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                            backoff.putIfAbsent(peerKey, System.currentTimeMillis() + backoffMs);
                            attempted.remove(peerKey);
                        })
                        .addListener(future -> {
                            if (!future.isSuccess()) {
                                // Don't blacklist cached peers on first attempt
                                attempted.remove(peerKey);
                            }
                        });
            } catch (Exception e) {
                log.warn("[main] Failed to connect to cached peer {}: {}",
                        peer.address(), e.getMessage());
                attempted.remove(peerKey);
            }
        }

        // 5b. Directly RLPx-dial DNS-resolved EL enodes (EIP-1459), bypassing discv4.
        // discv4's endpoint proof needs the remote to send us an *unsolicited* inbound
        // PING before it returns NEIGHBORS — which QEMU/SLIRP user-mode NAT (the Android
        // emulator's default) silently drops, so discv4 never bootstraps there. RLPx is
        // an *outbound* TCP connection, which SLIRP allows, and the ENR carries the
        // peer's secp256k1 key + TCP endpoint — everything connect() needs. So we get
        // EL/snap peers on the emulator with no discv4 and no TAP networking. Harmless
        // on the daemon (just a faster warm start). Capped so this doesn't become a dial
        // storm on platforms where discv4 already populates the table.
        int directDialed = 0;
        for (Enr enr : dnsElEnrs) {
            if (directDialed >= DNS_DIRECT_DIAL_LIMIT) break;
            // Whole body guarded so a single malformed ENR can't abort the loop;
            // getHostString() avoids an NPE if the ENR address is unresolved.
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
                log.info("[main] Direct RLPx dial of DNS EL enode {}", peerTcp);
                connector.connect(peerTcp, pub.get(), (incompatible, nodeIdHex) -> {
                            if (incompatible) {
                                blacklistedNodeIds.add(nodeIdHex);
                            }
                            long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                            backoff.putIfAbsent(key, System.currentTimeMillis() + backoffMs);
                            attempted.remove(key);
                        })
                        .addListener(future -> {
                            if (!future.isSuccess()) attempted.remove(key);
                        });
            } catch (Exception e) {
                log.warn("[main] Failed direct dial of DNS EL enode: {}", e.getMessage());
                if (peerKey != null) attempted.remove(peerKey);
            }
        }
        if (directDialed > 0) {
            log.info("[main] Direct-dialed {} DNS EL enode(s) (discv4-independent path)", directDialed);
        }

        // 6. discv4 discovery
        discV4 = new DiscV4Service(nodeKey, mergedBootnodes, entry -> {
            // Pause acquiring NEW peers while an ENS resolution is running: its
            // snap round-trips share the event loop with outbound dials, and a
            // dial burst inflates resolution latency. Existing peers stay.
            if (connector.isSnapHeavy()) return;
            if (entry.tcpPort() > 0 && attempted.size() < 2000) {
                String nodeIdHex = entry.nodeId().toHexString();
                if (blacklistedNodeIds.contains(nodeIdHex)) {
                    log.debug("[main] Skipping blacklisted node {}", nodeIdHex.substring(0, 16) + "...");
                    return;
                }
                String peerKey = entry.udpAddr().getAddress().getHostAddress()
                        + ":" + entry.tcpPort();
                Long expiry = backoff.get(peerKey);
                if (expiry != null) {
                    if (System.currentTimeMillis() < expiry) return;
                    backoff.remove(peerKey);
                }
                if (attempted.add(peerKey)) {
                    InetSocketAddress peerTcp = new InetSocketAddress(
                            entry.udpAddr().getAddress(), entry.tcpPort());
                    log.info("[main] Attempting RLPx connection to {}", peerTcp);
                    tryConnectWithKnownKey(connector, entry, peerTcp, nodeKey, attempted, peerKey, backoff, blacklistedNodeIds);
                }
            }
        });

        try {
            discV4.start(port);
        } catch (Exception e) {
            Throwable cause = e instanceof BindException ? e : e.getCause();
            String msg = (cause instanceof BindException)
                    ? "Cannot bind UDP port " + port + ": " + cause.getMessage()
                    + "\nIs another instance already running?"
                    : "Failed to start discovery: " + e.getMessage();
            close();
            throw new DaemonStartException(msg);
        }
        log.info("[daemon] discv4 started on UDP port {}. Waiting for peers...", port);

        // Beacon light client scaffolding (moved ahead of discv5 so its callback can
        // write to CLPeerCache as peers are discovered).
        beaconSyncState = new BeaconSyncState();
        final BeaconSyncState beaconSyncState = this.beaconSyncState;
        CLPeerCache clPeerCache = new CLPeerCache(config.clPeerCacheFile());

        // 6b. discv5 — the canonical CL peer discovery mechanism. Runs on a separate
        // UDP port from discv4 (default 9000, matching CL libp2p convention). The
        // callback filters to ENRs carrying the eth2 field with a matching fork digest,
        // converts to a libp2p multiaddr, and writes to CLPeerCache so the next
        // daemon start seeds BeaconLightClient with a refreshed list.
        //
        // Runtime integration with the running BLC is a follow-up: BLC freezes its
        // peer list at construction. The feedback loop is one daemon restart today.
        List<byte[]> acceptedForkDigests = network.acceptedForkDigests();
        log.info("[discv5] accepted fork_digests for network {}: {}",
                network.name(),
                acceptedForkDigests.stream()
                        .map(d -> "0x" + java.util.HexFormat.of().formatHex(d))
                        .toList());
        // Log the first few mismatches so we can tell whether the filter is
        // rejecting every peer (wrong expected digest?) vs. no peers arriving.
        java.util.concurrent.atomic.AtomicInteger mismatchesLogged =
                new java.util.concurrent.atomic.AtomicInteger();
        // Discovered peers land here; BLC is constructed a few lines below and
        // has this reference set once it's up so the discv5 callback can feed
        // fresh peers directly into its live pool, not just the on-disk cache.
        java.util.concurrent.atomic.AtomicReference<BeaconLightClient> blcRef =
                new java.util.concurrent.atomic.AtomicReference<>();
        discV5 = new DiscV5Service(nodeKey, network.clDiscv5Bootnodes(), enr -> {
            var eth2 = enr.eth2();
            if (eth2.isEmpty()) return;
            byte[] peerDigest = eth2.get().forkDigest();
            int matchIdx = -1;
            for (int i = 0; i < acceptedForkDigests.size(); i++) {
                if (java.util.Arrays.equals(peerDigest, acceptedForkDigests.get(i))) {
                    matchIdx = i;
                    break;
                }
            }
            if (matchIdx < 0) {
                int n = mismatchesLogged.incrementAndGet();
                if (n <= 5) {
                    log.info("[discv5] eth2 peer fork_digest=0x{} not in accepted set — rejected{}",
                            java.util.HexFormat.of().formatHex(peerDigest),
                            n == 5 ? " [further mismatch logs suppressed]" : "");
                }
                return;
            }
            final int mi = matchIdx;
            enr.toLibp2pMultiaddr().ifPresent(ma -> {
                String tier = mi == 0 ? "current" : "prior";
                clPeerCache.add(ma);
                BeaconLightClient blc = blcRef.get();
                boolean liveAdded = blc != null && blc.addPeer(ma);
                log.info("[discv5] CL peer {} (fork_digest {} match){}", ma, tier,
                        liveAdded ? " → live pool" : "");
            });
        });
        try {
            discV5.start(9000);
        } catch (Throwable t) {
            // Catch Throwable, not Exception: earlier we hit a NoClassDefFoundError
            // (library static-init) which slipped past an Exception handler and
            // killed the main thread while the Netty event loop kept the JVM alive
            // — the daemon lock stayed held but the IPC socket never got created.
            // discv5 is non-essential; EL keeps working and CL falls back to the
            // cache + hardcoded seed list.
            log.warn("[discv5] failed to start, continuing without CL discovery: {}", t.toString());
        }

        // 7. Beacon light client (consensus layer, runs on virtual thread)
        List<String> clPeers = new java.util.ArrayList<>(clPeerCache.load());
        // Append configured peers after cached ones (cached peers are tried first)
        for (String peer : network.clPeerMultiaddrs()) {
            if (!clPeers.contains(peer)) clPeers.add(peer);
        }
        // Append DNS-discovered CL peers (from enrtree:// resolution above). Deduped
        // against cached + configured entries.
        int clPeersBeforeDns = clPeers.size();
        for (Enr enr : dnsClEnrs) {
            enr.toLibp2pMultiaddr().ifPresent(ma -> {
                if (!clPeers.contains(ma)) clPeers.add(ma);
            });
        }
        if (clPeers.size() > clPeersBeforeDns) {
            log.info("[main] DNS discovery added {} CL peer(s) (total: {})",
                    clPeers.size() - clPeersBeforeDns, clPeers.size());
        }
        beaconLightClient = new BeaconLightClient(
                clPeers,
                network.checkpointRoot(),
                network.checkpointSlot(),
                network.currentForkVersion(),
                network.genesisValidatorsRoot(),
                beaconSyncState,
                network.beaconApiUrl(),
                clPeerCache::add,
                clPeerCache::markFailure,
                network.clGenesisTime());
        final BeaconLightClient beaconLightClient = this.beaconLightClient;
        // EIP-7892: apply active BPO blob-parameters so compute_fork_digest
        // folds them in per the Fulu spec (XOR of base fork_data_root[0..4]
        // with sha256(u64_le(epoch)||u64_le(max_blobs))[0..4]).
        beaconLightClient.setBlobParameters(
                network.activeBlobParamsEpoch(),
                network.activeBlobParamsMaxBlobs());
        // Prefer peers proven to serve catch-up last session (seeded with the
        // period they served), and persist new ones, so restarts target peers
        // that actually retain the checkpoint period instead of discovery noise.
        beaconLightClient.setProvenCatchUpServers(clPeerCache.servedPeriods());
        beaconLightClient.setOnCatchUpServed(clPeerCache::recordServed);
        // Seed light_client-capability verdicts from last session and persist new ones, so a
        // restart dials confirmed light-client servers first and deprioritizes peers proven
        // not to serve LC — instead of re-Identifying the whole fork-matched cache.
        beaconLightClient.setProvenLightClient(clPeerCache.lightClientConfirmed());
        beaconLightClient.setProvenNonLightClient(clPeerCache.lightClientDenied());
        beaconLightClient.setOnLightClientVerdict(clPeerCache::markLightClientBatch);
        // Persist/resume verified sync-committee state so restarts resume from the
        // last verified period and only catch up the delta (architecture-doc §
        // "recent sync committee data persisted locally"). purge-cache removes it.
        beaconLightClient.setSnapshotFile(config.syncSnapshotFile());
        // Off by default (short-session clients churn the mesh). Enable
        // with `-Pgossipsub=true` via gradle or `--gossipsub` on the CLI.
        beaconLightClient.setGossipsubEnabled(gossipsubEnabled);
        if (gossipsubEnabled) {
            log.info("[main] Gossipsub subscription ENABLED (observation-only)");
        }
        // Publish to discv5 callback; any eth2-matching ENRs seen from here on
        // out get added to BLC's live peer pool (not just the on-disk cache).
        blcRef.set(beaconLightClient);
        beaconLightClient.start();
        log.info("[daemon] Beacon light client started with {} CL peer(s) ({} cached)",
                clPeers.size(), clPeers.size() - network.clPeerMultiaddrs().size());

        // 8. IPC server
        commandHandler = new CommandHandler(discV4, discV5, connector, stopLatch, backoff, blacklistedNodeIds, beaconSyncState, beaconLightClient, network.clGenesisTime());
        server = new DaemonServer(socketPath, commandHandler);
        try {
            server.start();
        } catch (BindException e) {
            close();
            throw new DaemonStartException("Cannot bind IPC socket " + socketPath + ": " + e.getMessage()
                    + "\nIs another instance already running?");
        } catch (Exception e) {
            close();
            throw new DaemonStartException("Failed to start IPC server: " + e.getMessage());
        }

        // 8b. Verified JSON-RPC endpoint: the shared VerifiedRpcBackend (same
        // implementation the Android app hosts in NodeService) served over the
        // Ktor MyotisRpcServer. Bound loopback-only — the endpoint is
        // unauthenticated and TLS-less, so it must not be exposed on a routable
        // interface — and STRICT (null upstream): the daemon never proxies; a
        // method that can't be answered cryptographically verified errors.
        // Best-effort: if port 8545 is taken (another node / dev tool), the
        // daemon keeps running without RPC instead of crashing.
        try {
            // Deterministic port check up front: Ktor's CIO engine surfaces a bind
            // failure asynchronously, which a try/catch around start() can miss.
            try (java.net.ServerSocket probe = new java.net.ServerSocket()) {
                probe.setReuseAddress(true);
                probe.bind(new InetSocketAddress("127.0.0.1", 8545));
            }
            // Persist per-peer snap-serving verdicts into the EL peer cache so
            // proven snap-servers are dialed first on restart and repeat hangers
            // are deprioritized (same wiring as NodeService → AndroidPeerCache).
            final PeerCache peerCache = this.peerCache;
            io.myotis.rpc.SnapQualitySink snapQualitySink = new io.myotis.rpc.SnapQualitySink() {
                @Override public void recordSnapServed(InetSocketAddress address) {
                    peerCache.recordSnapServed(address);
                }
                @Override public void recordSnapFailure(InetSocketAddress address) {
                    peerCache.recordSnapFailure(address);
                }
            };
            io.myotis.rpc.RpcLogger rpcLogger = new io.myotis.rpc.RpcLogger() {
                @Override public void info(String message) { log.info(message); }
                @Override public void warn(String message) { log.warn(message); }
            };
            io.myotis.rpc.VerifiedRpcBackend backend = new io.myotis.rpc.VerifiedRpcBackend(
                    connector, beaconLightClient, beaconSyncState,
                    new com.jaeckel.ethp2p.app.rpc.JavaHttpCcipGateway(),
                    rpcLogger, io.myotis.rpc.RpcClock.monotonic(), snapQualitySink);
            try {
                // start() spins up the head warmer; a throw here (or in the server
                // start below) must still close the backend so its threads don't leak.
                backend.start();
                io.myotis.jsonrpc.MyotisRpcServer rpcServer =
                        new io.myotis.jsonrpc.MyotisRpcServer(8545, null, "127.0.0.1", backend);
                rpcServer.start();
                this.rpcServer = rpcServer;
                this.rpcBackend = backend;
                log.info("JSON-RPC listening on http://127.0.0.1:8545 (verified, strict)");
            } catch (Throwable serverEx) {
                backend.close();
                throw serverEx;
            }
        } catch (java.io.IOException bindEx) {
            log.warn("[rpc] port 8545 unavailable ({}); continuing without JSON-RPC",
                    bindEx.getMessage());
        } catch (Throwable t) {
            log.warn("[rpc] failed to start JSON-RPC server; continuing without it: {}",
                    t.toString());
        }

        log.info("[daemon] ready");
    }

    /**
     * Tear everything down. Idempotent and safe to call from a JVM shutdown hook,
     * a {@code stop} command, or a partially-failed {@link #start()}. Fires the stop
     * latch so any {@link #awaitStop()} caller wakes.
     */
    @Override
    public void close() {
        if (closed.getAndSet(true)) {
            // Still make sure a late awaiter wakes even on a redundant close.
            stopLatch.countDown();
            return;
        }
        log.info("[daemon] Shutting down");
        // Stop the RPC endpoint first so the port frees and no in-flight
        // request builds against torn-down components.
        if (rpcServer != null) {
            try { rpcServer.stop(); } catch (Throwable ignored) {}
        }
        if (rpcBackend != null) {
            try { rpcBackend.close(); } catch (Throwable ignored) {}
        }
        if (beaconLightClient != null) {
            try { beaconLightClient.close(); } catch (Throwable ignored) {}
        }
        if (server != null) {
            try { server.close(); } catch (Throwable ignored) {}
        }
        if (connector != null) {
            try { connector.close(); } catch (Throwable ignored) {}
        }
        if (discV5 != null) {
            try { discV5.close(); } catch (Throwable ignored) {}
        }
        if (discV4 != null) {
            try { discV4.close(); } catch (Throwable ignored) {}
        }
        if (peerCache != null) {
            try { peerCache.close(); } catch (Throwable ignored) {}   // last: drain queued cache writes after the final add()
        }
        try {
            if (fileLock != null) fileLock.release();
            if (lockChannel != null) lockChannel.close();
        } catch (Exception ignored) {}
        stopLatch.countDown();
        log.info("[daemon] Done.");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Dial-priority rank for a cached peer (lower = dialed first): proven
     * snap-servers, then snap-capable-but-unproven, then known snap hangers, then
     * plain-eth peers. Denied snap peers still outrank non-snap peers — state
     * roots change, so a peer that couldn't serve an old pivot may serve the
     * current head, and it's still snap-capable. Mirrors NodeService.snapDialRank.
     */
    private static int snapDialRank(PeerCache.CachedPeer p) {
        if (!p.snap()) return 3;
        return switch (p.snapQuality()) {
            case CONFIRMED -> 0;
            case UNKNOWN -> 1;
            case DENIED -> 2;
        };
    }

    /**
     * In discv4, the Neighbors response includes 64-byte node IDs (public keys).
     * We reconstruct the SECP256K1 public key and attempt connection.
     */
    private static void tryConnectWithKnownKey(
            RLPxConnector connector, KademliaTable.Entry entry,
            InetSocketAddress peerTcp, NodeKey localKey,
            Set<String> attempted, String peerKey,
            Map<String, Long> backoff, Set<String> blacklistedNodeIds) {
        try {
            Bytes nodeId = entry.nodeId();
            if (nodeId.size() != 64) {
                log.warn("[main] Node ID is not 64 bytes ({}b), skipping", nodeId.size());
                attempted.remove(peerKey);
                return;
            }
            SECP256K1.PublicKey peerPubkey = SECP256K1.PublicKey.fromBytes(nodeId);
            connector.connect(peerTcp, peerPubkey, (incompatible, nodeIdHex) -> {
                        if (incompatible) {
                            blacklistedNodeIds.add(nodeIdHex);
                            log.info("[main] Blacklisted node {} (incompatible network)", nodeIdHex.substring(0, 16) + "...");
                        }
                        long backoffMs = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                        backoff.putIfAbsent(peerKey, System.currentTimeMillis() + backoffMs);
                        attempted.remove(peerKey);
                    })
                    .addListener(future -> {
                        if (!future.isSuccess()) {
                            log.warn("[main] Connection to {} failed: {}",
                                    peerTcp, future.cause().getMessage());
                            backoff.putIfAbsent(peerKey, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
                            attempted.remove(peerKey);
                        }
                    });
        } catch (Exception e) {
            log.warn("[main] Failed to connect to {}: {}", peerTcp, e.getMessage());
            backoff.putIfAbsent(peerKey, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
            attempted.remove(peerKey);
        }
    }
}
