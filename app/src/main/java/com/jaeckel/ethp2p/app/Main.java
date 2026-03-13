package com.jaeckel.ethp2p.app;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv4.KademliaTable;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/**
 * ethp2p — daemon + CLI client.
 *
 * <h2>Usage</h2>
 * <pre>
 *   # Start daemon (blocks; creates /tmp/ethp2p.sock):
 *   ./gradlew :app:run
 *
 *   # Send a command to the running daemon (from a second terminal):
 *   ./gradlew :app:run -Pargs=status
 *   ./gradlew :app:run -Pargs=peers
 *   ./gradlew :app:run -Pargs="get-headers 21000000 3"
 *   ./gradlew :app:run -Pargs=stop
 *
 *   # Purge cached peers:
 *   ./gradlew :app:run -Pargs=purge-cache
 *
 *   # Use a testnet (default: mainnet):
 *   ./gradlew :app:run -Pnetwork=sepolia
 *   ./gradlew :app:run -Pnetwork=sepolia -Pargs=peers
 *
 *   # Or use nc directly:
 *   echo '{"cmd":"status"}' | nc -U /tmp/ethp2p.sock
 * </pre>
 *
 * <h2>Behaviour</h2>
 * <ul>
 *   <li>If the IPC socket exists → client mode: send one command, print response, exit.
 *   <li>If the IPC socket is absent → daemon mode: run discovery + RLPx, serve commands.
 * </ul>
 */
public final class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final int DEFAULT_PORT = 30303;
    private static final long BACKOFF_INCOMPATIBLE_MS = 10 * 60 * 1000L; // 10 min for wrong-chain peers
    private static final long BACKOFF_TRANSIENT_MS = 30 * 1000L; // 30s for transient failures (too many peers, etc.)

    /** Socket path; override via {@code ETHP2P_SOCKET} env var. Network-specific suffix for non-mainnet. */
    static Path socketPath(String networkName) {
        String env = System.getenv("ETHP2P_SOCKET");
        if (env != null) return Path.of(env);
        String suffix = "mainnet".equals(networkName) ? "" : "-" + networkName;
        return Path.of("/tmp/ethp2p" + suffix + ".sock");
    }

    /** Lock file path, network-suffixed like the socket. */
    static Path lockPath(String networkName) {
        String suffix = "mainnet".equals(networkName) ? "" : "-" + networkName;
        return Path.of("/tmp/ethp2p" + suffix + ".lock");
    }

    static Path cacheFile(String networkName) {
        String suffix = "mainnet".equals(networkName) ? "" : "-" + networkName;
        return Path.of("peers" + suffix + ".cache");
    }

    static Path clCacheFile(String networkName) {
        String suffix = "mainnet".equals(networkName) ? "" : "-" + networkName;
        // Place alongside the EL peer cache in the same directory
        return cacheFile(networkName).resolveSibling("cl-peers" + suffix + ".cache");
    }

    public static void main(String[] args) throws Exception {
        // Parse --network and --port flags from anywhere in args
        String networkName = "mainnet";
        int port = DEFAULT_PORT;
        List<String> remaining = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--network".equals(args[i]) && i + 1 < args.length) {
                networkName = args[++i];
            } else if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else {
                remaining.add(args[i]);
            }
        }
        String[] cmdArgs = remaining.toArray(new String[0]);

        Path socketPath = socketPath(networkName);
        Path lockPath = lockPath(networkName);
        boolean daemonAlive = isDaemonRunning(socketPath, lockPath);

        // Handle purge-cache before socket check — works without a running daemon
        if (cmdArgs.length > 0 && "purge-cache".equals(cmdArgs[0])) {
            PeerCache.purge(cacheFile(networkName));
            CLPeerCache.purge(clCacheFile(networkName));
            return;
        }

        if (cmdArgs.length > 0) {
            // ── Client mode ──────────────────────────────────────────────────
            if (!daemonAlive) {
                System.err.println("Daemon not running (cannot connect to: " + socketPath + ")");
                System.err.println("Start the daemon first: ./gradlew :app:run");
                System.exit(1);
            }
            DaemonClient.sendCommand(cmdArgs, socketPath);
        } else if (daemonAlive) {
            // ── Daemon already running ────────────────────────────────────────
            System.err.println("Daemon already running (socket: " + socketPath + ")");
            System.err.println("Commands:");
            System.err.println("  ./gradlew :app:run -Pargs=status");
            System.err.println("  ./gradlew :app:run -Pargs=peers");
            System.err.println("  ./gradlew :app:run -Pargs=\"get-headers 21000000 3\"");
            System.err.println("  ./gradlew :app:run -Pargs=stop");
            System.err.println("  ./gradlew :app:run -Pargs=purge-cache");
            System.exit(1);
        } else {
            // ── Daemon mode ──────────────────────────────────────────────────
            NetworkConfig network = NetworkConfig.byName(networkName);
            runDaemon(socketPath, lockPath, network, port);
        }
    }

    // -------------------------------------------------------------------------
    // Daemon
    // -------------------------------------------------------------------------

    private static void runDaemon(Path socketPath, Path lockPath, NetworkConfig network, int port) throws Exception {
        log.info("=== ethp2p Daemon ({}) ===", network.name());
        log.info("IPC socket: {}", socketPath);

        // 0. Acquire exclusive lock file — auto-released on process death (even kill -9)
        FileChannel lockChannel = FileChannel.open(lockPath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock fileLock = lockChannel.tryLock();
        if (fileLock == null) {
            System.err.println("Daemon already running (lock held: " + lockPath + ")");
            lockChannel.close();
            System.exit(1);
            return;
        }

        // 1. Load or generate node key
        Path keyFile = Path.of("nodekey.hex");
        NodeKey nodeKey = NodeKey.loadOrGenerate(keyFile);
        log.info("Node ID: {}", nodeKey.nodeId().toHexString());

        // 2. Latch that triggers graceful shutdown (stop command or SIGTERM)
        CountDownLatch stopLatch = new CountDownLatch(1);

        // 3. Peer cache
        PeerCache peerCache = new PeerCache(cacheFile(network.name()));

        // 4. RLPx connector
        Set<String> attempted = ConcurrentHashMap.newKeySet();
        Map<String, Long> backoff = new ConcurrentHashMap<>();
        Set<String> blacklistedNodeIds = ConcurrentHashMap.newKeySet();
        RLPxConnector connector = new RLPxConnector(nodeKey, port, network, headers -> {
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

        // 5. Connect to cached peers immediately
        List<PeerCache.CachedPeer> cached = peerCache.load();
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

        // 6. discv4 discovery
        DiscV4Service discV4 = new DiscV4Service(nodeKey, network.bootnodes(), entry -> {
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
            if (cause instanceof BindException) {
                System.err.println("Cannot bind UDP port " + port + ": " + cause.getMessage());
                System.err.println("Is another instance already running?");
            } else {
                System.err.println("Failed to start discovery: " + e.getMessage());
            }
            fileLock.release();
            lockChannel.close();
            System.exit(1);
            return;
        }
        log.info("[daemon] discv4 started on UDP port {}. Waiting for peers...", port);

        // 7. Beacon light client (consensus layer, runs on virtual thread)
        BeaconSyncState beaconSyncState = new BeaconSyncState();
        CLPeerCache clPeerCache = new CLPeerCache(clCacheFile(network.name()));
        List<String> clPeers = new java.util.ArrayList<>(clPeerCache.load());
        // Append configured peers after cached ones (cached peers are tried first)
        for (String peer : network.clPeerMultiaddrs()) {
            if (!clPeers.contains(peer)) clPeers.add(peer);
        }
        BeaconLightClient beaconLightClient = new BeaconLightClient(
                clPeers,
                network.checkpointRoot(),
                network.currentForkVersion(),
                network.genesisValidatorsRoot(),
                beaconSyncState,
                network.beaconApiUrl(),
                clPeerCache::add);
        beaconLightClient.start();
        log.info("[daemon] Beacon light client started with {} CL peer(s) ({} cached)",
                clPeers.size(), clPeers.size() - network.clPeerMultiaddrs().size());

        // 8. IPC server
        CommandHandler commandHandler = new CommandHandler(discV4, connector, stopLatch, backoff, blacklistedNodeIds, beaconSyncState, beaconLightClient);
        DaemonServer server = new DaemonServer(socketPath, commandHandler);
        try {
            server.start();
        } catch (BindException e) {
            System.err.println("Cannot bind IPC socket " + socketPath + ": " + e.getMessage());
            System.err.println("Is another instance already running?");
            discV4.close();
            fileLock.release();
            lockChannel.close();
            System.exit(1);
            return;
        } catch (Exception e) {
            System.err.println("Failed to start IPC server: " + e.getMessage());
            discV4.close();
            fileLock.release();
            lockChannel.close();
            System.exit(1);
            return;
        }

        // 9. Shutdown hook for Ctrl-C / SIGTERM — cleanup happens here
        //    because the JVM may exit before the main thread resumes after await().
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("[daemon] Shutdown hook triggered");
            beaconLightClient.close();
            server.close();
            connector.close();
            discV4.close();
            try { fileLock.release(); lockChannel.close(); } catch (Exception ignored) {}
            stopLatch.countDown();
            log.info("[daemon] Done.");
        }, "shutdown-hook"));

        // 9. Block until "stop" command or signal
        stopLatch.await();

        // Cleanup for graceful "stop" command (shutdown hook handles Ctrl-C/SIGTERM)
        beaconLightClient.close();
        server.close();
        connector.close();
        discV4.close();
        try { fileLock.release(); lockChannel.close(); } catch (Exception ignored) {}
        log.info("[daemon] Done.");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Check if a daemon is actually listening on the socket.
     * Tries to connect; if it succeeds the daemon is alive.
     * If the socket file exists but no one is listening, it's stale — delete it.
     */
    private static boolean isDaemonRunning(Path socketPath, Path lockPath) {
        // Try socket first
        if (Files.exists(socketPath)) {
            try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                ch.connect(UnixDomainSocketAddress.of(socketPath));
                return true;
            } catch (Exception e) {
                // Socket exists but nobody listening — check lock before declaring stale
            }
        }

        // Fallback: check if lock file is held by another process
        if (Files.exists(lockPath)) {
            try (FileChannel fc = FileChannel.open(lockPath,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                FileLock lock = fc.tryLock();
                if (lock == null) {
                    // Lock held → daemon is running but socket is missing
                    System.err.println("WARNING: Daemon is running (lock held: " + lockPath
                            + ") but IPC socket is missing (" + socketPath + ")");
                    return true;
                }
                // Lock acquired → no daemon running; release immediately
                lock.release();
            } catch (Exception ignored) {}
        }

        // No daemon running; clean up stale socket if present
        if (Files.exists(socketPath)) {
            log.debug("[main] Removing stale socket file: {}", socketPath);
            try { Files.deleteIfExists(socketPath); } catch (Exception ignored) {}
        }
        return false;
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
