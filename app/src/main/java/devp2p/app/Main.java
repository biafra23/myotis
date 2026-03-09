package devp2p.app;

import devp2p.core.crypto.NodeKey;
import devp2p.core.types.BlockHeader;
import devp2p.networking.NetworkConfig;
import devp2p.networking.discv4.DiscV4Service;
import devp2p.networking.discv4.KademliaTable;
import devp2p.networking.eth.messages.BlockHeadersMessage;
import devp2p.networking.rlpx.RLPxConnector;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/**
 * devp2p Playground — daemon + CLI client.
 *
 * <h2>Usage</h2>
 * <pre>
 *   # Start daemon (blocks; creates /tmp/devp2p.sock):
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
 *   echo '{"cmd":"status"}' | nc -U /tmp/devp2p.sock
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

    private static final int UDP_PORT = 30303;
    private static final int TCP_PORT = 30303;
    private static final long BACKOFF_INCOMPATIBLE_MS = 10 * 60 * 1000L; // 10 min for wrong-chain peers
    private static final long BACKOFF_TRANSIENT_MS = 30 * 1000L; // 30s for transient failures (too many peers, etc.)

    /** Socket path; override via {@code DEVP2P_SOCKET} env var. Network-specific suffix for non-mainnet. */
    static Path socketPath(String networkName) {
        String env = System.getenv("DEVP2P_SOCKET");
        if (env != null) return Path.of(env);
        String suffix = "mainnet".equals(networkName) ? "" : "-" + networkName;
        return Path.of("/tmp/devp2p" + suffix + ".sock");
    }

    static Path cacheFile(String networkName) {
        String suffix = "mainnet".equals(networkName) ? "" : "-" + networkName;
        return Path.of("peers" + suffix + ".cache");
    }

    public static void main(String[] args) throws Exception {
        // Parse --network flag from anywhere in args
        String networkName = "mainnet";
        List<String> remaining = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--network".equals(args[i]) && i + 1 < args.length) {
                networkName = args[++i];
            } else {
                remaining.add(args[i]);
            }
        }
        String[] cmdArgs = remaining.toArray(new String[0]);

        Path socketPath = socketPath(networkName);
        boolean daemonAlive = isDaemonRunning(socketPath);

        // Handle purge-cache before socket check — works without a running daemon
        if (cmdArgs.length > 0 && "purge-cache".equals(cmdArgs[0])) {
            PeerCache.purge(cacheFile(networkName));
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
            runDaemon(socketPath, network);
        }
    }

    // -------------------------------------------------------------------------
    // Daemon
    // -------------------------------------------------------------------------

    private static void runDaemon(Path socketPath, NetworkConfig network) throws Exception {
        log.info("=== devp2p Playground Daemon ({}) ===", network.name());
        log.info("IPC socket: {}", socketPath);

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
        RLPxConnector connector = new RLPxConnector(nodeKey, TCP_PORT, network, headers -> {
            if (!headers.isEmpty()) {
                log.info("\n=== BLOCK HEADERS RECEIVED ===");
                for (BlockHeadersMessage.VerifiedHeader vh : headers) {
                    BlockHeader h = vh.header();
                    log.info("  Block #{}", h.number);
                    log.info("  Hash:      0x{}", vh.hash().toHexString());
                    log.info("  StateRoot: 0x{}", h.stateRoot.toHexString());
                    log.info("  TxRoot:    0x{}", h.transactionsRoot.toHexString());
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
                connector.connect(peer.address(), pubKey, incompatible -> {
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
                    tryConnectWithKnownKey(connector, entry, peerTcp, nodeKey, attempted, peerKey, backoff);
                }
            }
        });

        discV4.start(UDP_PORT);
        log.info("[daemon] discv4 started on UDP port {}. Waiting for peers...", UDP_PORT);

        // 7. IPC server
        CommandHandler commandHandler = new CommandHandler(discV4, connector, stopLatch, backoff);
        DaemonServer server = new DaemonServer(socketPath, commandHandler);
        server.start();

        // 8. Shutdown hook for Ctrl-C / SIGTERM — cleanup happens here
        //    because the JVM may exit before the main thread resumes after await().
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("[daemon] Shutdown hook triggered");
            server.close();
            connector.close();
            discV4.close();
            stopLatch.countDown();
            log.info("[daemon] Done.");
        }, "shutdown-hook"));

        // 9. Block until "stop" command or signal
        stopLatch.await();

        // Cleanup for graceful "stop" command (shutdown hook handles Ctrl-C/SIGTERM)
        server.close();
        connector.close();
        discV4.close();
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
    private static boolean isDaemonRunning(Path socketPath) {
        if (!Files.exists(socketPath)) return false;
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(socketPath));
            return true;
        } catch (Exception e) {
            // Stale socket file — remove it
            log.debug("[main] Removing stale socket file: {}", socketPath);
            try { Files.deleteIfExists(socketPath); } catch (Exception ignored) {}
            return false;
        }
    }

    /**
     * In discv4, the Neighbors response includes 64-byte node IDs (public keys).
     * We reconstruct the SECP256K1 public key and attempt connection.
     */
    private static void tryConnectWithKnownKey(
            RLPxConnector connector, KademliaTable.Entry entry,
            InetSocketAddress peerTcp, NodeKey localKey,
            Set<String> attempted, String peerKey,
            Map<String, Long> backoff) {
        try {
            Bytes nodeId = entry.nodeId();
            if (nodeId.size() != 64) {
                log.warn("[main] Node ID is not 64 bytes ({}b), skipping", nodeId.size());
                attempted.remove(peerKey);
                return;
            }
            SECP256K1.PublicKey peerPubkey = SECP256K1.PublicKey.fromBytes(nodeId);
            connector.connect(peerTcp, peerPubkey, incompatible -> {
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
