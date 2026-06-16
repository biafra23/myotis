package com.jaeckel.ethp2p.app;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import io.myotis.node.ChainPorts;
import io.myotis.node.ChainStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 *
 * <p>The per-network node stack (EL + discv4 + discv5 + beacon light client + verified
 * JSON-RPC) lives in {@link ChainStack} (module {@code :node-core}), shared with the
 * Android app. This class owns the daemon-specific shell: the lock file, the Unix-socket
 * IPC server, and the shutdown latch.
 */
public final class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final int DEFAULT_PORT = 30303;

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

    static Path syncSnapshotFile(String networkName) {
        String suffix = "mainnet".equals(networkName) ? "" : "-" + networkName;
        return cacheFile(networkName).resolveSibling("sync-state" + suffix + ".snapshot");
    }


    public static void main(String[] args) throws Exception {
        // Parse --network and --port flags from anywhere in args
        String networkName = "mainnet";
        int port = DEFAULT_PORT;
        boolean gossipsubEnabled = false;
        List<String> remaining = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--network".equals(args[i]) && i + 1 < args.length) {
                networkName = args[++i];
            } else if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--gossipsub".equals(args[i])) {
                gossipsubEnabled = true;
            } else {
                remaining.add(args[i]);
            }
        }
        // System property fallback so Android / other embedders can opt in
        // without touching CLI args.
        if (!gossipsubEnabled
                && Boolean.parseBoolean(System.getProperty("beacon.gossipsub", "false"))) {
            gossipsubEnabled = true;
        }
        String[] cmdArgs = remaining.toArray(new String[0]);

        Path socketPath = socketPath(networkName);
        Path lockPath = lockPath(networkName);
        boolean daemonAlive = isDaemonRunning(socketPath, lockPath);

        // Handle purge-cache before socket check — works without a running daemon
        if (cmdArgs.length > 0 && "purge-cache".equals(cmdArgs[0])) {
            PeerCache.purge(cacheFile(networkName));
            CLPeerCache.purge(clCacheFile(networkName));
            try {
                if (java.nio.file.Files.deleteIfExists(syncSnapshotFile(networkName))) {
                    System.out.println("Sync snapshot purged: " + syncSnapshotFile(networkName));
                }
            } catch (java.io.IOException e) {
                System.err.println("Failed to purge sync snapshot: " + e.getMessage());
            }
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
            runDaemon(socketPath, lockPath, network, port, gossipsubEnabled);
        }
    }

    // -------------------------------------------------------------------------
    // Daemon
    // -------------------------------------------------------------------------

    private static void runDaemon(Path socketPath, Path lockPath, NetworkConfig network, int port,
                                  boolean gossipsubEnabled) throws Exception {
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

        // 1. Node identity (one network per daemon today → the shared nodekey.hex).
        NodeKey nodeKey = NodeKey.loadOrGenerate(Path.of("nodekey.hex"));

        // 2. Latch that triggers graceful shutdown (stop command or SIGTERM).
        CountDownLatch stopLatch = new CountDownLatch(1);

        // 3. File-backed peer caches, exposed to ChainStack via adapters.
        PeerCache peerCache = new PeerCache(cacheFile(network.name()));
        CLPeerCache clPeerCache = new CLPeerCache(clCacheFile(network.name()));

        // 4. The network's full stack. EL port honors the legacy --port flag (default
        //    30303); CL discv5 stays 9000 and verified JSON-RPC stays 8545 — unchanged
        //    single-network behavior. (Per-network default ports kick in once the
        //    registry runs several stacks at once.)
        ChainStack stack = new ChainStack(
                network,
                new ChainPorts(port, 9000, 8545),
                nodeKey,
                new PeerCacheAdapter(peerCache),
                new ClPeerCacheAdapter(clPeerCache),
                new com.jaeckel.ethp2p.app.rpc.JavaHttpCcipGateway(),
                syncSnapshotFile(network.name()),
                gossipsubEnabled);

        if (!stack.start()) {
            System.err.println("Failed to start " + network.name() + " node stack");
            try { fileLock.release(); lockChannel.close(); } catch (Exception ignored) {}
            System.exit(1);
            return;
        }

        // 5. IPC server over the stack's live components.
        CommandHandler commandHandler = new CommandHandler(
                stack.discV4(), stack.discV5(), stack.connector(), stopLatch,
                stack.backoff(), stack.blacklistedNodeIds(),
                stack.beaconSyncState(), stack.beaconLightClient(),
                network.clGenesisTime(), network.secondsPerSlot());
        DaemonServer server = new DaemonServer(socketPath, commandHandler);
        try {
            server.start();
        } catch (Exception e) {
            System.err.println("Failed to start IPC server: " + e.getMessage());
            stack.shutdown();
            try { fileLock.release(); lockChannel.close(); } catch (Exception ignored) {}
            System.exit(1);
            return;
        }

        // 6. Shutdown hook for Ctrl-C / SIGTERM — cleanup happens here because the JVM
        //    may exit before the main thread resumes after await().
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("[daemon] Shutdown hook triggered");
            stack.shutdown();
            try { server.close(); } catch (Throwable ignored) {}
            try { fileLock.release(); lockChannel.close(); } catch (Exception ignored) {}
            stopLatch.countDown();
            log.info("[daemon] Done.");
        }, "shutdown-hook"));

        // 7. Block until "stop" command or signal, then clean up (the hook covers the
        //    Ctrl-C/SIGTERM path).
        stopLatch.await();
        stack.shutdown();
        try { server.close(); } catch (Throwable ignored) {}
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
}
