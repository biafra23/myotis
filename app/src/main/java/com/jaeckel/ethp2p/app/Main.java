package com.jaeckel.ethp2p.app;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import io.myotis.node.ChainPorts;
import io.myotis.node.ChainStack;
import io.myotis.node.NodeRegistry;
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
 *   # Host several networks in ONE process, each on its own ports + IPC socket:
 *   ./gradlew :app:run -Pnetwork=mainnet,gnosis
 *
 *   # Send a command to a running daemon (targets one network's socket):
 *   ./gradlew :app:run -Pargs=status
 *   ./gradlew :app:run -Pnetwork=gnosis -Pargs=beacon-status
 *   ./gradlew :app:run -Pargs=stop
 *
 *   # Purge cached peers / use a testnet:
 *   ./gradlew :app:run -Pargs=purge-cache
 *   ./gradlew :app:run -Pnetwork=sepolia
 * </pre>
 *
 * <h2>Behaviour</h2>
 * <ul>
 *   <li>With command args → client mode: send one command to the (first) network's
 *       socket, print the response, exit.
 *   <li>Without args → daemon mode: host every {@code --network} in this process.
 * </ul>
 *
 * <p>Each network's node stack (EL + discv4 + discv5 + beacon light client + verified
 * JSON-RPC) lives in {@link ChainStack} (module {@code :node-core}), shared with the
 * Android app, and is held by a {@link NodeRegistry}. This class owns the daemon shell:
 * the per-network lock files + Unix-socket IPC servers, and the shutdown latch.
 */
public final class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final int DEFAULT_PORT = 30303;
    /** Snap-peer target the daemon's per-stack maintainer keeps topped up. */
    private static final int SNAP_PEER_TARGET = 32;

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

    /**
     * Node-identity key file. A single-network daemon keeps the shared {@code nodekey.hex}
     * (unchanged). When hosting several networks in one process each gets a distinct key
     * ({@code nodekey-<net>.hex}; mainnet keeps {@code nodekey.hex}) so each advertises its
     * own ENR/fork-id instead of colliding under one node id in the discovery DHTs.
     */
    static Path nodeKeyFile(String networkName, boolean perNetwork) {
        if (!perNetwork || "mainnet".equals(networkName)) return Path.of("nodekey.hex");
        return Path.of("nodekey-" + networkName + ".hex");
    }


    public static void main(String[] args) throws Exception {
        // Parse --network (comma-separated list), --port, --gossipsub from anywhere in args.
        List<String> networkNames = new ArrayList<>();
        int port = DEFAULT_PORT;
        boolean gossipsubEnabled = false;
        List<String> remaining = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--network".equals(args[i]) && i + 1 < args.length) {
                for (String n : args[++i].split(",")) {
                    String trimmed = n.trim();
                    if (!trimmed.isEmpty() && !networkNames.contains(trimmed)) networkNames.add(trimmed);
                }
            } else if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--gossipsub".equals(args[i])) {
                gossipsubEnabled = true;
            } else {
                remaining.add(args[i]);
            }
        }
        if (networkNames.isEmpty()) networkNames.add("mainnet");
        // System property fallback so Android / other embedders can opt in
        // without touching CLI args.
        if (!gossipsubEnabled
                && Boolean.parseBoolean(System.getProperty("beacon.gossipsub", "false"))) {
            gossipsubEnabled = true;
        }
        String[] cmdArgs = remaining.toArray(new String[0]);

        // Client commands / purge target a single network — the first listed.
        String primary = networkNames.get(0);
        Path primarySocket = socketPath(primary);
        Path primaryLock = lockPath(primary);

        // Handle purge-cache before socket check — works without a running daemon
        if (cmdArgs.length > 0 && "purge-cache".equals(cmdArgs[0])) {
            PeerCache.purge(cacheFile(primary));
            CLPeerCache.purge(clCacheFile(primary));
            try {
                if (java.nio.file.Files.deleteIfExists(syncSnapshotFile(primary))) {
                    System.out.println("Sync snapshot purged: " + syncSnapshotFile(primary));
                }
            } catch (java.io.IOException e) {
                System.err.println("Failed to purge sync snapshot: " + e.getMessage());
            }
            return;
        }

        if (cmdArgs.length > 0) {
            // ── Client mode (single network) ─────────────────────────────────
            if (!isDaemonRunning(primarySocket, primaryLock)) {
                System.err.println("Daemon not running (cannot connect to: " + primarySocket + ")");
                System.err.println("Start the daemon first: ./gradlew :app:run");
                System.exit(1);
            }
            DaemonClient.sendCommand(cmdArgs, primarySocket);
            return;
        }

        // ── Daemon mode (one or more networks in this process) ───────────────
        List<NetworkConfig> networks = new ArrayList<>();
        for (String n : networkNames) networks.add(NetworkConfig.byName(n));
        for (NetworkConfig net : networks) {
            if (isDaemonRunning(socketPath(net.name()), lockPath(net.name()))) {
                System.err.println("Daemon already running for " + net.name()
                        + " (socket: " + socketPath(net.name()) + ")");
                if (networks.size() == 1) {
                    System.err.println("Commands:");
                    System.err.println("  ./gradlew :app:run -Pargs=status");
                    System.err.println("  ./gradlew :app:run -Pargs=peers");
                    System.err.println("  ./gradlew :app:run -Pargs=stop");
                }
                System.exit(1);
            }
        }
        runDaemon(networks, port, gossipsubEnabled);
    }

    // -------------------------------------------------------------------------
    // Daemon
    // -------------------------------------------------------------------------

    private static void runDaemon(List<NetworkConfig> networks, int portOverride,
                                  boolean gossipsubEnabled) throws Exception {
        boolean multi = networks.size() > 1;
        log.info("=== ethp2p Daemon ({}) ===",
                String.join(", ", networks.stream().map(NetworkConfig::name).toList()));

        // 0. Acquire every target network's exclusive lock up front; release all and
        //    abort if any is held (another daemon already owns that network).
        List<FileChannel> lockChannels = new ArrayList<>();
        List<FileLock> fileLocks = new ArrayList<>();
        for (NetworkConfig network : networks) {
            FileChannel ch = FileChannel.open(lockPath(network.name()),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            FileLock lk = ch.tryLock();
            if (lk == null) {
                System.err.println("Daemon already running (lock held: " + lockPath(network.name()) + ")");
                ch.close();
                releaseAll(fileLocks, lockChannels);
                System.exit(1);
                return;
            }
            lockChannels.add(ch);
            fileLocks.add(lk);
        }

        CountDownLatch stopLatch = new CountDownLatch(1);
        NodeRegistry registry = new NodeRegistry();
        List<DaemonServer> servers = new ArrayList<>();

        // 1. Build, start, and IPC-wire each network's stack.
        for (NetworkConfig network : networks) {
            log.info("IPC socket ({}): {}", network.name(), socketPath(network.name()));

            // Single-network stays byte-identical: legacy --port/30303 + discv5 9000 +
            // RPC 8545 + shared nodekey.hex. Multi-network uses pinned per-network ports
            // + per-network identity so the stacks don't collide.
            ChainPorts ports = multi
                    ? ChainPorts.defaultsFor(network)
                    : new ChainPorts(portOverride, 9000, 8545);
            NodeKey nodeKey = NodeKey.loadOrGenerate(nodeKeyFile(network.name(), multi));

            PeerCache peerCache = new PeerCache(cacheFile(network.name()));
            CLPeerCache clPeerCache = new CLPeerCache(clCacheFile(network.name()));
            ChainStack stack = new ChainStack(
                    network, ports, nodeKey,
                    new PeerCacheAdapter(peerCache),
                    new ClPeerCacheAdapter(clPeerCache),
                    new com.jaeckel.ethp2p.app.rpc.JavaHttpCcipGateway(),
                    syncSnapshotFile(network.name()),
                    gossipsubEnabled);
            // Keep snap peers topped up from the cache + a refreshing EIP-1459 DNS pool —
            // the discv4-independent path. Helps networks with scarce snap peers (Gnosis)
            // retain a snap/1 peer for verified state reads. dnsServers=null → resolver's
            // default DNS (the daemon, unlike Android, has system DNS config).
            stack.configureSnapMaintainer(SNAP_PEER_TARGET, null);

            if (!stack.start()) {
                System.err.println("Failed to start " + network.name() + " node stack");
                registry.shutdownAll();
                closeAll(servers);
                releaseAll(fileLocks, lockChannels);
                System.exit(1);
                return;
            }
            registry.add(stack);

            CommandHandler commandHandler = new CommandHandler(
                    stack.discV4(), stack.discV5(), stack.connector(), stopLatch,
                    stack.backoff(), stack.blacklistedNodeIds(),
                    stack.beaconSyncState(), stack.beaconLightClient(),
                    network.clGenesisTime(), network.secondsPerSlot());
            DaemonServer server = new DaemonServer(socketPath(network.name()), commandHandler);
            try {
                server.start();
            } catch (Exception e) {
                System.err.println("Failed to start IPC server for " + network.name() + ": " + e.getMessage());
                registry.shutdownAll();
                closeAll(servers);
                releaseAll(fileLocks, lockChannels);
                System.exit(1);
                return;
            }
            servers.add(server);
        }

        // 2. Run cleanup exactly once, whether reached via the await() below or the
        //    shutdown hook (Ctrl-C / SIGTERM, or normal exit after await returns).
        java.util.concurrent.atomic.AtomicBoolean cleaned = new java.util.concurrent.atomic.AtomicBoolean(false);
        Runnable cleanup = () -> {
            if (!cleaned.compareAndSet(false, true)) return;
            registry.shutdownAll();
            closeAll(servers);
            releaseAll(fileLocks, lockChannels);
        };

        // A `stop` command on ANY network's socket trips the shared latch and tears the
        // whole process down. The hook covers the JVM-exits-before-main-resumes case.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("[daemon] Shutdown hook triggered");
            cleanup.run();
            stopLatch.countDown();
            log.info("[daemon] Done.");
        }, "shutdown-hook"));

        // 3. Block until "stop" command or signal, then clean up.
        stopLatch.await();
        cleanup.run();
        log.info("[daemon] Done.");
    }

    private static void closeAll(List<DaemonServer> servers) {
        for (DaemonServer s : servers) {
            try { s.close(); } catch (Throwable ignored) {}
        }
    }

    private static void releaseAll(List<FileLock> locks, List<FileChannel> channels) {
        for (FileLock lk : locks) {
            try { lk.release(); } catch (Exception ignored) {}
        }
        for (FileChannel ch : channels) {
            try { ch.close(); } catch (Exception ignored) {}
        }
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
