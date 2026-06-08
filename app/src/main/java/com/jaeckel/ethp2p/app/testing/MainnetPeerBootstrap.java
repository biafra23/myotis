package com.jaeckel.ethp2p.app.testing;

import com.jaeckel.ethp2p.app.snap.EthHandlerSnapPeer;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.eth.EthHandler;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import io.myotis.evm.world.SnapPeer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * Stand up a single RLPx connection to a known mainnet snap/1 peer for
 * integration tests. Wraps the same {@link RLPxConnector} +
 * {@link EthHandler} machinery {@code :app.Main} runs in the daemon,
 * just without the discovery / cache / multi-peer churn.
 *
 * <p>Usage:
 * <pre>{@code
 *   try (var session = MainnetPeerBootstrap.dial(enode, Duration.ofSeconds(30))) {
 *       SnapPeer peer = session.peer();
 *       // ... run an executor against `peer` ...
 *   }
 * }</pre>
 *
 * <p>This used to be the TODO that blocked every Phase 1–5 mainnet IT
 * (see {@code MainnetCallViewIT.connectToMainnetPeer}). The bootstrap
 * helper landing here unblocks all of them.
 */
public final class MainnetPeerBootstrap {

    private MainnetPeerBootstrap() {}

    /**
     * An open RLPx session against one peer. Holds the {@link RLPxConnector}
     * and the {@link SnapPeer} wrapper; {@link #close()} shuts down the
     * connector's NIO event loop.
     */
    public static final class Session implements AutoCloseable {
        private final RLPxConnector connector;
        private final SnapPeer peer;
        private final EthHandler handler;

        Session(RLPxConnector connector, EthHandler handler, SnapPeer peer) {
            this.connector = connector;
            this.handler = handler;
            this.peer = peer;
        }

        public SnapPeer peer() { return peer; }
        public EthHandler ethHandler() { return handler; }

        @Override
        public void close() {
            connector.close();
        }
    }

    /**
     * Dial the configured peer and wait until it appears in
     * {@link RLPxConnector#activeSnapHandlers()} — i.e. the eth handshake
     * has reached READY and snap/1 was negotiated.
     *
     * @param enodeUrl  {@code enode://<128-char-uncompressed-pubkey-hex>@host:tcpPort}
     * @param network   network the peer is on (almost always {@link NetworkConfig#MAINNET})
     * @param timeout   wall-clock budget for connect + eth/snap handshake
     */
    public static Session dial(String enodeUrl, NetworkConfig network, Duration timeout)
            throws Exception {
        Enode enode = Enode.parse(enodeUrl);

        // We're the dialing side, so the locally-announced TCP port is
        // informational — peers may put it in their PeerInfo logs but it
        // doesn't have to be reachable. 0 also signals "no inbound" cleanly.
        NodeKey nodeKey = NodeKey.generate();
        int localPort = 0;

        // No-op callbacks: the IT pulls state via the EthHandler directly,
        // and we don't care about header push notifications or peer-cache
        // population here.
        RLPxConnector connector = new RLPxConnector(
                nodeKey, localPort, network, headers -> {}, (addr, pubKeyHex, snap) -> {});

        try {
            connector.connect(enode.address(), enode.publicKey());
            EthHandler handler = waitForSnapReady(connector, timeout);
            SnapPeer peer = new EthHandlerSnapPeer(handler);
            return new Session(connector, handler, peer);
        } catch (Exception failure) {
            // If we never got a usable peer, free the NIO threads before
            // propagating — otherwise the test JVM hangs on the leaked
            // NioEventLoopGroup.
            try { connector.close(); } catch (Exception ignored) {}
            throw failure;
        }
    }

    /** Convenience overload defaulting to {@link NetworkConfig#MAINNET}. */
    public static Session dial(String enodeUrl, Duration timeout) throws Exception {
        return dial(enodeUrl, NetworkConfig.MAINNET, timeout);
    }

    /**
     * Poll {@code activeSnapHandlers()} until one is available or the
     * deadline elapses. Polling rather than a callback keeps this helper
     * tiny: we don't touch RLPxConnector's PeerReadyCallback wiring, and
     * the handshake completes well inside one poll interval on a live peer.
     */
    private static EthHandler waitForSnapReady(RLPxConnector connector, Duration timeout)
            throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            List<EthHandler> ready = connector.activeSnapHandlers();
            if (!ready.isEmpty()) return ready.get(0);
            Thread.sleep(200);
        }
        // One last check after the sleep window in case the handshake
        // landed right as the clock rolled over.
        List<EthHandler> ready = connector.activeSnapHandlers();
        if (!ready.isEmpty()) return ready.get(0);
        throw new TimeoutException(
                "Peer did not reach eth+snap READY within " + timeout);
    }

    /** Parsed {@code enode://pubkey@host:port}. */
    record Enode(SECP256K1.PublicKey publicKey, InetSocketAddress address) {
        static Enode parse(String enodeUrl) {
            if (!enodeUrl.startsWith("enode://")) {
                throw new IllegalArgumentException(
                        "Expected enode://<pubkey>@<host>:<port>, got: " + enodeUrl);
            }
            String body = enodeUrl.substring("enode://".length());
            int at = body.indexOf('@');
            int colon = body.lastIndexOf(':');
            if (at <= 0 || colon <= at) {
                throw new IllegalArgumentException(
                        "Malformed enode URL: " + enodeUrl);
            }
            String pubHex = body.substring(0, at);
            String host = body.substring(at + 1, colon);
            int port = Integer.parseInt(body.substring(colon + 1));
            SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(
                    Bytes.fromHexString("0x" + pubHex));
            return new Enode(pubKey, new InetSocketAddress(host, port));
        }
    }
}
