package devp2p.networking.rlpx;

import devp2p.core.crypto.NodeKey;
import devp2p.networking.NetworkConfig;
import devp2p.networking.eth.EthHandler;
import devp2p.networking.eth.messages.BlockBodiesMessage;
import devp2p.networking.eth.messages.BlockHeadersMessage;
import org.apache.tuweni.bytes.Bytes32;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Manages outbound RLPx TCP connections to Ethereum peers.
 *
 * For each connection:
 *   1. Establishes TCP via Netty NioSocketChannel
 *   2. RLPxHandler performs ECIES handshake
 *   3. EthHandler handles eth/68 protocol
 *
 * Android-safe: uses NIO only (no epoll/kqueue).
 */
public final class RLPxConnector implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(RLPxConnector.class);

    /** Callback when a peer reaches READY state: (address, publicKeyHex). */
    public interface PeerReadyCallback {
        void onPeerReady(InetSocketAddress address, String publicKeyHex);
    }

    /** Callback when a peer connection closes, with incompatibility info. */
    public interface PeerCloseCallback {
        void onPeerClose(boolean incompatibleNetwork);
    }

    private final NodeKey localKey;
    private final int tcpPort;
    private final NetworkConfig network;
    private final NioEventLoopGroup group;
    private final Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders;
    private final PeerReadyCallback peerReadyCallback;
    private final Set<EthHandler> activeHandlers = ConcurrentHashMap.newKeySet();

    public RLPxConnector(NodeKey localKey, int tcpPort, NetworkConfig network,
                         Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders,
                         PeerReadyCallback peerReadyCallback) {
        this.localKey = localKey;
        this.tcpPort = tcpPort;
        this.network = network;
        this.group = new NioEventLoopGroup(4);
        this.onHeaders = onHeaders;
        this.peerReadyCallback = peerReadyCallback;
    }

    /**
     * Connect to a peer asynchronously.
     *
     * @param peerAddr      peer's TCP address
     * @param peerPublicKey peer's secp256k1 public key (64 bytes)
     */
    public ChannelFuture connect(InetSocketAddress peerAddr, SECP256K1.PublicKey peerPublicKey) {
        return connect(peerAddr, peerPublicKey, null);
    }

    public ChannelFuture connect(InetSocketAddress peerAddr, SECP256K1.PublicKey peerPublicKey,
                                  PeerCloseCallback closeCallback) {
        log.info("[rlpx] Connecting to {} ...", peerAddr);

        String pubKeyHex = peerPublicKey.bytes().toHexString();
        Runnable onReady = () -> {
            if (peerReadyCallback != null) {
                peerReadyCallback.onPeerReady(peerAddr, pubKeyHex);
            }
        };
        EthHandler ethHandler = new EthHandler(localKey, tcpPort, network, onHeaders, onReady);
        ethHandler.setRemoteAddress(peerAddr.getAddress().getHostAddress() + ":" + peerAddr.getPort());

        Bootstrap bootstrap = new Bootstrap()
            .group(group)
            .channel(NioSocketChannel.class)    // NIO only, no epoll/kqueue
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10_000)
            .option(ChannelOption.SO_KEEPALIVE, true)
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    // RLPxHandler routes decoded messages to EthHandler
                    RLPxHandler rlpxHandler = new RLPxHandler(
                        localKey, peerPublicKey,
                        msg -> ethHandler.onMessage(ch.pipeline().firstContext(), msg)
                    );
                    ch.pipeline().addLast("rlpx", rlpxHandler);
                    ch.pipeline().addLast("eth", ethHandler);
                    ch.closeFuture().addListener(f -> {
                        activeHandlers.remove(ethHandler);
                        if (closeCallback != null) {
                            closeCallback.onPeerClose(ethHandler.isIncompatibleNetwork());
                        }
                    });
                }
            });

        ChannelFuture connectFuture = bootstrap.connect(peerAddr);
        connectFuture.addListener((ChannelFuture f) -> {
            if (f.isSuccess()) {
                activeHandlers.add(ethHandler);
            } else {
                log.debug("[rlpx] Connection to {} failed: {}", peerAddr, f.cause().getMessage());
            }
        });
        return connectFuture;
    }

    /**
     * Request block headers from any active READY peer.
     *
     * @return a future that completes with the headers, or a failed future if no peer is available
     */
    public CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> requestBlockHeaders(
            long blockNumber, int count) {
        Iterator<EthHandler> it = activeHandlers.iterator();
        while (it.hasNext()) {
            EthHandler handler = it.next();
            if (!handler.isReady()) {
                continue;
            }
            CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> future =
                    handler.requestBlockHeadersAsync(blockNumber, count);
            if (future != null) {
                log.info("[rlpx] Routed GetBlockHeaders(block={}, count={}) to active peer", blockNumber, count);
                return future;
            }
            // Handler reported ready but requestBlockHeadersAsync returned null —
            // channel likely closed between the two checks; remove it.
            it.remove();
        }
        return CompletableFuture.failedFuture(
                new IllegalStateException("No active peer with completed eth handshake"));
    }

    /**
     * Request block bodies from any active READY peer.
     *
     * @return a future that completes with the bodies, or a failed future if no peer is available
     */
    public CompletableFuture<List<BlockBodiesMessage.BlockBody>> requestBlockBodies(
            Bytes32... hashes) {
        Iterator<EthHandler> it = activeHandlers.iterator();
        while (it.hasNext()) {
            EthHandler handler = it.next();
            if (!handler.isReady()) continue;
            CompletableFuture<List<BlockBodiesMessage.BlockBody>> future =
                    handler.requestBlockBodiesAsync(hashes);
            if (future != null) {
                log.info("[rlpx] Routed GetBlockBodies({} hashes) to active peer", hashes.length);
                return future;
            }
            it.remove();
        }
        return CompletableFuture.failedFuture(
                new IllegalStateException("No active peer with completed eth handshake"));
    }

    public record PeerInfo(String remoteAddress, String state) {}

    public List<PeerInfo> getActivePeers() {
        List<PeerInfo> result = new ArrayList<>();
        for (EthHandler handler : activeHandlers) {
            String addr = handler.getRemoteAddress();
            String state = handler.getState().name();
            result.add(new PeerInfo(addr != null ? addr : "unknown", state));
        }
        return result;
    }

    @Override
    public void close() {
        group.shutdownGracefully();
        log.info("[rlpx] Connector stopped");
    }
}
