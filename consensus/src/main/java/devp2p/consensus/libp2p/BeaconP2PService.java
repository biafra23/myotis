package devp2p.consensus.libp2p;

import io.libp2p.core.Host;
import io.libp2p.core.P2PChannel;
import io.libp2p.core.PeerId;
import io.libp2p.core.StreamPromise;
import io.libp2p.core.crypto.KeyType;
import io.libp2p.core.dsl.HostBuilder;
import io.libp2p.core.multiformats.Multiaddr;
import io.libp2p.core.multistream.ProtocolBinding;
import io.libp2p.core.multistream.ProtocolDescriptor;
import io.libp2p.core.mux.StreamMuxerProtocol;
import io.libp2p.protocol.Identify;
import io.libp2p.protocol.IdentifyController;
import io.libp2p.security.noise.NoiseXXSecureChannel;
import io.libp2p.transport.tcp.TcpTransport;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Manages libp2p connections to Consensus Layer peers and executes req/resp
 * light client protocols defined in the Ethereum 2 specification.
 *
 * <p>Each protocol is registered with the libp2p host at startup. Per-request
 * state (request bytes, response future) is passed through a concurrent queue
 * that the binding dequeues from when {@code initChannel} is called.
 */
public class BeaconP2PService implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(BeaconP2PService.class);

    static final String BOOTSTRAP =
            "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy";
    static final String UPDATES =
            "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy";
    static final String FINALITY =
            "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy";
    static final String OPTIMISTIC =
            "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy";
    static final String BLOCKS_BY_RANGE =
            "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";

    private volatile Host host;
    private Identify identifyBinding;

    /** One binding per protocol, registered once at startup. */
    private final Map<String, QueuedReqRespBinding> bindings = new ConcurrentHashMap<>();

    public BeaconP2PService() {}

    /**
     * Start the underlying libp2p host and register light client protocol handlers.
     */
    public void start() {
        host = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> new NoiseXXSecureChannel(key, muxers))
                .muxer(StreamMuxerProtocol::getYamux)
                .muxer(StreamMuxerProtocol::getMplex)
                .listen("/ip4/0.0.0.0/tcp/0") // ephemeral port; some peers reject dial-only hosts
                // Ethereum CL spec requires secp256k1 identity keys
                .builderModifier(b -> b.getIdentity().random(KeyType.SECP256K1))
                .build();

        // Log connection events for debugging handshake issues
        host.addConnectionHandler(conn -> {
            log.info("[beacon-p2p] Connection established to peer={} remote={} local={}",
                    conn.secureSession().getRemoteId(),
                    conn.remoteAddress(),
                    conn.localAddress());
        });

        // Register identify protocol to query remote peer capabilities
        identifyBinding = new Identify();
        host.addProtocolHandler(identifyBinding);

        // Register protocol bindings before starting
        for (String proto : List.of(BOOTSTRAP, UPDATES, FINALITY, OPTIMISTIC, BLOCKS_BY_RANGE)) {
            QueuedReqRespBinding binding = new QueuedReqRespBinding(proto);
            bindings.put(proto, binding);
            host.addProtocolHandler(binding);
        }

        host.start().join();
        log.info("[beacon-p2p] libp2p host started, peerId={}, listenAddrs={}",
                host.getPeerId(), host.listenAddresses());
    }

    @Override
    public void close() {
        Host h = host;
        if (h != null) {
            h.stop().join();
            log.info("[beacon-p2p] libp2p host stopped");
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Disconnect all existing connections to a peer, forcing fresh connections
     * on subsequent requests. This is needed when a stale connection causes
     * "Failed to open stream" errors (e.g. after a bootstrap empty response).
     */
    public void disconnectPeer(String peerMultiaddr) {
        Host h = host;
        if (h == null) return;
        try {
            PeerId peerId = new Multiaddr(peerMultiaddr).getPeerId();
            if (peerId == null) return;
            for (io.libp2p.core.Connection conn : h.getNetwork().getConnections()) {
                if (peerId.equals(conn.secureSession().getRemoteId())) {
                    log.debug("[beacon-p2p] Disconnecting stale connection to {}", peerMultiaddr);
                    h.getNetwork().disconnect(conn);
                }
            }
        } catch (Exception e) {
            log.debug("[beacon-p2p] Error disconnecting {}: {}", peerMultiaddr, e.getMessage());
        }
    }

    /**
     * Query a peer's supported protocols via the libp2p Identify protocol.
     * Logs all protocols the peer advertises — diagnostic tool.
     */
    public CompletableFuture<Void> queryIdentify(String peerMultiaddr) {
        Host h = host;
        if (h == null) return CompletableFuture.failedFuture(new IllegalStateException("not started"));

        try {
            Multiaddr peerAddr = new Multiaddr(peerMultiaddr);
            PeerId peerId = peerAddr.getPeerId();
            if (peerId == null) return CompletableFuture.failedFuture(new IllegalArgumentException("no peer id"));

            CompletableFuture<io.libp2p.core.Connection> connFuture = findOrConnect(h, peerId, peerAddr);
            return connFuture.thenCompose(conn -> {
                StreamPromise<IdentifyController> streamPromise =
                        conn.muxerSession().createStream(identifyBinding);
                return streamPromise.getController().thenCompose(ctrl -> ctrl.id());
            }).thenAccept(idMsg -> {
                List<?> protocols = idMsg.getProtocolsList();
                log.info("[beacon-p2p] Identify response from {}: {} protocols", peerMultiaddr, protocols.size());
                for (Object proto : protocols) {
                    String protoStr = proto.toString();
                    if (protoStr.contains("light_client") || protoStr.contains("eth2")) {
                        log.info("[beacon-p2p]   MATCH: {}", protoStr);
                    }
                }
                // Log all protocols at debug level
                for (Object proto : protocols) {
                    log.debug("[beacon-p2p]   proto: {}", proto);
                }
            }).exceptionally(ex -> {
                log.warn("[beacon-p2p] Identify failed for {}: {}", peerMultiaddr, ex.getMessage());
                return null;
            });
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    public CompletableFuture<byte[]> requestBootstrap(String peerMultiaddr, byte[] blockRoot32) {
        if (blockRoot32 == null || blockRoot32.length != 32) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("blockRoot32 must be exactly 32 bytes"));
        }
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(blockRoot32);
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        return doReqResp(peerMultiaddr, BOOTSTRAP, requestPayload)
                .thenApply(BeaconP2PService::decodeSingleResponse);
    }

    public CompletableFuture<byte[]> requestFinalityUpdate(String peerMultiaddr) {
        // No request body for finality_update — send nothing, just close write side
        return doReqResp(peerMultiaddr, FINALITY, new byte[0])
                .thenApply(BeaconP2PService::decodeSingleResponse);
    }

    public CompletableFuture<byte[]> requestOptimisticUpdate(String peerMultiaddr) {
        // No request body for optimistic_update — send nothing, just close write side
        return doReqResp(peerMultiaddr, OPTIMISTIC, new byte[0])
                .thenApply(BeaconP2PService::decodeSingleResponse);
    }

    public CompletableFuture<List<byte[]>> requestUpdatesByRange(
            String peerMultiaddr, long startPeriod, int count) {
        byte[] sszRequest = encodeUpdatesByRangeRequest(startPeriod, count);
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(sszRequest);
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        return doReqResp(peerMultiaddr, UPDATES, requestPayload)
                .thenApply(raw -> {
                    try {
                        return decodeUpdatesByRangeResponse(raw, count);
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to decode updates_by_range response", e);
                    }
                });
    }

    /**
     * Request beacon blocks by slot range from a CL peer.
     * Returns a list of SSZ-decoded SignedBeaconBlock payloads.
     */
    public CompletableFuture<List<byte[]>> requestBlocksByRange(
            String peerMultiaddr, long startSlot, long count) {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(startSlot);
        buf.putLong(count);
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(buf.array());
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        return doReqResp(peerMultiaddr, BLOCKS_BY_RANGE, requestPayload)
                .thenApply(raw -> {
                    try {
                        return decodeMultiChunkResponse(raw, count);
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to decode blocks_by_range response", e);
                    }
                });
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private static byte[] decodeSingleResponse(byte[] raw) {
        try {
            ReqRespCodec.DecodeResult result = ReqRespCodec.decodeResponse(raw);
            return result.sszPayload();
        } catch (IOException e) {
            throw new RuntimeException("Failed to decode response", e);
        }
    }

    /**
     * Find or create a connection to the peer, then open a muxed stream for the
     * given protocol — matching Teku's pattern of reusing connections.
     */
    private CompletableFuture<byte[]> doReqResp(
            String peerMultiaddr, String protocolId, byte[] requestBytes) {

        Host h = host;
        if (h == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("BeaconP2PService not started"));
        }

        CompletableFuture<byte[]> responseFuture = new CompletableFuture<>();

        QueuedReqRespBinding binding = bindings.get(protocolId);
        if (binding == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("No binding registered for " + protocolId));
        }

        try {
            Multiaddr peerAddr = new Multiaddr(peerMultiaddr);
            PeerId peerId = peerAddr.getPeerId();
            if (peerId == null) {
                return CompletableFuture.failedFuture(
                        new IllegalArgumentException("Cannot extract PeerId from: " + peerMultiaddr));
            }

            log.debug("[beacon-p2p] Opening stream {} to {}", protocolId, peerMultiaddr);

            // Step 1: Find existing connection or establish a new one
            CompletableFuture<io.libp2p.core.Connection> connFuture = findOrConnect(h, peerId, peerAddr);

            connFuture.whenComplete((conn, connEx) -> {
                if (connEx != null) {
                    log.debug("[beacon-p2p] Connection failed to {}: {} ({})",
                            peerMultiaddr, connEx.getMessage(), connEx.getClass().getSimpleName());
                    responseFuture.completeExceptionally(
                            new RuntimeException("Failed to connect to " + peerMultiaddr, connEx));
                    return;
                }

                // Step 2: Enqueue request state, then open a stream on the muxer
                binding.enqueue(requestBytes, responseFuture);

                try {
                    StreamPromise<?> streamPromise =
                            conn.muxerSession().createStream(binding);

                    streamPromise.getStream().whenComplete((stream, ex) -> {
                        if (ex != null && !responseFuture.isDone()) {
                            log.debug("[beacon-p2p] Stream open failed to {}: {} ({})",
                                    peerMultiaddr, ex.getMessage(), ex.getClass().getSimpleName());
                            Throwable cause = ex;
                            while (cause.getCause() != null) cause = cause.getCause();
                            if (cause != ex) {
                                log.debug("[beacon-p2p]   root cause: {} ({})",
                                        cause.getMessage(), cause.getClass().getSimpleName());
                            }
                            responseFuture.completeExceptionally(
                                    new RuntimeException("Failed to open stream to " + peerMultiaddr, ex));
                        }
                    });

                    streamPromise.getController().whenComplete((ctrl, ex) -> {
                        if (ex != null && !responseFuture.isDone()) {
                            log.debug("[beacon-p2p] Protocol negotiation failed for {} to {}: {}",
                                    protocolId, peerMultiaddr, ex.getMessage());
                            responseFuture.completeExceptionally(
                                    new RuntimeException("Protocol negotiation failed", ex));
                        }
                    });
                } catch (Exception e) {
                    if (!responseFuture.isDone()) {
                        responseFuture.completeExceptionally(
                                new RuntimeException("Failed to create stream to " + peerMultiaddr, e));
                    }
                }
            });

        } catch (Exception e) {
            log.debug("[beacon-p2p] Connection init failed to {}: {}", peerMultiaddr, e.getMessage());
            responseFuture.completeExceptionally(
                    new RuntimeException("Failed to initiate connection to " + peerMultiaddr, e));
        }

        return responseFuture;
    }

    /**
     * Find an existing connection to the peer, or establish a new one.
     */
    private CompletableFuture<io.libp2p.core.Connection> findOrConnect(
            Host h, PeerId peerId, Multiaddr peerAddr) {
        // Check for an existing connection first
        for (io.libp2p.core.Connection conn : h.getNetwork().getConnections()) {
            if (peerId.equals(conn.secureSession().getRemoteId())) {
                return CompletableFuture.completedFuture(conn);
            }
        }
        // No existing connection — establish a new one
        return h.getNetwork().connect(peerId, peerAddr);
    }

    private static byte[] encodeUpdatesByRangeRequest(long startPeriod, int count) {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(startPeriod);
        buf.putLong(count);
        return buf.array();
    }

    private static List<byte[]> decodeUpdatesByRangeResponse(byte[] raw, int expectedCount)
            throws IOException {
        return decodeMultiChunkResponse(raw, expectedCount);
    }

    /**
     * Decode a multi-chunk eth2 req/resp response (used by both updates_by_range
     * and blocks_by_range). Each chunk: 1B result + 4B fork_digest + varint len + snappy data.
     */
    private static List<byte[]> decodeMultiChunkResponse(byte[] raw, long expectedCount)
            throws IOException {
        List<byte[]> items = new ArrayList<>();
        int pos = 0;
        while (pos < raw.length && items.size() < expectedCount) {
            byte resultCode = raw[pos];
            if (resultCode != 0) {
                log.warn("[beacon-p2p] Multi-chunk response item {} error code {}", items.size(), resultCode);
                break;
            }
            pos++;
            if (pos + 4 > raw.length) break;
            pos += 4; // skip fork digest
            ReqRespCodec.VarintResult varint = ReqRespCodec.readVarint(raw, pos);
            pos = varint.nextPos();
            int compressedLength = varint.value();
            if (compressedLength == 0) { items.add(new byte[0]); continue; }
            if (pos + compressedLength > raw.length) break;
            byte[] compressed = new byte[compressedLength];
            System.arraycopy(raw, pos, compressed, 0, compressedLength);
            pos += compressedLength;
            items.add(ReqRespCodec.snappyDecompress(compressed));
        }
        return items;
    }

    // =========================================================================
    // Queued protocol binding: registered once, handles multiple requests
    // =========================================================================

    /**
     * A reusable ProtocolBinding registered with the host. Per-request state
     * (request bytes + response future) is passed through a FIFO queue.
     */
    static class QueuedReqRespBinding implements ProtocolBinding<ReqRespController> {

        private final String protocolId;
        private final ConcurrentLinkedQueue<PendingRequest> pendingRequests = new ConcurrentLinkedQueue<>();

        record PendingRequest(byte[] requestBytes, CompletableFuture<byte[]> responseFuture) {}

        QueuedReqRespBinding(String protocolId) {
            this.protocolId = protocolId;
        }

        void enqueue(byte[] requestBytes, CompletableFuture<byte[]> responseFuture) {
            pendingRequests.add(new PendingRequest(requestBytes, responseFuture));
        }

        @Override
        public ProtocolDescriptor getProtocolDescriptor() {
            return new ProtocolDescriptor(protocolId);
        }

        @Override
        public CompletableFuture<ReqRespController> initChannel(P2PChannel channel, String negotiatedProtocol) {
            PendingRequest pending = pendingRequests.poll();
            if (pending == null) {
                return CompletableFuture.failedFuture(
                        new IllegalStateException("No pending request for " + protocolId));
            }

            // Cast to Stream to access closeWrite() for half-close
            io.libp2p.core.Stream stream = (io.libp2p.core.Stream) channel;
            ReqRespController controller = new ReqRespController(
                    pending.requestBytes, pending.responseFuture, stream);
            channel.pushHandler(controller.nettyHandler());
            return controller.getReadyFuture();
        }
    }

    // =========================================================================
    // Controller: handles a single stream's I/O
    // =========================================================================

    static class ReqRespController {

        private final byte[] requestBytes;
        private final CompletableFuture<byte[]> responseFuture;
        private final CompletableFuture<ReqRespController> readyFuture = new CompletableFuture<>();
        private final ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream();
        private final io.libp2p.core.Stream stream;
        private volatile boolean writeClosedOnly;

        ReqRespController(byte[] requestBytes, CompletableFuture<byte[]> responseFuture,
                          io.libp2p.core.Stream stream) {
            this.requestBytes = requestBytes;
            this.responseFuture = responseFuture;
            this.stream = stream;
        }

        CompletableFuture<ReqRespController> getReadyFuture() {
            return readyFuture;
        }

        ChannelHandler nettyHandler() {
            return new SimpleChannelInboundHandler<ByteBuf>() {

                @Override
                public void channelActive(ChannelHandlerContext ctx) throws Exception {
                    log.debug("[beacon-p2p] channelActive fired, writing {} request bytes",
                            requestBytes != null ? requestBytes.length : 0);
                    // Send request bytes then half-close write side per eth2 req/resp spec.
                    writeClosedOnly = true;  // Mark that next channelInactive is from our closeWrite
                    if (requestBytes != null && requestBytes.length > 0) {
                        ctx.writeAndFlush(Unpooled.wrappedBuffer(requestBytes)).addListener(f -> {
                            log.debug("[beacon-p2p] Request write complete, success={}", f.isSuccess());
                            stream.closeWrite();
                            log.debug("[beacon-p2p] closeWrite() called");
                        });
                    } else {
                        stream.closeWrite();
                        log.debug("[beacon-p2p] closeWrite() called (empty request)");
                    }
                    readyFuture.complete(ReqRespController.this);
                    super.channelActive(ctx);
                }

                @Override
                protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                    int readable = msg.readableBytes();
                    log.debug("[beacon-p2p] channelRead0: {} bytes received", readable);
                    byte[] bytes = new byte[readable];
                    msg.readBytes(bytes);
                    responseBuffer.write(bytes, 0, bytes.length);
                }

                @Override
                public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                    log.debug("[beacon-p2p] channelInactive fired, buffer size={}, writeClosedOnly={}",
                            responseBuffer.size(), writeClosedOnly);
                    if (writeClosedOnly) {
                        // This channelInactive is from our closeWrite(), not a full close.
                        // Ignore it — data may still arrive on the read side.
                        writeClosedOnly = false;
                        super.channelInactive(ctx);
                        return;
                    }
                    if (!responseFuture.isDone()) {
                        byte[] response = responseBuffer.toByteArray();
                        if (response.length == 0) {
                            responseFuture.completeExceptionally(
                                    new RuntimeException("Empty response (stream closed without data)"));
                        } else {
                            responseFuture.complete(response);
                        }
                    }
                    super.channelInactive(ctx);
                }

                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                    log.debug("[beacon-p2p] exceptionCaught: {}", cause.getMessage());
                    if (!responseFuture.isDone()) {
                        responseFuture.completeExceptionally(cause);
                    }
                    if (!readyFuture.isDone()) {
                        readyFuture.completeExceptionally(cause);
                    }
                    ctx.close();
                }
            };
        }
    }
}
