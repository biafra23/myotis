package com.jaeckel.ethp2p.consensus.libp2p;

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

    /** Cached Identify protocol lists per peer ID (populated lazily). */
    private final Map<String, List<String>> peerProtocols = new ConcurrentHashMap<>();

    /** Cached agent version (client ID) per peer ID. */
    private final Map<String, String> peerAgentVersions = new ConcurrentHashMap<>();

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

        // Log connection events and auto-query Identify for protocol support
        host.addConnectionHandler(conn -> {
            String pid = conn.secureSession().getRemoteId().toString();
            log.info("[beacon-p2p] Connection established to peer={} remote={} local={}",
                    pid, conn.remoteAddress(), conn.localAddress());
            // Automatically query Identify to cache supported protocols
            try {
                StreamPromise<IdentifyController> sp =
                        conn.muxerSession().createStream(identifyBinding);
                sp.getController().thenCompose(ctrl -> ctrl.id()).thenAccept(idMsg -> {
                    List<String> protos = idMsg.getProtocolsList().stream()
                            .map(Object::toString).toList();
                    peerProtocols.put(pid, protos);
                    String agent = idMsg.getAgentVersion();
                    if (agent != null && !agent.isEmpty()) {
                        peerAgentVersions.put(pid, agent);
                    }
                    long lcCount = protos.stream().filter(p -> p.contains("light_client")).count();
                    log.debug("[beacon-p2p] Identify auto-query for {}: agent={}, {} protocols ({} light_client)",
                            pid, agent, protos.size(), lcCount);
                }).exceptionally(ex -> {
                    log.debug("[beacon-p2p] Identify auto-query failed for {}: {}", pid, ex.getMessage());
                    return null;
                });
            } catch (Exception e) {
                log.debug("[beacon-p2p] Failed to start Identify for {}: {}", pid, e.getMessage());
            }
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

    /** Info about a connected CL peer. */
    public record PeerInfo(String peerId, String remoteAddress, List<String> protocols, String agentVersion) {
        /** Whether this peer advertises any light_client protocol. */
        public boolean supportsLightClient() {
            return protocols != null && protocols.stream()
                    .anyMatch(p -> p.contains("light_client"));
        }
    }

    /**
     * Return info about all currently connected CL peers.
     * For each peer, attempts to retrieve cached Identify protocol lists.
     */
    public List<PeerInfo> getConnectedPeers() {
        Host h = host;
        if (h == null) return List.of();
        List<PeerInfo> result = new ArrayList<>();
        for (io.libp2p.core.Connection conn : h.getNetwork().getConnections()) {
            String peerId = conn.secureSession().getRemoteId().toString();
            String remote = conn.remoteAddress().toString();
            List<String> protocols = peerProtocols.get(peerId);
            String agent = peerAgentVersions.get(peerId);
            result.add(new PeerInfo(peerId, remote,
                    protocols != null ? protocols : List.of(),
                    agent));
        }
        return result;
    }

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
                List<String> protoStrings = protocols.stream()
                        .map(Object::toString).toList();
                // Cache protocol list and agent version keyed by peer ID
                try {
                    PeerId pid = new Multiaddr(peerMultiaddr).getPeerId();
                    if (pid != null) {
                        peerProtocols.put(pid.toString(), protoStrings);
                        String agent = idMsg.getAgentVersion();
                        if (agent != null && !agent.isEmpty()) {
                            peerAgentVersions.put(pid.toString(), agent);
                        }
                    }
                } catch (Exception ignored) {}
                log.info("[beacon-p2p] Identify response from {}: {} protocols", peerMultiaddr, protoStrings.size());
                for (String protoStr : protoStrings) {
                    if (protoStr.contains("light_client") || protoStr.contains("eth2")) {
                        log.info("[beacon-p2p]   MATCH: {}", protoStr);
                    }
                }
                // Log all protocols at debug level
                for (String protoStr : protoStrings) {
                    log.debug("[beacon-p2p]   proto: {}", protoStr);
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
        } catch (Exception e) {
            log.warn("[beacon-p2p] Failed to decode response ({} bytes): {} — first 20 bytes: {}",
                    raw.length, e.getMessage(), bytesToHex(raw, 20));
            throw new RuntimeException("Failed to decode response: " + e.getMessage(), e);
        }
    }

    private static String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, limit); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
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
                log.debug("[beacon-p2p] Connection ready for {}, enqueueing and creating stream for {}",
                        peerMultiaddr, protocolId);
                binding.enqueue(requestBytes, responseFuture);

                try {
                    StreamPromise<?> streamPromise =
                            conn.muxerSession().createStream(binding);
                    log.debug("[beacon-p2p] createStream() returned for {} to {}", protocolId, peerMultiaddr);

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
     * and blocks_by_range). Each chunk: 1B result + 4B fork_digest + varint(uncompressed_len) + snappy data.
     * The varint is the uncompressed SSZ length, NOT the compressed length.
     * We scan snappy frames to find chunk boundaries, using the expected uncompressed
     * length to resolve ambiguity between snappy compressed frames (type 0x00) and
     * the next chunk's result code (also 0x00).
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
            int uncompressedLength = varint.value();
            if (uncompressedLength == 0) { items.add(new byte[0]); continue; }

            // Scan snappy frames to find the end of this chunk's compressed data
            int snappyStart = pos;
            pos = skipSnappyFrames(raw, pos, uncompressedLength);
            int compressedLength = pos - snappyStart;
            if (compressedLength <= 0) break;
            byte[] compressed = new byte[compressedLength];
            System.arraycopy(raw, snappyStart, compressed, 0, compressedLength);
            items.add(ReqRespCodec.snappyDecompress(compressed));
        }
        return items;
    }

    /**
     * Skip past one complete snappy framed stream. Snappy frames:
     * - Stream identifier: 0xff + 3-byte LE length (always 6) + "sNaPpY"
     * - Compressed: 0x00 + 3-byte LE length + data
     * - Uncompressed: 0x01 + 3-byte LE length + data
     *
     * Tracks decompressed output to stop when the expected uncompressed length
     * is reached, preventing ambiguity between snappy compressed frames (0x00)
     * and the next response chunk's result code (also 0x00).
     *
     * @param data              raw response bytes
     * @param pos               start position of the snappy stream
     * @param uncompressedLength expected total decompressed output for this chunk
     * @return position after the last frame belonging to this chunk
     */
    private static int skipSnappyFrames(byte[] data, int pos, int uncompressedLength) {
        int decompressedSoFar = 0;
        while (pos < data.length) {
            int chunkType = data[pos] & 0xFF;
            if (chunkType != 0xFF && chunkType != 0x00 && chunkType != 0x01) {
                // Not a snappy frame — this is the start of the next chunk's result code
                break;
            }
            if (pos + 4 > data.length) break;
            int frameLen = (data[pos + 1] & 0xFF)
                    | ((data[pos + 2] & 0xFF) << 8)
                    | ((data[pos + 3] & 0xFF) << 16);
            // Bounds check: frame must fit within the data
            if (pos + 4 + frameLen > data.length) {
                // Truncated frame — consume remaining data
                pos = data.length;
                break;
            }

            // Track decompressed output to know when this chunk is complete
            if (chunkType == 0x01 && frameLen > 4) {
                // Uncompressed frame: 4 bytes CRC32C + raw data
                decompressedSoFar += frameLen - 4;
            } else if (chunkType == 0x00 && frameLen > 4) {
                // Compressed frame: 4 bytes CRC32C + snappy block
                // Snappy block starts with a varint for uncompressed block length
                try {
                    int snappyBlockStart = pos + 4 + 4; // frame header (4) + CRC32C (4)
                    ReqRespCodec.VarintResult blockSize =
                            ReqRespCodec.readVarint(data, snappyBlockStart);
                    decompressedSoFar += blockSize.value();
                } catch (Exception e) {
                    // Can't read varint — likely not a real snappy frame
                    break;
                }
            }
            // 0xFF is stream identifier — contributes 0 decompressed bytes

            pos += 4 + frameLen;

            // Stop when we've accounted for all expected decompressed bytes
            if (decompressedSoFar >= uncompressedLength && uncompressedLength > 0) {
                break;
            }
        }
        return pos;
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
            // Drain stale (already-timed-out) requests from the queue
            PendingRequest pending = null;
            while (true) {
                pending = pendingRequests.poll();
                if (pending == null) {
                    log.warn("[beacon-p2p] No pending request for {} — queue was empty!", protocolId);
                    return CompletableFuture.failedFuture(
                            new IllegalStateException("No pending request for " + protocolId));
                }
                if (!pending.responseFuture.isDone()) break;
                log.debug("[beacon-p2p] Skipping stale request for {}", protocolId);
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
        private volatile boolean dataReceived;
        private volatile boolean channelFullyClosed;
        private volatile java.util.concurrent.ScheduledFuture<?> completionTimer;

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
                    dataReceived = true;
                    byte[] bytes = new byte[readable];
                    msg.readBytes(bytes);
                    responseBuffer.write(bytes, 0, bytes.length);
                    log.debug("[beacon-p2p] channelRead0: {} bytes received, total={}, channelClosed={}",
                            readable, responseBuffer.size(), channelFullyClosed);
                }

                @Override
                public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
                    if (!dataReceived || responseFuture.isDone()) {
                        super.channelReadComplete(ctx);
                        return;
                    }

                    if (channelFullyClosed) {
                        // Channel is inactive but buffered data is still being delivered
                        // in multiple batches (e.g., 1+4+3+10 bytes, then 25680 bytes
                        // arriving ~40ms later). Use a short delay to accumulate all
                        // buffered reads before completing.
                        var prevClosed = completionTimer;
                        if (prevClosed != null) prevClosed.cancel(false);
                        completionTimer = ctx.executor().schedule(() -> {
                            if (!responseFuture.isDone() && responseBuffer.size() > 0) {
                                log.debug("[beacon-p2p] Completing response (post-close timer): {} bytes",
                                        responseBuffer.size());
                                responseFuture.complete(responseBuffer.toByteArray());
                            }
                        }, 150, java.util.concurrent.TimeUnit.MILLISECONDS);
                        super.channelReadComplete(ctx);
                        return;
                    }

                    // Don't use a short timer — large responses (e.g. bootstrap ~25KB)
                    // can arrive in multiple TCP segments spaced >200ms apart, which
                    // would cause premature completion with truncated data.
                    // Instead, rely on channelInactive (stream close) to complete.
                    // Use a long safety timer (5s) only as a fallback for muxer
                    // implementations that don't reliably fire channelInactive.
                    var prev = completionTimer;
                    if (prev != null) prev.cancel(false);
                    completionTimer = ctx.executor().schedule(() -> {
                        if (!responseFuture.isDone() && responseBuffer.size() > 0) {
                            log.debug("[beacon-p2p] Completing response (safety timer): {} bytes",
                                    responseBuffer.size());
                            responseFuture.complete(responseBuffer.toByteArray());
                        }
                    }, 5000, java.util.concurrent.TimeUnit.MILLISECONDS);
                    super.channelReadComplete(ctx);
                }

                @Override
                public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                    log.debug("[beacon-p2p] channelInactive fired, buffer size={}, dataReceived={}, writeClosedOnly={}",
                            responseBuffer.size(), dataReceived, writeClosedOnly);
                    if (writeClosedOnly && !dataReceived) {
                        // This channelInactive is from our closeWrite(), not a full close.
                        // Ignore it — data may still arrive on the read side.
                        // Only ignore if no data received yet — if data already arrived,
                        // the remote has responded and this is a real close.
                        writeClosedOnly = false;
                        super.channelInactive(ctx);
                        return;
                    }
                    writeClosedOnly = false;
                    // Mark channel as fully closed — any subsequent channelRead0
                    // calls are delivering buffered data and should complete immediately.
                    channelFullyClosed = true;
                    if (!dataReceived && responseBuffer.size() == 0) {
                        // No data arrived yet. Data may still come via buffered channelRead0
                        // after this event. Don't complete the future — let the caller's
                        // timeout or a subsequent channelRead0 handle it.
                        log.debug("[beacon-p2p] Channel closed with no data yet, waiting for buffered reads");
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
