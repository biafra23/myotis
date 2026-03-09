package devp2p.networking.eth;

import devp2p.core.crypto.NodeKey;
import devp2p.networking.NetworkConfig;
import devp2p.networking.eth.messages.*;
import devp2p.networking.rlpx.RLPxHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * eth/68 protocol handler.
 *
 * Sits above the RLPxHandler in the pipeline. Receives decoded RLPxMessages
 * and implements the eth sub-protocol state machine:
 *
 *   AWAITING_HELLO → AWAITING_STATUS → READY
 *
 * Message code offsets (after p2p base):
 *   p2p:  0x00 Hello, 0x01 Disconnect, 0x02 Ping, 0x03 Pong
 *   eth:  0x10 Status, 0x11 NewBlockHashes, 0x13 GetBlockHeaders, 0x14 BlockHeaders, ...
 */
public final class EthHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(EthHandler.class);

    // p2p sub-protocol message codes
    private static final int P2P_HELLO = 0x00;
    private static final int P2P_DISCONNECT = 0x01;
    private static final int P2P_PING = 0x02;
    private static final int P2P_PONG = 0x03;

    // eth/68 offsets from capability base (0x10)
    private static final int ETH_STATUS = 0x10;
    private static final int ETH_GET_BLOCK_HEADERS = 0x13;
    private static final int ETH_BLOCK_HEADERS = 0x14;
    private static final int ETH_GET_BLOCK_BODIES = 0x15;
    private static final int ETH_BLOCK_BODIES = 0x16;

    public enum State { AWAITING_HELLO, AWAITING_STATUS, READY }
    private volatile State state = State.AWAITING_HELLO;
    private volatile String remoteAddress;
    private volatile String peerBestHash; // what peer claimed in Status
    private volatile String ourBestHash;  // what we claimed in Status
    private volatile boolean incompatibleNetwork; // confirmed wrong chain

    private final NodeKey nodeKey;
    private final int tcpPort;
    private final NetworkConfig network;
    private final Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders;
    private final Runnable onReady;
    private final AtomicLong requestId = new AtomicLong(1);
    private final ConcurrentMap<Long, CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>>>
            pendingRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<List<BlockBodiesMessage.BlockBody>>>
            pendingBodyRequests = new ConcurrentHashMap<>();


    // Cache received headers so we can serve them back to peers (by block number)
    private final ConcurrentMap<Long, byte[]> headerCache = new ConcurrentHashMap<>();
    // Cache by block hash hex string for hash-based lookups
    private final ConcurrentMap<String, byte[]> hashCache = new ConcurrentHashMap<>();

    private RLPxHandler rlpxHandler; // reference to the RLPx layer for sending
    private volatile ChannelHandlerContext readyCtx; // stored when state reaches READY
    private volatile long readyTimestamp; // when we entered READY state
    private int negotiatedEthVersion = StatusMessage.MAX_ETH_VERSION;

    public EthHandler(NodeKey nodeKey, int tcpPort, NetworkConfig network,
                      Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders,
                      Runnable onReady) {
        this.nodeKey = nodeKey;
        this.tcpPort = tcpPort;
        this.network = network;
        this.onHeaders = onHeaders;
        this.onReady = onReady;

        // Pre-cache genesis block header so we can serve it when peers test us
        if ("mainnet".equals(network.name())) {
            byte[] genesisRlp = NetworkConfig.MAINNET_GENESIS_HEADER_RLP;
            // Verify hash matches (BouncyCastle is registered by now via NodeKey)
            org.apache.tuweni.bytes.Bytes32 computed =
                    org.apache.tuweni.crypto.Hash.keccak256(org.apache.tuweni.bytes.Bytes.wrap(genesisRlp));
            if (!computed.equals(network.genesisHash())) {
                throw new IllegalStateException("Genesis header RLP hash mismatch: " + computed.toHexString());
            }
            headerCache.put(0L, genesisRlp);
            hashCache.put(network.genesisHash().toHexString(), genesisRlp);
            log.info("[eth] Pre-cached mainnet genesis header ({} bytes, hash={})",
                    genesisRlp.length, network.genesisHash().toShortHexString());
        }
    }

    /** Set the remote address early (at connect time), before the handshake completes. */
    public void setRemoteAddress(String address) {
        this.remoteAddress = address;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
        if ("RLPX_READY".equals(evt)) {
            // Store remote address early so it's available before READY state
            var addr = ctx.channel().remoteAddress();
            if (addr != null) {
                remoteAddress = addr.toString().replaceFirst("^/", "");
            }
            // Retrieve the RLPx handler from the pipeline
            rlpxHandler = (RLPxHandler) ctx.pipeline().get("rlpx");
            sendHello(ctx);

            // Handshake timeout: close if not READY within 30 seconds
            ctx.executor().schedule(() -> {
                if (state != State.READY) {
                    log.warn("[eth] Handshake timeout (30s), closing {}", remoteAddress);
                    ctx.close();
                }
            }, 30, TimeUnit.SECONDS);
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (state == State.AWAITING_STATUS) {
            log.warn("[eth] Peer {} closed without responding to Status", remoteAddress);
        } else if (state == State.AWAITING_HELLO) {
            log.warn("[eth] Peer {} closed before Hello exchange", remoteAddress);
        }
        // Complete all pending request futures exceptionally on disconnect
        Exception cause = new java.io.IOException("Channel closed: " + remoteAddress);
        if (!pendingRequests.isEmpty()) {
            pendingRequests.values().forEach(f -> f.completeExceptionally(cause));
            pendingRequests.clear();
        }
        if (!pendingBodyRequests.isEmpty()) {
            pendingBodyRequests.values().forEach(f -> f.completeExceptionally(cause));
            pendingBodyRequests.clear();
        }
        super.channelInactive(ctx);
    }

    /** Called by RLPxHandler when a decoded message arrives. */
    public void onMessage(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        log.info("[eth] Received message code=0x{} state={}", Integer.toHexString(msg.code()), state);
        switch (state) {
            case AWAITING_HELLO -> handleHello(ctx, msg);
            case AWAITING_STATUS -> handleStatus(ctx, msg);
            case READY -> handleReady(ctx, msg);
        }
    }

    // -------------------------------------------------------------------------
    // State: AWAITING_HELLO
    // -------------------------------------------------------------------------
    // Eth versions we advertise in our Hello
    private static final java.util.Set<Integer> OUR_ETH_VERSIONS = java.util.Set.of(67, 68, 69);

    private void handleHello(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        if (msg.code() == P2P_HELLO) {
            HelloMessage hello = HelloMessage.decode(msg.payload());
            log.info("[eth] Hello from peer: {}", hello);

            // Negotiate highest eth version that BOTH sides support
            int bestEthVersion = hello.capabilities.stream()
                .filter(c -> c.name().equals("eth") && OUR_ETH_VERSIONS.contains(c.version()))
                .mapToInt(HelloMessage.Capability::version)
                .max().orElse(-1);
            if (bestEthVersion < 0) {
                log.warn("[eth] Peer does not support eth/67+, disconnecting (caps={})", hello.capabilities);
                ctx.close();
                return;
            }
            negotiatedEthVersion = bestEthVersion;
            log.info("[eth] Negotiated eth/{}", negotiatedEthVersion);
            state = State.AWAITING_STATUS;
            sendStatus(ctx);
        } else if (msg.code() == P2P_DISCONNECT) {
            log.info("[eth] Peer disconnected during Hello (reason={})", decodeDisconnectReason(msg.payload()));
            ctx.close();
        }
    }

    // -------------------------------------------------------------------------
    // State: AWAITING_STATUS
    // -------------------------------------------------------------------------
    private void handleStatus(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        if (msg.code() == ETH_STATUS) {
            log.info("[eth] Received Status raw payload ({} bytes): {}", msg.payload().length,
                bytesToHex(msg.payload(), msg.payload().length));
            StatusMessage status;
            try {
                status = negotiatedEthVersion >= 69
                    ? StatusMessage.decode69(msg.payload())
                    : StatusMessage.decode(msg.payload());
            } catch (Exception e) {
                log.error("[eth] Failed to decode Status from peer: {} | payload[{}]={}", e.getMessage(),
                    msg.payload().length,
                    bytesToHex(msg.payload(), msg.payload().length));
                ctx.close();
                return;
            }
            peerBestHash = status.bestHash.toShortHexString();
            log.info("[eth] Status from peer: {} (bestHash={})", status, peerBestHash);
            if (!status.isCompatible(network.networkId(), network.genesisHash())) {
                log.warn("[eth] Incompatible network: chainId={}, genesis={}",
                    status.networkId, status.genesisHash);
                incompatibleNetwork = true;
                ctx.close();
                return;
            }
            state = State.READY;
            readyCtx = ctx;
            readyTimestamp = System.currentTimeMillis();
            log.info("[eth] Peer ready! Requesting peer's best block and recent headers...");
            if (onReady != null) onReady.run();
            // Request the peer's advertised best block by hash
            requestBlockHeadersByHash(ctx, status.bestHash);
            requestBlockHeaders(ctx, 21_000_000L, 1);
        } else if (msg.code() == P2P_PING) {
            sendPong(ctx);
        } else if (msg.code() == P2P_DISCONNECT) {
            log.info("[eth] Peer disconnected during Status exchange (reason={})", decodeDisconnectReason(msg.payload()));
            ctx.close();
        } else {
            log.info("[eth] Unexpected msg during Status: code=0x{}", Integer.toHexString(msg.code()));
        }
    }

    // -------------------------------------------------------------------------
    // State: READY
    // -------------------------------------------------------------------------
    private void handleReady(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        switch (msg.code()) {
            case ETH_GET_BLOCK_HEADERS -> {
                // Peer is requesting headers from us. Serve from cache or return empty.
                try {
                    org.apache.tuweni.bytes.Bytes payload = org.apache.tuweni.bytes.Bytes.wrap(msg.payload());
                    long[] reqIdHolder = new long[1];
                    long[] blockNumHolder = new long[1];
                    int[] countHolder = new int[1];
                    String[] hashHolder = new String[1];     // short hex for logging
                    String[] fullHashHolder = new String[1]; // full hex for cache lookup
                    org.apache.tuweni.rlp.RLP.decodeList(payload, reader -> {
                        reqIdHolder[0] = reader.readLong();
                        reader.readList(r -> {
                            org.apache.tuweni.bytes.Bytes start = r.readValue();
                            if (start.size() <= 8) {
                                blockNumHolder[0] = start.toLong();
                                hashHolder[0] = null;
                                fullHashHolder[0] = null;
                            } else {
                                blockNumHolder[0] = -1;
                                hashHolder[0] = start.toShortHexString();
                                fullHashHolder[0] = start.toHexString();
                            }
                            countHolder[0] = r.readInt();
                            return null;
                        });
                        return null;
                    });
                    long reqId = reqIdHolder[0];
                    long blockNum = blockNumHolder[0];
                    int count = countHolder[0];
                    String requestedHash = hashHolder[0];
                    String fullHash = fullHashHolder[0];

                    // Try to serve from cache — by hash or by number
                    java.util.List<byte[]> cached = new java.util.ArrayList<>();
                    if (fullHash != null) {
                        byte[] h = hashCache.get(fullHash);
                        if (h != null) cached.add(h);
                    } else if (blockNum >= 0) {
                        for (int i = 0; i < count && cached.size() < count; i++) {
                            byte[] h = headerCache.get(blockNum + i);
                            if (h != null) cached.add(h);
                            else break;
                        }
                    }

                    byte[] response = org.apache.tuweni.rlp.RLP.encodeList(w -> {
                        w.writeLong(reqId);
                        w.writeList(l -> {
                            for (byte[] h : cached) {
                                l.writeRLP(org.apache.tuweni.bytes.Bytes.wrap(h));
                            }
                        });
                    }).toArrayUnsafe();

                    String requested = requestedHash != null
                        ? "hash=" + requestedHash
                        : "block=" + blockNum;
                    long msSinceReady = readyTimestamp > 0
                        ? System.currentTimeMillis() - readyTimestamp : -1;
                    log.info("[eth] PEER ASKS: GetBlockHeaders({}, count={}, reqId={}) | " +
                             "WE CLAIMED bestHash={} | PEER CLAIMED bestHash={} | " +
                             "SERVING {} from cache (cacheSize={}) | {}ms after READY",
                        requested, count, reqId, ourBestHash, peerBestHash,
                        cached.size(), headerCache.size(), msSinceReady);
                    rlpxHandler.sendMessage(ctx, ETH_BLOCK_HEADERS, response);
                } catch (Exception e) {
                    log.warn("[eth] Failed to handle GetBlockHeaders from peer", e);
                }
            }
            case ETH_BLOCK_HEADERS -> {
                try {
                    BlockHeadersMessage.DecodeResult decoded =
                        BlockHeadersMessage.decodeWithRequestId(msg.payload());
                    log.info("[eth] Received {} block headers (reqId={})",
                            decoded.headers().size(), decoded.requestId());
                    for (BlockHeadersMessage.VerifiedHeader vh : decoded.headers()) {
                        byte[] raw = vh.rawRlp().toArrayUnsafe();
                        headerCache.put(vh.header().number, raw);
                        hashCache.put(vh.hash().toHexString(), raw);
                        log.debug("[eth] Cached header for block #{} hash={}",
                                vh.header().number, vh.hash().toShortHexString());
                    }
                    // Complete pending future
                    CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> future =
                        pendingRequests.remove(decoded.requestId());
                    if (future != null) {
                        future.complete(decoded.headers());
                    }
                    onHeaders.accept(decoded.headers());
                } catch (Exception e) {
                    log.error("[eth] Failed to decode BlockHeaders", e);
                }
            }
            case ETH_BLOCK_BODIES -> {
                try {
                    BlockBodiesMessage.DecodeResult decoded =
                        BlockBodiesMessage.decode(msg.payload());
                    log.info("[eth] Received {} block bodies (reqId={})",
                            decoded.bodies().size(), decoded.requestId());
                    CompletableFuture<List<BlockBodiesMessage.BlockBody>> future =
                        pendingBodyRequests.remove(decoded.requestId());
                    if (future != null) {
                        future.complete(decoded.bodies());
                    }
                } catch (Exception e) {
                    log.error("[eth] Failed to decode BlockBodies", e);
                }
            }
            case P2P_PING -> sendPong(ctx);
            case P2P_DISCONNECT -> {
                log.info("[eth] Peer disconnected (reason={})", decodeDisconnectReason(msg.payload()));
                ctx.close();
            }
            default -> log.debug("[eth] Unhandled message 0x{} ({} bytes) from {}",
                Integer.toHexString(msg.code()), msg.payload().length, remoteAddress);
        }
    }

    // -------------------------------------------------------------------------
    // Sending
    // -------------------------------------------------------------------------
    private void sendHello(ChannelHandlerContext ctx) {
        log.debug("[eth] Sending Hello");
        byte[] payload = HelloMessage.encode(nodeKey.publicKeyBytes(), tcpPort);
        rlpxHandler.sendMessage(ctx, P2P_HELLO, payload);
    }

    private void sendStatus(ChannelHandlerContext ctx) {
        ourBestHash = network.bestBlockHash().toShortHexString();
        byte[] payload = StatusMessage.encode(
            negotiatedEthVersion, network.networkId(), network.genesisHash(),
            network.bestBlockHash(), network.forkIdHash(), network.forkNext());
        log.info("[eth] Sending Status ({} bytes, eth/{}): bestHash={} forkIdHash={} forkNext={} hex={}",
            payload.length, negotiatedEthVersion, ourBestHash,
            bytesToHex(network.forkIdHash(), network.forkIdHash().length),
            network.forkNext(), bytesToHex(payload, payload.length));
        rlpxHandler.sendMessage(ctx, ETH_STATUS, payload);
    }

    public void requestBlockHeadersByHash(ChannelHandlerContext ctx, org.apache.tuweni.bytes.Bytes32 hash) {
        long reqId = requestId.getAndIncrement();
        log.info("[eth] GetBlockHeaders by hash={} reqId={}", hash.toShortHexString(), reqId);
        byte[] payload = GetBlockHeadersMessage.encodeByHash(reqId, hash, 1, 0, false);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_HEADERS, payload);
    }

    public void requestBlockHeaders(ChannelHandlerContext ctx, long blockNumber, int count) {
        long reqId = requestId.getAndIncrement();
        log.debug("[eth] GetBlockHeaders block={} count={} reqId={}", blockNumber, count, reqId);
        byte[] payload = GetBlockHeadersMessage.encodeByNumber(reqId, blockNumber, count, 0, false);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_HEADERS, payload);
    }

    /**
     * Request block headers and return a future that completes when the response arrives.
     * Uses the stored ChannelHandlerContext from the READY state.
     *
     * @return a future, or null if this handler is not in READY state
     */
    public CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> requestBlockHeadersAsync(
            long blockNumber, int count) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return null;

        CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> future = new CompletableFuture<>();
        long reqId = requestId.getAndIncrement();
        pendingRequests.put(reqId, future);
        log.debug("[eth] GetBlockHeaders (async) block={} count={} reqId={}", blockNumber, count, reqId);
        byte[] payload = GetBlockHeadersMessage.encodeByNumber(reqId, blockNumber, count, 0, false);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_HEADERS, payload);
        return future;
    }

    /**
     * Request block bodies and return a future that completes when the response arrives.
     *
     * @return a future, or null if this handler is not in READY state
     */
    public CompletableFuture<List<BlockBodiesMessage.BlockBody>> requestBlockBodiesAsync(
            org.apache.tuweni.bytes.Bytes32... hashes) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return null;

        CompletableFuture<List<BlockBodiesMessage.BlockBody>> future = new CompletableFuture<>();
        long reqId = requestId.getAndIncrement();
        pendingBodyRequests.put(reqId, future);
        log.debug("[eth] GetBlockBodies (async) hashes={} reqId={}", hashes.length, reqId);
        byte[] payload = GetBlockBodiesMessage.encode(reqId, hashes);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_BODIES, payload);
        return future;
    }

    public State getState() {
        return state;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    /** Returns true if this peer was confirmed on an incompatible network. */
    public boolean isIncompatibleNetwork() {
        return incompatibleNetwork;
    }

    /** Returns true if this handler has completed the eth handshake. */
    public boolean isReady() {
        return state == State.READY && readyCtx != null;
    }

    private void sendPong(ChannelHandlerContext ctx) {
        rlpxHandler.sendMessage(ctx, P2P_PONG, new byte[0]);
    }

    private static String bytesToHex(byte[] b, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }

    /**
     * Decode disconnect reason from RLP payload.
     * Disconnect payload: RLP([reason]) = [0xC1, reason_byte] or [0xC0] (empty)
     */
    private static int decodeDisconnectReason(byte[] payload) {
        if (payload.length == 0) return -1;
        int first = payload[0] & 0xFF;
        if (first < 0x80) return first;          // raw byte (non-standard)
        if (first == 0xC0) return 0;             // empty list
        if (first >= 0xC1 && payload.length >= 2) return payload[1] & 0xFF; // list[reason]
        return -1;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("[eth] Exception", cause);
        ctx.close();
    }
}
