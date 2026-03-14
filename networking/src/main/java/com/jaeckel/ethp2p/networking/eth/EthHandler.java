package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.ChainHead;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.eth.messages.*;
import com.jaeckel.ethp2p.networking.rlpx.RLPxHandler;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetAccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetStorageRangesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    // snap/1 message codes depend on negotiated eth version:
    //   eth/67-68: protocol length 17, snap base = 0x10 + 17 = 0x21
    //   eth/69:    protocol length 18 (adds BlockRangeUpdate at 0x11), snap base = 0x10 + 18 = 0x22
    private int snapGetAccountRange  = 0x21; // updated after Hello negotiation
    private int snapAccountRange     = 0x22;
    private int snapGetStorageRanges = 0x23;
    private int snapStorageRanges    = 0x24;

    public enum State { AWAITING_HELLO, AWAITING_STATUS, READY }
    private volatile State state = State.AWAITING_HELLO;
    private volatile String remoteAddress;
    private volatile String peerBestHash; // what peer claimed in Status (short hex for logging)
    private volatile org.apache.tuweni.bytes.Bytes32 peerBestBlockHash; // full hash for queries
    private volatile String ourBestHash;  // what we claimed in Status
    private volatile boolean incompatibleNetwork; // confirmed wrong chain
    private volatile boolean snapNegotiated = false;
    private volatile String clientId;
    private volatile boolean snapServingFailed = false;
    private volatile org.apache.tuweni.bytes.Bytes32 latestStateRoot;
    private volatile long latestStateRootBlockNumber = -1;

    private final NodeKey nodeKey;
    private final int tcpPort;
    private final NetworkConfig network;
    private final ChainHead chainHead;
    private final Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders;
    private final Runnable onReady;
    private final AtomicLong requestId = new AtomicLong(1);
    private final ConcurrentMap<Long, CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>>>
            pendingRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<List<BlockBodiesMessage.BlockBody>>>
            pendingBodyRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<AccountRangeMessage.DecodeResult>>
            pendingSnapRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<StorageRangesMessage.DecodeResult>>
            pendingStorageRequests = new ConcurrentHashMap<>();


    // Cache received headers so we can serve them back to peers (by block number)
    private static final int MAX_CACHE_ENTRIES = 10_000;
    private final Map<Long, byte[]> headerCache = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<Long, byte[]> eldest) {
                    return size() > MAX_CACHE_ENTRIES;
                }
            });
    // Cache by block hash hex string for hash-based lookups
    private final Map<String, byte[]> hashCache = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, byte[]> eldest) {
                    return size() > MAX_CACHE_ENTRIES;
                }
            });

    private RLPxHandler rlpxHandler; // reference to the RLPx layer for sending
    private volatile ChannelHandlerContext readyCtx; // stored when state reaches READY
    private volatile long readyTimestamp; // when we entered READY state
    private int negotiatedEthVersion = 68; // default, updated during Hello negotiation

    public EthHandler(NodeKey nodeKey, int tcpPort, NetworkConfig network,
                      ChainHead chainHead,
                      Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders,
                      Runnable onReady) {
        this.nodeKey = nodeKey;
        this.tcpPort = tcpPort;
        this.network = network;
        this.chainHead = chainHead;
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
            log.warn("[eth] Peer {} ({}) closed without responding to Status (we sent eth/{})",
                remoteAddress, clientId != null ? clientId : "unknown", negotiatedEthVersion);
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
        if (!pendingSnapRequests.isEmpty()) {
            pendingSnapRequests.values().forEach(f -> f.completeExceptionally(cause));
            pendingSnapRequests.clear();
        }
        if (!pendingStorageRequests.isEmpty()) {
            pendingStorageRequests.values().forEach(f -> f.completeExceptionally(cause));
            pendingStorageRequests.clear();
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
            this.clientId = hello.clientId;

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
            // eth/69 adds BlockRangeUpdate (0x11), making protocol length 18 instead of 17
            int ethProtocolLength = negotiatedEthVersion >= 69 ? 18 : 17;
            int snapBase = 0x10 + ethProtocolLength; // p2p base (16) + eth length
            snapGetAccountRange  = snapBase;
            snapAccountRange     = snapBase + 1;
            snapGetStorageRanges = snapBase + 2;
            snapStorageRanges    = snapBase + 3;
            log.info("[eth] snap base offset: 0x{} (eth length={})",
                Integer.toHexString(snapBase), ethProtocolLength);
            snapNegotiated = hello.capabilities.stream()
                .anyMatch(c -> c.name().equals("snap") && c.version() == 1);
            log.info("[eth] snap/1 {}", snapNegotiated ? "negotiated" : "NOT supported by peer");
            state = State.AWAITING_STATUS;
            sendStatus(ctx);
        } else if (msg.code() == P2P_DISCONNECT) {
            int reason = decodeDisconnectReason(msg.payload());
            log.info("[eth] Peer {} disconnected during Hello (reason={}/{})",
                remoteAddress, reason, disconnectReasonName(reason));
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
            peerBestBlockHash = status.bestHash;
            log.info("[eth] Status from peer: {} (bestHash={})", status, peerBestHash);
            // Update chain head from peer's Status (especially eth/69 which reports latestBlock)
            // This ensures subsequent Status messages to other peers use a realistic block number
            if (status.latestBlock > 0) {
                chainHead.update(status.latestBlock, status.bestHash);
                log.info("[eth] Updated chain head from peer Status: block={} hash={}",
                    status.latestBlock, peerBestHash);
            }
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
            int reason = decodeDisconnectReason(msg.payload());
            log.info("[eth] Peer {} ({}) disconnected during Status exchange (reason={}/{}, eth/{})",
                remoteAddress, clientId != null ? clientId : "unknown",
                reason, disconnectReasonName(reason), negotiatedEthVersion);
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
                            int requestedCount = r.readInt();
                            requestedCount = Math.max(0, Math.min(requestedCount, 1024));
                            countHolder[0] = requestedCount;
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
                        chainHead.update(vh.header().number, vh.hash());
                        if (vh.header().number > latestStateRootBlockNumber) {
                            latestStateRootBlockNumber = vh.header().number;
                            latestStateRoot = vh.header().stateRoot;
                        }
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
                int reason = decodeDisconnectReason(msg.payload());
                log.info("[eth] Peer {} ({}) disconnected in READY (reason={}/{})",
                    remoteAddress, clientId != null ? clientId : "unknown",
                    reason, disconnectReasonName(reason));
                ctx.close();
            }
            default -> {
                if (msg.code() == snapAccountRange) {
                    handleSnapAccountRange(msg);
                } else if (msg.code() == snapGetAccountRange) {
                    handleSnapGetAccountRange(ctx, msg);
                } else if (msg.code() == snapStorageRanges) {
                    handleSnapStorageRanges(msg);
                } else if (msg.code() == snapGetStorageRanges) {
                    handleSnapGetStorageRanges(ctx, msg);
                } else {
                    log.debug("[eth] Unhandled message 0x{} ({} bytes) from {}",
                        Integer.toHexString(msg.code()), msg.payload().length, remoteAddress);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Snap message handlers
    // -------------------------------------------------------------------------
    private void handleSnapAccountRange(RLPxHandler.RLPxMessage msg) {
        long snapReqId = -1;
        try {
            snapReqId = AccountRangeMessage.extractRequestId(msg.payload());
        } catch (Exception ignored) {}
        try {
            AccountRangeMessage.DecodeResult decoded = AccountRangeMessage.decode(msg.payload());
            log.info("[snap] AccountRange: {} accounts (reqId={})",
                decoded.accounts().size(), decoded.requestId());
            CompletableFuture<AccountRangeMessage.DecodeResult> f =
                pendingSnapRequests.remove(decoded.requestId());
            if (f != null) f.complete(decoded);
        } catch (Exception e) {
            log.error("[snap] Failed to decode AccountRange (reqId={}): {}",
                snapReqId, e.getMessage());
            if (snapReqId >= 0) {
                CompletableFuture<AccountRangeMessage.DecodeResult> f =
                    pendingSnapRequests.remove(snapReqId);
                if (f != null) f.completeExceptionally(e);
            }
        }
    }

    private void handleSnapGetAccountRange(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        try {
            long snapReqId = AccountRangeMessage.extractRequestId(msg.payload());
            byte[] emptyResponse = AccountRangeMessage.encodeEmpty(snapReqId);
            rlpxHandler.sendMessage(ctx, snapAccountRange, emptyResponse);
            log.debug("[snap] Responded with empty AccountRange (reqId={})", snapReqId);
        } catch (Exception e) {
            log.debug("[snap] Failed to respond to GetAccountRange: {}", e.getMessage());
        }
    }

    private void handleSnapStorageRanges(RLPxHandler.RLPxMessage msg) {
        long snapReqId = -1;
        try {
            snapReqId = StorageRangesMessage.extractRequestId(msg.payload());
        } catch (Exception ignored) {}
        try {
            StorageRangesMessage.DecodeResult decoded = StorageRangesMessage.decode(msg.payload());
            log.info("[snap] StorageRanges: {} slots (reqId={})",
                decoded.slots().size(), decoded.requestId());
            CompletableFuture<StorageRangesMessage.DecodeResult> f =
                pendingStorageRequests.remove(decoded.requestId());
            if (f != null) f.complete(decoded);
        } catch (Exception e) {
            log.error("[snap] Failed to decode StorageRanges (reqId={}): {}",
                snapReqId, e.getMessage());
            if (snapReqId >= 0) {
                CompletableFuture<StorageRangesMessage.DecodeResult> f =
                    pendingStorageRequests.remove(snapReqId);
                if (f != null) f.completeExceptionally(e);
            }
        }
    }

    private void handleSnapGetStorageRanges(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        try {
            long snapReqId = StorageRangesMessage.extractRequestId(msg.payload());
            byte[] emptyResponse = StorageRangesMessage.encodeEmpty(snapReqId);
            rlpxHandler.sendMessage(ctx, snapStorageRanges, emptyResponse);
            log.debug("[snap] Responded with empty StorageRanges (reqId={})", snapReqId);
        } catch (Exception e) {
            log.debug("[snap] Failed to respond to GetStorageRanges: {}", e.getMessage());
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
        // Always use chain-head mode with current forkId (post-merge standard)
        ChainHead.Head head = chainHead.get();
        byte[] forkIdHash = network.forkIdHash();
        long forkNext = network.forkNext();
        org.apache.tuweni.bytes.Bytes32 bestHash = head.blockNumber() > 0 ? head.blockHash() : network.bestBlockHash();
        long blockNumber = head.blockNumber();
        String modeLabel = "CHAINHEAD";

        ourBestHash = bestHash.toShortHexString();
        byte[] payload = StatusMessage.encode(
            negotiatedEthVersion, network.networkId(), network.genesisHash(),
            bestHash, forkIdHash, forkNext, blockNumber);
        log.info("[eth] Sending Status [{}] ({} bytes, eth/{}): bestHash={} block={} forkIdHash={} forkNext={} peer={} hex={}",
            modeLabel, payload.length, negotiatedEthVersion, ourBestHash, blockNumber,
            bytesToHex(forkIdHash, forkIdHash.length), forkNext,
            clientId != null ? clientId : remoteAddress,
            bytesToHex(payload, payload.length));
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

    /**
     * Fetch a single account from the snap/1 state trie.
     *
     * Always fetches a fresh block header from this peer (using their best block hash)
     * to get a recent state root that the peer is guaranteed to have available.
     * Stale state roots get silently dropped by peers (Geth prunes beyond 128 blocks).
     *
     * @param address 20-byte Ethereum address
     * @return future completing with the AccountRange decode result, or null if not READY
     */
    public CompletableFuture<AccountRangeMessage.DecodeResult> requestAccountAsync(
            org.apache.tuweni.bytes.Bytes address,
            org.apache.tuweni.bytes.Bytes32 explicitStateRoot) {
        if (explicitStateRoot == null) {
            return requestAccountAsync(address);
        }
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return null;
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));

        org.apache.tuweni.bytes.Bytes32 accountHash =
            org.apache.tuweni.crypto.Hash.keccak256(address);

        log.info("[snap] Using explicit stateRoot={} for account query", explicitStateRoot.toShortHexString());
        return sendGetAccountRange(ctx, accountHash, explicitStateRoot)
            .orTimeout(10, TimeUnit.SECONDS);
    }

    public CompletableFuture<AccountRangeMessage.DecodeResult> requestAccountAsync(
            org.apache.tuweni.bytes.Bytes address) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return null;
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));

        org.apache.tuweni.bytes.Bytes32 accountHash =
            org.apache.tuweni.crypto.Hash.keccak256(address);

        // Always fetch a fresh header from this peer to get a non-pruned state root
        CompletableFuture<AccountRangeMessage.DecodeResult> result = new CompletableFuture<>();
        long reqId = requestId.getAndIncrement();
        CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> headerFut = new CompletableFuture<>();
        pendingRequests.put(reqId, headerFut);
        org.apache.tuweni.bytes.Bytes32 hash = peerBestBlockHash;
        if (hash == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("No best block hash from peer"));
        }
        byte[] headerPayload = GetBlockHeadersMessage.encodeByHash(reqId, hash, 1, 0, false);
        log.info("[snap] Fetching fresh header (hash={}) from peer {} before snap query",
            hash.toShortHexString(), remoteAddress);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_HEADERS, headerPayload);
        // 5-second timeout: if this peer doesn't respond, fail fast so RLPxConnector tries the next
        headerFut.orTimeout(5, TimeUnit.SECONDS).thenAccept(headers -> {
            if (headers.isEmpty()) {
                result.completeExceptionally(new RuntimeException("No header returned for state root"));
                return;
            }
            long blockNum = headers.get(0).header().number;
            // Reject obviously stale headers. We use a static minimum rather than
            // chainHead because chainHead can be poisoned by malicious peers.
            // Mainnet is ~24.6M as of March 2026; 20M gives ample margin.
            if (blockNum < 20_000_000) {
                log.warn("[snap] Peer {} returned stale header (block #{}), skipping",
                        remoteAddress, blockNum);
                result.completeExceptionally(new RuntimeException(
                    "Peer returned stale header (block #" + blockNum + ")"));
                return;
            }
            org.apache.tuweni.bytes.Bytes32 freshStateRoot = headers.get(0).header().stateRoot;
            log.info("[snap] Using fresh stateRoot={} from block #{}", freshStateRoot.toShortHexString(),
                blockNum);
            sendGetAccountRange(ctx, accountHash, freshStateRoot)
                .orTimeout(10, TimeUnit.SECONDS)
                .whenComplete((r, ex) -> {
                    if (ex != null) result.completeExceptionally(ex);
                    else result.complete(r.withStateRoot(freshStateRoot, blockNum));
                });
        }).exceptionally(ex -> {
            log.warn("[snap] Header fetch from {} failed: {}", remoteAddress, ex.getMessage());
            pendingRequests.remove(reqId); // clean up
            result.completeExceptionally(ex);
            return null;
        });
        return result;
    }

    private CompletableFuture<AccountRangeMessage.DecodeResult> sendGetAccountRange(
            ChannelHandlerContext ctx,
            org.apache.tuweni.bytes.Bytes32 accountHash,
            org.apache.tuweni.bytes.Bytes32 stateRoot) {
        long reqId = requestId.getAndIncrement();
        CompletableFuture<AccountRangeMessage.DecodeResult> future = new CompletableFuture<>();
        pendingSnapRequests.put(reqId, future);
        org.apache.tuweni.bytes.Bytes32 limitHash = org.apache.tuweni.bytes.Bytes32.fromHexString(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        byte[] payload = GetAccountRangeMessage.encode(reqId, stateRoot, accountHash, limitHash, 128 * 1024L);
        log.info("[snap] GetAccountRange reqId={} accountHash={} stateRoot={}",
            reqId, accountHash.toShortHexString(), stateRoot.toShortHexString());
        rlpxHandler.sendMessage(ctx, snapGetAccountRange, payload);
        return future;
    }

    /**
     * Fetch storage slots for a contract from the snap/1 storage trie.
     *
     * <p>Fetches a fresh block header from this peer to get a non-pruned state root,
     * then sends GetStorageRanges for the given account and storage key.
     *
     * @param contractAddress 20-byte contract address
     * @param storageKeyHash  32-byte keccak256(storageSlotKey) — the trie key
     * @return future completing with the StorageRanges decode result, or null if not READY
     */
    public CompletableFuture<StorageRangesMessage.DecodeResult> requestStorageAsync(
            org.apache.tuweni.bytes.Bytes contractAddress,
            org.apache.tuweni.bytes.Bytes32 storageKeyHash) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return null;
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));

        org.apache.tuweni.bytes.Bytes32 accountHash =
            org.apache.tuweni.crypto.Hash.keccak256(contractAddress);

        // Fetch fresh header for non-pruned state root
        CompletableFuture<StorageRangesMessage.DecodeResult> result = new CompletableFuture<>();
        long reqId = requestId.getAndIncrement();
        CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> headerFut = new CompletableFuture<>();
        pendingRequests.put(reqId, headerFut);
        org.apache.tuweni.bytes.Bytes32 hash = peerBestBlockHash;
        if (hash == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("No best block hash from peer"));
        }
        byte[] headerPayload = GetBlockHeadersMessage.encodeByHash(reqId, hash, 1, 0, false);
        log.info("[snap] Fetching fresh header for storage query from peer {}", remoteAddress);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_HEADERS, headerPayload);

        headerFut.orTimeout(5, TimeUnit.SECONDS).thenAccept(headers -> {
            if (headers.isEmpty()) {
                result.completeExceptionally(new RuntimeException("No header returned for state root"));
                return;
            }
            long blockNum = headers.get(0).header().number;
            if (blockNum < 1_000_000) {
                log.warn("[snap] Peer {} returned stale header (block #{}), skipping for storage query",
                    remoteAddress, blockNum);
                result.completeExceptionally(new RuntimeException(
                    "Peer returned stale header (block #" + blockNum + ")"));
                return;
            }
            org.apache.tuweni.bytes.Bytes32 freshStateRoot = headers.get(0).header().stateRoot;
            log.info("[snap] Using fresh stateRoot={} for storage query from block #{}",
                freshStateRoot.toShortHexString(), blockNum);
            sendGetStorageRanges(ctx, accountHash, storageKeyHash, freshStateRoot)
                .orTimeout(10, TimeUnit.SECONDS)
                .whenComplete((r, ex) -> {
                    if (ex != null) result.completeExceptionally(ex);
                    else result.complete(r);
                });
        }).exceptionally(ex -> {
            log.warn("[snap] Header fetch from {} failed for storage query: {}", remoteAddress, ex.getMessage());
            pendingRequests.remove(reqId);
            result.completeExceptionally(ex);
            return null;
        });
        return result;
    }

    /**
     * Fetch storage slots with an explicit state root.
     */
    public CompletableFuture<StorageRangesMessage.DecodeResult> requestStorageAsync(
            org.apache.tuweni.bytes.Bytes contractAddress,
            org.apache.tuweni.bytes.Bytes32 storageKeyHash,
            org.apache.tuweni.bytes.Bytes32 explicitStateRoot) {
        if (explicitStateRoot == null) {
            return requestStorageAsync(contractAddress, storageKeyHash);
        }
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return null;
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));

        org.apache.tuweni.bytes.Bytes32 accountHash =
            org.apache.tuweni.crypto.Hash.keccak256(contractAddress);

        return sendGetStorageRanges(ctx, accountHash, storageKeyHash, explicitStateRoot)
            .orTimeout(10, TimeUnit.SECONDS);
    }

    private CompletableFuture<StorageRangesMessage.DecodeResult> sendGetStorageRanges(
            ChannelHandlerContext ctx,
            org.apache.tuweni.bytes.Bytes32 accountHash,
            org.apache.tuweni.bytes.Bytes32 storageKeyHash,
            org.apache.tuweni.bytes.Bytes32 stateRoot) {
        long reqId = requestId.getAndIncrement();
        CompletableFuture<StorageRangesMessage.DecodeResult> future = new CompletableFuture<>();
        pendingStorageRequests.put(reqId, future);
        org.apache.tuweni.bytes.Bytes32 limitHash = org.apache.tuweni.bytes.Bytes32.fromHexString(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        byte[] payload = GetStorageRangesMessage.encode(
            reqId, stateRoot, accountHash, storageKeyHash, limitHash, 128 * 1024L);
        log.info("[snap] GetStorageRanges reqId={} accountHash={} slotHash={} stateRoot={}",
            reqId, accountHash.toShortHexString(), storageKeyHash.toShortHexString(),
            stateRoot.toShortHexString());
        rlpxHandler.sendMessage(ctx, snapGetStorageRanges, payload);
        return future;
    }

    public String getClientId() { return clientId; }

    public boolean isSnapNegotiated() { return snapNegotiated; }

    public boolean isSnapServingFailed() { return snapServingFailed; }

    public void markSnapServingFailed() { snapServingFailed = true; }

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
     * RLP encoding of 0 is 0x80 (empty byte string), not 0x00.
     */
    private static int decodeDisconnectReason(byte[] payload) {
        if (payload.length == 0) return -1;
        int first = payload[0] & 0xFF;
        if (first < 0x80) return first;          // raw byte (non-standard)
        if (first == 0x80) return 0;             // RLP integer 0
        if (first == 0xC0) return 0;             // empty list = reason 0
        if (first >= 0xC1 && payload.length >= 2) {
            int reason = payload[1] & 0xFF;
            if (reason == 0x80) return 0;        // RLP integer 0 inside list
            if (reason < 0x80) return reason;    // single-byte integer
            return reason;                       // fallback
        }
        return -1;
    }

    private static final String[] DISCONNECT_REASONS = {
        "DiscRequested", "DiscNetworkError", "DiscProtocolError", "DiscUselessPeer",
        "DiscTooManyPeers", "DiscAlreadyConnected", "DiscIncompatibleVersion",
        "DiscInvalidIdentity", "DiscQuittingPeer", "DiscUnexpectedIdentity",
        "DiscSelf", "DiscReadTimeout", "DiscSubprotocolError"
    };

    private static String disconnectReasonName(int reason) {
        if (reason >= 0 && reason < DISCONNECT_REASONS.length) return DISCONNECT_REASONS[reason];
        if (reason == 16) return "DiscSubprotocolError";
        return "Unknown(" + reason + ")";
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("[eth] Exception", cause);
        ctx.close();
    }
}
