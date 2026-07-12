package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.ChainHead;
import com.jaeckel.ethp2p.networking.ConnectionErrors;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.eth.messages.*;
import com.jaeckel.ethp2p.networking.rlpx.RLPxHandler;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.ByteCodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetAccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetByteCodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetStorageRangesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetTrieNodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.TrieNodesMessage;
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
    private static final int ETH_TRANSACTIONS = 0x12;
    private static final int ETH_GET_BLOCK_HEADERS = 0x13;
    private static final int ETH_BLOCK_HEADERS = 0x14;
    private static final int ETH_GET_BLOCK_BODIES = 0x15;
    private static final int ETH_BLOCK_BODIES = 0x16;
    private static final int ETH_GET_RECEIPTS = 0x1f; // eth msg 0x0f + base 0x10
    private static final int ETH_RECEIPTS = 0x20;     // eth msg 0x10 + base 0x10

    // snap/1 message codes depend on negotiated eth version:
    //   eth/67-68: protocol length 17, snap base = 0x10 + 17 = 0x21
    //   eth/69:    protocol length 18 (adds BlockRangeUpdate at 0x11), snap base = 0x10 + 18 = 0x22
    //
    // Snap message ids (offsets from snapBase) per the snap/1 wire spec:
    //   0x00 GetAccountRange / 0x01 AccountRange
    //   0x02 GetStorageRanges / 0x03 StorageRanges
    //   0x04 GetByteCodes    / 0x05 ByteCodes
    //   0x06 GetTrieNodes    / 0x07 TrieNodes
    private int snapGetAccountRange  = 0x21; // updated after Hello negotiation
    private int snapAccountRange     = 0x22;
    private int snapGetStorageRanges = 0x23;
    private int snapStorageRanges    = 0x24;
    private int snapGetByteCodes     = 0x25;
    private int snapByteCodes        = 0x26;
    private int snapGetTrieNodes     = 0x27;
    private int snapTrieNodes        = 0x28;

    public enum State { AWAITING_HELLO, AWAITING_STATUS, READY }
    private volatile State state = State.AWAITING_HELLO;
    private volatile String remoteAddress;
    private volatile String peerBestHash; // what peer claimed in Status (short hex for logging)
    private volatile org.apache.tuweni.bytes.Bytes32 peerBestBlockHash; // full hash for queries
    private volatile String ourBestHash;  // what we claimed in Status
    private volatile boolean incompatibleNetwork; // confirmed wrong chain
    private volatile boolean snapNegotiated = false;
    private volatile String clientId;
    /** How long an empty snap response benches a peer from the serving pool. NOT permanent:
     *  an empty response usually means the peer's flat snapshot hadn't yet caught up to the
     *  (often bleeding-edge) root we asked for — it serves a slightly older/newer root fine.
     *  Permanent exclusion monotonically decayed the serving pool to zero over a long session
     *  (every confirm-screen / balance-sweep storage fetch that came back empty retired
     *  another good peer), so a node with 50+ snap-negotiated peers went amber and could not
     *  build a verified head while the UI still counted them. A short cooldown routes around a
     *  momentarily-lagging peer without throwing it away for the rest of the connection. */
    private static final long SNAP_SERVING_COOLDOWN_NS = TimeUnit.MILLISECONDS.toNanos(30_000L);
    /** Monotonic {@link System#nanoTime()} deadline until which this peer is benched from the
     *  snap serving pool (0 = not benched). nanoTime, not currentTimeMillis: a wall-clock
     *  adjustment (NTP / manual) must not extend or prematurely expire the cooldown. */
    private volatile long snapServingFailedUntilNs = 0L;
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
    private final ConcurrentMap<Long, CompletableFuture<List<List<org.apache.tuweni.bytes.Bytes>>>>
            pendingReceiptRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<AccountRangeMessage.DecodeResult>>
            pendingSnapRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<StorageRangesMessage.DecodeResult>>
            pendingStorageRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<ByteCodesMessage.DecodeResult>>
            pendingByteCodeRequests = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, CompletableFuture<TrieNodesMessage.DecodeResult>>
            pendingTrieNodeRequests = new ConcurrentHashMap<>();


    // Default eth/69 served-block window: how many blocks below the head we retain and
    // advertise as servable. Kept small on purpose — we are a light client, not an
    // archive node, and over-advertising invites history requests we cannot answer.
    // The connector constructs the (shared) window with this default; a later Settings
    // knob overrides it live. See ServedHeaderWindow.
    public static final int DEFAULT_SERVED_BLOCK_WINDOW = 32;

    // Per-connection cache of received headers (used for our own request/response
    // bookkeeping). Serving to peers goes through the SHARED servedWindow below, which
    // is what the advertised eth/69 range is derived from.
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

    // Shared store of recent headers we can serve, and the source of the advertised
    // eth/69 block range. Owned by the connector, shared across all peer connections, so
    // a header fetched on one connection is servable (and advertised) on all of them.
    private final ServedHeaderWindow servedWindow;
    // Set by the connector; invoked after we cache new headers so the connector can push a
    // BlockRangeUpdate to eth/69 peers when the servable range grows. Null in test fixtures.
    private volatile Runnable onWindowUpdated;

    private RLPxHandler rlpxHandler; // reference to the RLPx layer for sending
    private volatile ChannelHandlerContext readyCtx; // stored when state reaches READY
    private volatile long readyTimestamp; // when we entered READY state
    // volatile: written on this connection's event-loop thread during Hello, but read
    // cross-thread from the connector's BlockRangeUpdate broadcast (which iterates all
    // connections' handlers).
    private volatile int negotiatedEthVersion = 68; // default, updated during Hello negotiation
    // eth/69 (EIP-7642) BlockRangeUpdate, message id 0x11 within the eth capability.
    // On eth/68 the same id is the obsolete NewBlockHashes, so this is version-gated.
    private static final int ETH_BLOCK_RANGE_UPDATE = 0x11;

    /** Optional sink for mempool-gossip tx hashes, set by the connector. When present
     *  AND {@link TxGossipObserver#watchingAny()} is true, inbound Transactions (0x12)
     *  and NewPooledTransactionHashes (0x18) are decoded and their hashes reported so a
     *  node can watch its own just-broadcast tx propagate. Null / not-watching = the
     *  firehose stays dropped untouched (its normal cheap path). */
    private volatile TxGossipObserver txGossipObserver;

    /** Hard cap on hashes decoded per gossip message — bounds event-loop work even if a
     *  peer announces a huge batch while we happen to be watching. */
    private static final int MAX_GOSSIP_HASHES_PER_MSG = 256;

    /** Set the gossip observer (idempotent; the connector calls this on every handler). */
    public void setTxGossipObserver(TxGossipObserver observer) {
        this.txGossipObserver = observer;
    }

    public EthHandler(NodeKey nodeKey, int tcpPort, NetworkConfig network,
                      ChainHead chainHead, ServedHeaderWindow servedWindow,
                      Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders,
                      Runnable onReady) {
        this.nodeKey = nodeKey;
        this.tcpPort = tcpPort;
        this.network = network;
        this.chainHead = chainHead;
        this.servedWindow = servedWindow;
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

    /** Register a listener the connector uses to broadcast a BlockRangeUpdate when our
     *  servable window grows (idempotent). */
    public void setWindowUpdateListener(Runnable r) {
        this.onWindowUpdated = r;
    }

    /**
     * Send an eth/69 BlockRangeUpdate advertising our current servable range. No-op
     * unless we're READY on an eth/69 peer. Called by the connector when the shared
     * window grows so already-connected peers learn they can ask us for more.
     */
    public void sendBlockRangeUpdate() {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY || negotiatedEthVersion < 69) return;
        ChainHead.Head head = chainHead.get();
        // Advertise only held blocks — both ends of the Range, not the chain head.
        ServedHeaderWindow.Range r = servedWindow.advertise(head.blockNumber(), head.blockHash());
        byte[] payload = BlockRangeUpdateMessage.encode(r.earliest(), r.latest(), r.latestHash());
        rlpxHandler.sendMessage(ctx, ETH_BLOCK_RANGE_UPDATE, payload);
        log.debug("[eth] Sent BlockRangeUpdate range=[{},{}] to {}",
                r.earliest(), r.latest(), clientId != null ? clientId : remoteAddress);
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
        if (!pendingReceiptRequests.isEmpty()) {
            pendingReceiptRequests.values().forEach(f -> f.completeExceptionally(cause));
            pendingReceiptRequests.clear();
        }
        super.channelInactive(ctx);
    }

    /** Called by RLPxHandler when a decoded message arrives. */
    public void onMessage(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        // TRACE, not INFO: this runs on the netty event-loop thread for EVERY
        // inbound message, and full-node peers flood us with mempool gossip
        // (Transactions 0x12 / NewPooledTransactionHashes 0x18) — hundreds per
        // second. At INFO each one formats + writes to logcat and the in-app
        // LogBuffer ring on the event loop, starving snap-response processing
        // and inflating ENS-resolution RTTs from ~100ms to multiple seconds on
        // Android. Keep it for deep debugging only.
        log.trace("[eth] Received message code=0x{} state={}", Integer.toHexString(msg.code()), state);
        switch (state) {
            case AWAITING_HELLO -> handleHello(ctx, msg);
            case AWAITING_STATUS -> handleStatus(ctx, msg);
            case READY -> handleReady(ctx, msg);
        }
    }

    // -------------------------------------------------------------------------
    // State: AWAITING_HELLO
    // -------------------------------------------------------------------------
    // Eth versions we support. eth/66 is the floor: it introduced request-IDs
    // (our GetBlockHeaders / snap requests rely on them) and shares the Status +
    // snap-base layout with 67/68 — accepting it widens the usable snap-peer pool.
    // eth/65 and below lack request-IDs and stay rejected.
    private static final java.util.Set<Integer> OUR_ETH_VERSIONS = java.util.Set.of(66, 67, 68, 69);

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
                log.warn("[eth] Peer does not support eth/66+, disconnecting (caps={})", hello.capabilities);
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
            snapGetByteCodes     = snapBase + 4;
            snapByteCodes        = snapBase + 5;
            snapGetTrieNodes     = snapBase + 6;
            snapTrieNodes        = snapBase + 7;
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
            if (!status.isCompatible(network.networkId(), network.genesisHash())) {
                log.warn("[eth] Incompatible network: chainId={}, genesis={}",
                    status.networkId, status.genesisHash);
                incompatibleNetwork = true;
                ctx.close();
                return;
            }
            // Update chain head only after confirming the peer is on our network.
            // Peers on foreign networks (e.g. BOB Network networkId=60808 with its
            // own genesis) can otherwise poison ChainHead with block numbers from
            // an unrelated chain, which then causes header requests routed to real
            // peers to come back empty.
            if (status.latestBlock > 0) {
                chainHead.update(status.latestBlock, status.bestHash);
                log.info("[eth] Updated chain head from peer Status: block={} hash={}",
                    status.latestBlock, peerBestHash);
            }
            state = State.READY;
            readyCtx = ctx;
            readyTimestamp = System.currentTimeMillis();
            log.info("[eth] Peer ready! Requesting peer's best block and recent headers...");
            if (onReady != null) onReady.run();
            // Request the peer's advertised best block by hash
            requestBlockHeadersByHash(ctx, status.bestHash);
            // Sanity-probe a known post-merge block. Use the network's sensible-head
            // floor rather than a hardcoded mainnet block: 21_000_000 is post-merge on
            // mainnet but PRE-merge (AuRa) on Gnosis (merged at 25.3M), whose legacy
            // header layout fails to decode. minSensibleHeadBlock() is post-merge on
            // every configured network. Skip when unknown (0).
            long probeBlock = network.minSensibleHeadBlock();
            if (probeBlock > 0) requestBlockHeaders(ctx, probeBlock, 1);
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

                    // Serve from the shared served-window (what we advertise), falling
                    // back to this connection's own header cache. By hash or by number.
                    java.util.List<byte[]> cached = new java.util.ArrayList<>();
                    if (fullHash != null) {
                        byte[] h = servedWindow.getByHash(fullHash);
                        if (h == null) h = hashCache.get(fullHash);
                        if (h != null) cached.add(h);
                    } else if (blockNum >= 0) {
                        for (int i = 0; i < count && cached.size() < count; i++) {
                            byte[] h = servedWindow.getByNumber(blockNum + i);
                            if (h == null) h = headerCache.get(blockNum + i);
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
                        // Make it servable to peers via the shared window + advertised range.
                        servedWindow.put(vh.header().number, vh.hash(), raw);
                        log.debug("[eth] Cached header for block #{} hash={}",
                                vh.header().number, vh.hash().toShortHexString());
                        chainHead.update(vh.header().number, vh.hash());
                        if (vh.header().number > latestStateRootBlockNumber) {
                            latestStateRootBlockNumber = vh.header().number;
                            latestStateRoot = vh.header().stateRoot;
                        }
                    }
                    // Our servable range may have grown — let the connector push a
                    // BlockRangeUpdate to eth/69 peers who were told a narrower range.
                    if (!decoded.headers().isEmpty()) {
                        Runnable w = onWindowUpdated;
                        if (w != null) w.run();
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
            case ETH_RECEIPTS -> {
                long reqId = peekRequestId(msg.payload());
                try {
                    // eth/69 (EIP-7642) receipts arrive bloomless + envelope-flattened;
                    // decode69 recomputes the bloom and re-canonicalizes so downstream
                    // receiptsRoot verification is identical across versions.
                    ReceiptsMessage.DecodeResult decoded = negotiatedEthVersion >= 69
                            ? ReceiptsMessage.decode69(msg.payload())
                            : ReceiptsMessage.decode(msg.payload());
                    log.info("[eth] Received receipts for {} block(s) (reqId={})",
                            decoded.perBlockReceipts().size(), decoded.requestId());
                    CompletableFuture<List<List<org.apache.tuweni.bytes.Bytes>>> future =
                            pendingReceiptRequests.remove(decoded.requestId());
                    if (future != null) future.complete(decoded.perBlockReceipts());
                } catch (Exception e) {
                    log.error("[eth] Failed to decode Receipts", e);
                    // Don't leave the requester hanging on a malformed response.
                    if (reqId >= 0) {
                        CompletableFuture<List<List<org.apache.tuweni.bytes.Bytes>>> future =
                                pendingReceiptRequests.remove(reqId);
                        if (future != null) future.completeExceptionally(e);
                    }
                }
            }
            case ETH_BLOCK_RANGE_UPDATE -> {
                // eth/69: a peer telling us its servable range changed. We don't yet route
                // requests by peer range, so just log it. On eth/68 id 0x11 is the obsolete
                // NewBlockHashes — the version guard drops it here (a light client ignores
                // NewBlockHashes regardless), so it deliberately never reaches `default`.
                if (negotiatedEthVersion >= 69) {
                    try {
                        BlockRangeUpdateMessage.Decoded u = BlockRangeUpdateMessage.decode(msg.payload());
                        log.debug("[eth] Peer BlockRangeUpdate: range=[{},{}] from {}",
                                u.earliestBlock(), u.latestBlock(),
                                clientId != null ? clientId : remoteAddress);
                    } catch (Exception e) {
                        log.debug("[eth] Malformed BlockRangeUpdate ignored: {}", e.getMessage());
                    }
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
                } else if (msg.code() == snapByteCodes) {
                    handleSnapByteCodes(msg);
                } else if (msg.code() == snapGetByteCodes) {
                    handleSnapGetByteCodes(ctx, msg);
                } else if (msg.code() == snapTrieNodes) {
                    handleSnapTrieNodes(msg);
                } else if (msg.code() == snapGetTrieNodes) {
                    handleSnapGetTrieNodes(ctx, msg);
                } else if ((msg.code() == ETH_TRANSACTIONS || msg.code() == NewPooledTransactionHashesMessage.CODE)
                        && isWatchingGossip()) {
                    // Mempool gossip we'd normally drop — but a watcher (a node with an
                    // unconfirmed broadcast of its own) wants to see that hash come back.
                    // Only reached while watchingAny() is true, so the firehose stays
                    // free the rest of the time.
                    matchOwnTxGossip(msg);
                } else {
                    // TRACE, not DEBUG: the ignored codes are dominated by
                    // high-frequency mempool gossip (0x12 / 0x18) every full-node
                    // peer broadcasts unsolicited. Logging each at DEBUG on the
                    // event loop (logcat + LogBuffer) was a major source of
                    // event-loop contention during snap-heavy ENS resolution.
                    log.trace("[eth] Ignoring 0x{} ({}, {} bytes) from {}",
                        Integer.toHexString(msg.code()), ignoredEthMessageReason(msg.code()),
                        msg.payload().length, remoteAddress);
                }
            }
        }
    }

    /**
     * Human-readable reason an eth-protocol message is intentionally not consumed.
     * These aren't missing handlers: a light wallet verifies state via header
     * chain + snap proofs, so transaction-pool and block-propagation gossip
     * (which every full node broadcasts unsolicited) has no use here and is
     * dropped on purpose. Codes are absolute wire ids (eth base 0x10).
     */
    /** Read just the leading requestId of a {@code [requestId, ...]} payload; -1 if
     *  unreadable. Lets the ETH_RECEIPTS handler fail the right pending future when the
     *  full decode throws, instead of leaving the requester hung. */
    private static long peekRequestId(byte[] payload) {
        try {
            return org.apache.tuweni.rlp.RLP.decodeList(
                    org.apache.tuweni.bytes.Bytes.wrap(payload),
                    reader -> reader.readLong());
        } catch (Exception e) {
            return -1;
        }
    }

    private static String ignoredEthMessageReason(int code) {
        return switch (code) {
            case 0x11 -> "NewBlockHashes — pre-Merge block gossip, obsolete; light wallet tracks heads via the beacon chain";
            case 0x12 -> "Transactions — mempool broadcast, not needed for state verification";
            case 0x17 -> "NewBlock — pre-Merge block propagation, obsolete post-Merge";
            case 0x18 -> "NewPooledTransactionHashes — mempool announcement, not needed for state verification";
            case 0x19 -> "GetPooledTransactions — peer asking us for mempool txs; we serve none";
            case 0x1a -> "PooledTransactions — mempool response we never requested";
            case 0x1d -> "GetReceipts — peer asking us for receipts; we serve none";
            case 0x1e -> "Receipts — not requested; wallet verifies via state proofs";
            default   -> "unrecognised eth/snap message code for the negotiated protocol";
        };
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

    private void handleSnapByteCodes(RLPxHandler.RLPxMessage msg) {
        long snapReqId = -1;
        try {
            snapReqId = ByteCodesMessage.extractRequestId(msg.payload());
        } catch (Exception ignored) {}
        try {
            ByteCodesMessage.DecodeResult decoded = ByteCodesMessage.decode(msg.payload());
            log.info("[snap] ByteCodes: {} entries (reqId={})",
                decoded.codes().size(), decoded.requestId());
            CompletableFuture<ByteCodesMessage.DecodeResult> f =
                pendingByteCodeRequests.remove(decoded.requestId());
            if (f != null) f.complete(decoded);
        } catch (Exception e) {
            log.error("[snap] Failed to decode ByteCodes (reqId={}): {}",
                snapReqId, e.getMessage());
            if (snapReqId >= 0) {
                CompletableFuture<ByteCodesMessage.DecodeResult> f =
                    pendingByteCodeRequests.remove(snapReqId);
                if (f != null) f.completeExceptionally(e);
            }
        }
    }

    private void handleSnapGetByteCodes(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        // We never serve bytecode — answer with an empty list so the peer
        // doesn't time out and disconnect us.
        try {
            long snapReqId = GetByteCodesMessage.decode(msg.payload()).requestId();
            byte[] emptyResponse = ByteCodesMessage.encodeEmpty(snapReqId);
            rlpxHandler.sendMessage(ctx, snapByteCodes, emptyResponse);
            log.debug("[snap] Responded with empty ByteCodes (reqId={})", snapReqId);
        } catch (Exception e) {
            log.debug("[snap] Failed to respond to GetByteCodes: {}", e.getMessage());
        }
    }

    private void handleSnapTrieNodes(RLPxHandler.RLPxMessage msg) {
        long snapReqId = -1;
        try {
            snapReqId = TrieNodesMessage.extractRequestId(msg.payload());
        } catch (Exception ignored) {}
        try {
            TrieNodesMessage.DecodeResult decoded = TrieNodesMessage.decode(msg.payload());
            log.info("[snap] TrieNodes: {} nodes (reqId={})",
                decoded.nodes().size(), decoded.requestId());
            CompletableFuture<TrieNodesMessage.DecodeResult> f =
                pendingTrieNodeRequests.remove(decoded.requestId());
            if (f != null) f.complete(decoded);
        } catch (Exception e) {
            log.error("[snap] Failed to decode TrieNodes (reqId={}): {}",
                snapReqId, e.getMessage());
            if (snapReqId >= 0) {
                CompletableFuture<TrieNodesMessage.DecodeResult> f =
                    pendingTrieNodeRequests.remove(snapReqId);
                if (f != null) f.completeExceptionally(e);
            }
        }
    }

    private void handleSnapGetTrieNodes(ChannelHandlerContext ctx, RLPxHandler.RLPxMessage msg) {
        // Same policy as GetByteCodes: empty response so the peer doesn't
        // time out. We're a wallet, not a serving full node.
        try {
            long snapReqId = GetTrieNodesMessage.decode(msg.payload()).requestId();
            byte[] emptyResponse = TrieNodesMessage.encodeEmpty(snapReqId);
            rlpxHandler.sendMessage(ctx, snapTrieNodes, emptyResponse);
            log.debug("[snap] Responded with empty TrieNodes (reqId={})", snapReqId);
        } catch (Exception e) {
            log.debug("[snap] Failed to respond to GetTrieNodes: {}", e.getMessage());
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
        org.apache.tuweni.bytes.Bytes32 headHash = head.blockNumber() > 0 ? head.blockHash() : network.bestBlockHash();
        long blockNumber = head.blockNumber();
        // eth/69 block range: advertise only what we actually hold, never [0, head] and
        // never latest=head (head is the network's head from peers, not a block we hold).
        // Both ends of the window's Range are held headers (or genesis). eth/67-68 has no
        // range; it announces the head as bestHash for fork/sync as before.
        ServedHeaderWindow.Range range = servedWindow.advertise(blockNumber, headHash);
        boolean eth69 = negotiatedEthVersion >= 69;
        org.apache.tuweni.bytes.Bytes32 bestHash = eth69 ? range.latestHash() : headHash;
        long latestBlock = eth69 ? range.latest() : blockNumber;
        long earliestBlock = range.earliest();
        String modeLabel = "CHAINHEAD";

        ourBestHash = bestHash.toShortHexString();
        byte[] payload = StatusMessage.encode(
            negotiatedEthVersion, network.networkId(), network.genesisHash(),
            bestHash, forkIdHash, forkNext, earliestBlock, latestBlock);
        log.info("[eth] Sending Status [{}] ({} bytes, eth/{}): bestHash={} range=[{},{}] forkIdHash={} forkNext={} peer={} hex={}",
            modeLabel, payload.length, negotiatedEthVersion, ourBestHash, earliestBlock, latestBlock,
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
     * Probe THIS peer for the header at its own current best-block hash.
     *
     * <p>This is the right primitive to use before any snap/1 query: peers
     * prune state outside a ~128-block window, so the only stateRoot a peer
     * is reliably willing to serve is the one anchored at its own current
     * head. Callers should pair the returned header's {@code stateRoot} with
     * the peer it came from — a stateRoot from peer A is not safe to use
     * against peer B, which is exactly the bug that triggers
     * {@code InvalidProof[... missing node ... (path idx=0)]} when the
     * verifier descends from a root the responding peer doesn't have.
     *
     * <p>Returns failed future if the peer is not READY or hasn't reported a
     * best-block hash yet (i.e., hasn't completed the eth handshake).
     */
    public CompletableFuture<com.jaeckel.ethp2p.core.types.BlockHeader> requestFreshHeadHeaderAsync() {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("EthHandler not READY"));
        }
        org.apache.tuweni.bytes.Bytes32 hash = peerBestBlockHash;
        if (hash == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("No best block hash from peer"));
        }
        long reqId = requestId.getAndIncrement();
        CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> headerFut = new CompletableFuture<>();
        pendingRequests.put(reqId, headerFut);
        byte[] payload = GetBlockHeadersMessage.encodeByHash(reqId, hash, 1, 0, false);
        log.debug("[eth] GetBlockHeaders (fresh head, hash={}) reqId={}",
            hash.toShortHexString(), reqId);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_HEADERS, payload);
        return headerFut.orTimeout(5, TimeUnit.SECONDS)
            .whenComplete((r, ex) -> pendingRequests.remove(reqId))
            .thenApply(headers -> {
                if (headers.isEmpty()) {
                    throw new RuntimeException("Peer returned no header for its own best hash");
                }
                return headers.get(0).header();
            });
    }

    /**
     * Fetch this peer's CURRENT head header by NUMBER.
     *
     * <p>Unlike the no-arg {@link #requestFreshHeadHeaderAsync()} — which re-fetches the
     * block hash the peer announced in its connect-time {@code Status}
     * ({@link #peerBestBlockHash}) and therefore can never advance past the head the peer
     * had when it connected — this asks the peer for a forward window of {@code window}
     * headers starting at {@code fromNumber} and returns the HIGHEST header the peer
     * actually serves: its live head as of now.
     *
     * <p>Pass {@code fromNumber} = the beacon-finalized block number (a block every
     * fresh-enough peer is guaranteed to have) and {@code window} sized to span
     * finalized→head, so the result lands at (or just above) the beacon-verified head.
     * An empty response means the peer does not even hold the finalized block — i.e. it
     * is behind the finality floor — and is surfaced as a failure so the caller skips it.
     *
     * <p>The returned header is NOT trusted here; the caller verifies it against the
     * beacon anchor (finalized→head) before pinning it.
     */
    public CompletableFuture<com.jaeckel.ethp2p.core.types.BlockHeader> requestFreshHeadHeaderAsync(
            long fromNumber, int window) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("EthHandler not READY"));
        }
        long reqId = requestId.getAndIncrement();
        CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> headerFut = new CompletableFuture<>();
        pendingRequests.put(reqId, headerFut);
        byte[] payload = GetBlockHeadersMessage.encodeByNumber(reqId, fromNumber, window, 0, false);
        log.debug("[eth] GetBlockHeaders (live head probe from #{} window={}) reqId={}",
            fromNumber, window, reqId);
        rlpxHandler.sendMessage(ctx, ETH_GET_BLOCK_HEADERS, payload);
        return headerFut.orTimeout(5, TimeUnit.SECONDS)
            .whenComplete((r, ex) -> pendingRequests.remove(reqId))
            .thenApply(headers -> {
                if (headers.isEmpty()) {
                    throw new RuntimeException(
                        "Peer served no header at/above finalized #" + fromNumber
                        + " (behind the finality floor)");
                }
                // The peer returns the contiguous slice it has from fromNumber upward;
                // the highest-numbered entry is its live head (or fromNumber+window-1 if
                // the peer is further ahead than the window spans). Pick the max rather
                // than assume ordering.
                com.jaeckel.ethp2p.core.types.BlockHeader best = headers.get(0).header();
                for (BlockHeadersMessage.VerifiedHeader vh : headers) {
                    if (vh.header().number > best.number) best = vh.header();
                }
                return best;
            });
    }

    /**
     * Broadcast one or more raw signed transactions to this peer (eth Transactions
     * 0x12). Fire-and-forget — Transactions has no response. The wallet user signs
     * and submits the tx; we only gossip the bytes so they reach a block producer.
     *
     * @return false if this handler is not in READY state (nothing sent)
     */
    public boolean sendTransactions(byte[]... rawTxs) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY || rawTxs == null || rawTxs.length == 0) return false;
        byte[] payload = com.jaeckel.ethp2p.networking.eth.messages.TransactionsMessage.encode(rawTxs);
        rlpxHandler.sendMessage(ctx, ETH_TRANSACTIONS, payload);
        return true;
    }

    /** Cheap event-loop guard: is an observer present and actively watching for hashes?
     *  Read once into a local so a concurrent clear can't NPE between check and use. */
    private boolean isWatchingGossip() {
        TxGossipObserver o = txGossipObserver;
        return o != null && o.watchingAny();
    }

    /**
     * Decode the tx hashes from an inbound Transactions (0x12) / NewPooledTransactionHashes
     * (0x18) gossip message and report each to the observer, which matches them against the
     * node's own broadcast txs. Only invoked while {@link #isWatchingGossip()} holds, so the
     * decode cost is paid only during the short window a send of ours is unconfirmed.
     * Best-effort throughout: the decoders never throw on malformed peer input, and a null
     * observer race is a no-op.
     */
    private void matchOwnTxGossip(RLPxHandler.RLPxMessage msg) {
        TxGossipObserver observer = txGossipObserver;
        if (observer == null) return;
        List<org.apache.tuweni.bytes.Bytes32> hashes = msg.code() == ETH_TRANSACTIONS
                ? com.jaeckel.ethp2p.networking.eth.messages.TransactionsMessage
                        .hashes(msg.payload(), MAX_GOSSIP_HASHES_PER_MSG)
                : com.jaeckel.ethp2p.networking.eth.messages.NewPooledTransactionHashesMessage
                        .hashes(msg.payload(), negotiatedEthVersion, MAX_GOSSIP_HASHES_PER_MSG);
        for (org.apache.tuweni.bytes.Bytes32 h : hashes) observer.onTxHashSeen(h);
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
     * Request consensus-encoded receipts for the given block hashes; the future completes
     * with one receipt list per block (request order). Null if not in READY state. The
     * caller verifies the receipts by rebuilding the receipts trie and comparing its root
     * to the beacon-anchored header's {@code receiptsRoot} (peer data is never trusted).
     */
    public CompletableFuture<List<List<org.apache.tuweni.bytes.Bytes>>> requestReceiptsAsync(
            org.apache.tuweni.bytes.Bytes32... hashes) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return null;

        CompletableFuture<List<List<org.apache.tuweni.bytes.Bytes>>> future = new CompletableFuture<>();
        long reqId = requestId.getAndIncrement();
        pendingReceiptRequests.put(reqId, future);
        log.debug("[eth] GetReceipts (async) hashes={} reqId={}", hashes.length, reqId);
        byte[] payload = GetReceiptsMessage.encode(reqId, hashes);
        rlpxHandler.sendMessage(ctx, ETH_GET_RECEIPTS, payload);
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
        // Timeout + pendingSnapRequests cleanup are applied inside sendGetAccountRange.
        return sendGetAccountRange(ctx, accountHash, explicitStateRoot);
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
            // Reject obviously stale headers. We use a static per-network minimum
            // rather than chainHead because chainHead can be poisoned by malicious
            // peers. (A flat mainnet-scale literal here rejected EVERY honest
            // sepolia peer — sepolia's head is far below mainnet's.)
            if (blockNum < network.minSensibleHeadBlock()) {
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

    /**
     * Soft response-size cap for single-key snap proofs (GetAccountRange /
     * GetStorageRanges). We only ever need the boundary proof for one key, not a
     * state-sync page. Per the snap/1 spec this is a soft limit on the account
     * /slot data and the responder still returns at least one entry plus the
     * COMPLETE proof, so the proof we verify is never truncated. 4 KiB keeps the
     * discarded data page tiny (~30x smaller than the old 128 KiB), which is what
     * makes ENS resolution feasible over Android's mobile/wifi link.
     */
    private static final long SNAP_RESPONSE_BYTES = 4 * 1024L;

    private CompletableFuture<AccountRangeMessage.DecodeResult> sendGetAccountRange(
            ChannelHandlerContext ctx,
            org.apache.tuweni.bytes.Bytes32 accountHash,
            org.apache.tuweni.bytes.Bytes32 stateRoot) {
        long reqId = requestId.getAndIncrement();
        CompletableFuture<AccountRangeMessage.DecodeResult> future = new CompletableFuture<>();
        pendingSnapRequests.put(reqId, future);
        // Keep the full [origin, ffff] range — its absent/boundary-proof
        // semantics are what the verifier (and the CCIP resolution path) rely on
        // — but cap responseBytes hard. The peer returns at least one account
        // plus the COMPLETE boundary proof regardless of the cap, so the proof we
        // actually use is never truncated, while the discarded account page
        // shrinks from ~128 KB (~2700 accounts) to a few KB. The old 128 KB page
        // was fine on a LAN daemon but cost seconds per read on Android's
        // mobile/wifi link (plus parsing 2700 RLP entries on ART), which blew the
        // ENS-resolution timeout budget (jesse.cb.id timed out).
        org.apache.tuweni.bytes.Bytes32 limitHash = org.apache.tuweni.bytes.Bytes32.fromHexString(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        byte[] payload = GetAccountRangeMessage.encode(reqId, stateRoot, accountHash, limitHash, SNAP_RESPONSE_BYTES);
        log.info("[snap] GetAccountRange reqId={} accountHash={} stateRoot={}",
            reqId, accountHash.toShortHexString(), stateRoot.toShortHexString());
        rlpxHandler.sendMessage(ctx, snapGetAccountRange, payload);
        // Apply the timeout here (where the reqId is in scope) and clear the
        // pendingSnapRequests entry on any terminal outcome — completion,
        // exception, or timeout. Without this, an orTimeout firing while the
        // peer stays connected would leak the entry until channelInactive.
        return future.orTimeout(10, TimeUnit.SECONDS)
            .whenComplete((r, ex) -> pendingSnapRequests.remove(reqId));
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
            // Same per-network staleness floor as the account path above.
            if (blockNum < network.minSensibleHeadBlock()) {
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

        // Timeout + pendingStorageRequests cleanup are applied inside sendGetStorageRanges.
        return sendGetStorageRanges(ctx, accountHash, storageKeyHash, explicitStateRoot);
    }

    private CompletableFuture<StorageRangesMessage.DecodeResult> sendGetStorageRanges(
            ChannelHandlerContext ctx,
            org.apache.tuweni.bytes.Bytes32 accountHash,
            org.apache.tuweni.bytes.Bytes32 storageKeyHash,
            org.apache.tuweni.bytes.Bytes32 stateRoot) {
        long reqId = requestId.getAndIncrement();
        CompletableFuture<StorageRangesMessage.DecodeResult> future = new CompletableFuture<>();
        pendingStorageRequests.put(reqId, future);
        // Same fix as sendGetAccountRange: keep the [origin, ffff] range for its
        // boundary-proof semantics but cap responseBytes so we don't pull a
        // ~128 KB slot page (~2700 slots) we discard — only the proof is used.
        org.apache.tuweni.bytes.Bytes32 limitHash = org.apache.tuweni.bytes.Bytes32.fromHexString(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        byte[] payload = GetStorageRangesMessage.encode(
            reqId, stateRoot, accountHash, storageKeyHash, limitHash, SNAP_RESPONSE_BYTES);
        log.info("[snap] GetStorageRanges reqId={} accountHash={} slotHash={} stateRoot={}",
            reqId, accountHash.toShortHexString(), storageKeyHash.toShortHexString(),
            stateRoot.toShortHexString());
        rlpxHandler.sendMessage(ctx, snapGetStorageRanges, payload);
        // Same pattern as sendGetAccountRange: timeout + cleanup keyed on the
        // reqId we just allocated, so timeouts don't leak pendingStorageRequests
        // entries on a still-connected peer.
        return future.orTimeout(10, TimeUnit.SECONDS)
            .whenComplete((r, ex) -> pendingStorageRequests.remove(reqId));
    }

    /**
     * Fetch bytecode by code hash via snap/1 GetByteCodes.
     *
     * <p>Bytecode is immutable, so this request does not need a state root —
     * the caller must verify the response by hashing each returned blob and
     * matching against the originally-requested hash.
     *
     * @param hashes 32-byte keccak256 hashes of the bytecodes to fetch
     * @return future completing with the ByteCodes decode result, or null if not READY
     */
    public CompletableFuture<ByteCodesMessage.DecodeResult> requestByteCodesAsync(
            java.util.List<org.apache.tuweni.bytes.Bytes32> hashes) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return CompletableFuture.failedFuture(
            new IllegalStateException("EthHandler not READY"));
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));

        long reqId = requestId.getAndIncrement();
        CompletableFuture<ByteCodesMessage.DecodeResult> future = new CompletableFuture<>();
        pendingByteCodeRequests.put(reqId, future);
        byte[] payload = GetByteCodesMessage.encode(reqId, hashes, 128 * 1024L);
        log.info("[snap] GetByteCodes reqId={} hashes={}", reqId, hashes.size());
        rlpxHandler.sendMessage(ctx, snapGetByteCodes, payload);
        return future.orTimeout(10, TimeUnit.SECONDS)
            .whenComplete((r, ex) -> pendingByteCodeRequests.remove(reqId));
    }

    /**
     * Direct {@link GetAccountRangeMessage} send keyed by account-hash, no
     * fresh-header probe. The caller already has a stateRoot and just wants
     * the proof that lets it verify the account leaf at {@code accountHash}
     * — that's exactly what {@link SnapBackedStateOracle} needs.
     *
     * <p>Use this instead of {@link #requestTrieNodesAsync} when the goal is
     * a verifiable account record. {@code GetTrieNodes} returns only the
     * node at the requested path (per geth's snap handler), not the
     * root-to-leaf proof — so the MPT verifier can never descend from the
     * stateRoot. {@code GetAccountRange} returns the proof.
     */
    public CompletableFuture<AccountRangeMessage.DecodeResult> requestAccountByHashAsync(
            org.apache.tuweni.bytes.Bytes32 accountHash,
            org.apache.tuweni.bytes.Bytes32 stateRoot) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return CompletableFuture.failedFuture(
            new IllegalStateException("EthHandler not READY"));
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));
        return sendGetAccountRange(ctx, accountHash, stateRoot);
    }

    /**
     * Direct {@link GetStorageRangesMessage} send keyed by account-hash and
     * slot-hash. Same rationale as {@link #requestAccountByHashAsync} —
     * returns the storage proof rooted at the account's storageRoot.
     *
     * <p>{@code stateRoot} is the world state root the request anchors at;
     * the peer uses it to look up the account by hash and then serves the
     * storage proof from that account's storageRoot.
     */
    public CompletableFuture<StorageRangesMessage.DecodeResult> requestStorageByHashAsync(
            org.apache.tuweni.bytes.Bytes32 accountHash,
            org.apache.tuweni.bytes.Bytes32 slotHash,
            org.apache.tuweni.bytes.Bytes32 stateRoot) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return CompletableFuture.failedFuture(
            new IllegalStateException("EthHandler not READY"));
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));
        return sendGetStorageRanges(ctx, accountHash, slotHash, stateRoot);
    }

    /**
     * Fetch trie nodes via snap/1 GetTrieNodes for the given path sets.
     *
     * <p>Each {@link GetTrieNodesMessage.PathSet} addresses one account in
     * the world state trie; subsequent storage paths within the set are
     * looked up in that account's storage trie. The caller is responsible
     * for verifying every returned node against {@code stateRoot} via the
     * MPT proof verifier in {@code :core}.
     *
     * <p>Note: geth's GetTrieNodes handler returns only the node at the
     * requested path, not the root-to-leaf proof. For account/storage leaf
     * lookups that need to verify against {@code stateRoot}, prefer
     * {@link #requestAccountByHashAsync} / {@link #requestStorageByHashAsync},
     * which return proofs.
     *
     * @param stateRoot the trusted state root to query against
     * @param paths     path sets the peer should resolve
     * @return future completing with the TrieNodes decode result
     */
    public CompletableFuture<TrieNodesMessage.DecodeResult> requestTrieNodesAsync(
            org.apache.tuweni.bytes.Bytes32 stateRoot,
            java.util.List<GetTrieNodesMessage.PathSet> paths) {
        ChannelHandlerContext ctx = readyCtx;
        if (ctx == null || state != State.READY) return CompletableFuture.failedFuture(
            new IllegalStateException("EthHandler not READY"));
        if (!snapNegotiated) return CompletableFuture.failedFuture(
            new UnsupportedOperationException("snap/1 not negotiated with this peer"));

        long reqId = requestId.getAndIncrement();
        CompletableFuture<TrieNodesMessage.DecodeResult> future = new CompletableFuture<>();
        pendingTrieNodeRequests.put(reqId, future);
        byte[] payload = GetTrieNodesMessage.encode(reqId, stateRoot, paths, 128 * 1024L);
        log.info("[snap] GetTrieNodes reqId={} root={} paths={}",
            reqId, stateRoot.toShortHexString(), paths.size());
        rlpxHandler.sendMessage(ctx, snapGetTrieNodes, payload);
        return future.orTimeout(10, TimeUnit.SECONDS)
            .whenComplete((r, ex) -> pendingTrieNodeRequests.remove(reqId));
    }

    public String getClientId() { return clientId; }

    public boolean isSnapNegotiated() { return snapNegotiated; }

    public boolean isSnapServingFailed() {
        long until = snapServingFailedUntilNs;
        // `now - until < 0` (not `now < until`) is the overflow-safe nanoTime comparison.
        return until != 0L && (System.nanoTime() - until < 0);
    }

    /** Bench this peer from the serving pool for {@link #SNAP_SERVING_COOLDOWN_NS}, after
     *  which it automatically rejoins and gets another chance (its snapshot will have
     *  advanced). Replaces the old permanent flag that decayed the pool to zero. */
    public void markSnapServingFailed() {
        long until = System.nanoTime() + SNAP_SERVING_COOLDOWN_NS;
        // nanoTime can legitimately be 0; remap so 0 keeps meaning "not benched".
        snapServingFailedUntilNs = (until == 0L) ? 1L : until;
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
        // Peer-churn disconnects (connection reset, broken pipe, …) are routine — one-line DEBUG,
        // no stacktrace. Only genuinely unexpected failures log at ERROR with the full cause.
        if (ConnectionErrors.isBenignDisconnect(cause)) {
            log.debug("[eth] peer disconnected: {}", ConnectionErrors.describe(cause));
        } else {
            log.error("[eth] Exception", cause);
        }
        ctx.close();
    }
}
