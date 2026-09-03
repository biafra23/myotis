package com.jaeckel.ethp2p.networking.rlpx;

import com.jaeckel.ethp2p.core.concurrent.Futures;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.ChainHead;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.eth.EthHandler;
import com.jaeckel.ethp2p.networking.eth.ServedHeaderWindow;
import com.jaeckel.ethp2p.networking.eth.ServeStats;
import com.jaeckel.ethp2p.networking.eth.TxGossipObserver;
import com.jaeckel.ethp2p.networking.eth.messages.BlockBodiesMessage;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
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
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.concurrent.TimeUnit;

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

    /**
     * Callback when a peer reaches READY state. {@code snapSupported} reports
     * whether the peer negotiated snap/1 (known by READY, since capabilities are
     * exchanged in Hello) — lets the peer cache record which cached peers can
     * serve state, so a restart can reconnect snap peers first.
     */
    public interface PeerReadyCallback {
        void onPeerReady(InetSocketAddress address, String publicKeyHex, boolean snapSupported);
    }

    /** Callback when a peer connection closes, with incompatibility info and node identity.
     *  {@code busy} = the peer sent Disconnect(0x04 TooManyPeers) at any phase: an
     *  ALIVE node with no free slots — callers should back off patiently instead of
     *  treating it like a generic transient failure. (0x04 says nothing about the
     *  peer's chain — full wrong-chain nodes send it too, so busy alone must never
     *  promote a peer to any verified/known-good tier.) */
    public interface PeerCloseCallback {
        void onPeerClose(boolean incompatibleNetwork, boolean busy, String nodeIdHex);
    }

    private final NodeKey localKey;
    private final int tcpPort;
    private final NetworkConfig network;
    private final ChainHead chainHead;
    private final NioEventLoopGroup group;
    private final Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders;
    private final PeerReadyCallback peerReadyCallback;
    private final Set<EthHandler> activeHandlers = ConcurrentHashMap.newKeySet();
    /** Shared store of recent headers we advertise + serve via the eth/69 block range,
     *  one per network, shared across all peer connections. */
    private final ServedHeaderWindow servedWindow;
    /** Stack-owned serve counters (nullable); passed to every handler. */
    private final ServeStats serveStats;
    /** Last eth/69 range we broadcast, to suppress duplicate BlockRangeUpdate spam.
     *  Guarded by {@link #rangeBroadcastLock} (event-loop threads race to update it). */
    private long lastBroadcastEarliest = -1;
    private long lastBroadcastLatest = -1;
    private final Object rangeBroadcastLock = new Object();
    /** Optional mempool-gossip sink, applied to every handler so a node can watch its
     *  own broadcast txs propagate. Null until a consumer (the RPC backend) registers. */
    private volatile TxGossipObserver txGossipObserver;

    /**
     * Re-entrant counter of in-progress snap-heavy operations (ENS resolution).
     * While > 0, the discovery dial loop should hold off on opening NEW peer
     * connections: an ENS resolution issues a long, latency-sensitive chain of
     * snap round-trips on the shared NioEventLoopGroup, and a burst of
     * concurrent outbound dials (each an ECIES handshake + up to a 10 s pending
     * connect) competes for those same event-loop threads, inflating per-read
     * latency. Existing peers are untouched — we only pause acquiring new ones
     * for the (seconds-long) duration of the query.
     */
    private final java.util.concurrent.atomic.AtomicInteger snapHeavyOps =
        new java.util.concurrent.atomic.AtomicInteger(0);

    /** Mark the start of a snap-heavy op (ENS resolution); pair with {@link #exitSnapHeavy()}. */
    public void enterSnapHeavy() { snapHeavyOps.incrementAndGet(); }

    /** Mark the end of a snap-heavy op. */
    public void exitSnapHeavy() { snapHeavyOps.decrementAndGet(); }

    /** True while at least one snap-heavy op is in progress — the dial loop pauses new connects. */
    public boolean isSnapHeavy() { return snapHeavyOps.get() > 0; }

    public RLPxConnector(NodeKey localKey, int tcpPort, NetworkConfig network,
                         Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders,
                         PeerReadyCallback peerReadyCallback) {
        this(localKey, tcpPort, network, onHeaders, peerReadyCallback, null);
    }

    /** @param serveStats stack-owned inbound-serve counters shared across connections and
     *                    across connector rebuilds (pause/resume); null → not counted */
    public RLPxConnector(NodeKey localKey, int tcpPort, NetworkConfig network,
                         Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders,
                         PeerReadyCallback peerReadyCallback, ServeStats serveStats) {
        this.localKey = localKey;
        this.tcpPort = tcpPort;
        this.network = network;
        this.chainHead = new ChainHead(network.genesisHash());
        this.group = new NioEventLoopGroup(4);
        this.onHeaders = onHeaders;
        this.peerReadyCallback = peerReadyCallback;
        this.serveStats = serveStats;
        // Seed genesis (always servable for fork probes) where we embed its RLP.
        byte[] genesisRlp = "mainnet".equals(network.name())
                ? NetworkConfig.MAINNET_GENESIS_HEADER_RLP : null;
        this.servedWindow = new ServedHeaderWindow(
                EthHandler.DEFAULT_SERVED_BLOCK_WINDOW, network.genesisHash(), genesisRlp);
    }

    /** The shared served-header window (for a later Settings-driven size knob). */
    public ServedHeaderWindow servedWindow() {
        return servedWindow;
    }

    /**
     * Broadcast our current eth/69 servable range to already-connected peers when it
     * changes. Called after a connection caches new recent headers. The dedup decision is
     * made under a lock (event-loop threads race here), but the actual sends happen outside
     * it — each {@link EthHandler#sendBlockRangeUpdate} re-reads the window itself.
     */
    private void broadcastRangeIfChanged() {
        ChainHead.Head head = chainHead.get();
        ServedHeaderWindow.Range r = servedWindow.advertise(head.blockNumber(), head.blockHash());
        synchronized (rangeBroadcastLock) {
            if (r.earliest() == lastBroadcastEarliest && r.latest() == lastBroadcastLatest) return;
            lastBroadcastEarliest = r.earliest();
            lastBroadcastLatest = r.latest();
        }
        for (EthHandler h : activeHandlers) {
            h.sendBlockRangeUpdate();
        }
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
        // Filled in below once the EthHandler exists; onReady reads its snap
        // negotiation state (set during the Hello exchange, before READY).
        final EthHandler[] handlerRef = new EthHandler[1];
        Runnable onReady = () -> {
            if (peerReadyCallback != null) {
                boolean snap = handlerRef[0] != null && handlerRef[0].isSnapNegotiated();
                peerReadyCallback.onPeerReady(peerAddr, pubKeyHex, snap);
            }
        };
        EthHandler ethHandler = new EthHandler(localKey, tcpPort, network, chainHead, servedWindow, serveStats, onHeaders, onReady);
        handlerRef[0] = ethHandler;
        // When this connection caches new recent headers, our servable range may grow —
        // tell already-connected eth/69 peers via BlockRangeUpdate.
        ethHandler.setWindowUpdateListener(this::broadcastRangeIfChanged);
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
                            closeCallback.onPeerClose(ethHandler.isIncompatibleNetwork(),
                                ethHandler.isPeerBusy(), pubKeyHex);
                        }
                    });
                }
            });

        ChannelFuture connectFuture = bootstrap.connect(peerAddr);
        connectFuture.addListener((ChannelFuture f) -> {
            if (f.isSuccess()) {
                activeHandlers.add(ethHandler);
                // Apply the gossip observer AFTER joining activeHandlers, closing the
                // race with setTxGossipObserver: that setter writes the (volatile) field
                // then iterates active handlers, so ordering it "add then read field"
                // here guarantees delivery on every interleaving — either the setter's
                // iteration sees this handler, or this read sees the setter's write.
                ethHandler.setTxGossipObserver(txGossipObserver);
            } else {
                log.debug("[rlpx] Connection to {} failed: {}", peerAddr, f.cause().getMessage());
            }
        });
        return connectFuture;
    }

    /** Round-robin cursor for backfill peer selection (fairness + no single peer
     *  both hammered and trusted with every fill). Deliberately NOT shared with
     *  {@link #bodyReceiptRr}: a bodies/receipts burst advancing a shared cursor by
     *  ~a multiple of the ready-set size would pin every backfill onto the same
     *  start peer. */
    private final java.util.concurrent.atomic.AtomicInteger backfillRr =
            new java.util.concurrent.atomic.AtomicInteger();

    /**
     * Backfill fetch: request headers RAW (no auto-admission — the caller
     * validates the batch against the beacon anchor before putting it into the
     * served window) from a ROTATING ready peer. Null when no peer is ready.
     */
    public CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> backfillHeaders(
            long blockNumber, int count) {
        List<EthHandler> ready = new java.util.ArrayList<>();
        for (EthHandler h : activeHandlers) {
            if (h.isReady()) ready.add(h);
        }
        if (ready.isEmpty()) return null;
        int start = Math.floorMod(backfillRr.getAndIncrement(), ready.size());
        for (int i = 0; i < ready.size(); i++) {
            EthHandler h = ready.get((start + i) % ready.size());
            CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> f =
                    h.requestBlockHeadersRawAsync(blockNumber, count);
            if (f != null) {
                log.debug("[rlpx] backfill GetBlockHeaders(block={}, count={}) via {}",
                        blockNumber, count, h.getRemoteAddress());
                return f;
            }
        }
        return null;
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
        return Futures.failedFuture(
                new IllegalStateException("No active peer with completed eth handshake"));
    }

    /**
     * Request a large range of block headers in batches from the same peer.
     * Each batch is up to 1024 headers; the results are concatenated.
     * Tries each ready peer in turn until one succeeds.
     */
    public CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> requestBlockHeadersBatched(
            long startBlock, int totalCount) {
        List<EthHandler> readyPeers = new java.util.ArrayList<>();
        for (EthHandler h : activeHandlers) {
            if (h.isReady()) readyPeers.add(h);
        }
        if (readyPeers.isEmpty()) {
            return Futures.failedFuture(
                    new IllegalStateException("No active peer with completed eth handshake"));
        }
        return tryBatchedPeer(readyPeers, 0, startBlock, totalCount);
    }

    private CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> tryBatchedPeer(
            List<EthHandler> peers, int peerIndex, long startBlock, int totalCount) {
        if (peerIndex >= peers.size()) {
            return Futures.failedFuture(new IllegalStateException(
                    "All " + peers.size() + " peers failed to serve batched headers"));
        }
        EthHandler handler = peers.get(peerIndex);
        log.info("[rlpx] Batched header request: block={}, count={}, peer={} ({}/{})",
                startBlock, totalCount, handler.getRemoteAddress(), peerIndex + 1, peers.size());
        return Futures.exceptionallyCompose(
                fetchBatch(handler, startBlock, totalCount, new java.util.ArrayList<>(totalCount)),
                ex -> {
                    log.warn("[rlpx] Batched request failed on peer {}: {}, trying next",
                            handler.getRemoteAddress(), failureKind(ex));
                    return tryBatchedPeer(peers, peerIndex + 1, startBlock, totalCount);
                });
    }

    private CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> fetchBatch(
            EthHandler handler, long startBlock, int remaining,
            List<BlockHeadersMessage.VerifiedHeader> accumulated) {
        if (remaining <= 0) return CompletableFuture.completedFuture(accumulated);
        int count = Math.min(remaining, 1024);
        CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> future =
                handler.requestBlockHeadersAsync(startBlock, count);
        if (future == null) {
            return Futures.failedFuture(
                    new IllegalStateException("Peer disconnected during batched header fetch"));
        }
        return Futures.orTimeout(future, 10, java.util.concurrent.TimeUnit.SECONDS).thenCompose(batch -> {
            if (batch.size() != count) {
                return Futures.failedFuture(new RuntimeException(
                        "Expected " + count + " headers, got " + batch.size()));
            }
            accumulated.addAll(batch);
            return fetchBatch(handler, startBlock + count, remaining - count, accumulated);
        });
    }

    /** How many READY peers a bodies/receipts request rotates across before giving
     *  up. Bounds worst-case latency (x {@link #BODY_RECEIPT_TIMEOUT_MS}) while making
     *  an all-empty outcome astronomically unlikely: at the ~35% single-peer empty
     *  rate observed in #359, 8 tries is 0.35^8 ~= 0.02%. Mirrors the snap side's
     *  {@code SNAP_ORACLE_MAX_ATTEMPTS}. */
    private static final int BODY_RECEIPT_MAX_PEERS = 8;
    /** Per-peer deadline for a bodies/receipts fetch — the rotation policy's own
     *  per-attempt bound (it also covers the unit tests' un-bounded fake suppliers).
     *  Aliases {@code EthHandler}'s self-cleaning request deadline so the two can't
     *  drift; the rationale for the 10 s value lives there. Worst case
     *  (cap x this = 80 s) is longer than any caller's own budget (30-60 s
     *  {@code .get()}/orTimeout), but reaching it needs every tried peer to HANG —
     *  clean empties rotate in ~1 RTT; a caller deadline merely truncates what it
     *  can observe, and the orphaned rotation stays bounded per attempt. */
    private static final long BODY_RECEIPT_TIMEOUT_MS =
            EthHandler.BODY_RECEIPT_REQUEST_TIMEOUT_MS;

    /** Round-robin start cursor for bodies/receipts rotation: {@code activeHandlers}
     *  iterates in a stable order between membership changes, so without it every
     *  call would start at the same peer — a never-serving first peer would tax each
     *  request, and wide callers (the 128-deep receipt scan, feeHistory pipelining)
     *  would herd their whole burst onto one peer at a time. */
    private final java.util.concurrent.atomic.AtomicInteger bodyReceiptRr =
            new java.util.concurrent.atomic.AtomicInteger();

    /**
     * Request block bodies, ROTATING across active READY peers (#359). The
     * bodies path previously took the first ready peer and treated its empty
     * reply as terminal, so a peer that simply didn't hold the block failed the
     * whole call (~1-in-3 on mainnet); the header path already rotates, and this
     * brings bodies in line.
     *
     * @return the first peer's COMPLETE reply; an empty list when every tried
     *     peer replied-but-empty (so the caller's stale/again fallback fires,
     *     exactly as a single empty reply did before, only now after rotation);
     *     a failed future when there is no READY peer, or when every attempt
     *     errored without a clean reply (a transport problem -> the caller's -32000).
     */
    public CompletableFuture<List<BlockBodiesMessage.BlockBody>> requestBlockBodies(
            Bytes32... hashes) {
        return rotateRequest("GetBlockBodies(" + hashes.length + ")", hashes.length,
                h -> h.requestBlockBodiesAsync(hashes));
    }

    /**
     * Request consensus-encoded receipts for the given block hashes, ROTATING
     * across active READY peers (#359) — same shape as {@link #requestBlockBodies},
     * so {@code eth_getTransactionReceipt} (polled right after a send) no longer
     * rides on a single peer's reply. Callers MUST verify the result against a
     * trusted {@code header.receiptsRoot} before use.
     */
    public CompletableFuture<List<List<Bytes>>> requestReceipts(Bytes32... hashes) {
        return rotateRequest("GetReceipts(" + hashes.length + ")", hashes.length,
                h -> h.requestReceiptsAsync(hashes));
    }

    /** Log-friendly failure description: a bare {@code TimeoutException} (the
     *  shape {@code Futures.orTimeout} completes with) has a null message, so
     *  fall back to the exception itself rather than logging "null". */
    private static Object failureKind(Throwable ex) {
        return ex.getMessage() != null ? ex.getMessage() : ex;
    }

    /** Build a per-peer attempt supplier list from the current READY peers (capped
     *  at {@link #BODY_RECEIPT_MAX_PEERS}), starting at the {@link #bodyReceiptRr}
     *  cursor so consecutive calls spread over the whole ready set instead of
     *  re-taxing the same stable-first peers (and, with more ready peers than the
     *  cap, every peer gets a turn rather than a fixed first eight), and run them
     *  through {@link #rotate}. Each supplier calls {@code async} lazily and logs
     *  when the attempt actually starts; a peer that dropped between snapshot and
     *  invocation yields a null future, which {@link #rotate} skips without
     *  counting. */
    private <T> CompletableFuture<List<T>> rotateRequest(
            String what, int expected,
            java.util.function.Function<EthHandler, CompletableFuture<List<T>>> async) {
        List<EthHandler> ready = new ArrayList<>();
        for (EthHandler h : activeHandlers) {
            if (h.isReady()) ready.add(h);
        }
        if (ready.isEmpty()) {
            return Futures.failedFuture(
                    new IllegalStateException("No active peer with completed eth handshake"));
        }
        int cap = Math.min(ready.size(), BODY_RECEIPT_MAX_PEERS);
        int start = Math.floorMod(bodyReceiptRr.getAndIncrement(), ready.size());
        List<Supplier<CompletableFuture<List<T>>>> attempts = new ArrayList<>(cap);
        for (int i = 0; i < cap; i++) {
            EthHandler h = ready.get((start + i) % ready.size());
            int idx = i + 1;
            attempts.add(() -> {
                CompletableFuture<List<T>> fut = async.apply(h);
                if (fut == null) return null;
                log.info("[rlpx] {} -> {} ({}/{})", what, h.getRemoteAddress(), idx, cap);
                return fut;
            });
        }
        return rotate(what, expected, attempts, BODY_RECEIPT_TIMEOUT_MS);
    }

    /**
     * Pure rotation policy (no EthHandler, unit-testable): try each attempt in
     * order until one returns a reply of at least {@code expected} size.
     * <ul>
     *   <li>A clean but short/empty reply -> rotate, and remember a clean empty was
     *       seen (the block just isn't being served by that peer).</li>
     *   <li>An exception (incl. the per-attempt timeout) -> rotate, remember it.</li>
     *   <li>A null future (peer gone) -> skip, not counted as an attempt.</li>
     * </ul>
     * On exhaustion: an empty list if any clean empty was seen (so the caller's
     * existing empty-reply fallback fires, only now after genuine rotation), else
     * the last error (a pure-transport failure the caller surfaces as -32000).
     *
     * <p>Known limit: the acceptance gate is SIZE-only — root verification stays
     * with the caller (trust model), so a byzantine peer answering with the right
     * NUMBER of junk items terminates rotation here and fails only at the caller's
     * root check, which falls back without retrying the remaining peers. Safety
     * holds (junk never verifies); availability of the path is what such a peer
     * controls. Rotating on verification failure would need the trusted roots (or a
     * verify callback) at this layer — deferred with the peer-quality scoring
     * follow-up (#400).
     */
    static <T> CompletableFuture<List<T>> rotate(
            String what, int expected,
            List<Supplier<CompletableFuture<List<T>>>> attempts, long perAttemptTimeoutMs) {
        return rotateFrom(what, expected, attempts, 0, false, null, perAttemptTimeoutMs);
    }

    private static <T> CompletableFuture<List<T>> rotateFrom(
            String what, int expected, List<Supplier<CompletableFuture<List<T>>>> attempts,
            int i, boolean sawCleanEmpty, Throwable lastEx, long perAttemptTimeoutMs) {
        if (i >= attempts.size()) {
            if (sawCleanEmpty) {
                return CompletableFuture.completedFuture(List.of());
            }
            return Futures.failedFuture(lastEx != null ? lastEx
                    : new IllegalStateException("all peer(s) failed to serve " + what));
        }
        CompletableFuture<List<T>> f = attempts.get(i).get();
        if (f == null) {
            return rotateFrom(what, expected, attempts, i + 1, sawCleanEmpty, lastEx, perAttemptTimeoutMs);
        }
        return Futures.orTimeout(f, perAttemptTimeoutMs, TimeUnit.MILLISECONDS)
                .handle((list, ex) -> {
                    if (ex == null && list != null && list.size() >= expected) {
                        return CompletableFuture.completedFuture(list);
                    }
                    boolean cleanEmpty = (ex == null);
                    return rotateFrom(what, expected, attempts, i + 1,
                            sawCleanEmpty || cleanEmpty, cleanEmpty ? lastEx : ex, perAttemptTimeoutMs);
                })
                .thenCompose(x -> x);
    }

    /**
     * Gossip a raw signed transaction to <em>every</em> READY eth peer (eth
     * Transactions 0x12). A light client doesn't relay the mempool, so peers may
     * not re-propagate our gossip — broadcasting widely maximizes the chance the
     * tx reaches a block producer.
     *
     * @return the number of peers the tx was sent to
     */
    public int broadcastTransaction(byte[] rawTx) {
        int sent = 0;
        for (EthHandler handler : activeHandlers) {
            if (handler.isReady() && handler.sendTransactions(rawTx)) sent++;
        }
        log.info("[rlpx] Broadcast transaction to {} peer(s)", sent);
        return sent;
    }

    /**
     * Register (or clear, with null) the mempool-gossip observer. Stored for handlers
     * created later and pushed to every currently-active handler, so a node that just
     * broadcast a tx can watch for that hash returning over Transactions (0x12) /
     * NewPooledTransactionHashes (0x18) gossip. Idempotent.
     */
    public void setTxGossipObserver(TxGossipObserver observer) {
        this.txGossipObserver = observer;
        for (EthHandler handler : activeHandlers) {
            handler.setTxGossipObserver(observer);
        }
    }

    /**
     * Fetch a single account from the snap/1 state trie via any active READY + snap peer.
     * Automatically retries with the next snap peer if the first one fails.
     *
     * @param address 20-byte Ethereum address
     * @return future completing with the AccountRange result, or failed future if no snap peer available
     */
    public CompletableFuture<AccountRangeMessage.DecodeResult> requestAccount(Bytes address) {
        return requestAccount(address, null);
    }

    public CompletableFuture<AccountRangeMessage.DecodeResult> requestAccount(
            Bytes address, Bytes32 stateRoot) {
        List<EthHandler> snapPeers = new ArrayList<>();
        for (EthHandler handler : activeHandlers) {
            if (handler.isReady() && handler.isSnapNegotiated() && !handler.isSnapServingFailed()) {
                snapPeers.add(handler);
            }
        }
        if (snapPeers.isEmpty()) {
            return Futures.failedFuture(
                new IllegalStateException("No active peer with snap/1 support"));
        }
        return trySnapPeer(address, stateRoot, snapPeers, 0);
    }

    private CompletableFuture<AccountRangeMessage.DecodeResult> trySnapPeer(
            Bytes address, Bytes32 stateRoot, List<EthHandler> peers, int index) {
        if (index >= peers.size()) {
            return Futures.failedFuture(
                new IllegalStateException("All " + peers.size() + " snap peers failed to serve account data"));
        }
        EthHandler handler = peers.get(index);
        CompletableFuture<AccountRangeMessage.DecodeResult> future =
            stateRoot != null
                ? handler.requestAccountAsync(address, stateRoot)
                : handler.requestAccountAsync(address);
        if (future == null) {
            return trySnapPeer(address, stateRoot, peers, index + 1);
        }
        log.info("[rlpx] Routed snap GetAccountRange for {} to peer {} ({}/{})",
            address.toShortHexString(), handler.getRemoteAddress(), index + 1, peers.size());
        return Futures.exceptionallyCompose(future, ex -> {
            log.warn("[rlpx] Snap request failed on peer {}: {}, trying next peer",
                handler.getRemoteAddress(), failureKind(ex));
            // Don't permanently mark as failed — disconnects and timeouts are usually transient
            return trySnapPeer(address, stateRoot, peers, index + 1);
        });
    }

    /**
     * Fetch storage slots for a contract via snap/1 from any active snap peer.
     * Automatically retries with the next snap peer if the first one fails.
     *
     * @param contractAddress 20-byte contract address
     * @param storageKeyHash  32-byte keccak256(storageSlotKey) — the trie key
     * @return future completing with the StorageRanges result
     */
    public CompletableFuture<StorageRangesMessage.DecodeResult> requestStorage(
            Bytes contractAddress, Bytes32 storageKeyHash) {
        return requestStorage(contractAddress, storageKeyHash, null);
    }

    public CompletableFuture<StorageRangesMessage.DecodeResult> requestStorage(
            Bytes contractAddress, Bytes32 storageKeyHash, Bytes32 stateRoot) {
        List<EthHandler> snapPeers = new ArrayList<>();
        for (EthHandler handler : activeHandlers) {
            if (handler.isReady() && handler.isSnapNegotiated() && !handler.isSnapServingFailed()) {
                snapPeers.add(handler);
            }
        }
        if (snapPeers.isEmpty()) {
            return Futures.failedFuture(
                new IllegalStateException("No active peer with snap/1 support"));
        }
        return trySnapStoragePeer(contractAddress, storageKeyHash, stateRoot, snapPeers, 0);
    }

    private CompletableFuture<StorageRangesMessage.DecodeResult> trySnapStoragePeer(
            Bytes contractAddress, Bytes32 storageKeyHash, Bytes32 stateRoot,
            List<EthHandler> peers, int index) {
        if (index >= peers.size()) {
            return Futures.failedFuture(
                new IllegalStateException("All " + peers.size() + " snap peers failed to serve storage data"));
        }
        EthHandler handler = peers.get(index);
        CompletableFuture<StorageRangesMessage.DecodeResult> future = stateRoot != null
            ? handler.requestStorageAsync(contractAddress, storageKeyHash, stateRoot)
            : handler.requestStorageAsync(contractAddress, storageKeyHash);
        if (future == null) {
            return trySnapStoragePeer(contractAddress, storageKeyHash, stateRoot, peers, index + 1);
        }
        log.info("[rlpx] Routed snap GetStorageRanges for {} to peer {} ({}/{})",
            storageKeyHash.toShortHexString(), handler.getRemoteAddress(), index + 1, peers.size());
        // One decision point on THIS peer's outcome, with the retry recursion outside
        // it: wrapping the recursion in the failure handler (the previous shape)
        // replayed the remaining peer list once per level — up to 2^n snap requests
        // on a fully-failing pool instead of n.
        return future.handle((result, ex) -> {
            if (ex != null) {
                log.warn("[rlpx] Snap storage request failed on peer {}: {}, trying next peer",
                    handler.getRemoteAddress(), failureKind(ex));
                return trySnapStoragePeer(contractAddress, storageKeyHash, stateRoot, peers, index + 1);
            }
            if (result.slots().isEmpty() && result.proof().isEmpty()) {
                log.warn("[rlpx] Peer {} returned empty storage response, trying next peer",
                    handler.getRemoteAddress());
                benchReadFailure(handler);
                return trySnapStoragePeer(contractAddress, storageKeyHash, stateRoot, peers, index + 1);
            }
            // No streak clear here: nothing on this path is verified (the proof
            // check happens in the caller), and the serve credit must not be
            // spoofable with junk bytes — clears, like strikes, come only from
            // the oracle path, post-verification (SnapPeer.reportServed).
            return CompletableFuture.completedFuture(result);
        }).thenCompose(Function.identity());
    }

    /** Consecutive verified-read failures at which a peer is DISCONNECTED instead of
     *  benched, freeing its slot for a fresh candidate (the snap maintainer refills on
     *  serving count). Twin of the Rust engine's {@code READ_FAILS_EVICT}
     *  (rust/myotis-net/src/el/pool.rs), and deliberately equal to the peer caches'
     *  snap-failure DENIED threshold ({@code PeerCache}/{@code AndroidPeerCache}
     *  {@code SNAP_FAILURE_THRESHOLD} — they can't import this constant, hosts don't
     *  see {@code :networking}; {@code PeerCacheTest} pins the equality) so eviction
     *  and the persisted verdict move in lockstep: the read that evicts is the read
     *  that denies. */
    public static final int READ_FAILS_EVICT = 3;

    /** Outcome of one banked verified-read failure. */
    enum ReadFailureVerdict { SHIELD, BENCH, EVICT }

    /** The pure ladder, extracted for tests: the sole serving peer is shielded (an
     *  empty response there is likelier OUR stale root than a broken peer, and
     *  benching it flaps the serving pool between 0 and 1); otherwise the streak
     *  benches until it reaches {@link #READ_FAILS_EVICT}, then evicts. */
    static ReadFailureVerdict readFailureVerdict(boolean anotherServing, int failsAfterBank) {
        if (!anotherServing) {
            return ReadFailureVerdict.SHIELD;
        }
        return failsAfterBank >= READ_FAILS_EVICT ? ReadFailureVerdict.EVICT
                                                  : ReadFailureVerdict.BENCH;
    }

    /** True when a serving snap peer other than {@code failed} exists. Caller must hold
     *  the connector monitor (the scan and the subsequent bench/evict must be atomic
     *  against other benchers, or the last two serving peers can each see the other as
     *  still serving and both leave the pool). Counts UN-BENCHED peers — deliberately
     *  narrower than the Rust twin's shield (any live pool peer, benched included,
     *  pool.rs): it mirrors the pre-eviction {@code benchUnlessLastServing} predicate,
     *  and stops striking once the rest of the pool is already benched, which a
     *  whole-pool outage (our stale root, not the peers') would otherwise turn into a
     *  pool-wide eviction. */
    private boolean anotherServing(EthHandler failed) {
        for (EthHandler h : activeHandlers) {
            if (h != failed && h.isReady() && h.isSnapNegotiated() && !h.isSnapServingFailed()) {
                return true;
            }
        }
        return false;
    }

    /** Bench a peer whose response failed a read, without banking an eviction strike —
     *  for PER-RESPONSE failure paths (one storage request rotating N peers fires this
     *  N times, and concurrent requests multiply it): banking here would let a couple
     *  of stale-root queries walk healthy peers to eviction, and this path has no
     *  cache access, so an eviction from it could not write the DENIED verdict the
     *  ladder promises ("the read that evicts is the read that denies"). Strikes come
     *  only from {@link #recordReadFailure}, whose oracle caller dedupes per root
     *  context and pairs each strike with a cache verdict. */
    public synchronized void benchReadFailure(EthHandler failed) {
        if (anotherServing(failed)) {
            failed.markSnapServingFailed();
        } else {
            log.info("[rlpx] Not benching {} — last serving snap peer (empty response likely "
                + "a stale-root request)", failed.getRemoteAddress());
        }
    }

    /** A verified read failed against this peer: bench it for the cooldown, or — on the
     *  {@link #READ_FAILS_EVICT}th CONSECUTIVE failure — disconnect it so the maintainer
     *  replaces it (a 30s bench routes around a momentary lag; it cannot rotate out a
     *  peer that keeps failing, which is how a stale pool held every slot in the Rust
     *  engine's 2026-09-02 incident). The last un-benched serving snap peer is shielded
     *  (no strike banked either — matching the Rust pool's sole-peer shield). Callers
     *  must dedupe to at most one call per peer per failed READ (the oracle gates on
     *  its per-root-context deny set) — per-response paths use
     *  {@link #benchReadFailure} instead. Note "consecutive" means no intervening
     *  serve: routing prefers proven servers, so a struck peer may not be re-tried
     *  soon, and strikes from unrelated transient lags can accumulate to an eviction —
     *  acceptable, since eviction only costs a re-dial and the cache verdict needs the
     *  same three failures it always did.
     *
     *  @return true when a strike was banked (BENCH/EVICT); false on the sole-peer
     *      SHIELD — callers pairing this with a persisted failure verdict must skip
     *      that write too, or three shielded outages would persist DENIED against
     *      the one peer that kept serving (the guard Rust's record_quality keeps). */
    public synchronized boolean recordReadFailure(EthHandler failed) {
        boolean anotherServing = anotherServing(failed);
        // Judged on the post-bank streak; the bank itself happens per branch because
        // the shield must not strike. Bank and clear both happen under the connector
        // monitor (recordReadServed is synchronized too), so streak+1 IS the
        // post-bank value.
        switch (readFailureVerdict(anotherServing, failed.snapReadFailStreak() + 1)) {
            case SHIELD -> {
                // Zero the streak, matching the Rust twin: keeping banked
                // strikes frozen through a shielded phase would evict the peer
                // on its very next failure the instant the pool regrows,
                // before it has actually failed as a NON-sole peer.
                failed.clearSnapReadFailures();
                log.info(
                    "[rlpx] Not benching {} — last serving snap peer (empty response likely "
                        + "a stale-root request)", failed.getRemoteAddress());
                return false;
            }
            case BENCH -> {
                failed.bankSnapReadFailure();
                failed.markSnapServingFailed();
            }
            case EVICT -> {
                failed.bankSnapReadFailure();
                // Bench BEFORE the close: removal from activeHandlers happens
                // asynchronously in the close-future listener, so without this
                // a just-evicted peer still satisfies the anotherServing scan
                // above and two concurrent evictions could drain the pool past
                // the shield (the Rust twin's prune_closed guards the same
                // corpse-counting hole, pool.rs).
                failed.markSnapServingFailed();
                log.info("[rlpx] Evicting snap peer {} after {} consecutive verified-read "
                    + "failures — freeing the slot for a fresh candidate",
                    failed.getRemoteAddress(), READ_FAILS_EVICT);
                failed.evict();
            }
        }
        return true;
    }

    /** A verified read served from this peer — reset its consecutive-failure streak.
     *  Synchronized with {@link #recordReadFailure} so a concurrent serve can't zero a
     *  streak between that method's read and its bank. */
    public synchronized void recordReadServed(EthHandler served) {
        served.clearSnapReadFailures();
    }

    public record PeerInfo(String remoteAddress, String state, boolean snapSupported, String clientId) {}

    public List<PeerInfo> getActivePeers() {
        List<PeerInfo> result = new ArrayList<>();
        for (EthHandler handler : activeHandlers) {
            String addr = handler.getRemoteAddress();
            String state = handler.getState().name();
            boolean snap = handler.isSnapNegotiated();
            String clientId = handler.getClientId();
            result.add(new PeerInfo(addr != null ? addr : "unknown", state, snap, clientId));
        }
        return result;
    }

    /** Best chain head we've heard about across all peers. Used by callers that
     *  need a recent block number for header fetches (e.g. {@code resolve-ens}
     *  reads the latest header to populate {@code BlockContext}). */
    public ChainHead.Head getChainHead() {
        return chainHead.get();
    }

    /** Network configuration (chain id, genesis hash, fork id, …) the connector
     *  was constructed with. Exposed so command handlers don't need a separate
     *  reference passed through every constructor. */
    public NetworkConfig getNetwork() {
        return network;
    }

    /**
     * Snapshot of currently-active READY peers that have negotiated snap/1
     * and are not flagged as snap-serving-failed. Used by callers that need
     * to drive snap-protocol traffic directly through an {@link EthHandler}
     * (e.g. {@code :app}'s {@code resolve-ens} command, which builds the
     * EVM executor stack on top of one of these handlers). The returned
     * list is a snapshot — handlers may disconnect afterwards, callers
     * should be prepared to fall through to the next entry on failure.
     */
    public List<EthHandler> activeSnapHandlers() {
        List<EthHandler> result = new ArrayList<>();
        for (EthHandler handler : activeHandlers) {
            if (handler.isReady() && handler.isSnapNegotiated() && !handler.isSnapServingFailed()) {
                result.add(handler);
            }
        }
        return result;
    }

    @Override
    public void close() {
        group.shutdownGracefully();
        log.info("[rlpx] Connector stopped");
    }
}
