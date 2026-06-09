package com.jaeckel.ethp2p.networking.rlpx;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.ChainHead;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.eth.EthHandler;
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

    /** Callback when a peer connection closes, with incompatibility info and node identity. */
    public interface PeerCloseCallback {
        void onPeerClose(boolean incompatibleNetwork, String nodeIdHex);
    }

    private final NodeKey localKey;
    private final int tcpPort;
    private final NetworkConfig network;
    private final ChainHead chainHead;
    private final NioEventLoopGroup group;
    private final Consumer<List<BlockHeadersMessage.VerifiedHeader>> onHeaders;
    private final PeerReadyCallback peerReadyCallback;
    private final Set<EthHandler> activeHandlers = ConcurrentHashMap.newKeySet();

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
        this.localKey = localKey;
        this.tcpPort = tcpPort;
        this.network = network;
        this.chainHead = new ChainHead(network.genesisHash());
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
        // Filled in below once the EthHandler exists; onReady reads its snap
        // negotiation state (set during the Hello exchange, before READY).
        final EthHandler[] handlerRef = new EthHandler[1];
        Runnable onReady = () -> {
            if (peerReadyCallback != null) {
                boolean snap = handlerRef[0] != null && handlerRef[0].isSnapNegotiated();
                peerReadyCallback.onPeerReady(peerAddr, pubKeyHex, snap);
            }
        };
        EthHandler ethHandler = new EthHandler(localKey, tcpPort, network, chainHead, onHeaders, onReady);
        handlerRef[0] = ethHandler;
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
                            closeCallback.onPeerClose(ethHandler.isIncompatibleNetwork(), pubKeyHex);
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
            return CompletableFuture.failedFuture(
                    new IllegalStateException("No active peer with completed eth handshake"));
        }
        return tryBatchedPeer(readyPeers, 0, startBlock, totalCount);
    }

    private CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>> tryBatchedPeer(
            List<EthHandler> peers, int peerIndex, long startBlock, int totalCount) {
        if (peerIndex >= peers.size()) {
            return CompletableFuture.failedFuture(new IllegalStateException(
                    "All " + peers.size() + " peers failed to serve batched headers"));
        }
        EthHandler handler = peers.get(peerIndex);
        log.info("[rlpx] Batched header request: block={}, count={}, peer={} ({}/{})",
                startBlock, totalCount, handler.getRemoteAddress(), peerIndex + 1, peers.size());
        return fetchBatch(handler, startBlock, totalCount, new java.util.ArrayList<>(totalCount))
                .exceptionallyCompose(ex -> {
                    log.warn("[rlpx] Batched request failed on peer {}: {}, trying next",
                            handler.getRemoteAddress(), ex.getMessage());
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
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Peer disconnected during batched header fetch"));
        }
        return future.orTimeout(10, java.util.concurrent.TimeUnit.SECONDS).thenCompose(batch -> {
            if (batch.size() != count) {
                return CompletableFuture.failedFuture(new RuntimeException(
                        "Expected " + count + " headers, got " + batch.size()));
            }
            accumulated.addAll(batch);
            return fetchBatch(handler, startBlock + count, remaining - count, accumulated);
        });
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

    /**
     * Request consensus-encoded receipts for the given block hashes from any active READY
     * peer. The future completes with one receipt list per block (request order). Callers
     * MUST verify the result against a trusted {@code header.receiptsRoot} before use.
     *
     * @return a future, or a failed future if no peer is available
     */
    public CompletableFuture<List<List<Bytes>>> requestReceipts(Bytes32... hashes) {
        Iterator<EthHandler> it = activeHandlers.iterator();
        while (it.hasNext()) {
            EthHandler handler = it.next();
            if (!handler.isReady()) continue;
            CompletableFuture<List<List<Bytes>>> future = handler.requestReceiptsAsync(hashes);
            if (future != null) {
                log.info("[rlpx] Routed GetReceipts({} hashes) to active peer", hashes.length);
                return future;
            }
            it.remove();
        }
        return CompletableFuture.failedFuture(
                new IllegalStateException("No active peer with completed eth handshake"));
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
            return CompletableFuture.failedFuture(
                new IllegalStateException("No active peer with snap/1 support"));
        }
        return trySnapPeer(address, stateRoot, snapPeers, 0);
    }

    private CompletableFuture<AccountRangeMessage.DecodeResult> trySnapPeer(
            Bytes address, Bytes32 stateRoot, List<EthHandler> peers, int index) {
        if (index >= peers.size()) {
            return CompletableFuture.failedFuture(
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
        return future.exceptionallyCompose(ex -> {
            log.warn("[rlpx] Snap request failed on peer {}: {}, trying next peer",
                handler.getRemoteAddress(), ex.getMessage());
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
            return CompletableFuture.failedFuture(
                new IllegalStateException("No active peer with snap/1 support"));
        }
        return trySnapStoragePeer(contractAddress, storageKeyHash, stateRoot, snapPeers, 0);
    }

    private CompletableFuture<StorageRangesMessage.DecodeResult> trySnapStoragePeer(
            Bytes contractAddress, Bytes32 storageKeyHash, Bytes32 stateRoot,
            List<EthHandler> peers, int index) {
        if (index >= peers.size()) {
            return CompletableFuture.failedFuture(
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
        return future.thenCompose(result -> {
            if (result.slots().isEmpty() && result.proof().isEmpty()) {
                log.warn("[rlpx] Peer {} returned empty storage response, trying next peer",
                    handler.getRemoteAddress());
                handler.markSnapServingFailed();
                return trySnapStoragePeer(contractAddress, storageKeyHash, stateRoot, peers, index + 1);
            }
            return CompletableFuture.completedFuture(result);
        }).exceptionallyCompose(ex -> {
            log.warn("[rlpx] Snap storage request failed on peer {}: {}, trying next peer",
                handler.getRemoteAddress(), ex.getMessage());
            return trySnapStoragePeer(contractAddress, storageKeyHash, stateRoot, peers, index + 1);
        });
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
