package io.myotis.rpc;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.proof.OrderedTrieRoot;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.eth.EthHandler;
import com.jaeckel.ethp2p.networking.eth.messages.BlockBodiesMessage;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.eth.messages.Receipt;
import com.jaeckel.ethp2p.networking.eth.messages.TxFeeFields;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;

import io.myotis.rpc.snap.EthHandlerSnapPeer;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * The shared, verified JSON-RPC backend — one implementation of
 * {@link io.myotis.jsonrpc.MyotisRpcBackend} that both the Android app
 * ({@code NodeService}) and the {@code :app} CLI daemon construct around their
 * live node components. Ported from {@code NodeService}'s RPC region so the
 * verified-read machinery (head-context anchoring, snap-backed state oracle
 * wiring, fee derivation, the per-pinned-block frozen context) lives once.
 *
 * <p>All read paths are cryptographically verified: head contexts are anchored
 * to the beacon-finalized root via headerChain, bodies/receipts are checked
 * against transactionsRoot/receiptsRoot, accounts/storage against the anchored
 * stateRoot. A method that cannot be answered verified returns null so the
 * router errors (strict mode) — peer data is never trusted unverified.
 *
 * <p>Lifecycle: construct with the live components, call {@link #start()} once
 * the node is up (spins up the head warmer), and {@link #close()} on shutdown
 * (stops every executor this backend owns). The injected components are NOT
 * closed here — the host owns them.
 */
public final class VerifiedRpcBackend implements io.myotis.jsonrpc.MyotisRpcBackend, AutoCloseable {

    // ---------------------------------------------------------------------
    // Constants (ported from NodeService's RPC region)
    // ---------------------------------------------------------------------

    // Same bound the JVM daemon uses (CommandHandler.MAX_HEADER_CHAIN_GAP).
    // Caps how many headers we'll fetch to bridge from the beacon-finalized
    // block to the peer's head — i.e. the maximum gap the headerChain
    // verification path will tolerate. In normal operation the gap is small
    // (snap peers track head, BLC finality lags by ~12.8 minutes ≈ 64 blocks),
    // but the bound has to cover catch-up after a long offline period (e.g. a
    // phone waking from doze).
    private static final int MAX_HEADER_CHAIN_GAP = 8192;
    private static final long HEADER_CHAIN_TIMEOUT_SEC = 60;
    // How many recent blocks below the verified head to scan for a tx in
    // eth_getTransactionReceipt. Kept small to bound the bandwidth/battery cost of the
    // (trustless) body scan on mobile: ~8 blocks ≈ 1.5 min covers a wallet polling a
    // just-submitted tx. A pending/older tx isn't found here and falls through to the
    // proxy. Bodies within the window are fetched concurrently, so latency ≈ one
    // round-trip regardless of the count.
    private static final int RECEIPT_LOOKBACK_BLOCKS = 8;
    // Max blocks below the verified head we'll fetch+verify headers for to answer
    // eth_getBlockByNumber by number. "latest" is 1 header; older numbers cost a header
    // range, so bound it (MetaMask asks for "latest" for the fee market anyway).
    private static final int BLOCK_LOOKBACK_MAX = 256;

    private static final long ENS_TIMEOUT_SEC = 60;

    /** Reuse one beacon-anchored head context across a burst of reads (a MetaMask
     *  page load fires hundreds of eth_calls + account reads) instead of re-probing
     *  peers + re-anchoring per call. ~12s keeps "latest" within ~1 block while
     *  amortizing the expensive (and fallback-prone) peer-probe + headerChain anchor
     *  across the whole burst. */
    private static final long RPC_HEAD_TTL_MS = 12_000;
    /** Budget for ONE blocking snap-fetch wave ({@code .get()}); NOT a hard
     *  per-request cap. A method that does sequential fetches spends it per fetch —
     *  e.g. eth_getCode (fetchAccount then fetchBytecode) and an eth_call whose EVM
     *  walks several SLOADs can exceed it in wall-clock; the response heartbeat
     *  (below) is what keeps such a request's socket alive, so there's no fixed
     *  request ceiling by design — the real bound is the wallet giving up.
     *  120s per wave, not the wallet-timeout-shaped 30s of old: the HTTP layer now
     *  heartbeats the response (whitespace trickle, see MyotisRpcServer) so the
     *  wallet's socket stays alive as long as WE keep computing — the bottleneck
     *  calls (MetaMask's ~1000-token BalanceChecker sweep, the Multicall3 confirm
     *  simulation on thin mobile peers) can now CONVERGE in one attempt, accumulating
     *  StateProofCache slots for the whole window, instead of being killed at 30s and
     *  restarted from scratch by the wallet's retry (which kept mobile from ever
     *  finishing). */
    private static final long RPC_CALL_TIMEOUT_SEC = 120;
    /** Snap-oracle per-fetch retry budget. Each attempt rotates to a different ready
     *  snap peer (the probed peer first), so a slow/dead peer fails over instead of
     *  burning the whole RPC_CALL_TIMEOUT on one peer. */
    private static final int SNAP_ORACLE_MAX_ATTEMPTS = 8;
    /** Head-build budget — includes the headerChain anchoring fetch. */
    private static final long RPC_ACCOUNT_TIMEOUT_SEC = HEADER_CHAIN_TIMEOUT_SEC + 10;
    /** Overall budget for the (parallel) snap-peer head probe. */
    private static final long PEER_PROBE_TIMEOUT_SEC = 15;
    /** Keep serving the last successfully-built head up to this age while a refresh
     *  is in flight. It's still beacon-anchored, just a few blocks stale — serving
     *  it bridges transient rebuild gaps (head just advanced, peers' flat state not
     *  yet caught up) instead of proxying. The warmer keeps it fresh (~5-15s). */
    private static final long RPC_HEAD_MAX_STALE_MS = 30_000;
    /** Max age a head context may have and still be served for a STATE-EXECUTION read
     *  (eth_call / getBalance / getCode / getStorageAt / estimateGas) — far tighter
     *  than the header-only {@link #RPC_HEAD_SERVE_STALE_MAX_MS} (~13 min). A state read
     *  must run against a stateRoot snap peers STILL retain: Geth keeps ~128 blocks of
     *  trie state and serves snap from a flat layer that lags the head, so a pinned root
     *  older than this is pruned out from under us — every connected peer denies it and
     *  the oracle rotation throws StateUnavailable, but only after burning the full 30s
     *  RPC_CALL_TIMEOUT rotating the set (the 1329-occurrence on-device storm). Beyond
     *  this we rebuild against a fresh, just-probed servable root or fast-error, never
     *  hand a doomed root to a 30s callView. Header-only reads keep the long stale
     *  window — their data needs no snap state.
     *
     *  <p>Two minutes, NOT the 30s warmer-fresh threshold: a root a few slots old
     *  (~10 blocks / 2 min) is still well within what snap peers retain, and on a phone
     *  an anchored-head rebuild takes 20-26s so the head's age routinely peaks at
     *  30-50s in HEALTHY operation between warmer ticks — a 30s cap would reject those
     *  perfectly-servable roots and manufacture -32000s. The roots that actually fail
     *  are minutes-old (the ~12-min beacon-finalized fallback, or a per-number pin held
     *  across a long retry storm). This bound catches those preemptively; the real
     *  storm-killer is {@link #evictUnservableHead} dropping a root the moment the
     *  oracle reports no peer serves it. */
    private static final long RPC_STATE_HEAD_MAX_STALE_MS = 120_000;
    /** When there's no usable head at all (cold start / long outage) and no build is
     *  in flight, wait only this long before giving up — a node with no snap peer can't
     *  build a head, so blocking the caller longer just delays the inevitable error. */
    private static final long RPC_HEAD_WAIT_MS = 5_000;
    /** When an anchored-head build IS already in flight (warmer or a prior read), ride
     *  it up to this longer cap instead of erroring at {@link #RPC_HEAD_WAIT_MS}. A cold
     *  anchored build on a phone (fetch+verify ~30 headers from beacon-finalized to head,
     *  then the first snap account fetch) routinely takes 10-30s; giving up at 5s makes a
     *  wallet's first read error even though the verified result is seconds away. Kept
     *  under typical wallet RPC timeouts so the call returns verified-but-slow, not failed. */
    private static final long RPC_HEAD_BUILD_WAIT_MS = 25_000;
    /** How far ABOVE the verified head a number-pinned read may sit and still be served
     *  (a wallet that just saw a newer block than our context). Small: a pin far above
     *  head is a genuinely future/unknown block. */
    private static final long RPC_BLOCK_NUM_TOLERANCE = 16;
    /** How far BELOW the context a number-pinned read may sit and still be served from
     *  the context's (newer) state. Wallets pin "latest"-intent reads to the last block
     *  they saw; when our calls are slow the chain advances past that pin before the read
     *  lands, leaving it tens of blocks behind. Serving the context's state for such a
     *  recent pin gives current-ish data (what the wallet wants) — far better than the
     *  instant error that emptied MetaMask's asset list. Beyond this (~13 min) the pin is
     *  genuinely historical and we can't represent it, so reject. */
    private static final long RPC_BLOCK_NUM_LAG_TOLERANCE = 64;
    /** Last-resort stale-serve horizon: when rebuilds keep failing (a heavy token
     *  sweep starving the snap peers, a peer-set outage), serve the last anchored
     *  head up to the SAME horizon the pinned-number check accepts —
     *  {@link #RPC_BLOCK_NUM_LAG_TOLERANCE} blocks (~13min at 12s slots). The
     *  context's verification never expires (it's beacon-anchored); only its
     *  freshness ages, and a wallet read against ~minutes-old verified state is
     *  strictly better than an instant error: MetaMask pins reads to a recent
     *  block number and re-polls anyway. Without this, every read during a
     *  sustained rebuild outage died with "no verified head" (the confirm-screen
     *  instant-ERROR storm) even though a perfectly servable context existed. */
    private static final long RPC_HEAD_SERVE_STALE_MAX_MS = RPC_BLOCK_NUM_LAG_TOLERANCE * 12_000;
    /** Nonce (eth_getTransactionCount) staleness ceiling — far TIGHTER than the
     *  general {@link #RPC_HEAD_SERVE_STALE_MAX_MS}. A stale nonce is uniquely
     *  dangerous: a wallet that signs a tx against a too-low nonce gets it rejected
     *  ("nonce too low") or silently replaces a still-pending tx. Balance / eth_call
     *  / block reads tolerate ~13 min of staleness because the wallet re-polls and a
     *  slightly-old verified value is harmless; the nonce drives what the user signs.
     *  Two minutes, NOT the 30s head-freshness bound: on a phone an anchored-head
     *  build takes 20-26s, so the head's age routinely peaks just past 30s between
     *  warmer ticks — at 30s the gate killed real MetaMask confirm flows on marginal
     *  misses (observed on-device: "head 32244ms stale -> not serving nonce"). Two
     *  minutes still guards genuinely outdated nonces (the wallet itself tracks its
     *  own pending txs; the gate only protects against same-account txs from
     *  elsewhere landing in the gap), while tolerating mobile build cadence. */
    private static final long RPC_NONCE_SERVE_STALE_MAX_MS = 120_000;

    /** keccak256("") — an account with this codeHash is an EOA (no contract code). */
    private static final byte[] EMPTY_CODE_HASH = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();

    // Cross-call cache of proof-verified account/storage state, keyed by stateRoot.
    // Shared across every head-context oracle so a wallet's repeated retries of a
    // heavy eth_call (MetaMask's ~1000-token BalanceChecker sweep / Multicall3
    // simulation) reuse already-fetched slots instead of re-proving hundreds each
    // time — turning a 30s-timeout retry-storm into a couple of converging attempts.
    // Bounded LRU per kind; ~64k storage slots ≈ a few MB.
    private static final int STATE_PROOF_CACHE_MAX = 65_536;

    // EVM pool. Was a single thread ("EVM is CPU-bound, oracle pinned to one
    // peer") — but the oracle rotates across peers now, and an EVM task spends
    // most of its wall-clock BLOCKED on snap fetch waves, not executing. A wallet
    // confirm screen fires ~20 eth_calls at once; serialized behind one thread
    // they queue for minutes and every one of them blows the 30s RPC deadline
    // (observed on-device). A small pool lets calls overlap their fetch waits.
    // Kept modest (3) so Besu interpretation can't peg the CPU alongside BLS.
    private static final int EVM_POOL_THREADS = 3;
    /** Calldata size at/below which an eth_call rides the reserved small lane. A
     *  wallet confirm screen's calls are tiny (36-byte balanceOf probes, ~516-byte
     *  Multicall3 simulations) while the background token sweep is ~32KB; without a
     *  reserved lane the sweep's 30s+ executions occupy every EVM thread and the
     *  confirm screen's calls queue to death behind them (observed live: the
     *  simulation timing out at 30s four times in a row during a sweep storm). */
    private static final int EVM_SMALL_CALLDATA_MAX = 4_096;
    /** Set by the RPC handler around callView/estimateGas invocations; read by the
     *  routing {@link #evmPool} when supplyAsync submits on the same thread. */
    private static final ThreadLocal<Boolean> EVM_SMALL_LANE = new ThreadLocal<>();
    /** Tasks older than this when dequeued are skipped: their RPC caller has long
     *  since given up, so running them would burn EVM-thread time for nobody —
     *  observed as a queue of dead confirm-screen calls starving the live retries
     *  that followed them. Slightly above the longest RPC wait (RPC_CALL_TIMEOUT_SEC,
     *  now 120s under response heartbeating) so a still-awaited task is never
     *  dropped early. */
    private static final long EVM_TASK_MAX_QUEUE_AGE_MS = RPC_CALL_TIMEOUT_SEC * 1000 + 5_000;

    /** Max blocks served per eth_feeHistory call (clamped per EIP-1559; MetaMask asks 5-10). */
    private static final int FEE_HISTORY_MAX_BLOCKS = 10;
    /** Blocks scanned for the priority-fee suggestion. */
    private static final int TIP_SUGGEST_BLOCKS = 3;
    /** Floor for the suggested tip: 0.1 gwei — keeps suggestions inclusive-but-sane
     *  when recent blocks are empty or full of zero-tip txs. */
    private static final java.math.BigInteger MIN_SUGGESTED_TIP =
            java.math.BigInteger.valueOf(100_000_000L);
    /** Tip suggestion cache TTL (~one block) — MetaMask polls fees every few seconds,
     *  and each recompute fetches TIP_SUGGEST_BLOCKS bodies. */
    private static final long TIP_CACHE_TTL_MS = 12_000;
    /** Refresh the snapshot when older than this (head warmer cadence is 5s). */
    private static final long FEE_SNAPSHOT_REFRESH_MS = 12_000;
    /** Don't serve a snapshot older than this — fall through to the cold path. */
    private static final long FEE_SNAPSHOT_MAX_SERVE_MS = 10 * 60_000;

    /** Contracts every MetaMask confirm flow hits: the ENS Registry (recipient
     *  reverse-resolution), Multicall3 (the confirm screen's transaction
     *  simulation) and the BalanceChecker (token sweep). */
    private static final String[] CONFIRM_WARM_CONTRACTS = {
            "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
            "0xcA11bde05977b3631167028862bE2a173976CA11",
            "0xb1F8e55c7f64D203C1400B9D8555d050F94aDF39",
    };

    /**
     * Probe account used only to confirm a peer can actually serve snap state at a
     * given root before we pin it for a whole head context. The beacon deposit
     * contract is present in every post-Merge state, so a non-empty proof for it
     * means the peer retains that root's trie.
     */
    private static final Bytes32 SNAP_PROBE_ACCOUNT_HASH =
            Hash.keccak256(Bytes.fromHexString("0x00000000219ab540356cBB839Cbe05303d7705Fa"));

    // ---------------------------------------------------------------------
    // Injected components (host-owned; never closed here)
    // ---------------------------------------------------------------------

    private final RLPxConnector connector;
    private final BeaconLightClient beaconLightClient;
    private final BeaconSyncState beaconSyncState;
    private final RpcLogger log;
    private final RpcClock clock;
    private final SnapQualitySink snapQuality;
    /** CCIP-Read (ERC-3668) gateway HTTP transport — host-specific (Ktor on
     *  Android, java.net.http on the daemon), so it's injected rather than owned. */
    private final io.myotis.evm.ccipread.CcipGateway ccipGateway;

    // ---------------------------------------------------------------------
    // Owned state (created here; stopped in close())
    // ---------------------------------------------------------------------

    /** Bytecode is keyed by hash, so this cache is valid forever across roots. */
    private final io.myotis.evm.world.BytecodeCache bytecodeCache =
            io.myotis.evm.world.BytecodeCache.inMemory();
    private final io.myotis.evm.world.StateProofCache stateProofCache =
            io.myotis.evm.world.StateProofCache.inMemory(STATE_PROOF_CACHE_MAX);

    /** Heavy lane: the token sweeps and other large calls (2 threads). */
    private final java.util.concurrent.ExecutorService evmPoolHeavy =
            java.util.concurrent.Executors.newFixedThreadPool(EVM_POOL_THREADS - 1, r -> {
                Thread t = new Thread(r, "rpc-evm-heavy");
                t.setDaemon(true);
                return t;
            });
    /** Small lane: one thread reserved for small-calldata calls so interactive
     *  reads never queue behind a sweep. */
    private final java.util.concurrent.ExecutorService evmPoolSmall =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "rpc-evm-small");
                t.setDaemon(true);
                return t;
            });
    /** Executor handed to the EVM stack: routes to the small or heavy lane (via the
     *  {@link #EVM_SMALL_LANE} hint the RPC handler sets on its own thread before
     *  invoking callView — supplyAsync calls execute() synchronously on that thread,
     *  so the hint is visible here; continuations submitted from other threads
     *  default to the heavy lane). Both lanes drop tasks that sat queued past
     *  {@link #EVM_TASK_MAX_QUEUE_AGE_MS}: a skipped task leaves its
     *  CompletableFuture incomplete — safe, because the only waiter timed out and
     *  abandoned it long before. Assigned in the constructor (not a field
     *  initializer) because the lambda reads the final clock/log fields, which
     *  javac's definite-assignment analysis rejects from an initializer. */
    private final java.util.concurrent.Executor evmPool;

    /** Runs the blocking, network-bound head build off the caller's thread so a
     *  request blocks only up to its own timeout. Single-thread: the future
     *  dedup means at most one build runs at a time. */
    private final java.util.concurrent.ExecutorService headBuildPool =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "rpc-head-build");
                t.setDaemon(true);
                return t;
            });

    private java.util.concurrent.ScheduledExecutorService headWarmer;

    private final Object rpcCallCtxLock = new Object();
    private CompletableFuture<RpcCallContext> rpcCallCtx;   // in-flight/fresh build (dedup)
    private long rpcCallCtxAtMs;
    // Last successfully-built anchored head + its build time, as one immutable
    // record behind a single ref so head and timestamp are read/written atomically
    // together (no torn read of new head with old timestamp). AtomicReference (not a
    // bare volatile) so eviction can compare-and-set: nulling a doomed head must not
    // clobber a fresher head the warmer set between the evictor's read and write.
    private final java.util.concurrent.atomic.AtomicReference<HeadWithTimestamp> lastGoodHead =
            new java.util.concurrent.atomic.AtomicReference<>();
    /**
     * Frozen anchored context per pinned block NUMBER. A wallet (MetaMask) pins a
     * confirm to one block and retries the same heavy calls against it for minutes.
     * Serving each retry against the <em>current</em> head — which the warmer rebuilds
     * to a new stateRoot every ~12-15s — reset the stateRoot-keyed StateProofCache on
     * every rebuild, so a 1000-slot BalanceChecker / Multicall3 simulation re-fetched
     * from scratch each retry and never converged (the persistent confirm-screen hang,
     * uptime-independent). Freezing the context — and thus its stateRoot — per pinned
     * number makes all retries hit one stable root, so the cache accumulates and the
     * call converges in a couple of tries. Bounded LRU (wallets pin a few recent
     * blocks); each entry ages out at {@link #RPC_HEAD_SERVE_STALE_MAX_MS}.
     */
    private final Map<Long, HeadWithTimestamp> pinnedHeadByNumber =
            java.util.Collections.synchronizedMap(
                    new java.util.LinkedHashMap<>(16, 0.75f, true) {
                        @Override protected boolean removeEldestEntry(
                                Map.Entry<Long, HeadWithTimestamp> e) {
                            return size() > 16;
                        }
                    });

    /** Raw bytes of transactions this node broadcast, keyed by lowercase 0x tx hash, so
     *  eth_getTransactionByHash can answer a just-sent tx as "pending" before it's mined
     *  (we hold the signed bytes — serving them is not a trust assumption). Bounded LRU;
     *  entries fall out as they age (they're served from verified blocks once mined). */
    private final Map<String, byte[]> sentTxCache = java.util.Collections.synchronizedMap(
            new java.util.LinkedHashMap<>(64, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, byte[]> e) {
                    return size() > 256;
                }
            });

    /** Suggested tip + when it was computed, one immutable unit behind a single
     *  volatile so a reader can't pair a fresh tip with a stale timestamp
     *  (same pattern as {@link HeadWithTimestamp}). */
    private record TipWithTimestamp(java.math.BigInteger tip, long atMs) {}
    private volatile TipWithTimestamp cachedSuggestedTip;
    /** Pre-computed (gasPrice, tip) snapshot, refreshed by the head warmer.
     *  eth_gasPrice / eth_maxPriorityFeePerGas serve from this in microseconds
     *  instead of paying the cold path (header anchor + header window + 3 block
     *  bodies over devp2p, observed 6-18s on-device) on the wallet's poll.
     *  MetaMask's confirm screen sits in skeleton until a fee poll returns and
     *  only re-polls every few minutes, so one slow answer stalls the screen for
     *  minutes. The snapshot is derived from the same verified data as the cold
     *  path — precomputing changes freshness, not trust. Serving a snapshot a
     *  minute or two old is fine: it's a fee suggestion, and the wallet re-polls. */
    private record FeeSnapshot(java.math.BigInteger gasPrice, java.math.BigInteger tip, long atMs) {}
    private volatile FeeSnapshot feeSnapshot;
    private final java.util.concurrent.atomic.AtomicBoolean feeRefreshing =
            new java.util.concurrent.atomic.AtomicBoolean();

    /** Last successfully-built latest/head block JSON (its number + when built), so a
     *  transient fetch failure on eth_getBlockByNumber can serve verified-but-stale
     *  data instead of erroring. MetaMask's block tracker polls "latest" and the
     *  re-fetch of a header window + bodies per call oscillates with the head context;
     *  a -32000 there empties the asset list / hangs the confirm screen. Only ever
     *  served for LATEST-ish tags or an exact number match within {@link
     *  #RPC_HEAD_SERVE_STALE_MAX_MS} — a number-pinned read for a different block must
     *  stay exact (error), never substitute a different block's data. */
    private record BlockSnapshot(String json, long number, long atMs) {}
    private volatile BlockSnapshot lastGoodLatestBlock;
    /** Last successfully-built eth_feeHistory result, keyed by the EXACT request
     *  signature (blockCount|newestBlock|percentiles). Served on a transient fetch
     *  failure only when the next request's signature matches and it's within {@link
     *  #RPC_HEAD_SERVE_STALE_MAX_MS}: an identical request yields identical verified
     *  data (just computed earlier), so this is correct-but-stale, never wrong. Fees
     *  drift slowly and the wallet re-polls, so a couple-minute-old fee history beats
     *  the -32000 that loops MetaMask's fee step and hangs the send screen. */
    private record FeeHistorySnapshot(String key, String json, long atMs) {}
    private volatile FeeHistorySnapshot lastGoodFeeHistory;

    /** Flipped by {@link #close()}; gates the warmer tick (mirrors NodeService's RUNNING). */
    private volatile boolean closed;

    // ---------------------------------------------------------------------
    // Records (EnsCall in NodeService is RpcCallContext here)
    // ---------------------------------------------------------------------

    /** The verified head context every read/call runs against: the EVM/ENS stack
     *  pinned to one (beacon-anchorable) state root. */
    private record RpcCallContext(io.myotis.ens.EnsResolver resolver,
                                  io.myotis.evm.BlockContext blockCtx,
                                  long blockNumber,
                                  boolean beaconVerified,
                                  io.myotis.evm.CcipReadEvmExecutor offchainExecutor,
                                  io.myotis.evm.world.SnapBackedStateOracle oracle) {}

    /** A snap peer paired with the fresh head it both reported and snap-serves. */
    private record PeerHead(EthHandler peer, BlockHeader header) {}

    /** A built anchored head plus when it was built (monotonic millis), held as one
     *  immutable unit so the serve-stale check reads both atomically. */
    private record HeadWithTimestamp(RpcCallContext head, long builtAtMs) {}

    // ---------------------------------------------------------------------
    // Construction / lifecycle
    // ---------------------------------------------------------------------

    public VerifiedRpcBackend(RLPxConnector connector,
                              BeaconLightClient beaconLightClient,
                              BeaconSyncState beaconSyncState,
                              io.myotis.evm.ccipread.CcipGateway ccipGateway,
                              RpcLogger log,
                              RpcClock clock,
                              SnapQualitySink snapQuality) {
        this.connector = java.util.Objects.requireNonNull(connector, "connector");
        this.beaconLightClient = java.util.Objects.requireNonNull(beaconLightClient, "beaconLightClient");
        this.beaconSyncState = java.util.Objects.requireNonNull(beaconSyncState, "beaconSyncState");
        this.ccipGateway = java.util.Objects.requireNonNull(ccipGateway, "ccipGateway");
        this.log = log != null ? log : RpcLogger.noop();
        this.clock = clock != null ? clock : RpcClock.monotonic();
        this.snapQuality = snapQuality != null ? snapQuality : SnapQualitySink.noop();
        final RpcClock clk = this.clock;
        final RpcLogger lg = this.log;
        this.evmPool = task -> {
            final long enqueuedAtMs = clk.elapsedMillis();
            boolean small = Boolean.TRUE.equals(EVM_SMALL_LANE.get());
            (small ? evmPoolSmall : evmPoolHeavy).execute(() -> {
                long ageMs = clk.elapsedMillis() - enqueuedAtMs;
                if (ageMs > EVM_TASK_MAX_QUEUE_AGE_MS) {
                    lg.info("[evm] skipping task queued " + ageMs
                            + "ms (caller deadline long past)");
                    return;
                }
                task.run();
            });
        };
    }

    /**
     * Pre-warm and keep-warm the shared anchored head: build it as soon as a snap
     * peer is ready (retrying every few seconds), so a wallet's first read hits a
     * ready cache instead of triggering a cold build — shrinking the post-start
     * window where reads error down to "time until first usable snap peer".
     * Cheap when warm: verifiedHeadCallContext reuses a fresh context.
     * Idempotent; mirrors NodeService.startHeadWarmer.
     */
    public synchronized void start() {
        if (headWarmer != null || closed) return;
        headWarmer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "rpc-head-warmer");
            t.setDaemon(true);
            return t;
        });
        headWarmer.scheduleWithFixedDelay(() -> {
            if (closed) return;
            try {
                verifiedHeadCallContext();
            } catch (Exception ignored) {
                // No usable snap peer / anchorable head yet — retry next tick.
            }
            // Keep the fee snapshot warm too: the wallet's confirm screen blocks on
            // its fee poll, and the cold computation takes seconds — paying it here
            // (off the RPC path) makes eth_gasPrice effectively instant.
            try {
                refreshFeeSnapshotIfStale();
            } catch (Throwable ignored) {
                // never kill the warmer tick
            }
        }, 3, 5, TimeUnit.SECONDS);
    }

    /** Stop every executor this backend owns and drop cached head state. The
     *  injected components (connector, light client, …) are the host's to close. */
    @Override
    public synchronized void close() {
        closed = true;
        if (headWarmer != null) {
            headWarmer.shutdownNow();
            headWarmer = null;
        }
        evmPoolHeavy.shutdownNow();
        evmPoolSmall.shutdownNow();
        headBuildPool.shutdownNow();
        // Drop the cached head context + last-good head so a later restart doesn't
        // briefly reuse one pinned to a now-dead peer (fails safe to error anyway).
        synchronized (rpcCallCtxLock) { rpcCallCtx = null; }
        lastGoodHead.set(null);
        pinnedHeadByNumber.clear();
        lastGoodLatestBlock = null;
        lastGoodFeeHistory = null;
    }

    // ---------------------------------------------------------------------
    // MyotisRpcBackend — bridges the Kotlin interface to the verified
    // machinery below (same delegation NodeService's anonymous backend used).
    // All blocking — called off the router's IO dispatcher.
    // ---------------------------------------------------------------------

    @Override
    public long chainId() {
        return connector.getNetwork().networkId();
    }

    @Override
    public Long headBlockNumber() {
        long n = beaconSyncState.getOptimisticBlockNumber();
        return n > 0 ? Long.valueOf(n) : null;
    }

    @Override
    public String syncState() {
        return beaconSyncState.getSyncState(connector.getNetwork().clGenesisTime()).name();
    }

    @Override
    public byte[] call(byte[] to, byte[] data, String block) {
        return rpcCall(to, data, block);
    }

    @Override
    public java.math.BigInteger getBalance(byte[] address, String block) {
        io.myotis.evm.world.AccountState a = rpcAccountState(address, block);
        return a == null ? null : a.balance();
    }

    @Override
    public Long getTransactionCount(byte[] address, String block) {
        // Nonce safety: gate on a FRESH head. Unlike balance/eth_call/block reads
        // (which serve up to ~13 min stale because the wallet re-polls and old-but-
        // verified is harmless), a stale nonce is what the wallet SIGNS against —
        // too low and the tx is rejected or replaces a pending one. If the verified
        // head is older than RPC_NONCE_SERVE_STALE_MAX_MS, error so the wallet
        // retries against a current head instead of receiving an outdated nonce.
        long headAge = headAgeMs();  // read once: the head can advance between calls
        if (headAge > RPC_NONCE_SERVE_STALE_MAX_MS) {
            log.info("[rpc] eth_getTransactionCount: head " + headAge
                    + "ms stale (> " + RPC_NONCE_SERVE_STALE_MAX_MS
                    + "ms) -> not serving nonce");
            return null;
        }
        io.myotis.evm.world.AccountState a = rpcAccountState(address, block);
        return a == null ? null : Long.valueOf(a.nonce());
    }

    @Override
    public byte[] getCode(byte[] address, String block) {
        return rpcCode(address, block);
    }

    @Override
    public byte[] getStorageAt(byte[] address, byte[] slot, String block) {
        return rpcStorageAt(address, slot, block);
    }

    @Override
    public byte[] sendRawTransaction(byte[] rawTx) {
        return rpcSendRawTransaction(rawTx);
    }

    @Override
    public String getTransactionReceipt(byte[] txHash) {
        return rpcGetTransactionReceipt(txHash, "latest");
    }

    @Override
    public String getTransactionByHash(byte[] txHash) {
        return rpcGetTransactionByHash(txHash);
    }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        return rpcGetBlockByNumber(block, fullTransactions);
    }

    @Override
    public java.math.BigInteger gasPrice() {
        return rpcGasPrice();
    }

    @Override
    public java.math.BigInteger maxPriorityFeePerGas() {
        return rpcMaxPriorityFeePerGas();
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        return rpcFeeHistory(blockCount, newestBlock, rewardPercentiles);
    }

    @Override
    public java.math.BigInteger estimateGas(byte[] from, byte[] to, byte[] data,
                                            java.math.BigInteger value) {
        return rpcEstimateGas(from, to, data, value);
    }

    // ---------------------------------------------------------------------
    // ENS forward resolution (name -> address) — shared by the daemon CLI and
    // the Android UI so the resolution POLICY lives once. Built on the same
    // verified prepareEnsCall EVM/ENS stack the RPC reads use.
    // ---------------------------------------------------------------------

    /** One resolution attempt against a specific root + whether a CCIP gateway answered. */
    private record EnsAttempt(EnsResolution resolution, boolean usedOffchain) {}

    /**
     * Verified ENS forward resolution. {@code AUTO} resolves against the
     * beacon-verified FINALIZED state first and only falls back to the (fresher,
     * peer-claimed → marked unverified) PEER_HEAD when finalized yields no record
     * AND didn't already consume an ERC-3668 offchain answer (re-resolving would
     * just repeat the same gateway round-trips for the same non-answer). A specific
     * root resolves only against that root. Never throws — failures surface as an
     * {@link EnsResolution} carrying the reason in {@code error()}.
     *
     * <p>Blocking work (peer-head probing, EVM execution) runs on the EVM pool, so
     * this is safe to call from a UI/event thread. Pauses peer acquisition for the
     * resolution's duration so its snap round-trips aren't starved by dial bursts.
     */
    public CompletableFuture<EnsResolution> resolveEns(
            String name, io.myotis.ens.EnsResolutionRoot mode) {
        final String trimmed = name == null ? "" : name.trim();
        RLPxConnector conn = connector;
        if (conn == null) {
            return CompletableFuture.completedFuture(
                    new EnsResolution(trimmed, null, -1, false, "node not running"));
        }
        if (trimmed.isEmpty()) {
            return CompletableFuture.completedFuture(
                    new EnsResolution(trimmed, null, -1, false, "empty name"));
        }
        final io.myotis.ens.EnsResolutionRoot m =
                (mode == null) ? io.myotis.ens.EnsResolutionRoot.AUTO : mode;
        conn.enterSnapHeavy();
        // The composition below can throw SYNCHRONOUSLY before any future is returned —
        // supplyAsync(supplier, evmPool) rethrows a RejectedExecutionException if the pool
        // is shut down / saturated. That would escape past the whenComplete cleanup and
        // leak the snap-heavy state we just entered (and break the "never throws"
        // contract). Guard it: on a synchronous failure, release snap-heavy and fold the
        // error into a completed result like every async failure path does.
        try {
            final CompletableFuture<EnsResolution> result;
            if (m == io.myotis.ens.EnsResolutionRoot.AUTO) {
                result = attemptResolveEns(trimmed, io.myotis.ens.EnsResolutionRoot.FINALIZED)
                        .thenCompose(fin -> {
                            // Verified hit, or an offchain (CCIP) answer already determined
                            // by the gateway (not by which state root we ran against) → done.
                            if (fin.resolution().addressHex() != null || fin.usedOffchain()) {
                                return CompletableFuture.completedFuture(fin.resolution());
                            }
                            // No record at the finalized block (or it couldn't be served) →
                            // fall back to the peer head for a fresher, peer-claimed answer.
                            return attemptResolveEns(trimmed, io.myotis.ens.EnsResolutionRoot.PEER_HEAD)
                                    .thenApply(EnsAttempt::resolution);
                        });
            } else {
                result = attemptResolveEns(trimmed, m).thenApply(EnsAttempt::resolution);
            }
            return result.whenComplete((r, ex) -> conn.exitSnapHeavy());
        } catch (Throwable t) {
            conn.exitSnapHeavy();
            return CompletableFuture.completedFuture(
                    new EnsResolution(trimmed, null, -1, false, unwrap(t)));
        }
    }

    /** One resolution attempt against {@code root}. Never throws (folds every failure
     *  into an {@link EnsAttempt} so {@link #resolveEns}'s AUTO fallback can compose). */
    private CompletableFuture<EnsAttempt> attemptResolveEns(
            String trimmed, io.myotis.ens.EnsResolutionRoot root) {
        // prepareEnsCall is blocking (peer-head probing) — run it on the EVM pool, never
        // the caller's thread, so this is UI-thread-safe. The probe and the EVM execution
        // that follows share the pool, keeping the pinned-peer oracle contention-free.
        return CompletableFuture.<RpcCallContext>supplyAsync(() -> {
            try {
                return prepareEnsCall(root);
            } catch (Exception e) {
                throw new java.util.concurrent.CompletionException(e);
            }
        }, evmPool).thenCompose(call -> {
            final boolean verified = call.beaconVerified();
            return call.resolver().resolveAddress(trimmed, call.blockCtx())
                    .orTimeout(ENS_TIMEOUT_SEC, TimeUnit.SECONDS)
                    .handle((opt, ex) -> {
                        final boolean usedOffchain = call.offchainExecutor().usedOffchain();
                        if (ex != null) {
                            log.info("[ens] resolveAddress failed for " + trimmed
                                    + ": " + unwrap(ex));
                            return new EnsAttempt(new EnsResolution(
                                    trimmed, null, call.blockNumber(), verified, unwrap(ex)),
                                    usedOffchain);
                        }
                        if (opt == null || opt.isEmpty()) {
                            return new EnsAttempt(new EnsResolution(trimmed, null,
                                    call.blockNumber(), verified, "name does not resolve"),
                                    usedOffchain);
                        }
                        return new EnsAttempt(new EnsResolution(
                                trimmed, opt.get().toHex(), call.blockNumber(), verified, null),
                                usedOffchain);
                    });
        }).exceptionally(ex -> {
            // Only prepareEnsCall reaches here. FINALIZED can legitimately fail (no
            // finalized header yet, or no snap peer retains it) — return a null-address
            // result so AUTO can fall back. Peel the CompletionException wrapper.
            Throwable cause = (ex instanceof java.util.concurrent.CompletionException
                    && ex.getCause() != null) ? ex.getCause() : ex;
            return new EnsAttempt(
                    new EnsResolution(trimmed, null, -1,
                            root == io.myotis.ens.EnsResolutionRoot.FINALIZED, unwrap(cause)),
                    false);
        });
    }

    // ---------------------------------------------------------------------
    // Shared anchored-head context resolution
    // ---------------------------------------------------------------------

    /** Only fresh-head tags are served verified for now; others → error. */
    private static boolean isLatestTag(String block) {
        return block == null || block.isEmpty()
                || block.equals("latest") || block.equals("pending");
    }

    /**
     * The shared beacon-anchored head context for "latest"-ish reads, or null
     * (→ router errors, logged). Every verified RPC read/call resolves the head
     * HERE so the head is anchored to the beacon-finalized root once per {@link
     * #RPC_HEAD_TTL_MS} window and reused — instead of each call independently
     * re-fetching a head + re-running the headerChain anchor (the slow, fragile
     * step that produced the high fallback rate). The context's stateRoot
     * is beacon-anchored, so reads against its {@code oracle} stay fully verified.
     */
    private RpcCallContext verifiedHeadFor(String block) {
        // Resolve the requested block. Latest-ish tags (and safe/finalized, which we
        // don't track separately) serve the anchored head. A specific block NUMBER is
        // served from the anchored head iff it's within RPC_BLOCK_NUM_TOLERANCE of it:
        // we can only serve the head's snap state, but wallets (MetaMask) pin reads to
        // the just-fetched latest number, which is at/near the head. Without this every
        // number-pinned eth_getBalance/eth_call was rejected instantly (the empty-list bug).
        long requestedNum = -1; // -1 = latest-ish
        if (!isLatestTag(block)) {
            if (!"safe".equals(block) && !"finalized".equals(block)) {
                try {
                    requestedNum = Long.decode(block);
                } catch (Exception e) {
                    log.info("[rpc] unsupported block tag '" + block + "' -> not served");
                    return null;
                }
                if (requestedNum < 0) return null;
            }
        }
        // Pinned-number fast path: reuse the context already frozen to this number so
        // its (fixed) stateRoot lets the StateProofCache accumulate across the wallet's
        // minutes-long retries instead of resetting every time the head rebuilds.
        if (requestedNum >= 0) {
            HeadWithTimestamp frozen = pinnedHeadByNumber.get(requestedNum);
            // State-read reuse bound: a frozen root older than a few slots is pruned by
            // snap peers (StateUnavailable). Cap reuse tight so retries on a pinned
            // number rebuild against a servable root rather than re-pay a 30s rotation on
            // a dead one — the StateProofCache still accumulates within the window.
            if (frozen != null && clock.elapsedMillis() - frozen.builtAtMs()
                    < RPC_STATE_HEAD_MAX_STALE_MS) {
                return frozen.head();
            }
        }
        RpcCallContext ctx = anchoredHeadOrWait(RPC_STATE_HEAD_MAX_STALE_MS);
        if (ctx == null) return null;
        if (requestedNum >= 0) {
            // A pinned number means "the latest block I saw" — wallets fetch
            // eth_blockNumber (our beacon OPTIMISTIC head) and pin the very next reads
            // to it. The serving context can legitimately sit behind that number: the
            // finalized fallback is ~2 epochs older, a snap peer's head a few blocks.
            // So accept anything between the context and the optimistic head (+slack):
            // those reads get the same verified state a "latest" call would get from
            // this context — rejecting them just because the context lags the chain
            // turned every number-pinned call into an instant error whenever snap fell
            // back to finalized (MetaMask: empty asset list, stuck confirm screen).
            // Numbers BELOW the context keep the strict tolerance: the caller asked
            // for genuinely older state, which this context cannot represent.
            BeaconSyncState bss = beaconSyncState;
            long optimistic = bss != null ? bss.getOptimisticBlockNumber() : 0;
            long upperBound = Math.max(ctx.blockNumber(), optimistic) + RPC_BLOCK_NUM_TOLERANCE;
            long lowerBound = ctx.blockNumber() - RPC_BLOCK_NUM_LAG_TOLERANCE;
            if (requestedNum < lowerBound || requestedNum > upperBound) {
                log.info("[rpc] requested block " + requestedNum + " outside servable ["
                        + lowerBound + ".." + upperBound + "] (ctx=" + ctx.blockNumber()
                        + ", optimistic=" + optimistic + ") -> not served");
                return null;
            }
            // Freeze this context for the number so every subsequent retry pinned to it
            // resolves the SAME root (cache accumulation). First pin wins; it ages out.
            // On a concurrent first-read race the putIfAbsent loser must serve the
            // WINNER's context, not its own — otherwise two contexts with different
            // stateRoots briefly serve the same pinned number, splitting the
            // StateProofCache across roots for that block.
            HeadWithTimestamp existing = pinnedHeadByNumber.putIfAbsent(requestedNum,
                    new HeadWithTimestamp(ctx, clock.elapsedMillis()));
            if (existing != null) {
                return existing.head();
            }
        }
        return ctx;
    }

    /** Resolve the shared beacon-anchored head context, waiting briefly for a fresh
     *  build if none is available. Returns null if no verified head can be produced.
     *  {@code maxStaleMs} caps how old a last-resort stale head may be: STATE-execution
     *  callers pass the tight {@link #RPC_STATE_HEAD_MAX_STALE_MS} (the root must still
     *  be snap-servable); header-only callers pass the long {@link
     *  #RPC_HEAD_SERVE_STALE_MAX_MS}. */
    private RpcCallContext anchoredHeadOrWait(long maxStaleMs) {
        // Fast path: serve the last good head if it's recent enough. It stays
        // beacon-anchored; a few seconds stale beats erroring, and it bridges the
        // brief windows where a TTL-expiry rebuild can't yet anchor the just-
        // advanced head. The background warmer keeps this fresh (~5-15s).
        HeadWithTimestamp good = lastGoodHead.get();
        if (good != null
                && clock.elapsedMillis() - good.builtAtMs() < RPC_HEAD_MAX_STALE_MS) {
            return good.head();
        }
        // No usable head (cold start / sustained outage): wait for a build before
        // giving up. The deadline is adaptive — recomputed each iteration: while an
        // anchored-head build is actually in flight (warmer or a prior read), ride it
        // up to RPC_HEAD_BUILD_WAIT_MS so a read arriving mid-build returns verified-
        // but-slow; with no build possible (no snap peer) it falls back at the short
        // RPC_HEAD_WAIT_MS. Each build attempt is capped at the remaining time.
        long start = clock.elapsedMillis();
        Exception last = null;
        while (true) {
            long now = clock.elapsedMillis();
            long deadline = start + (headBuildInFlight() ? RPC_HEAD_BUILD_WAIT_MS : RPC_HEAD_WAIT_MS);
            long remainingMs = deadline - now;
            if (remainingMs <= 0) break;
            try {
                return verifiedHeadCallContext(remainingMs, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                last = e;
                HeadWithTimestamp g = lastGoodHead.get();   // a concurrent build may have just succeeded
                if (g != null && clock.elapsedMillis() - g.builtAtMs() < RPC_HEAD_MAX_STALE_MS) {
                    return g.head();
                }
                try { Thread.sleep(300); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        // Last resort: a stale-but-anchored head beats erroring. Its verification
        // hasn't expired — it's just old — and verifiedHeadFor's pinned-number
        // bounds still reject pins this context genuinely can't represent. The
        // warmer keeps retrying fresh builds in the background regardless.
        HeadWithTimestamp stale = lastGoodHead.get();
        if (stale != null && clock.elapsedMillis() - stale.builtAtMs() < maxStaleMs) {
            log.info("[rpc] serving STALE anchored head (block #"
                    + stale.head().blockNumber() + ", "
                    + (clock.elapsedMillis() - stale.builtAtMs()) / 1000
                    + "s old, cap " + maxStaleMs / 1000 + "s) — rebuild failing: "
                    + (last != null ? unwrap(last) : "timeout"));
            return stale.head();
        }
        log.info("[rpc] no verified head after "
                + (clock.elapsedMillis() - start) + "ms -> error: "
                + (last != null ? unwrap(last) : "timeout"));
        return null;
    }

    /** Age (ms) of the last successfully-built anchored head, or {@code Long.MAX_VALUE}
     *  if none has been built yet. Used to hold nonce serving to a tighter freshness
     *  bound than the general stale-serve horizon. */
    private long headAgeMs() {
        HeadWithTimestamp good = lastGoodHead.get();
        return good == null ? Long.MAX_VALUE : clock.elapsedMillis() - good.builtAtMs();
    }

    /** Public readiness probe: age (ms) of the last verified head, {@code Long.MAX_VALUE}
     *  if none built yet. A host UI surfaces "warmed up" from this — a recent head means
     *  wallet reads/calls (eth_call, balances, the confirm-screen simulation) will serve
     *  rather than hit the "no verified head" path. This is the third readiness gate
     *  beyond beacon-SYNCED and snap-peers-connected, and the one nothing else exposes. */
    public long verifiedHeadAgeMs() {
        return headAgeMs();
    }

    /** True while an anchored-head build is in flight (warmer or a prior read), so a
     *  waiting read can ride it instead of erroring early. */
    private boolean headBuildInFlight() {
        CompletableFuture<RpcCallContext> f;
        synchronized (rpcCallCtxLock) { f = rpcCallCtx; }
        return f != null && !f.isDone();
    }

    /** Build (or reuse within {@link #RPC_HEAD_TTL_MS}) a snap-peer head context
     *  whose state root is anchored back to the beacon-finalized root, so reads +
     *  EVM calls run against cryptographically-verified state. Blocking. */
    /** Full-budget variant for the background warmer. */
    private RpcCallContext verifiedHeadCallContext() throws Exception {
        return verifiedHeadCallContext(RPC_ACCOUNT_TIMEOUT_SEC * 1000L, TimeUnit.MILLISECONDS);
    }

    private RpcCallContext verifiedHeadCallContext(long timeout, TimeUnit unit) throws Exception {
        CompletableFuture<RpcCallContext> future;
        boolean build = false;
        synchronized (rpcCallCtxLock) {
            long now = clock.elapsedMillis();
            // Reuse an in-flight build (regardless of age — never start a parallel
            // one) or a completed-OK result still within the TTL.
            if (rpcCallCtx != null
                    && (!rpcCallCtx.isDone()
                        || (!rpcCallCtx.isCompletedExceptionally() && now - rpcCallCtxAtMs < RPC_HEAD_TTL_MS))) {
                future = rpcCallCtx;
            } else {
                future = new CompletableFuture<>();
                rpcCallCtx = future;
                rpcCallCtxAtMs = now;
                build = true;
            }
        }
        // Build on a background thread so the caller only blocks up to `timeout`
        // (honoring verifiedHeadFor's bounded wait even when this call triggers the
        // build). A burst of concurrent reads shares the one builder's future.
        if (build) {
            final CompletableFuture<RpcCallContext> f = future;
            try {
                headBuildPool.execute(() -> {
                    try {
                        RpcCallContext ctx = buildAnchoredHead();
                        lastGoodHead.set(new HeadWithTimestamp(ctx, clock.elapsedMillis()));
                        f.complete(ctx);
                        // After the future is completed (readers unblocked), prime the
                        // confirm-critical contracts at this root so a wallet's first
                        // confirm-screen calls start from warm state — see the method doc.
                        primeConfirmContracts(ctx);
                    } catch (Throwable t) {
                        f.completeExceptionally(t);
                        synchronized (rpcCallCtxLock) {
                            if (rpcCallCtx == f) rpcCallCtx = null;   // let the next call retry
                        }
                    }
                });
            } catch (java.util.concurrent.RejectedExecutionException rex) {  // shutting down
                f.completeExceptionally(rex);
                synchronized (rpcCallCtxLock) { if (rpcCallCtx == f) rpcCallCtx = null; }
            }
        }
        try {
            return future.get(timeout, unit);   // build continues in the background on timeout
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw (cause instanceof Exception) ? (Exception) cause : new Exception(cause);
        }
    }

    /**
     * Build a fully beacon-verified head context, preferring the freshest
     * snap-servable head (PEER_HEAD, anchored to finalized via headerChain) and
     * falling back to the beacon-finalized root (verified directly by the light
     * client, ~12 min stale) when no peer serves a fresh head. Both paths are
     * cryptographically anchored to the beacon chain — so under poor snap
     * conditions reads stay verified (just staler) instead of all erroring.
     */
    private RpcCallContext buildAnchoredHead() throws Exception {
        try {
            RpcCallContext ctx = prepareEnsCall(io.myotis.ens.EnsResolutionRoot.PEER_HEAD);
            if (anchorHeadToBeacon(ctx.blockNumber(), ctx.blockCtx().stateRoot())) {
                // anchorHeadToBeacon ran the full headerChain verify from beacon-finalized
                // to this head, so it IS cryptographically anchored now — but prepareEnsCall
                // initialized the PEER_HEAD flag to false. Reflect the verification in the
                // returned context so beaconVerified() is true (eth_getBlockByNumber /
                // eth_getTransactionReceipt gate on it; without this they reject the freshly
                // anchored head and only the finalized fallback ever passed).
                return new RpcCallContext(ctx.resolver(), ctx.blockCtx(), ctx.blockNumber(),
                        true, ctx.offchainExecutor(), ctx.oracle());
            }
            log.info("[rpc] fresh head not beacon-anchored (block #"
                    + ctx.blockNumber() + "); falling back to finalized");
        } catch (Exception headEx) {
            log.info("[rpc] no snap-servable fresh head (" + unwrap(headEx)
                    + "); falling back to finalized");
        }
        // Fallback: the beacon-finalized execution root, verified directly by the
        // light client (no headerChain needed). Throws if no peer retains it.
        return prepareEnsCall(io.myotis.ens.EnsResolutionRoot.FINALIZED);
    }

    /**
     * Prime the confirm-critical contracts at a freshly-built head: fetch each
     * account record (banked per-root in the {@link #stateProofCache}) and its
     * bytecode (banked forever in the {@link #bytecodeCache} — code is keyed by
     * hash, so this is one fetch per contract per process lifetime). Without this,
     * the FIRST confirm after a node restart paid the cold fetch waves inside the
     * wallet's own 30s call deadline and timed out (observed live: the Multicall3
     * simulation and ENS resolver probes erroring at 30s on a cold root while warm
     * runs take 1-3s). Runs on the head-build thread after the context future has
     * completed, so readers are never delayed by it. Best-effort: failures just
     * mean the next real call pays the (retryable) cold cost as before.
     */
    private void primeConfirmContracts(RpcCallContext ctx) {
        try {
            byte[] root = ctx.blockCtx().stateRoot();
            List<CompletableFuture<?>> warms = new ArrayList<>();
            for (String hex : CONFIRM_WARM_CONTRACTS) {
                io.myotis.evm.Address addr = io.myotis.evm.Address.fromHex(hex);
                warms.add(ctx.oracle().fetchAccount(root, addr)
                        .thenCompose(acct -> ctx.oracle().fetchBytecode(acct.codeHash()))
                        .exceptionally(t -> null));   // best-effort per contract
            }
            CompletableFuture.allOf(warms.toArray(new CompletableFuture<?>[0]))
                    .get(20, TimeUnit.SECONDS);
            log.info("[rpc] primed " + CONFIRM_WARM_CONTRACTS.length
                    + " confirm-critical contract(s) at block #" + ctx.blockNumber());
        } catch (Throwable t) {
            log.info("[rpc] confirm-contract prime skipped: " + unwrap(t));
        }
    }

    /** True iff {@code peerStateRoot} at {@code peerBlock} chains back to the
     *  beacon-finalized execution root (same headerChain method as get-account). */
    private boolean anchorHeadToBeacon(long peerBlock, byte[] peerStateRoot) throws Exception {
        BeaconLightClient blc = beaconLightClient;
        RLPxConnector conn = connector;
        if (blc == null || conn == null) return false;
        com.jaeckel.ethp2p.consensus.types.LightClientHeader fin =
                blc.getStore().getFinalizedHeader();
        if (fin == null) return false;
        com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader exec = fin.execution();
        if (exec.blockNumber() == peerBlock) {
            // Head is exactly the finalized block — roots must match directly.
            return java.util.Arrays.equals(exec.stateRoot(), peerStateRoot);
        }
        return verifyHeaderChainBatched(conn, exec.blockNumber(), peerBlock,
                exec.stateRoot(), peerStateRoot)
                .get(HEADER_CHAIN_TIMEOUT_SEC + 5, TimeUnit.SECONDS);
    }

    /**
     * Build the EVM/ENS stack. The {@code root} selects which state the
     * contracts run against — see {@link io.myotis.ens.EnsResolutionRoot}:
     * FINALIZED anchors to the light client's beacon-verified finalized state
     * (verified root, no head probe); PEER_HEAD uses a snap peer's latest head
     * (freshest, anchored separately by {@link #anchorHeadToBeacon}). Mirrors
     * {@code CommandHandler.prepareEnsCall} / {@code NodeService.prepareEnsCall}.
     * Blocking — never call on a caller-facing thread without a budget.
     */
    private RpcCallContext prepareEnsCall(io.myotis.ens.EnsResolutionRoot root) throws Exception {
        RLPxConnector conn = connector;
        if (conn == null) throw new IllegalStateException("node not running");
        List<EthHandler> snapPeers = conn.activeSnapHandlers();
        if (snapPeers.isEmpty()) {
            throw new IllegalStateException("No active peer with snap/1 support");
        }

        io.myotis.evm.BlockContext blockCtx;
        long blockNumber;
        boolean verified;
        EthHandler pinned;

        if (root == io.myotis.ens.EnsResolutionRoot.FINALIZED) {
            // Resolve against the beacon-verified finalized execution header — the
            // resulting state is anchored to a beacon-attested root (snap proofs
            // verify against it). ~12 min stale (finality lag). A snap peer must
            // still retain that block's state, which they often DON'T (Geth prunes
            // trie state beyond ~128 blocks and serves snap from a flat layer
            // lagging the head). So we don't blindly pin a peer — we probe each one
            // for the finalized root and pin the first that actually serves it. If
            // none do, we throw and the caller falls back / errors.
            BeaconLightClient blc = beaconLightClient;
            if (blc == null) throw new IllegalStateException("beacon light client not running");
            com.jaeckel.ethp2p.consensus.types.LightClientHeader fin = blc.getStore().getFinalizedHeader();
            if (fin == null) throw new IllegalStateException("no beacon-verified finalized header yet");
            com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader exec = fin.execution();
            Bytes32 finRoot = Bytes32.wrap(exec.stateRoot());
            pinned = firstPeerServing(snapPeers, finRoot);
            if (pinned == null) {
                throw new IllegalStateException(
                        "no snap peer retains the beacon-finalized state (block #"
                        + exec.blockNumber() + ")");
            }
            blockCtx = new io.myotis.evm.BlockContext(
                    exec.stateRoot(),
                    exec.blockNumber(),
                    exec.timestamp(),
                    leUint256ToBigInteger(exec.baseFeePerGas()),
                    io.myotis.evm.Address.of(exec.feeRecipient()),
                    exec.prevRandao(),
                    java.math.BigInteger.valueOf(conn.getNetwork().networkId()),
                    exec.gasLimit());
            blockNumber = exec.blockNumber();
            verified = true;
        } else {
            // PEER_HEAD: each peer's bleeding-edge head root is frequently NOT yet
            // snap-servable (the flat state lags the head). Walk every peer: fetch
            // its fresh head, then PROBE that the peer actually serves a snap
            // account at that root before pinning it — the same resilience
            // get-account gets by retrying across peers. The first peer that passes
            // both is pinned for the whole context (one consistent root).
            final long minHead = conn.getNetwork().minSensibleHeadBlock();
            // Live staleness floor: a peer whose head is BEHIND the beacon-finalized
            // exec block can never anchor (anchorHeadToBeacon verifies the chain
            // finalized→head, and finality has already passed it) — yet such a peer
            // happily snap-serves its frozen root and can win the probe race below,
            // forcing every build into the finalized fallback while fresh-headed
            // peers sit connected. Observed on-device: two peers frozen at the same
            // head for 5+ min starved number-pinned reads.
            long finalizedFloor = -1;
            BeaconLightClient blcFloor = beaconLightClient;
            if (blcFloor != null) {
                com.jaeckel.ethp2p.consensus.types.LightClientHeader finHdr =
                        blcFloor.getStore().getFinalizedHeader();
                if (finHdr != null) finalizedFloor = finHdr.execution().blockNumber();
            }
            final long headFloor = Math.max(minHead, finalizedFloor);
            // Probe every ready snap peer CONCURRENTLY — fetch its fresh head, then
            // probe that it snap-serves that head root — and award the FIRST to
            // qualify. The old serial walk paid each unresponsive peer's timeout in
            // turn (the dominant build cost, and a frequent fallback trigger);
            // running the probes in parallel collapses that to ~one round-trip.
            List<CompletableFuture<PeerHead>> probes = new ArrayList<>();
            for (EthHandler peer : snapPeers) {
                if (!peer.isReady() || peer.isSnapServingFailed()) continue;
                CompletableFuture<BlockHeader> headFut = peer.requestFreshHeadHeaderAsync();
                if (headFut == null) continue;
                probes.add(headFut.thenCompose(fresh -> {
                    if (fresh.number < headFloor) {
                        throw new java.util.concurrent.CompletionException(
                                new IllegalStateException("stale head #" + fresh.number
                                        + " (< floor #" + headFloor + ")"));
                    }
                    // servesRoot, but async: the peer must return a non-empty proof
                    // for the probe account at its head root.
                    return peer.requestAccountByHashAsync(SNAP_PROBE_ACCOUNT_HASH, fresh.stateRoot)
                            .thenApply(probe -> {
                                if (probe.proof() == null || probe.proof().isEmpty()) {
                                    throw new java.util.concurrent.CompletionException(
                                            new IllegalStateException(
                                                    "peer does not snap-serve head root (block #"
                                                            + fresh.number + ")"));
                                }
                                return new PeerHead(peer, fresh);
                            });
                }));
            }
            PeerHead chosen;
            try {
                chosen = firstSuccess(probes, PEER_PROBE_TIMEOUT_SEC);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "No snap peer served a fresh head root (" + unwrap(e) + ")");
            }
            EthHandler headPeer = chosen.peer();
            BlockHeader header = chosen.header();
            blockCtx = new io.myotis.evm.BlockContext(
                    header.stateRoot.toArrayUnsafe(),
                    header.number,
                    header.timestamp,
                    header.baseFeePerGas,
                    io.myotis.evm.Address.of(header.beneficiary.toArrayUnsafe()),
                    header.mixHashOrPrevRandao.toArrayUnsafe(),
                    java.math.BigInteger.valueOf(conn.getNetwork().networkId()),
                    header.gasLimit);
            blockNumber = header.number;
            verified = false;
            pinned = headPeer;
        }

        // Snap requests carry the stateRoot explicitly, so ANY connected snap peer
        // that retains blockCtx's trie can serve them — not just the one we probed.
        // The oracle retries across peers (peerSupplier.get() per attempt); rotate the
        // supplier so a peer that times out fails over to others instead of funnelling
        // all retries into one dead peer (every eth_call against that context then hit
        // the 30s timeout while OTHER peers held the same state). The probed peer is
        // tried first (known to serve this root); subsequent attempts round-robin the
        // rest of the ready snap set.
        final EthHandler probedPeer = pinned;
        final RLPxConnector oracleConn = conn;
        final java.util.concurrent.atomic.AtomicInteger rotation =
                new java.util.concurrent.atomic.AtomicInteger();
        // Peers that returned an empty proof / no-state for THIS head's stateRoot — they
        // don't retain its trie (a chunk of the pool lags the head). Deny them for this
        // context so the rotation converges on peers that actually serve the root instead
        // of re-handing out empty-proof peers and exhausting every fetch's retries (the
        // cause of heavy-multicall eth_call 30s failures). Per-context; cleared next build.
        final java.util.Set<EthHandler> rootDenied =
                java.util.concurrent.ConcurrentHashMap.newKeySet();
        // Persisted EL-cache quality signal (via the injected SnapQualitySink): a
        // non-empty proof confirms the peer as snap-serving (dialed first on
        // restart); the same root-unavailable event that deprioritizes it for this
        // head also feeds a failure verdict so repeat hangers are deprioritized
        // across restarts.
        io.myotis.evm.world.SnapBackedStateOracle oracle =
                new io.myotis.evm.world.SnapBackedStateOracle(
                        () -> {
                            int n = rotation.getAndIncrement();
                            if (n == 0 && probedPeer.isReady() && !probedPeer.isSnapServingFailed()
                                    && !rootDenied.contains(probedPeer)) {
                                final EthHandler pp = probedPeer;
                                return new EthHandlerSnapPeer(
                                        pp,
                                        () -> { rootDenied.add(pp); recordSnapQuality(pp, false); },
                                        () -> recordSnapQuality(pp, true));
                            }
                            // activeSnapHandlers() already returns only ready, snap-negotiated,
                            // non-failed peers; drop the ones denied for this root.
                            List<EthHandler> ready = new ArrayList<>();
                            for (EthHandler p : oracleConn.activeSnapHandlers()) {
                                if (!rootDenied.contains(p)) ready.add(p);
                            }
                            if (ready.isEmpty()) return null;
                            final EthHandler chosen =
                                    ready.get(Math.floorMod(n, ready.size()));
                            return new EthHandlerSnapPeer(
                                    chosen,
                                    () -> { rootDenied.add(chosen); recordSnapQuality(chosen, false); },
                                    () -> recordSnapQuality(chosen, true));
                        },
                        bytecodeCache,
                        SNAP_ORACLE_MAX_ATTEMPTS,
                        stateProofCache);
        io.myotis.evm.DefaultEvmExecutor base =
                new io.myotis.evm.DefaultEvmExecutor(oracle, bytecodeCache, evmPool);
        io.myotis.evm.PrefetchingEvmExecutor prefetching =
                new io.myotis.evm.PrefetchingEvmExecutor(base);
        io.myotis.evm.ccipread.CcipReadHandler ccip =
                new io.myotis.evm.ccipread.CcipReadHandler(ccipGateway);
        io.myotis.evm.CcipReadEvmExecutor executor =
                new io.myotis.evm.CcipReadEvmExecutor(prefetching, ccip);
        io.myotis.ens.EnsResolver resolver =
                io.myotis.ens.EnsResolver.forChainId(executor, conn.getNetwork().networkId());
        return new RpcCallContext(resolver, blockCtx, blockNumber, verified, executor, oracle);
    }

    /** First ready snap peer that returns a non-empty account proof at {@code root},
     *  or null. Probes all peers CONCURRENTLY (same rationale as the PEER_HEAD probe)
     *  and awards the first to serve the root. */
    private EthHandler firstPeerServing(List<EthHandler> peers, Bytes32 root) {
        List<CompletableFuture<EthHandler>> probes = new ArrayList<>();
        for (EthHandler peer : peers) {
            if (!peer.isReady() || peer.isSnapServingFailed()) continue;
            probes.add(peer.requestAccountByHashAsync(SNAP_PROBE_ACCOUNT_HASH, root)
                    .thenApply(probe -> {
                        if (probe.proof() == null || probe.proof().isEmpty()) {
                            throw new java.util.concurrent.CompletionException(
                                    new IllegalStateException("peer does not serve root"));
                        }
                        return peer;
                    }));
        }
        try {
            return firstSuccess(probes, PEER_PROBE_TIMEOUT_SEC);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Resolve to the first future that completes <em>successfully</em> (non-null),
     * ignoring failures; if every future fails, throw the last failure; if none
     * resolves within {@code timeoutSec}, throw {@link java.util.concurrent.TimeoutException}.
     * Hung futures are simply never awaited again — harmless, and bounded by the
     * overall timeout. Used to run the snap-peer head probes in parallel.
     */
    private static <T> T firstSuccess(List<CompletableFuture<T>> futures, long timeoutSec)
            throws Exception {
        if (futures.isEmpty()) throw new IllegalStateException("no ready snap peers");
        CompletableFuture<T> result = new CompletableFuture<>();
        java.util.concurrent.atomic.AtomicInteger remaining =
                new java.util.concurrent.atomic.AtomicInteger(futures.size());
        java.util.concurrent.atomic.AtomicReference<Throwable> lastErr =
                new java.util.concurrent.atomic.AtomicReference<>();
        for (CompletableFuture<T> f : futures) {
            f.whenComplete((v, e) -> {
                if (e == null && v != null) {
                    if (result.complete(v)) {
                        // First winner: cancel the rest so losing probes don't keep
                        // burning CPU/battery/data in the background on mobile.
                        for (CompletableFuture<T> other : futures) {
                            if (other != f) other.cancel(true);
                        }
                    }
                } else {
                    if (e != null) lastErr.set(e);
                    if (remaining.decrementAndGet() == 0) {
                        Throwable le = lastErr.get();
                        result.completeExceptionally(le != null ? le
                                : new IllegalStateException("no peer qualified"));
                    }
                }
            });
        }
        try {
            return result.get(timeoutSec, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException ee) {
            Throwable c = ee.getCause() != null ? ee.getCause() : ee;
            throw (c instanceof Exception) ? (Exception) c : new Exception(c);
        }
    }

    // ---------------------------------------------------------------------
    // Verified reads (eth_call / accounts / code / storage / sendRaw)
    // ---------------------------------------------------------------------

    /** eth_call over the shared anchored head. Returns raw ABI bytes, or null to error. */
    private byte[] rpcCall(byte[] to, byte[] data, String block) {
        // Identify the call up front: target + 4-byte selector + calldata size + block
        // tag. eth_call failures were undiagnosable as "eth_call -> proxy: Timeout" —
        // with hundreds of MetaMask poll variants we need to know WHICH contract/method
        // is being asked for (e.g. its confirm-screen simulation multicall).
        String desc = (to != null && to.length == 20 ? Bytes.wrap(to).toHexString() : "?")
                + " sel=" + (data != null && data.length >= 4
                        ? Bytes.wrap(data, 0, 4).toHexString() : "0x")
                + " dataLen=" + (data == null ? 0 : data.length)
                + " block=" + block;
        RpcCallContext h = verifiedHeadFor(block);
        if (h == null || to == null || to.length != 20) {
            log.info("[rpc] eth_call " + desc + " -> no verified head for block tag");
            return null;
        }
        long t0 = clock.elapsedMillis();
        // Route small calls onto the reserved EVM lane so a confirm screen's tiny
        // probes/simulations never queue behind a ~32KB token-sweep storm. The hint
        // is read synchronously by evmPool when callView's supplyAsync submits on
        // this thread; cleared in finally so the handler thread doesn't leak it.
        boolean smallLane = (data == null || data.length <= EVM_SMALL_CALLDATA_MAX);
        if (smallLane) EVM_SMALL_LANE.set(Boolean.TRUE);
        try {
            byte[] out = h.offchainExecutor()
                    .callView(io.myotis.evm.Address.of(to), data == null ? new byte[0] : data,
                            h.blockCtx())
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            log.info("[rpc] eth_call " + desc + " ok in "
                    + (clock.elapsedMillis() - t0) + "ms");
            return out;
        } catch (Exception e) {
            log.info("[rpc] eth_call " + desc + " -> error after "
                    + (clock.elapsedMillis() - t0) + "ms: "
                    + describeEvmError(e));
            if (isStateUnavailable(e)) evictUnservableHead(h);
            return null;
        } finally {
            if (smallLane) EVM_SMALL_LANE.remove();
        }
    }

    /** Verified account record at the shared anchored head, or null (→ error). The
     *  oracle hash-verifies the account against the anchored stateRoot (storageRoot
     *  + codeHash come from the proven trie leaf), and verifies account ABSENCE via
     *  an exclusion proof — so a missing account is a verified zero, not an error. */
    private io.myotis.evm.world.AccountState rpcAccountState(byte[] address, String block) {
        RpcCallContext h = verifiedHeadFor(block);
        if (h == null || address == null || address.length != 20) return null;
        try {
            return h.oracle()
                    .fetchAccount(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(address))
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.info("[rpc] account read -> error: " + unwrap(e));
            if (isStateUnavailable(e)) evictUnservableHead(h);
            return null;
        }
    }

    /** eth_getCode: bytecode verified (keccak256(code)==proven codeHash), or null to error. */
    private byte[] rpcCode(byte[] address, String block) {
        RpcCallContext h = verifiedHeadFor(block);
        if (h == null || address == null || address.length != 20) return null;
        try {
            byte[] codeHash = h.oracle()
                    .fetchAccount(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(address))
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS).codeHash();
            if (java.util.Arrays.equals(codeHash, EMPTY_CODE_HASH)) return new byte[0];  // EOA
            return h.oracle().fetchBytecode(codeHash).get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.info("[rpc] eth_getCode -> error: " + unwrap(e));
            if (isStateUnavailable(e)) evictUnservableHead(h);
            return null;
        }
    }

    /** eth_getStorageAt: the 32-byte value at {@code slot32}, proven against the
     *  account's verified storageRoot (absent slots verify as zero via the oracle's
     *  exclusion proof). Null → error. */
    private byte[] rpcStorageAt(byte[] address, byte[] slot32, String block) {
        RpcCallContext h = verifiedHeadFor(block);
        if (h == null || address == null || address.length != 20
                || slot32 == null || slot32.length != 32) return null;
        try {
            java.math.BigInteger value = h.oracle()
                    .fetchStorage(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(address),
                            new java.math.BigInteger(1, slot32))
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            return word32(value);
        } catch (Exception e) {
            log.info("[rpc] eth_getStorageAt -> error: " + unwrap(e));
            if (isStateUnavailable(e)) evictUnservableHead(h);
            return null;
        }
    }

    /** True iff the throwable chain carries the oracle's "no connected snap peer serves
     *  this stateRoot" verdict ({@link io.myotis.evm.EvmExecutionError.StateUnavailable}).
     *  That root has been pruned out from under the cached context; the wrapper
     *  ({@link #evictUnservableHead}) drops it so the next read rebuilds. */
    private static boolean isStateUnavailable(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof io.myotis.evm.EvmExecutionException ee
                    && ee.error() instanceof io.myotis.evm.EvmExecutionError.StateUnavailable) {
                return true;
            }
        }
        return false;
    }

    /** Evict a head context whose stateRoot no connected snap peer can serve, so the
     *  next state read rebuilds against a fresh, snap-servable root instead of re-paying
     *  a full 30s oracle rotation on the same dead root (the StateUnavailable storm).
     *  Drops it from both caches — the per-number pin and the shared last-good head.
     *  Trust is untouched: this only invalidates a freshness cache, never relaxes
     *  verification (every served root is still beacon-anchored and proof-checked). */
    private void evictUnservableHead(RpcCallContext doomed) {
        if (doomed == null) return;
        pinnedHeadByNumber.values().removeIf(hw -> hw.head() == doomed);
        boolean evicted = false;
        // Compare-and-set, NOT a plain null: only clear lastGoodHead if it still holds
        // the doomed context. A bare `lastGoodHead = null` would race the warmer/builder
        // — if it set a FRESH head between our read and write, we'd wipe a perfectly good
        // head and force a needless rebuild. CAS nulls only the doomed one.
        HeadWithTimestamp g = lastGoodHead.get();
        if (g != null && g.head() == doomed && lastGoodHead.compareAndSet(g, null)) {
            evicted = true;
        }
        // Also drop the build-dedup future if it completed with this doomed context:
        // verifiedHeadCallContext reuses a completed-OK rpcCallCtx for up to
        // RPC_HEAD_TTL_MS (12s), so without this the very next read (which calls
        // anchoredHeadOrWait -> verifiedHeadCallContext after we nulled lastGoodHead)
        // would be handed the same dead context straight back and skip the rebuild.
        synchronized (rpcCallCtxLock) {
            if (rpcCallCtx != null && rpcCallCtx.isDone()
                    && !rpcCallCtx.isCompletedExceptionally()
                    && rpcCallCtx.getNow(null) == doomed) {
                rpcCallCtx = null;
                evicted = true;
            }
        }
        if (evicted) {
            log.info("[rpc] evicted unservable head #" + doomed.blockNumber()
                    + " (no snap peer retains its state) — will rebuild");
        }
    }

    /** eth_sendRawTransaction: gossip the user-signed tx to peers; return its hash
     *  (keccak256 of the raw bytes), or null if no peer took it. Myotis never signs
     *  or originates a tx — this only relays bytes the user submitted. */
    private byte[] rpcSendRawTransaction(byte[] rawTx) {
        RLPxConnector conn = connector;
        if (conn == null || rawTx == null || rawTx.length == 0) return null;
        try {
            int sent = conn.broadcastTransaction(rawTx);
            if (sent == 0) return null;   // no peer reached → let the router report it
            byte[] txHash = Hash.keccak256(Bytes.wrap(rawTx)).toArrayUnsafe();
            sentTxCache.put(Bytes.wrap(txHash).toHexString(), rawTx.clone());
            log.info("[rpc] eth_sendRawTransaction broadcast to " + sent
                    + " peer(s), hash=" + Bytes.wrap(txHash).toHexString());
            return txHash;
        } catch (Exception e) {
            log.info("[rpc] eth_sendRawTransaction failed: " + unwrap(e));
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Verified tx / receipt / block serving
    // ---------------------------------------------------------------------

    /**
     * eth_getTransactionByHash. Scans the recent beacon-verified block window for the tx
     * (body verified vs transactionsRoot); if found, returns it with block context. If not
     * yet mined but this node broadcast it, returns it as pending (blockNumber null) from
     * the sent-tx cache. "null" for a verified-unknown tx; Java null when not verifiable.
     */
    private String rpcGetTransactionByHash(byte[] txHash) {
        RLPxConnector conn = connector;
        if (conn == null || txHash == null || txHash.length != 32) return null;
        Bytes32 want = Bytes32.wrap(txHash);
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) {
                // Can't verify chain inclusion right now — but if it's our own just-sent tx
                // we can still honestly answer "pending" from the signed bytes we hold.
                byte[] ourRaw = sentTxCache.get(want.toHexString());
                return ourRaw != null ? buildTxJson(ourRaw, want, null, -1, -1) : null;
            }
            long headNum = anchor.number();
            int count = (int) Math.min(RECEIPT_LOOKBACK_BLOCKS, headNum + 1);
            long start = headNum - count + 1;
            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(start, count)
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!anchor.anchors(window)) return null;

            List<CompletableFuture<List<BlockBodiesMessage.BlockBody>>> bodyFutures =
                    new ArrayList<>(window.size());
            for (BlockHeadersMessage.VerifiedHeader vh : window) {
                bodyFutures.add(conn.requestBlockBodies(vh.hash()));
            }
            for (int hi = window.size() - 1; hi >= 0; hi--) {
                BlockHeader h = window.get(hi).header();
                Bytes32 blockHash = window.get(hi).hash();
                List<BlockBodiesMessage.BlockBody> bodies;
                try {
                    bodies = bodyFutures.get(hi).get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
                } catch (Exception e) { continue; }
                if (bodies.isEmpty()) continue;
                List<Bytes> txs = bodies.get(0).transactions();
                if (!OrderedTrieRoot.verify(txs, h.transactionsRoot)) continue;
                for (int i = 0; i < txs.size(); i++) {
                    if (Hash.keccak256(txs.get(i)).equals(want)) {
                        log.info("[rpc] eth_getTransactionByHash found in block #"
                                + h.number + " index " + i);
                        return buildTxJson(txs.get(i).toArrayUnsafe(), want, blockHash, h.number, i);
                    }
                }
            }
            // Verified head + anchored window, not in it. If it's our own broadcast, it's
            // pending; otherwise a verified "unknown tx".
            byte[] ourRaw = sentTxCache.get(want.toHexString());
            return ourRaw != null ? buildTxJson(ourRaw, want, null, -1, -1) : "null";
        } catch (Exception e) {
            log.info("[rpc] eth_getTransactionByHash failed: " + unwrap(e));
            return null;
        }
    }

    /** Build the eth_getTransactionByHash JSON. blockHash null + blockNum/index < 0 = pending.
     *  Returns Java null (NOT the literal "null") when the tx can't be decoded: the tx WAS
     *  found/held, so this is "can't render it verified" → the caller errors, never a
     *  misleading "tx not found". */
    private static String buildTxJson(byte[] rawTx, Bytes32 txHash,
                                      Bytes32 blockHash, long blockNum, int index) {
        com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.DecodedTx t =
                com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.decode(Bytes.wrap(rawTx));
        if (t == null) return null; // unrenderable tx type — can't-serve, not unknown-tx
        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"hash\":\"").append(txHash.toHexString()).append("\"");
        if (blockHash != null) {
            sb.append(",\"blockHash\":\"").append(blockHash.toHexString()).append("\"");
            sb.append(",\"blockNumber\":\"").append(hexQuantity(blockNum)).append("\"");
            sb.append(",\"transactionIndex\":\"").append(hexQuantity(index)).append("\"");
        } else {
            sb.append(",\"blockHash\":null,\"blockNumber\":null,\"transactionIndex\":null");
        }
        sb.append(",\"type\":\"").append(hexQuantity(t.type())).append("\"");
        if (t.chainId() != null) sb.append(",\"chainId\":\"").append(hexQuantity(t.chainId())).append("\"");
        sb.append(",\"nonce\":\"").append(hexQuantity(t.nonce())).append("\"");
        if (t.from() != null) sb.append(",\"from\":\"").append(t.from().toHexString()).append("\"");
        if (!t.to().isEmpty()) sb.append(",\"to\":\"").append(t.to().toHexString()).append("\"");
        else sb.append(",\"to\":null");
        sb.append(",\"value\":\"0x").append(t.value().toString(16)).append("\"");
        sb.append(",\"gas\":\"").append(hexQuantity(t.gas())).append("\"");
        if (t.gasPrice() != null) {
            sb.append(",\"gasPrice\":\"0x").append(t.gasPrice().toString(16)).append("\"");
        }
        if (t.maxFeePerGas() != null) {
            sb.append(",\"maxFeePerGas\":\"0x").append(t.maxFeePerGas().toString(16)).append("\"");
            sb.append(",\"maxPriorityFeePerGas\":\"0x")
              .append(t.maxPriorityFeePerGas().toString(16)).append("\"");
        }
        sb.append(",\"input\":\"").append(t.input().isEmpty() ? "0x" : t.input().toHexString()).append("\"");
        // v is a QUANTITY (recovery id / EIP-155 v); typed txs also carry yParity (0/1).
        sb.append(",\"v\":\"0x").append(t.v().toString(16)).append("\"");
        if (t.type() >= 1) {
            sb.append(",\"yParity\":\"0x").append(t.v().toString(16)).append("\"");
        }
        // r and s are 32-byte DATA — left-pad, never QUANTITY (odd-length / unpadded
        // breaks clients expecting exactly 32 bytes).
        sb.append(",\"r\":\"").append(Bytes.wrap(word32(t.r())).toHexString()).append("\"");
        sb.append(",\"s\":\"").append(Bytes.wrap(word32(t.s())).toHexString()).append("\"");
        sb.append("}");
        return sb.toString();
    }

    /**
     * eth_getTransactionReceipt — trustlessly. Scans a bounded window of recent blocks
     * below the beacon-anchored verified head: for each, fetches the block body and
     * verifies it against the header's {@code transactionsRoot} (rebuilding the tx trie)
     * before trusting that the tx is in that block at a given index; then fetches the
     * block's receipts and verifies them against the header's {@code receiptsRoot} before
     * returning the matching receipt as JSON. Returns null (→ error / pending) if the tx
     * isn't found verified in the window. Peer data is never trusted unverified.
     *
     * <p>Returns the verified core fields (status, gasUsed, logs, block context, type);
     * from / to / contractAddress / effectiveGasPrice (which need tx decode + sender
     * recovery) are a follow-up.
     */
    private String rpcGetTransactionReceipt(byte[] txHash, String block) {
        RLPxConnector conn = connector;
        if (conn == null || txHash == null || txHash.length != 32) return null;
        try {
            // Headers-only anchor (snap head preferred, beacon optimistic fallback):
            // receipts need verified headers + bodies, not snap state, so this path
            // keeps working through snap-peer outages — see headerAnchor().
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            long headNum = anchor.number();

            int count = (int) Math.min(RECEIPT_LOOKBACK_BLOCKS, headNum + 1);
            long start = headNum - count + 1;
            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(start, count)
                    // Future.get(timeout) kept (over CompletableFuture.orTimeout) so the
                    // same code runs unmodified on Android API 29 hosts.
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            // Anchor the window: its last header must BE the verified head and every
            // header must hash-link to the next's parentHash.
            if (!anchor.anchors(window)) {
                log.info("[rpc] eth_getTransactionReceipt: header window failed to anchor");
                return null;
            }

            Bytes32 want = Bytes32.wrap(txHash);
            // Fire the body fetches concurrently rather than 32 sequential round-trips:
            // worst case (tx pending / outside the window) is then ~one round-trip of
            // latency instead of the sum. The window itself is the bandwidth bound.
            List<CompletableFuture<List<BlockBodiesMessage.BlockBody>>> bodyFutures =
                    new ArrayList<>(window.size());
            for (BlockHeadersMessage.VerifiedHeader vh : window) {
                bodyFutures.add(conn.requestBlockBodies(vh.hash()));
            }
            for (int hi = window.size() - 1; hi >= 0; hi--) {
                BlockHeader h = window.get(hi).header();
                Bytes32 blockHash = window.get(hi).hash();
                List<BlockBodiesMessage.BlockBody> bodies;
                try {
                    bodies = bodyFutures.get(hi).get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
                } catch (Exception e) {
                    continue; // body fetch failed/timed out for this block — skip it
                }
                if (bodies.isEmpty()) continue;
                List<Bytes> txs = bodies.get(0).transactions();
                // Verify the body before trusting which txs (and indices) it contains.
                if (!OrderedTrieRoot.verify(txs, h.transactionsRoot)) {
                    log.info("[rpc] block #" + h.number + " body failed transactionsRoot verify");
                    continue;
                }
                int idx = -1;
                for (int i = 0; i < txs.size(); i++) {
                    if (Hash.keccak256(txs.get(i)).equals(want)) { idx = i; break; }
                }
                if (idx < 0) continue;

                // Found. Fetch + verify the block's receipts against receiptsRoot.
                List<List<Bytes>> rcptBlocks = conn
                        .requestReceipts(blockHash)
                        .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
                if (rcptBlocks.isEmpty()) return null;
                List<Bytes> receipts = rcptBlocks.get(0);
                if (!OrderedTrieRoot.verify(receipts, h.receiptsRoot)) {
                    log.info("[rpc] block #" + h.number + " receipts failed receiptsRoot verify");
                    return null;
                }
                if (idx >= receipts.size()) return null;
                log.info("[rpc] eth_getTransactionReceipt verified tx in block #"
                        + h.number + " index " + idx);
                return buildReceiptJson(receipts, idx, h, blockHash, want);
            }
            // Verified head + anchored window, but the tx isn't in it → a VERIFIED
            // "not seen yet": return the JSON-null literal (eth's pending/unknown), NOT
            // Java null (which means "couldn't verify" → router error).
            return "null";
        } catch (Exception e) {
            log.info("[rpc] eth_getTransactionReceipt failed: " + unwrap(e));
            return null; // couldn't verify → router errors (not a misleading "pending")
        }
    }

    /** Build the eth_getTransactionReceipt JSON object from VERIFIED receipt bytes.
     *  {@code txHash} is the body's tx hash (already confirmed == the requested hash). */
    private static String buildReceiptJson(List<Bytes> receipts, int idx,
                                           BlockHeader h, Bytes32 blockHash, Bytes32 txHash) {
        Receipt r = Receipt.decode(receipts.get(idx));
        // Single pass over the preceding receipts: gasUsed needs receipt[idx-1]'s
        // cumulative, logIndex needs the running log count — decode each only once.
        long prevCum = 0L;
        int logBase = 0;
        for (int j = 0; j < idx; j++) {
            Receipt prev = Receipt.decode(receipts.get(j));
            logBase += prev.logs().size();
            if (j == idx - 1) prevCum = prev.cumulativeGasUsed();
        }
        long gasUsed = r.cumulativeGasUsed() - prevCum;

        String txHashHex = txHash.toHexString();
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"transactionHash\":\"").append(txHashHex).append("\"");
        sb.append(",\"transactionIndex\":\"").append(hexQuantity(idx)).append("\"");
        sb.append(",\"blockHash\":\"").append(blockHash.toHexString()).append("\"");
        sb.append(",\"blockNumber\":\"").append(hexQuantity(h.number)).append("\"");
        sb.append(",\"cumulativeGasUsed\":\"").append(hexQuantity(r.cumulativeGasUsed())).append("\"");
        sb.append(",\"gasUsed\":\"").append(hexQuantity(gasUsed)).append("\"");
        if (r.hasStatus()) {
            sb.append(",\"status\":\"").append(r.success() ? "0x1" : "0x0").append("\"");
        }
        sb.append(",\"type\":\"").append(hexQuantity(r.type())).append("\"");
        sb.append(",\"logsBloom\":\"").append(r.logsBloom().toHexString()).append("\"");
        sb.append(",\"logs\":[");
        for (int k = 0; k < r.logs().size(); k++) {
            Receipt.Log log = r.logs().get(k);
            if (k > 0) sb.append(",");
            sb.append("{\"address\":\"").append(log.address().toHexString()).append("\"");
            sb.append(",\"topics\":[");
            for (int t = 0; t < log.topics().size(); t++) {
                if (t > 0) sb.append(",");
                sb.append("\"").append(log.topics().get(t).toHexString()).append("\"");
            }
            sb.append("],\"data\":\"").append(log.data().toHexString()).append("\"");
            sb.append(",\"blockNumber\":\"").append(hexQuantity(h.number)).append("\"");
            sb.append(",\"blockHash\":\"").append(blockHash.toHexString()).append("\"");
            sb.append(",\"transactionHash\":\"").append(txHashHex).append("\"");
            sb.append(",\"transactionIndex\":\"").append(hexQuantity(idx)).append("\"");
            sb.append(",\"logIndex\":\"").append(hexQuantity(logBase + k)).append("\"");
            sb.append(",\"removed\":false}");
        }
        sb.append("]}");
        return sb.toString();
    }

    /**
     * eth_getBlockByNumber, verified. Serves the block header fields from a
     * beacon-anchored verified header plus the tx hashes from a body checked against
     * transactionsRoot — no snap state needed (so it works even where eth_call can't).
     * Returns the block JSON when verified; the literal "null" for a non-existent
     * (future) block (eth's standard); Java null when it can't verify (not synced)
     * → router errors. fullTransactions=true (full tx objects, needs tx decode + sender
     * recovery) is a follow-up — returns Java null for now.
     */
    private String rpcGetBlockByNumber(String block, boolean fullTx) {
        RLPxConnector conn = connector;
        if (conn == null || fullTx) return null;
        // Classify the request up front so a fetch failure can decide whether stale-
        // serving is safe: only LATEST-ish tags (the wallet's block tracker) may fall
        // back to the cached head block; a number-pin must stay exact (see serveStaleBlock).
        String b = (block == null) ? "latest" : block;
        boolean isTag;
        switch (b) {
            case "latest": case "pending": case "safe": case "finalized":
                isTag = true; break;
            case "earliest":
                return null; // genesis not served verified here (rarely needed)
            default:
                isTag = false;
        }
        long pinned = -1;
        if (!isTag) {
            try { pinned = Long.decode(b); } catch (Exception e) { return null; }
            if (pinned < 0) return null;                    // invalid (negative) block number
        }
        try {
            // Headers-only anchor: snap-built head when available, beacon optimistic
            // exec payload otherwise — block serving must survive snap-peer outages
            // (MetaMask's block tracker polls this and hangs the UI without it).
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return serveStaleBlock(isTag, pinned);
            long headNum = anchor.number();

            long target = isTag ? headNum : pinned;
            if (target > headNum) return "null";            // future/unknown block → eth null
            long back = headNum - target;
            if (back >= BLOCK_LOOKBACK_MAX) return null;     // too far to verify cheaply → error

            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(target, (int) (back + 1))
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!anchor.anchors(window)) return serveStaleBlock(isTag, pinned);
            BlockHeadersMessage.VerifiedHeader vh = window.get(0); // target is first in [target..head]

            List<BlockBodiesMessage.BlockBody> bodies = conn
                    .requestBlockBodies(vh.hash())
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (bodies.isEmpty()) return serveStaleBlock(isTag, pinned);
            List<Bytes> txs = bodies.get(0).transactions();
            if (!OrderedTrieRoot.verify(txs, vh.header().transactionsRoot)) return serveStaleBlock(isTag, pinned);

            String json = buildBlockJson(vh, txs);
            // Cache the head block (target == headNum) as the last-good latest; a fetch
            // failure on a later "latest" poll then serves this verified block bounded-stale
            // instead of erroring. Historical pins aren't cached (they aren't "latest").
            if (target == headNum) {
                lastGoodLatestBlock = new BlockSnapshot(json, target, clock.elapsedMillis());
            }
            return json;
        } catch (Exception e) {
            log.info("[rpc] eth_getBlockByNumber failed: " + unwrap(e));
            return serveStaleBlock(isTag, pinned);
        }
    }

    /** Serve the last-good latest block when a fresh fetch couldn't complete. Returns
     *  null (→ error) unless we have a cached head block within {@link
     *  #RPC_HEAD_SERVE_STALE_MAX_MS} AND serving it is correct: any LATEST-ish tag gets
     *  the freshest verified block we hold; a number-pin gets it ONLY when it names that
     *  exact block. A pin for a different block must never receive substitute data. */
    private String serveStaleBlock(boolean isTag, long pinned) {
        BlockSnapshot snap = lastGoodLatestBlock;
        if (snap == null) return null;
        if (clock.elapsedMillis() - snap.atMs() >= RPC_HEAD_SERVE_STALE_MAX_MS) return null;
        if (isTag || pinned == snap.number()) {
            log.info("[rpc] eth_getBlockByNumber serving STALE block #" + snap.number()
                    + " (" + (clock.elapsedMillis() - snap.atMs()) / 1000 + "s old)");
            return snap.json();
        }
        return null;
    }

    /** Build the eth_getBlockByNumber JSON from a VERIFIED header + verified tx list
     *  (transactions as hashes; fullTransactions=true is handled upstream as a follow-up). */
    private static String buildBlockJson(BlockHeadersMessage.VerifiedHeader vh, List<Bytes> txs) {
        BlockHeader h = vh.header();
        StringBuilder sb = new StringBuilder(1024);
        sb.append("{\"number\":\"").append(hexQuantity(h.number)).append("\"");
        sb.append(",\"hash\":\"").append(vh.hash().toHexString()).append("\"");
        sb.append(",\"parentHash\":\"").append(h.parentHash.toHexString()).append("\"");
        sb.append(",\"nonce\":\"").append(h.nonce.toHexString()).append("\"");
        sb.append(",\"sha3Uncles\":\"").append(h.ommersHash.toHexString()).append("\"");
        sb.append(",\"logsBloom\":\"").append(h.logsBloom.toHexString()).append("\"");
        sb.append(",\"transactionsRoot\":\"").append(h.transactionsRoot.toHexString()).append("\"");
        sb.append(",\"stateRoot\":\"").append(h.stateRoot.toHexString()).append("\"");
        sb.append(",\"receiptsRoot\":\"").append(h.receiptsRoot.toHexString()).append("\"");
        sb.append(",\"miner\":\"").append(h.beneficiary.toHexString()).append("\"");
        sb.append(",\"difficulty\":\"0x").append(h.difficulty.toString(16)).append("\"");
        sb.append(",\"extraData\":\"").append(h.extraData.toHexString()).append("\"");
        sb.append(",\"gasLimit\":\"").append(hexQuantity(h.gasLimit)).append("\"");
        sb.append(",\"gasUsed\":\"").append(hexQuantity(h.gasUsed)).append("\"");
        sb.append(",\"timestamp\":\"").append(hexQuantity(h.timestamp)).append("\"");
        sb.append(",\"mixHash\":\"").append(h.mixHashOrPrevRandao.toHexString()).append("\"");
        if (h.baseFeePerGas != null) {
            sb.append(",\"baseFeePerGas\":\"0x").append(h.baseFeePerGas.toString(16)).append("\"");
        }
        if (h.withdrawalsRoot != null) {
            sb.append(",\"withdrawalsRoot\":\"").append(h.withdrawalsRoot.toHexString()).append("\"");
        }
        if (h.blobGasUsed >= 0) {
            sb.append(",\"blobGasUsed\":\"").append(hexQuantity(h.blobGasUsed)).append("\"");
        }
        if (h.excessBlobGas >= 0) {
            sb.append(",\"excessBlobGas\":\"").append(hexQuantity(h.excessBlobGas)).append("\"");
        }
        if (h.parentBeaconBlockRoot != null) {
            sb.append(",\"parentBeaconBlockRoot\":\"").append(h.parentBeaconBlockRoot.toHexString()).append("\"");
        }
        sb.append(",\"transactions\":[");
        for (int i = 0; i < txs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(Hash.keccak256(txs.get(i)).toHexString()).append("\"");
        }
        sb.append("],\"uncles\":[]}");
        return sb.toString();
    }

    // ---------------------------------------------------------------------
    // Header anchoring (headers-only verified serving)
    // ---------------------------------------------------------------------

    /** The contiguous header window [start..head] is valid iff its last header is the
     *  beacon-verified head (stateRoot match) and each header hash-links to the next. */
    private static boolean windowAnchoredToHead(List<BlockHeadersMessage.VerifiedHeader> window,
                                                byte[] headStateRoot) {
        if (window.isEmpty()) return false;
        BlockHeader last = window.get(window.size() - 1).header();
        if (!java.util.Arrays.equals(last.stateRoot.toArrayUnsafe(), headStateRoot)) return false;
        return windowHashLinked(window);
    }

    /** Like {@link #windowAnchoredToHead} but anchored by the head's block HASH —
     *  used with the beacon optimistic anchor, whose exec blockHash is what the
     *  light client verified. */
    private static boolean windowAnchoredToHash(List<BlockHeadersMessage.VerifiedHeader> window,
                                                byte[] headBlockHash) {
        if (window.isEmpty()) return false;
        if (!java.util.Arrays.equals(
                window.get(window.size() - 1).hash().toArrayUnsafe(), headBlockHash)) return false;
        return windowHashLinked(window);
    }

    private static boolean windowHashLinked(List<BlockHeadersMessage.VerifiedHeader> window) {
        for (int i = 0; i < window.size() - 1; i++) {
            if (!window.get(i).hash().equals(window.get(i + 1).header().parentHash)) return false;
        }
        return true;
    }

    /** A beacon-verified header anchor: block {@code number} plus either the head's
     *  {@code stateRoot} (snap-built head) or its block {@code hash} (beacon optimistic
     *  exec payload) — exactly one is non-null. */
    private record HeaderAnchor(long number, byte[] stateRoot, byte[] blockHash) {
        boolean anchors(List<BlockHeadersMessage.VerifiedHeader> window) {
            return stateRoot != null ? windowAnchoredToHead(window, stateRoot)
                                     : windowAnchoredToHash(window, blockHash);
        }
    }

    /**
     * Resolve a beacon-verified header anchor for block/receipt serving — paths that
     * need verified HEADERS but no snap state. Prefers the snap-built anchored head
     * (freshest, the chain tip); falls back to the beacon optimistic execution payload
     * (light-client-verified blockHash, at worst ~1 epoch stale) when no snap peer is
     * available — so eth_getBlockByNumber / eth_getTransactionReceipt keep working
     * through snap-peer outages (e.g. a cold start before discovery finds snap peers,
     * where MetaMask's block tracker previously died and hung the UI).
     */
    private HeaderAnchor headerAnchor() {
        RLPxConnector c = connector;
        // Only pay the anchored-head wait when a snap peer exists to build from.
        // Header anchoring needs verified headers, not snap STATE — so it keeps the
        // long stale window (a stale head still anchors a fetched header window).
        if (c != null && !c.activeSnapHandlers().isEmpty()) {
            RpcCallContext ctx = anchoredHeadOrWait(RPC_HEAD_SERVE_STALE_MAX_MS);
            if (ctx != null && ctx.beaconVerified()) {
                return new HeaderAnchor(ctx.blockNumber(), ctx.blockCtx().stateRoot(), null);
            }
        }
        // Stale-but-verified fallback BEFORE the optimistic head. A recently-built
        // anchored head is a block we actually verified and can re-anchor a header
        // window against (by stateRoot); the beacon OPTIMISTIC head below is a newer
        // block with no snap-servable state, so a header window fetched + verified
        // against it returns null and the caller hard-errors. During the transient
        // snap-peer gaps this node sees (head momentarily un-rebuildable), that turned
        // eth_feeHistory / eth_getBlockByNumber into -32000 errors — and MetaMask's
        // fee step loops on a feeHistory error, hanging the send screen after the
        // amount is entered. Preferring lastGoodHead keeps those methods answering
        // verified-but-slightly-stale data through the gap (same contract as the head
        // context's own stale-serve and the gasPrice/maxPriorityFee FeeSnapshot path).
        HeadWithTimestamp good = lastGoodHead.get();
        if (good != null && good.head().beaconVerified()
                && clock.elapsedMillis() - good.builtAtMs() < RPC_HEAD_SERVE_STALE_MAX_MS) {
            return new HeaderAnchor(good.head().blockNumber(),
                    good.head().blockCtx().stateRoot(), null);
        }
        BeaconSyncState bss = beaconSyncState;
        if (bss == null) return null;
        long n = bss.getOptimisticBlockNumber();
        byte[] h = bss.getOptimisticBlockHash();
        if (n <= 0 || h == null) return null;
        return new HeaderAnchor(n, null, h);
    }

    /**
     * Fetch headers in a single batch and verify the chain end-to-end.
     * Returns a future that completes with {@code true} iff:
     * <ul>
     *   <li>the first header's stateRoot equals the beacon-finalized root,</li>
     *   <li>the last header's stateRoot equals the peer's reported root,</li>
     *   <li>and every header's hash equals the next header's parentHash.</li>
     * </ul>
     */
    private CompletableFuture<Boolean> verifyHeaderChainBatched(
            RLPxConnector conn, long finalizedBlock, long peerBlock,
            byte[] beaconStateRoot, byte[] peerStateRoot) {
        long totalLong = peerBlock - finalizedBlock + 1;
        if (totalLong < 2 || totalLong > MAX_HEADER_CHAIN_GAP) {
            log.info("[verify] headerChain gap " + totalLong
                    + " out of range [2, " + MAX_HEADER_CHAIN_GAP + "]");
            return CompletableFuture.completedFuture(false);
        }
        int total = (int) totalLong;
        log.info("[verify] Fetching " + total + " headers from #"
                + finalizedBlock + " to #" + peerBlock);
        return conn.requestBlockHeadersBatched(finalizedBlock, total)
                .orTimeout(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS)
                .thenApply(headers -> {
                    boolean valid = verifyHeaderChain(headers, beaconStateRoot, peerStateRoot);
                    log.info("[verify] Full header chain (" + headers.size()
                            + " blocks) valid: " + valid);
                    return valid;
                });
    }

    /**
     * Pure verification of a contiguous header range. Identical algorithm to
     * {@code CommandHandler#verifyHeaderChain} in the JVM daemon.
     */
    private boolean verifyHeaderChain(List<BlockHeadersMessage.VerifiedHeader> headers,
                                      byte[] expectedFirstStateRoot,
                                      byte[] expectedLastStateRoot) {
        if (headers.isEmpty()) return false;

        byte[] firstStateRoot = headers.get(0).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(firstStateRoot, expectedFirstStateRoot)) return false;

        byte[] lastStateRoot = headers.get(headers.size() - 1).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(lastStateRoot, expectedLastStateRoot)) return false;

        for (int i = 0; i < headers.size() - 1; i++) {
            Bytes32 currentHash = headers.get(i).hash();
            Bytes32 nextParent = headers.get(i + 1).header().parentHash;
            if (!currentHash.equals(nextParent)) {
                log.info("[verify] hash chain break at index " + i
                        + ": block #" + headers.get(i).header().number
                        + " hash=" + currentHash.toShortHexString()
                        + " != block #" + headers.get(i + 1).header().number
                        + " parentHash=" + nextParent.toShortHexString());
                return false;
            }
        }
        return true;
    }

    /** Fetch the beacon-anchored header window [head-count+1 .. head]; null if it
     *  can't be fetched or doesn't anchor. */
    private List<BlockHeadersMessage.VerifiedHeader> anchoredHeaderWindow(
            HeaderAnchor anchor, int count) throws Exception {
        RLPxConnector conn = connector;
        if (conn == null) return null;
        long start = Math.max(0, anchor.number() - count + 1);
        List<BlockHeadersMessage.VerifiedHeader> window = conn
                .requestBlockHeadersBatched(start, (int) (anchor.number() - start + 1))
                .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
        return anchor.anchors(window) ? window : null;
    }

    // ---- Fee suggestion (verified) ----------------------------------------
    // MetaMask's signing screen blocks on fee data (eth_feeHistory / eth_gasPrice /
    // eth_maxPriorityFeePerGas) — without it the confirm UI sits in skeleton-loading
    // forever. All fee data here is derived from VERIFIED sources only: baseFee /
    // gasUsed / gasLimit from beacon-anchored headers, priority-fee tips from block
    // bodies verified against transactionsRoot (+ receipts verified against
    // receiptsRoot for gas-used percentile weighting).

    /** Recompute the fee snapshot if stale; called from the head-warmer tick (and
     *  as a side effect of a cold-path fee RPC). Single-flight; never throws. */
    private void refreshFeeSnapshotIfStale() {
        FeeSnapshot snap = feeSnapshot;
        long now = clock.elapsedMillis();
        if (snap != null && now - snap.atMs() < FEE_SNAPSHOT_REFRESH_MS) return;
        if (!feeRefreshing.compareAndSet(false, true)) return;
        try {
            java.math.BigInteger price = computeGasPriceCold();
            java.math.BigInteger tip = cachedSuggestedTip != null ? cachedSuggestedTip.tip() : null;
            if (price != null && tip != null) {
                feeSnapshot = new FeeSnapshot(price, tip, clock.elapsedMillis());
            }
        } catch (Throwable t) {
            log.info("[rpc] fee snapshot refresh failed: " + unwrap(t));
        } finally {
            feeRefreshing.set(false);
        }
    }

    /** Next block's base fee per the EIP-1559 update rule, from the parent header. */
    private static java.math.BigInteger nextBaseFee(BlockHeader h) {
        java.math.BigInteger base = h.baseFeePerGas;
        if (base == null) return java.math.BigInteger.ZERO; // pre-London (not mainnet today)
        long gasTarget = h.gasLimit / 2;
        if (gasTarget <= 0 || h.gasUsed == gasTarget) return base;
        java.math.BigInteger target = java.math.BigInteger.valueOf(gasTarget);
        if (h.gasUsed > gasTarget) {
            java.math.BigInteger delta = base
                    .multiply(java.math.BigInteger.valueOf(h.gasUsed - gasTarget))
                    .divide(target)
                    .divide(java.math.BigInteger.valueOf(8))
                    .max(java.math.BigInteger.ONE);
            return base.add(delta);
        }
        java.math.BigInteger delta = base
                .multiply(java.math.BigInteger.valueOf(gasTarget - h.gasUsed))
                .divide(target)
                .divide(java.math.BigInteger.valueOf(8));
        return base.subtract(delta);
    }

    /** A tx's effective priority fee plus the gas it used (receipt cumulative diff). */
    private record TxTip(java.math.BigInteger tip, long gasUsed) {}

    /** Per-tx (effectiveTip, gasUsed) of a block, from a body verified against
     *  transactionsRoot (+ receipts verified against receiptsRoot when
     *  {@code needGasWeights}). Null when the block can't be verified; empty for
     *  an empty block. Blocking wrapper around {@link #verifiedBlockTipsAsync}. */
    private List<TxTip> verifiedBlockTips(BlockHeadersMessage.VerifiedHeader vh,
                                          boolean needGasWeights) throws Exception {
        CompletableFuture<List<TxTip>> f = verifiedBlockTipsAsync(vh, needGasWeights);
        if (f == null) return null;
        return f.get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
    }

    /** Async {@link #verifiedBlockTips}: kicks off the body (and, when
     *  {@code needGasWeights}, receipt) fetch immediately and verifies/decodes when
     *  both land. Lets eth_feeHistory pipeline ALL its blocks' fetches concurrently —
     *  the old per-block blocking loop cost 2 sequential round-trips per block
     *  (observed 64s for one MetaMask feeHistory call on-device, which times out the
     *  wallet's fee poll and skeletons the confirm screen); concurrent fetches make
     *  the wall-clock one slowest-block round-trip. Completes with null (never
     *  exceptionally from verification) when the block can't be verified. */
    private CompletableFuture<List<TxTip>> verifiedBlockTipsAsync(
            BlockHeadersMessage.VerifiedHeader vh, boolean needGasWeights) {
        RLPxConnector conn = connector;
        if (conn == null) return null;
        BlockHeader h = vh.header();
        CompletableFuture<List<BlockBodiesMessage.BlockBody>> bodiesF =
                conn.requestBlockBodies(vh.hash())
                        .orTimeout(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
        CompletableFuture<List<List<Bytes>>> rcptF = needGasWeights
                ? conn.requestReceipts(vh.hash())
                        .orTimeout(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS)
                : CompletableFuture.completedFuture(null);
        return bodiesF.thenCombine(rcptF, (bodies, rcptBlocks) ->
                decodeBlockTips(h, bodies, rcptBlocks, needGasWeights));
    }

    /** Verify + decode one block's tips from its fetched body (and receipts when
     *  {@code needGasWeights}). Null when verification fails. */
    private List<TxTip> decodeBlockTips(BlockHeader h,
                                        List<BlockBodiesMessage.BlockBody> bodies,
                                        List<List<Bytes>> rcptBlocks,
                                        boolean needGasWeights) {
        if (bodies.isEmpty()) {
            log.info("[rpc] tips: no body for block #" + h.number);
            return null;
        }
        List<Bytes> txs = bodies.get(0).transactions();
        if (!OrderedTrieRoot.verify(txs, h.transactionsRoot)) {
            log.info("[rpc] tips: block #" + h.number + " body failed transactionsRoot verify");
            return null;
        }
        if (txs.isEmpty()) return java.util.Collections.emptyList();

        long[] gasUsed = null;
        if (needGasWeights) {
            if (rcptBlocks == null || rcptBlocks.isEmpty()) {
                log.info("[rpc] tips: no receipts for block #" + h.number);
                return null;
            }
            List<Bytes> receipts = rcptBlocks.get(0);
            if (receipts.size() != txs.size()
                    || !OrderedTrieRoot.verify(receipts, h.receiptsRoot)) {
                log.info("[rpc] tips: block #" + h.number + " receipts mismatch (got "
                        + receipts.size() + " for " + txs.size() + " txs) or root verify failed");
                return null;
            }
            gasUsed = new long[txs.size()];
            long prevCum = 0;
            for (int i = 0; i < receipts.size(); i++) {
                long cum = Receipt.decode(receipts.get(i)).cumulativeGasUsed();
                gasUsed[i] = cum - prevCum;
                prevCum = cum;
            }
        }

        java.math.BigInteger baseFee =
                h.baseFeePerGas != null ? h.baseFeePerGas : java.math.BigInteger.ZERO;
        List<TxTip> out = new ArrayList<>(txs.size());
        for (int i = 0; i < txs.size(); i++) {
            TxFeeFields f = TxFeeFields.decode(txs.get(i));
            if (f == null) { // verified body with an unparseable tx — bail
                log.info("[rpc] tips: block #" + h.number + " tx " + i
                        + " undecodable (" + (txs.get(i).isEmpty() ? "empty"
                        : "first byte 0x" + Integer.toHexString(txs.get(i).get(0) & 0xFF)) + ")");
                return null;
            }
            out.add(new TxTip(f.effectiveTip(baseFee), gasUsed != null ? gasUsed[i] : 0));
        }
        return out;
    }

    /** Suggested priority fee: median effective tip over the last
     *  {@link #TIP_SUGGEST_BLOCKS} verified blocks, floored at
     *  {@link #MIN_SUGGESTED_TIP}. Cached for ~one block. Null → can't verify. */
    private java.math.BigInteger rpcMaxPriorityFeePerGas() {
        // Serve the pre-computed snapshot first — same freshness contract as
        // eth_gasPrice (the head warmer refreshes it; the wallet re-polls).
        FeeSnapshot snap = feeSnapshot;
        if (snap != null && clock.elapsedMillis() - snap.atMs()
                < FEE_SNAPSHOT_MAX_SERVE_MS) {
            return snap.tip();
        }
        return computeMaxPriorityFeeCold();
    }

    private java.math.BigInteger computeMaxPriorityFeeCold() {
        TipWithTimestamp cached = cachedSuggestedTip;
        if (cached != null
                && clock.elapsedMillis() - cached.atMs() < TIP_CACHE_TTL_MS) {
            return cached.tip();
        }
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            List<BlockHeadersMessage.VerifiedHeader> window =
                    anchoredHeaderWindow(anchor, TIP_SUGGEST_BLOCKS);
            if (window == null) return null;
            List<java.math.BigInteger> tips = new ArrayList<>();
            for (BlockHeadersMessage.VerifiedHeader vh : window) {
                List<TxTip> blockTips = verifiedBlockTips(vh, false);
                if (blockTips == null) continue; // one unverifiable block doesn't kill the suggestion
                for (TxTip t : blockTips) tips.add(t.tip());
            }
            java.math.BigInteger tip;
            if (tips.isEmpty()) {
                tip = MIN_SUGGESTED_TIP;
            } else {
                java.util.Collections.sort(tips);
                tip = tips.get(tips.size() / 2).max(MIN_SUGGESTED_TIP);
            }
            cachedSuggestedTip = new TipWithTimestamp(tip, clock.elapsedMillis());
            return tip;
        } catch (Exception e) {
            log.info("[rpc] eth_maxPriorityFeePerGas failed: " + unwrap(e));
            return null;
        }
    }

    /** Legacy-style total gas price: next block's base fee + the suggested tip.
     *  Served from the pre-computed {@link #feeSnapshot} when available (the head
     *  warmer keeps it fresh) so the wallet's fee poll returns in microseconds;
     *  falls back to the cold path only before the first snapshot exists. */
    private java.math.BigInteger rpcGasPrice() {
        FeeSnapshot snap = feeSnapshot;
        if (snap != null && clock.elapsedMillis() - snap.atMs()
                < FEE_SNAPSHOT_MAX_SERVE_MS) {
            return snap.gasPrice();
        }
        java.math.BigInteger price = computeGasPriceCold();
        if (price != null) {
            java.math.BigInteger tip = cachedSuggestedTip != null ? cachedSuggestedTip.tip() : null;
            if (tip != null) {
                feeSnapshot = new FeeSnapshot(price, tip, clock.elapsedMillis());
            }
        }
        return price;
    }

    /** The cold gas-price computation (header anchor + window + tip from verified
     *  bodies). Seconds-slow on-device; callers should prefer {@link #feeSnapshot}. */
    private java.math.BigInteger computeGasPriceCold() {
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            List<BlockHeadersMessage.VerifiedHeader> window = anchoredHeaderWindow(anchor, 1);
            if (window == null || window.isEmpty()) return null;
            java.math.BigInteger tip = computeMaxPriorityFeeCold();
            if (tip == null) return null;
            return nextBaseFee(window.get(window.size() - 1).header()).add(tip);
        } catch (Exception e) {
            log.info("[rpc] eth_gasPrice failed: " + unwrap(e));
            return null;
        }
    }

    /**
     * eth_feeHistory from verified data. baseFeePerGas / gasUsedRatio come from the
     * beacon-anchored header window; reward percentiles (when requested) from bodies
     * verified against transactionsRoot + receipts verified against receiptsRoot,
     * using geth's gas-used-weighted percentile walk. blockCount is clamped to
     * {@link #FEE_HISTORY_MAX_BLOCKS}; the result reflects what was served.
     */
    private String rpcFeeHistory(long blockCount, String newestBlock, double[] percentiles) {
        // Exact request signature — a later identical request that can't be rebuilt is
        // served from lastGoodFeeHistory (same params => same verified data, just older).
        String key = blockCount + "|" + newestBlock + "|" + java.util.Arrays.toString(percentiles);
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return serveStaleFeeHistory(key);
            long headNum = anchor.number();

            long newest;
            String nb = (newestBlock == null) ? "latest" : newestBlock;
            switch (nb) {
                case "latest": case "pending": case "safe": case "finalized":
                    newest = headNum; break;
                case "earliest":
                    return null;
                default:
                    try { newest = Long.decode(nb); } catch (Exception e) { return null; }
            }
            if (newest < 0 || newest > headNum) return null;

            int count = (int) Math.min(Math.min(blockCount, FEE_HISTORY_MAX_BLOCKS), newest + 1);
            long oldest = newest - count + 1;
            if (headNum - oldest >= BLOCK_LOOKBACK_MAX) return null; // too far back to verify cheaply

            // One anchored window [oldest..head]; the requested span is its first
            // `count` entries (the window may extend past `newest` up to the head —
            // that's what anchors it, and it gives the ACTUAL next-block baseFee).
            List<BlockHeadersMessage.VerifiedHeader> window =
                    anchoredHeaderWindow(anchor, (int) (headNum - oldest + 1));
            if (window == null || window.size() < count) return serveStaleFeeHistory(key);

            StringBuilder sb = new StringBuilder(256);
            sb.append("{\"oldestBlock\":\"").append(hexQuantity(oldest)).append("\"");

            sb.append(",\"baseFeePerGas\":[");
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(",");
                java.math.BigInteger bf = window.get(i).header().baseFeePerGas;
                sb.append("\"0x").append((bf != null ? bf : java.math.BigInteger.ZERO).toString(16)).append("\"");
            }
            // Entry count+1: the next block after `newest` — its actual baseFee when the
            // window extends past newest, else the EIP-1559 prediction from `newest`.
            java.math.BigInteger nextBf = (count < window.size())
                    ? (window.get(count).header().baseFeePerGas != null
                        ? window.get(count).header().baseFeePerGas : java.math.BigInteger.ZERO)
                    : nextBaseFee(window.get(count - 1).header());
            sb.append(",\"0x").append(nextBf.toString(16)).append("\"]");

            sb.append(",\"gasUsedRatio\":[");
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(",");
                BlockHeader h = window.get(i).header();
                double ratio = h.gasLimit > 0 ? (double) h.gasUsed / (double) h.gasLimit : 0.0;
                sb.append(ratio);
            }
            sb.append("]");

            if (percentiles != null) {
                // Launch every block's body+receipt fetch CONCURRENTLY before consuming
                // any: the old one-block-at-a-time loop paid 2 sequential round-trips per
                // block (64s observed on-device for one MetaMask poll — far past the
                // wallet's timeout, skeletoning the confirm screen). Pipelined, the
                // wall-clock is one slowest-block fetch.
                List<CompletableFuture<List<TxTip>>> tipFutures = new ArrayList<>(count);
                for (int i = 0; i < count; i++) {
                    tipFutures.add(verifiedBlockTipsAsync(window.get(i), true));
                }
                sb.append(",\"reward\":[");
                for (int i = 0; i < count; i++) {
                    if (i > 0) sb.append(",");
                    CompletableFuture<List<TxTip>> f = tipFutures.get(i);
                    List<TxTip> tips = (f == null) ? null
                            : f.get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
                    if (tips == null) return serveStaleFeeHistory(key); // strict: no unverified rewards
                    sb.append(rewardJson(tips, percentiles));
                }
                sb.append("]");
            }
            sb.append("}");
            String json = sb.toString();
            lastGoodFeeHistory = new FeeHistorySnapshot(key, json, clock.elapsedMillis());
            return json;
        } catch (Exception e) {
            log.info("[rpc] eth_feeHistory failed: " + unwrap(e));
            return serveStaleFeeHistory(key);
        }
    }

    /** Serve the last-good feeHistory when a fresh build couldn't complete: only when
     *  the cached result was for the SAME request signature and is within {@link
     *  #RPC_HEAD_SERVE_STALE_MAX_MS}. Same params => identical verified data, so this is
     *  correct-but-stale (never wrong); fees drift slowly and the wallet re-polls. */
    private String serveStaleFeeHistory(String key) {
        FeeHistorySnapshot snap = lastGoodFeeHistory;
        if (snap == null || !snap.key().equals(key)) return null;
        if (clock.elapsedMillis() - snap.atMs() >= RPC_HEAD_SERVE_STALE_MAX_MS) return null;
        log.info("[rpc] eth_feeHistory serving STALE result ("
                + (clock.elapsedMillis() - snap.atMs()) / 1000 + "s old)");
        return snap.json();
    }

    /** Gas-used-weighted percentile rewards for one block (geth's algorithm): sort txs
     *  by tip, walk percentile thresholds over cumulative gasUsed. Empty block → zeros. */
    private static String rewardJson(List<TxTip> tips, double[] percentiles) {
        StringBuilder sb = new StringBuilder(percentiles.length * 12 + 2);
        sb.append("[");
        if (tips.isEmpty()) {
            for (int p = 0; p < percentiles.length; p++) {
                if (p > 0) sb.append(",");
                sb.append("\"0x0\"");
            }
            return sb.append("]").toString();
        }
        List<TxTip> sorted = new ArrayList<>(tips);
        sorted.sort(java.util.Comparator.comparing(TxTip::tip));
        long totalGas = 0;
        for (TxTip t : sorted) totalGas += t.gasUsed();
        int idx = 0;
        long cumGas = sorted.get(0).gasUsed();
        for (int p = 0; p < percentiles.length; p++) {
            if (p > 0) sb.append(",");
            double threshold = totalGas * percentiles[p] / 100.0;
            while (cumGas < threshold && idx < sorted.size() - 1) {
                idx++;
                cumGas += sorted.get(idx).gasUsed();
            }
            sb.append("\"0x").append(sorted.get(idx).tip().toString(16)).append("\"");
        }
        return sb.append("]").toString();
    }

    // ---------------------------------------------------------------------
    // eth_estimateGas
    // ---------------------------------------------------------------------

    /**
     * eth_estimateGas over the shared anchored head: runs the call in the local EVM
     * against snap-verified state with full gas accounting (intrinsic + execution +
     * 15% headroom — see {@code DefaultEvmExecutor.estimateGas}). A reverting tx gets
     * an error, not a number — the wallet must not broadcast it. Contract creation
     * (to=null) isn't served verified yet → null → router errors.
     */
    private java.math.BigInteger rpcEstimateGas(byte[] from, byte[] to, byte[] data,
                                                java.math.BigInteger value) {
        if (to == null || to.length != 20) return null;
        if (from != null && from.length != 20) return null;
        RpcCallContext h = anchoredHeadOrWait(RPC_STATE_HEAD_MAX_STALE_MS);
        if (h == null) return null;
        try {
            // Fast path: a value transfer with no calldata to a plain account costs
            // exactly 21000 — no EVM execution, no 15% headroom (it's exact). This is
            // MetaMask's send-ETH flow. We still fetch the recipient ONCE to confirm
            // it has no code (a contract receive()/fallback, or a 7702 delegation,
            // would execute and cost more) — but skip building+running the EVM, the
            // bulk of the per-estimate work on ART.
            boolean noData = data == null || data.length == 0;
            if (noData) {
                io.myotis.evm.world.AccountState acct = h.oracle()
                        .fetchAccount(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(to))
                        .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
                byte[] codeHash = acct == null ? null : acct.codeHash();
                if (codeHash != null && java.util.Arrays.equals(codeHash, EMPTY_CODE_HASH)) {
                    return java.math.BigInteger.valueOf(21_000);
                }
                // Has code (contract / 7702 EOA) → fall through to the full EVM estimate.
            }
            io.myotis.evm.UnsignedTransaction tx = new io.myotis.evm.UnsignedTransaction(
                    io.myotis.evm.Address.of(from != null ? from : new byte[20]),
                    io.myotis.evm.Address.of(to),
                    value != null ? value : java.math.BigInteger.ZERO,
                    data != null ? data : new byte[0],
                    null);
            Long gas = h.offchainExecutor().estimateGas(tx, h.blockCtx())
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            return gas == null ? null : java.math.BigInteger.valueOf(gas);
        } catch (Exception e) {
            log.info("[rpc] eth_estimateGas -> error: " + describeEvmError(e));
            if (isStateUnavailable(e)) evictUnservableHead(h);
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Snap quality bookkeeping (feeds the injected SnapQualitySink)
    // ---------------------------------------------------------------------

    /**
     * Feed a snap-serving verdict for {@code peer} into the host's peer cache (via
     * the injected {@link SnapQualitySink}) so good snap peers are remembered across
     * restarts (dialed first) and repeat hangers deprioritized. {@code served=true}
     * on a usable proof, {@code false} on a root-unavailable (empty/invalid proof,
     * timeout, IO). No-op if the handler's remote address can't be parsed.
     */
    private void recordSnapQuality(EthHandler peer, boolean served) {
        if (peer == null) return;
        InetSocketAddress addr = remoteAddressOf(peer);
        if (addr == null) return;
        try {
            if (served) snapQuality.recordSnapServed(addr);
            else snapQuality.recordSnapFailure(addr);
        } catch (RuntimeException ignore) {
            // Never let cache bookkeeping disrupt an in-flight RPC.
        }
    }

    /**
     * Parse {@link EthHandler#getRemoteAddress()} ("ip:port", or "[v6]:port") into an
     * unresolved {@link InetSocketAddress} whose {@code getHostString()} matches the
     * key the host's peer cache stored at dial time. Returns {@code null} on a
     * missing/malformed address.
     */
    private static InetSocketAddress remoteAddressOf(EthHandler peer) {
        String ra = peer.getRemoteAddress();
        if (ra == null || ra.isEmpty()) return null;
        int colon = ra.lastIndexOf(':');
        if (colon <= 0 || colon == ra.length() - 1) return null;
        String host = ra.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        try {
            int port = Integer.parseInt(ra.substring(colon + 1));
            return InetSocketAddress.createUnresolved(host, port);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Misc helpers
    // ---------------------------------------------------------------------

    /** Ethereum JSON-RPC QUANTITY: minimal hex, no leading zeros, 0 → "0x0". */
    private static String hexQuantity(long v) {
        return "0x" + Long.toHexString(v);
    }

    /** Render a storage value as a 32-byte big-endian word (drops BigInteger's
     *  two's-complement sign byte, left-pads short magnitudes). */
    private static byte[] word32(java.math.BigInteger v) {
        byte[] out = new byte[32];
        byte[] mag = v.toByteArray();
        int len = Math.min(mag.length, 32);
        System.arraycopy(mag, mag.length - len, out, 32 - len, len);
        return out;
    }

    /** Convert an SSZ uint256 (32-byte little-endian) to a non-negative BigInteger. */
    private static java.math.BigInteger leUint256ToBigInteger(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[i] = le[le.length - 1 - i];
        return new java.math.BigInteger(1, be);
    }

    /** Render an estimate/call failure, decoding EvmExecutionException revert data —
     *  the estimator packs halt diagnostics ("halt=... state=...") into Reverted bytes,
     *  which the default toString prints as an opaque [B@hash. */
    private static String describeEvmError(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof io.myotis.evm.EvmExecutionException ee
                    && ee.error() instanceof io.myotis.evm.EvmExecutionError.Reverted rev) {
                byte[] d = rev.data();
                boolean printable = d.length > 0;
                for (byte b : d) {
                    if (b < 0x20 || b > 0x7e) { printable = false; break; }
                }
                return "Reverted: " + (printable
                        ? new String(d, java.nio.charset.StandardCharsets.US_ASCII)
                        : Bytes.wrap(d).toHexString());
            }
        }
        return unwrap(e);
    }

    /**
     * Render the whole cause chain, deepest cause included. Library wrappers
     * (e.g. Caffeine throwing {@code IllegalStateException(className)} around a
     * reflective failure) otherwise mask the real incompatibility under a
     * misleading top-level message.
     */
    private static String unwrap(Throwable t) {
        StringBuilder sb = new StringBuilder();
        java.util.Set<Throwable> seen =
                java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (Throwable c = t; c != null && seen.add(c); c = c.getCause()) {
            if (sb.length() > 0) sb.append(" <- ");
            sb.append(c.getClass().getSimpleName());
            if (c.getMessage() != null) sb.append(": ").append(c.getMessage());
        }
        return sb.toString();
    }
}
