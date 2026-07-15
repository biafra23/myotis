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
 * {@link io.myotis.api.VerifiedReads} that both the Android app
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
public final class VerifiedRpcBackend implements io.myotis.api.VerifiedReads,
        com.jaeckel.ethp2p.networking.eth.TxGossipObserver, AutoCloseable {

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
    // tx lookup (eth_getTransactionReceipt / eth_getTransactionByHash) scans beacon-anchored
    // blocks for the tx. A FLAT window was a trap: at ~8 blocks the tx was discoverable for
    // only ~8 blocks (~40s on Gnosis's 5s blocks, ~1.5 min on mainnet) before the head
    // scrolled its block out of view — permanently — so a genuinely-mined tx reported "not
    // found" forever if the wallet didn't poll within that tiny window (acute on mobile with
    // flaky peers). Instead {@link #locateMinedTx} scans INCREMENTALLY: each poll fetches only
    // the blocks that appeared since the last poll and remembers how far it has scanned, so
    // coverage grows to span the whole time a tx is watched at ~one block of fetch per poll.
    // RECEIPT_INITIAL_LOOKBACK_BLOCKS: the first poll's lookback (catches a tx mined just
    // before watching began). RECEIPT_MAX_SCAN_BLOCKS_PER_POLL: caps per-poll catch-up so a
    // long gap (backgrounded/dozed app) can't trigger a huge fetch. RECEIPT_SCAN_TTL_MS: how
    // long a tx's scan state is retained (and kept discoverable) before eviction.
    private static final int RECEIPT_INITIAL_LOOKBACK_BLOCKS = 8;
    private static final int RECEIPT_MAX_SCAN_BLOCKS_PER_POLL = 128;
    private static final long RECEIPT_SCAN_TTL_MS = 10 * 60_000L;
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
    /** Tight timeout for the pre-stale-serve servability probe: we're already in the
     *  degraded last-resort path, so a doomed read should fail in a few seconds, not
     *  rotate the peer set for the full 30s callView. */
    private static final long RPC_STALE_PROBE_TIMEOUT_SEC = 3;
    /** A stale-head servability verdict is cached this long (keyed by root) so a burst
     *  of confirm-screen calls on one root shares a single probe. Short — a peer can
     *  drop the root between bursts, but within a couple seconds the verdict holds. */
    private static final long STALE_PROBE_CACHE_MS = 2_000;
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

    /** How long a broadcast-but-unmined nonce stays in {@link #pendingNonces}. After
     *  this the overlay drops it even if the mined count never caught up, so a tx that
     *  was dropped or replaced by the network can't permanently wedge the account at a
     *  nonce the chain will never reach. 90s comfortably covers normal inclusion (a few
     *  blocks) while bounding the wedge window if a send never lands. */
    private static final long PENDING_NONCE_TTL_MS = 90_000;

    /** How long we keep watching a broadcast tx for its hash to come back over gossip.
     *  Generous vs. typical inclusion (a few blocks): once a tx mines we stop watching
     *  it explicitly (verified inclusion), and the warmer evicts anything older than
     *  this so the gossip-decode hot path goes quiet when nothing of ours is live. */
    private static final long SENT_TX_WATCH_TTL_MS = 180_000;
    /** How often the warmer re-broadcasts still-pending, not-yet-propagated txs of ours.
     *  The initial eth_sendRawTransaction push only reaches the peers connected at that
     *  instant (as few as 0–3 on peer-thin chains like Gnosis), and a light client's peers
     *  may not re-propagate — so a tx sent during a lull can reach nobody and never mine.
     *  Re-pushing on this cadence picks up newly-connected peers until the tx is seen
     *  propagating, mined, or ages out at {@link #SENT_TX_WATCH_TTL_MS}. */
    private static final long TX_REBROADCAST_INTERVAL_MS = 20_000;

    /** keccak256("") — an account with this codeHash is an EOA (no contract code). */
    private static final byte[] EMPTY_CODE_HASH = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();

    // Cross-call cache of proof-verified account/storage state, keyed by stateRoot.
    // Shared across every head-context oracle so a wallet's repeated retries of a
    // heavy eth_call (MetaMask's ~1000-token BalanceChecker sweep / Multicall3
    // simulation) reuse already-fetched slots instead of re-proving hundreds each
    // time — turning a 30s-timeout retry-storm into a couple of converging attempts.
    // Bounded LRU per kind; ~64k storage slots ≈ a few MB.
    private static final int STATE_PROOF_CACHE_MAX = 65_536;

    /** How long a verified eth_call / estimateGas RESULT stays replayable (see
     *  {@link #callResultCache}). The result is keyed by stateRoot, so its value is
     *  ALWAYS correct for that state — this bound is staleness + memory, not safety.
     *  Mirrors {@link #RPC_HEAD_SERVE_STALE_MAX_MS}, the same horizon a pinned head
     *  itself stays servable, so a retry that still resolves to that head finds its
     *  result warm. Where StateProofCache (above) saves the per-slot snap proofs so a
     *  re-execution is cheaper, THIS cache saves the assembled answer so the common
     *  case — an identical call against an unchanged root — skips re-execution entirely. */
    private static final long CALL_RESULT_CACHE_TTL_MS = RPC_HEAD_SERVE_STALE_MAX_MS;
    /** Bound on distinct cached call/estimate answers. A confirm screen's Multicall3
     *  sweep + token list is a few hundred distinct calls; 512 covers a couple of those
     *  in flight at once. Each value is a small return blob, so this is low-MB. */
    private static final int CALL_RESULT_CACHE_MAX = 512;

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
    /** Fallback floor for the suggested tip (0.1 gwei), used only before the connector/network
     *  is available. The live floor is network-aware — see {@link #minSuggestedTip()} and
     *  {@code NetworkConfig#minSuggestedTipWei} — because 0.1 gwei over-suggests by orders of
     *  magnitude on cheap chains like Gnosis (~10 wei base fee). */
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
    /** Caps a HEAVY-lane EVM execution to ~half the live snap peers per concurrent snap
     *  request, so a token sweep can't starve the gating calls that share the pool.
     *  Initialised in the constructor (needs the connector for the live peer count). */
    private final SnapLaneGate snapLaneGate;
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

    /** Replayable eth_call results, keyed by the SAME {@code stateRoot:from:to:value:keccak(calldata)}
     *  string as {@link #inflightCalls}. An eth_call is deterministic given its anchored
     *  stateRoot, so once a (root, from, target, value, calldata) tuple has executed-and-verified
     *  the answer is reusable for as long as that root stays servable. The dominant real-world
     *  pattern is a user retrying a hung confirm screen — tap Confirm, it spins past the
     *  wallet's timeout, tap again — which re-issues the IDENTICAL call against the same
     *  pinned head; we replay the cached answer in microseconds instead of re-running the
     *  EVM + snap fetch waves on thin mobile peers. Crucially the leader's execution is NOT
     *  cancelled when its waiter times out (see {@link #rpcCall}); it finishes in the
     *  background and populates this cache, so even a call the wallet GAVE UP on lands here
     *  and the retry finds it warm. Reuse is never a trust relaxation: the key pins the
     *  exact stateRoot and every value was proof-verified against it before insertion — the
     *  served bytes are bit-identical to re-executing. */
    private final VerifiedResultCache<byte[]> callResultCache =
            new VerifiedResultCache<>(CALL_RESULT_CACHE_MAX, CALL_RESULT_CACHE_TTL_MS);

    /** Replayable eth_estimateGas results, keyed by {@code stateRoot:from:to:keccak(data):value}.
     *  Same rationale as {@link #callResultCache}: an estimate is deterministic given the
     *  anchored state, and estimateGas is a gating call on the confirm screen, so a retry
     *  against the same pinned head replays instead of re-running the binary-search EVM. */
    private final VerifiedResultCache<Long> estimateCache =
            new VerifiedResultCache<>(CALL_RESULT_CACHE_MAX, CALL_RESULT_CACHE_TTL_MS);

    /** Highest nonce this node has broadcast for a sender but not yet seen mined,
     *  keyed by lowercase 0x sender address, with the broadcast timestamp. A light
     *  node has no mempool, so without this two back-to-back sends from the same
     *  account collide on one nonce: the second reads {@code eth_getTransactionCount}
     *  while the first is still pending, gets the not-yet-incremented mined count, and
     *  reuses the first tx's nonce (MetaMask's "confirm screen hangs on the second
     *  send" symptom). We relayed these txs ourselves and hold the signed bytes, so
     *  reporting their nonce as pending is our own honest knowledge of the mempool we
     *  fed, not a trust assumption. The tracker expires an entry when the chain's mined
     *  count passes it (tx mined) or after {@link #PENDING_NONCE_TTL_MS} (tx likely
     *  dropped/replaced — never wedge the account). */
    private final PendingNonceTracker pendingNonces = new PendingNonceTracker(PENDING_NONCE_TTL_MS);

    /** Mini-mempool of our own broadcast txs, watched for their hashes returning over
     *  devp2p gossip (Transactions 0x12 / NewPooledTransactionHashes 0x18) to confirm
     *  propagation. Fed by {@link #onTxHashSeen} (the {@code TxGossipObserver} this
     *  backend registers on the connector); cleared on verified mining or TTL. */
    private final SentTxTracker sentTxWatch = new SentTxTracker(SENT_TX_WATCH_TTL_MS);

    /** Verified location of a mined tx: the (beacon-anchored) header it sits in, the block
     *  hash, the tx index, and the raw tx bytes. Cached per tx by {@link #locateMinedTx}. */
    private record TxLocation(BlockHeader header, Bytes32 blockHash, int index, byte[] txBytes) {}

    /** Per-tx incremental-scan cursor for {@link #locateMinedTx}: how far below/above we've
     *  already scanned, the last-touched time (for TTL eviction), and the cached location once
     *  found. {@code highScanned == Long.MIN_VALUE} means "never scanned". */
    private static final class TxScanState {
        long highScanned = Long.MIN_VALUE;
        // volatile: written under synchronized(st) in locateMinedTx but read under
        // synchronized(txScanStates) in the warmer eviction tick without holding st's lock —
        // volatile guarantees visibility and a non-torn 64-bit read across platforms.
        volatile long lastTouchedMs;
        TxLocation found;
    }

    /** Scan cursors keyed by lowercase 0x tx hash. Bounded by TTL eviction in the warmer tick. */
    private final Map<String, TxScanState> txScanStates =
            java.util.Collections.synchronizedMap(new java.util.HashMap<>());

    /** Last time the warmer re-broadcast pending txs (see {@link #TX_REBROADCAST_INTERVAL_MS}). */
    private volatile long lastTxRebroadcastMs;

    /** Recently-verified block hash → number, so eth_getBlockByHash (which wallets call right
     *  after a receipt to finalize a tx) can resolve to the verified by-number path. Populated
     *  whenever we verify a block (receipt scan / getBlockByNumber). Bounded LRU. */
    private final Map<String, Long> blockHashToNumber = java.util.Collections.synchronizedMap(
            new java.util.LinkedHashMap<>(64, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, Long> e) {
                    return size() > 512;
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

    /** System property controlling state-read freshness. Default is STRICT (the tight 2-min
     *  {@link #RPC_STATE_HEAD_MAX_STALE_MS} bound, fast-fail); set
     *  {@code -Dmyotis.rpc.strictStateFreshness=false} to opt INTO relaxed serving. The
     *  Android app surfaces this as a Settings toggle (OFF by default; it sets the property
     *  before building its stacks). See OPTIMISATIONS_AND_LIMITATIONS.md §2.14. */
    public static final String STRICT_STATE_FRESHNESS_PROP = "myotis.rpc.strictStateFreshness";

    /** Max age a stale-but-anchored head may have and still be served for a STATE-execution
     *  read (eth_call / getBalance / getCode / getStorageAt / estimateGas). STRICT BY DEFAULT
     *  (the tight 2-min {@link #RPC_STATE_HEAD_MAX_STALE_MS} bound) so a read fast-fails when
     *  no fresh fully-servable root exists, rather than grinding the 120s call timeout on a
     *  stale root that passes the cheap probe but isn't fully servable. The relaxed ~13-min
     *  horizon ({@link #RPC_HEAD_SERVE_STALE_MAX_MS}) is an explicit OPT-IN via
     *  {@link #STRICT_STATE_FRESHNESS_PROP} — see the constructor and
     *  OPTIMISATIONS_AND_LIMITATIONS.md §2.14 for why relaxing the default backfired. */
    private final long stateHeadStaleCapMs;

    public VerifiedRpcBackend(RLPxConnector connector,
                              BeaconLightClient beaconLightClient,
                              BeaconSyncState beaconSyncState,
                              io.myotis.evm.ccipread.CcipGateway ccipGateway,
                              RpcLogger log,
                              RpcClock clock,
                              SnapQualitySink snapQuality) {
        this.connector = java.util.Objects.requireNonNull(connector, "connector");
        // Heavy-lane snap concurrency cap = half the live snap peers (dynamic). The 30s
        // wait is only a deadlock safety net — permits free as in-flight requests complete.
        this.snapLaneGate = new SnapLaneGate(
                () -> this.connector.activeSnapHandlers().size(), 30_000L);
        this.beaconLightClient = java.util.Objects.requireNonNull(beaconLightClient, "beaconLightClient");
        this.beaconSyncState = java.util.Objects.requireNonNull(beaconSyncState, "beaconSyncState");
        this.ccipGateway = java.util.Objects.requireNonNull(ccipGateway, "ccipGateway");
        this.log = log != null ? log : RpcLogger.noop();
        this.clock = clock != null ? clock : RpcClock.monotonic();
        this.snapQuality = snapQuality != null ? snapQuality : SnapQualitySink.noop();
        // STRICT by default. Relaxing the cap *backfired*: the cheap single-account
        // stale-serve probe can pass on an older root that isn't FULLY servable for a real
        // execution, so eth_estimateGas / eth_call then grind the full 120 s RPC_CALL_TIMEOUT
        // on unservable state instead of fast-erroring — a confirm-screen *hang* that is
        // strictly worse than the prior instant -32000 (which the wallet retries). The
        // staleness was never the true blocker; when no fully-servable root exists, failing
        // fast is the right move. Relaxed stays available as an explicit OPT-IN for anyone who
        // wants to experiment (e.g. a chain with reliably deep snap peers). Default true =
        // strict; set the property false to opt into relaxed. See OPTIMISATIONS_AND_LIMITATIONS.md §2.14.
        boolean strictFreshness = Boolean.parseBoolean(
                System.getProperty(STRICT_STATE_FRESHNESS_PROP, "true"));
        this.stateHeadStaleCapMs =
                strictFreshness ? RPC_STATE_HEAD_MAX_STALE_MS : RPC_HEAD_SERVE_STALE_MAX_MS;
        this.log.info("[rpc] state-read head staleness cap = " + (stateHeadStaleCapMs / 1000)
                + "s (" + (strictFreshness ? "strict" : "relaxed") + ")");
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
                // Mark the lane on the pool thread so snap fetches issued during this task
                // know whether to acquire a heavy permit (see SnapLaneGate / EthHandlerSnapPeer).
                SnapLaneGate.enterLane(!small);
                try {
                    task.run();
                } finally {
                    SnapLaneGate.clearLane();
                }
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
        // Register as the mempool-gossip observer so peers report tx hashes for our
        // mini-mempool. Cheap when idle: handlers consult watchingAny() first.
        connector.setTxGossipObserver(this);
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
            // Age out gossip-watch entries for sends that never mined, so the
            // event-loop gossip-decode path goes quiet once nothing of ours is live.
            try {
                sentTxWatch.evictExpired(clock.elapsedMillis());
            } catch (Throwable ignored) {
                // never kill the warmer tick
            }
            // Age out per-tx receipt-scan cursors that nothing has polled recently, so the
            // map can't grow unbounded across many lookups (see locateMinedTx).
            try {
                long cutoff = clock.elapsedMillis() - RECEIPT_SCAN_TTL_MS;
                synchronized (txScanStates) {
                    txScanStates.values().removeIf(s -> s.lastTouchedMs < cutoff);
                }
            } catch (Throwable ignored) {
                // never kill the warmer tick
            }
            // Resilient re-broadcast: re-push still-pending, not-yet-propagated txs of ours to
            // whatever peers are connected NOW (picks up peers that joined after the original
            // send). See rebroadcastPendingTxs / TX_REBROADCAST_INTERVAL_MS.
            try {
                long now = clock.elapsedMillis();
                if (now - lastTxRebroadcastMs >= TX_REBROADCAST_INTERVAL_MS) {
                    lastTxRebroadcastMs = now;
                    rebroadcastPendingTxs();
                }
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
        // Stop receiving gossip callbacks before tearing down (connector is the host's
        // to close, but our observer registration is ours to retract).
        try {
            connector.setTxGossipObserver(null);
        } catch (Exception ignored) {
            // connector may already be torn down — nothing to retract.
        }
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
        callResultCache.clear();
        estimateCache.clear();
        lastGoodLatestBlock = null;
        lastGoodFeeHistory = null;
    }

    // ---------------------------------------------------------------------
    // io.myotis.api.VerifiedReads — bridges the engine-API contract to the
    // verified machinery below, converting BigInteger ⇄ decimal-String wei and
    // byte[] ⇄ hex at the boundary. All blocking — called off the router's IO
    // dispatcher (and from the engine-API host on a worker thread).
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
    public io.myotis.api.SyncState syncState() {
        return io.myotis.api.SyncState.valueOf(beaconSyncState.getSyncState(
                connector.getNetwork().clGenesisTime(),
                connector.getNetwork().secondsPerSlot()).name());
    }

    @Override
    public byte[] call(byte[] from, byte[] to, byte[] data,
                       String valueWei, String block) {
        return rpcCall(from, to, data, parseWei(valueWei), block);
    }

    @Override
    public String getBalance(byte[] address, String block) {
        io.myotis.evm.world.AccountState a = rpcAccountState(address, block);
        return a == null ? null : a.balance().toString();
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
        if (a == null) return null;
        long mined = a.nonce();
        // TRUST NOTE — the value returned for "latest"/numbered tags IS cryptographically
        // verified: it's the account nonce proven by a SNAP proof against a beacon-verified
        // state root. The "pending" overlay below is the one exception, and deliberately so:
        //
        //   * "pending" is by definition UN-provable — there is no state root for "not yet
        //     mined", so the SNAP-proof standard cannot apply to it. The honest meaning of
        //     "pending" is "latest mined + what's in flight".
        //   * The overlay's increment is NOT proof-backed against chain state, but it isn't
        //     arbitrary either: ourPendingNonce comes from a tx WE signed and broadcast
        //     (sender recovered by ECDSA from our own signature) — authenticated intent, not
        //     a peer's claim. We never trust a peer for it.
        //   * It only ever RAISES the nonce: max(verified mined, ourPending + 1). It can
        //     never report BELOW the proven mined count, and only ever for txs we relayed
        //     ourselves.
        //   * Worst case if our view is wrong (the tx was dropped/replaced): the wallet
        //     signs against a too-high nonce and that tx waits until the gap fills; the
        //     PENDING_NONCE_TTL_MS self-heals it. The failure mode is a delayed tx, never
        //     acceptance of forged chain state.
        //
        // So this is consistent with the "everything verified" anchor (the un-provable tag
        // gets our own authenticated knowledge, bounded above the verified floor) — but the
        // asymmetry is real: do NOT extend this overlay to "latest"/numbered tags, which
        // callers and on-chain logic treat as settled, proof-backed values.
        if (block != null && block.equals("pending")) {
            return Long.valueOf(pendingNonceOverlay(address, mined));
        }
        return Long.valueOf(mined);
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
    public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) {
        // VerifiedReads passes the hash as bytes (FFI-neutral); the internal lookup keys on
        // the 0x-hex string form. Fast-fail a null/wrong-length hash as "can't answer"
        // (Java null) rather than a verified "unknown block" (JSON "null") — a malformed
        // hash names nothing, so no verified verdict about it exists.
        if (blockHash32 == null || blockHash32.length != 32) return null;
        return rpcGetBlockByHash("0x" + org.apache.tuweni.bytes.Bytes.wrap(blockHash32).toUnprefixedHexString(),
                fullTransactions);
    }

    @Override
    public String getBlockReceipts(String blockSelector) {
        return rpcGetBlockReceipts(blockSelector);
    }

    @Override
    public String gasPrice() {
        java.math.BigInteger p = rpcGasPrice();
        return p == null ? null : p.toString();
    }

    @Override
    public String maxPriorityFeePerGas() {
        java.math.BigInteger p = rpcMaxPriorityFeePerGas();
        return p == null ? null : p.toString();
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        return rpcFeeHistory(blockCount, newestBlock, rewardPercentiles);
    }

    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        java.math.BigInteger gas = rpcEstimateGas(from, to, data, parseWei(valueWei));
        return gas == null ? null : Long.valueOf(gas.longValue());
    }

    /** Decode a decimal wei string from the {@link io.myotis.api.VerifiedReads} boundary to the
     *  BigInteger the internal EVM path uses. null → null (the router validated the range). */
    private static java.math.BigInteger parseWei(String decimal) {
        return decimal == null ? null : new java.math.BigInteger(decimal);
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
            if (call.resolver() == null) {
                // Chain has no pinned ENS deployment (see prepareEnsCall): names can't be
                // resolved here, but the verified head itself is fine for non-ENS reads.
                return CompletableFuture.completedFuture(new EnsAttempt(new EnsResolution(
                        trimmed, null, call.blockNumber(), verified,
                        "ENS not available on chain id " + connector.getNetwork().networkId()), false));
            }
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
    // ENS record-type lookups (text / contenthash / multi-coin / pubkey / abi /
    // DNS / interface-implementer / reverse) — the engine home of what the
    // daemon's IPC handlers used to build ad hoc. Same RpcCallContext machinery,
    // same AUTO ladder as resolveEns.
    // ---------------------------------------------------------------------

    /**
     * One record-type lookup outcome. {@code value == null} with {@code error == null}
     * is a <em>successful</em> "no such record"; {@code error != null} is a failure.
     * {@code verified} is true iff the lookup ran against beacon-finalized state.
     */
    public record EnsRecord<T>(T value, long blockNumber, boolean verified, String error) {}

    private record RecordAttempt<T>(EnsRecord<T> record, boolean usedOffchain) {}

    /** ENSIP-5 text record. */
    public CompletableFuture<EnsRecord<String>> resolveEnsText(
            String name, String key, io.myotis.ens.EnsResolutionRoot mode) {
        return resolveRecordWithMode("resolveText", mode,
                (r, ctx) -> r.resolveText(name, key, ctx));
    }

    /** ENSIP-7 contenthash. */
    public CompletableFuture<EnsRecord<byte[]>> resolveEnsContenthash(
            String name, io.myotis.ens.EnsResolutionRoot mode) {
        return resolveRecordWithMode("resolveContenthash", mode,
                (r, ctx) -> r.resolveContenthash(name, ctx));
    }

    /** ENSIP-9 multi-coin address (SLIP-44 coin type). */
    public CompletableFuture<EnsRecord<byte[]>> resolveEnsMultiCoinAddr(
            String name, long coinType, io.myotis.ens.EnsResolutionRoot mode) {
        return resolveRecordWithMode("resolveMultiCoinAddress", mode,
                (r, ctx) -> r.resolveMultiCoinAddress(name, coinType, ctx));
    }

    /** Pubkey record (secp256k1 x/y). */
    public CompletableFuture<EnsRecord<io.myotis.ens.EnsResolver.Pubkey>> resolveEnsPubkey(
            String name, io.myotis.ens.EnsResolutionRoot mode) {
        return resolveRecordWithMode("resolvePubkey", mode,
                (r, ctx) -> r.resolvePubkey(name, ctx));
    }

    /** ABI record (ENSIP-4); {@code contentTypes} is the accepted-encodings bitmask. */
    public CompletableFuture<EnsRecord<io.myotis.ens.EnsResolver.AbiRecord>> resolveEnsAbi(
            String name, long contentTypes, io.myotis.ens.EnsResolutionRoot mode) {
        return resolveRecordWithMode("resolveAbi", mode,
                (r, ctx) -> r.resolveAbi(name, contentTypes, ctx));
    }

    /** DNS record stored in ENS (ENSIP-6); {@code dnsNameWire} is the wire-encoded name. */
    public CompletableFuture<EnsRecord<byte[]>> resolveEnsDnsRecord(
            String name, byte[] dnsNameWire, int resource, io.myotis.ens.EnsResolutionRoot mode) {
        return resolveRecordWithMode("resolveDnsRecord", mode,
                (r, ctx) -> r.resolveDnsRecord(name, dnsNameWire, resource, ctx));
    }

    /** ERC-165 interface-implementer record. */
    public CompletableFuture<EnsRecord<io.myotis.evm.Address>> resolveEnsInterfaceImplementer(
            String name, byte[] interfaceId4, io.myotis.ens.EnsResolutionRoot mode) {
        return resolveRecordWithMode("resolveInterfaceImplementer", mode,
                (r, ctx) -> r.resolveInterfaceImplementer(name, interfaceId4, ctx));
    }

    /**
     * Reverse resolution (address → primary name) with the resolver's mandatory ENSIP-3
     * forward-verification. The returned record's value is the verified name.
     */
    public CompletableFuture<EnsRecord<String>> reverseResolveEns(
            byte[] address20, io.myotis.ens.EnsResolutionRoot mode) {
        final io.myotis.evm.Address addr;
        try {
            addr = io.myotis.evm.Address.of(address20);
        } catch (RuntimeException e) {
            // Keep the family's never-throws contract even for a bad-length array.
            return CompletableFuture.completedFuture(
                    new EnsRecord<>(null, -1, false, unwrap(e)));
        }
        return resolveRecordWithMode("resolveName", mode,
                (r, ctx) -> r.resolveName(addr, ctx));
    }

    /**
     * Shared mode dispatch + snap-heavy guard for the record lookups — mirrors
     * {@link #resolveEns}: AUTO tries FINALIZED and falls back to PEER_HEAD only when the
     * record was absent AND no CCIP gateway already determined the answer. Never throws.
     */
    private <T> CompletableFuture<EnsRecord<T>> resolveRecordWithMode(
            String label, io.myotis.ens.EnsResolutionRoot mode,
            java.util.function.BiFunction<io.myotis.ens.EnsResolver, io.myotis.evm.BlockContext,
                    CompletableFuture<java.util.Optional<T>>> call) {
        RLPxConnector conn = connector;
        if (conn == null) {
            return CompletableFuture.completedFuture(
                    new EnsRecord<>(null, -1, false, "node not running"));
        }
        final io.myotis.ens.EnsResolutionRoot m =
                (mode == null) ? io.myotis.ens.EnsResolutionRoot.AUTO : mode;
        conn.enterSnapHeavy();
        // Same synchronous-throw guard as resolveEns: supplyAsync can reject before any
        // future exists; don't leak the snap-heavy state on that path.
        try {
            final CompletableFuture<EnsRecord<T>> result;
            if (m == io.myotis.ens.EnsResolutionRoot.AUTO) {
                result = attemptResolveRecord(label, io.myotis.ens.EnsResolutionRoot.FINALIZED, call)
                        .thenCompose(fin -> {
                            if (fin.record().value() != null || fin.usedOffchain()) {
                                return CompletableFuture.completedFuture(fin.record());
                            }
                            return attemptResolveRecord(label,
                                    io.myotis.ens.EnsResolutionRoot.PEER_HEAD, call)
                                    .thenApply(RecordAttempt::record);
                        });
            } else {
                result = attemptResolveRecord(label, m, call).thenApply(RecordAttempt::record);
            }
            return result.whenComplete((r, ex) -> conn.exitSnapHeavy());
        } catch (Throwable t) {
            conn.exitSnapHeavy();
            return CompletableFuture.completedFuture(
                    new EnsRecord<>(null, -1, false, unwrap(t)));
        }
    }

    /** One record-lookup attempt against {@code root}. Never throws (mirrors
     *  {@link #attemptResolveEns}); an absent record is value=null with error=null. */
    private <T> CompletableFuture<RecordAttempt<T>> attemptResolveRecord(
            String label, io.myotis.ens.EnsResolutionRoot root,
            java.util.function.BiFunction<io.myotis.ens.EnsResolver, io.myotis.evm.BlockContext,
                    CompletableFuture<java.util.Optional<T>>> call) {
        return CompletableFuture.<RpcCallContext>supplyAsync(() -> {
            try {
                return prepareEnsCall(root);
            } catch (Exception e) {
                throw new java.util.concurrent.CompletionException(e);
            }
        }, evmPool).thenCompose(ctx -> {
            final boolean verified = ctx.beaconVerified();
            if (ctx.resolver() == null) {
                return CompletableFuture.completedFuture(new RecordAttempt<T>(new EnsRecord<>(
                        null, ctx.blockNumber(), verified,
                        "ENS not available on chain id " + connector.getNetwork().networkId()),
                        false));
            }
            return call.apply(ctx.resolver(), ctx.blockCtx())
                    .orTimeout(ENS_TIMEOUT_SEC, TimeUnit.SECONDS)
                    .handle((opt, ex) -> {
                        final boolean usedOffchain = ctx.offchainExecutor().usedOffchain();
                        if (ex != null) {
                            log.info("[ens] " + label + " failed: " + unwrap(ex));
                            return new RecordAttempt<T>(new EnsRecord<>(
                                    null, ctx.blockNumber(), verified, unwrap(ex)), usedOffchain);
                        }
                        T value = (opt == null || opt.isEmpty()) ? null : opt.get();
                        return new RecordAttempt<T>(new EnsRecord<>(
                                value, ctx.blockNumber(), verified, null), usedOffchain);
                    });
        }).exceptionally(ex -> {
            Throwable cause = (ex instanceof java.util.concurrent.CompletionException
                    && ex.getCause() != null) ? ex.getCause() : ex;
            return new RecordAttempt<T>(new EnsRecord<>(null, -1,
                    root == io.myotis.ens.EnsResolutionRoot.FINALIZED, unwrap(cause)), false);
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
        RpcCallContext ctx = anchoredHeadOrWait(stateHeadStaleCapMs, true);
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
     *  #RPC_HEAD_SERVE_STALE_MAX_MS}. {@code probeStaleServe} (state reads only) probes
     *  that a connected peer actually serves the stale head's root before returning it
     *  — so a doomed read fast-errors in ~{@link #RPC_STALE_PROBE_TIMEOUT_SEC}s instead
     *  of handing the dead root to a 30s callView that StateUnavailable-times-out. */
    private RpcCallContext anchoredHeadOrWait(long maxStaleMs, boolean probeStaleServe) {
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
            // Probe-before-serve for STATE reads: the rebuild just failed, so this aged
            // root may no longer be snap-servable. A quick probe (~RPC_STALE_PROBE_TIMEOUT
            // s) that some peer still serves it turns the common "serve dead root → 30s
            // StateUnavailable timeout, ×20 across a confirm-screen burst" into a fast
            // clean error the wallet can retry. Header-only callers skip the probe (they
            // anchor headers, not state). Cached briefly so a burst shares one probe.
            if (probeStaleServe && !anyPeerServesRoot(stale.head().blockCtx().stateRoot())) {
                log.info("[rpc] STALE head #" + stale.head().blockNumber() + " ("
                        + (clock.elapsedMillis() - stale.builtAtMs()) / 1000
                        + "s old) not snap-servable by any peer -> fast-error (skip 30s callView)");
                return null;
            }
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
            long optimisticHeadNum = -1;
            BeaconLightClient blcFloor = beaconLightClient;
            if (blcFloor != null) {
                com.jaeckel.ethp2p.consensus.types.LightClientHeader finHdr =
                        blcFloor.getStore().getFinalizedHeader();
                if (finHdr != null) finalizedFloor = finHdr.execution().blockNumber();
                com.jaeckel.ethp2p.consensus.types.LightClientHeader optHdr =
                        blcFloor.getStore().getOptimisticHeader();
                if (optHdr != null) optimisticHeadNum = optHdr.execution().blockNumber();
            }
            final long headFloor = Math.max(minHead, finalizedFloor);
            // When we have a beacon finalized anchor, probe each peer for its LIVE head by
            // NUMBER (forward window from the finalized block — which every fresh peer holds)
            // instead of its frozen connect-time Status hash. The Status hash never advances,
            // so a long-lived peer's "fresh head" drifts below headFloor as the chain moves and
            // starves GREEN once the LC is synced (acute on chains with few, sticky snap peers
            // like Gnosis). Window spans finalized→head so the result lands at/just above the
            // beacon-verified head; cap it so the response stays small on mobile links.
            final boolean byNumberProbe = finalizedFloor > 0;
            final long probeFrom = finalizedFloor;
            final int probeWindow = byNumberProbe
                    ? (int) Math.max(16, Math.min(256,
                        (optimisticHeadNum > finalizedFloor ? optimisticHeadNum - finalizedFloor : 0) + 16))
                    : 0;
            // Probe every ready snap peer CONCURRENTLY — fetch its fresh head, then
            // probe that it snap-serves that head root — and award the FIRST to
            // qualify. The old serial walk paid each unresponsive peer's timeout in
            // turn (the dominant build cost, and a frequent fallback trigger);
            // running the probes in parallel collapses that to ~one round-trip.
            List<CompletableFuture<PeerHead>> probes = new ArrayList<>();
            for (EthHandler peer : snapPeers) {
                if (!peer.isReady() || peer.isSnapServingFailed()) continue;
                CompletableFuture<BlockHeader> headFut = byNumberProbe
                        ? peer.requestFreshHeadHeaderAsync(probeFrom, probeWindow)
                        : peer.requestFreshHeadHeaderAsync();
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
        // Peers PROVEN to serve THIS root (returned a non-empty proof). Once the first
        // fetch wave discovers which peers retain the trie, every later fetch goes
        // STRAIGHT to a known server (load-balanced) instead of re-rolling the dice on
        // untried peers — most of which lag the head and would deny+retry. This is what
        // turns "16 peers, ~4 usable, rediscovered every wave" into "lock onto the ~4
        // servers and stay there", which also lets a rebuild converge fast and the head
        // stay up through peer churn. The probed peer seeds it.
        final java.util.Set<EthHandler> rootServed =
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
                            // PREFER peers already proven to serve this root — load-balance
                            // across just them (skip the deny+retry discovery cost).
                            List<EthHandler> served = new ArrayList<>();
                            for (EthHandler p : rootServed) {
                                if (p.isReady() && !p.isSnapServingFailed()
                                        && !rootDenied.contains(p)) served.add(p);
                            }
                            if (!served.isEmpty()) {
                                final EthHandler chosen = served.get(Math.floorMod(n, served.size()));
                                return new EthHandlerSnapPeer(
                                        chosen,
                                        () -> { rootDenied.add(chosen); rootServed.remove(chosen);
                                                recordSnapQuality(chosen, false); },
                                        () -> { rootServed.add(chosen); recordSnapQuality(chosen, true); },
                                        snapLaneGate);
                            }
                            // Discovery phase (none proven yet): probed peer first (known to
                            // serve), then round-robin the rest of the ready snap set.
                            if (n == 0 && probedPeer.isReady() && !probedPeer.isSnapServingFailed()
                                    && !rootDenied.contains(probedPeer)) {
                                final EthHandler pp = probedPeer;
                                return new EthHandlerSnapPeer(
                                        pp,
                                        () -> { rootDenied.add(pp); rootServed.remove(pp);
                                                recordSnapQuality(pp, false); },
                                        () -> { rootServed.add(pp); recordSnapQuality(pp, true); },
                                        snapLaneGate);
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
                                    () -> { rootDenied.add(chosen); rootServed.remove(chosen);
                                            recordSnapQuality(chosen, false); },
                                    () -> { rootServed.add(chosen); recordSnapQuality(chosen, true); });
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
        // ENS is optional: only resolveEnsName() uses the resolver — get-account,
        // get-storage and eth_call all run off executor/oracle/blockCtx. On chains with
        // no pinned ENS deployment (e.g. Gnosis, chainId 100) forChainId() throws; that
        // must NOT abort the whole verified-head build, or the head warmer can never pin
        // a PEER_HEAD context and the node never reaches GREEN. Leave the resolver null
        // and let resolveEnsName() fail gracefully for those chains.
        io.myotis.ens.EnsResolver resolver;
        try {
            resolver = io.myotis.ens.EnsResolver.forChainId(executor, conn.getNetwork().networkId());
        } catch (IllegalArgumentException noEns) {
            resolver = null;
        }
        return new RpcCallContext(resolver, blockCtx, blockNumber, verified, executor, oracle);
    }

    /** First ready snap peer that returns a non-empty account proof at {@code root},
     *  or null. Probes all peers CONCURRENTLY (same rationale as the PEER_HEAD probe)
     *  and awards the first to serve the root. */
    private EthHandler firstPeerServing(List<EthHandler> peers, Bytes32 root) {
        return firstPeerServing(peers, root, PEER_PROBE_TIMEOUT_SEC);
    }

    private EthHandler firstPeerServing(List<EthHandler> peers, Bytes32 root, long timeoutSec) {
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
            return firstSuccess(probes, timeoutSec);
        } catch (Exception e) {
            return null;
        }
    }

    /** Quick liveness probe (≤{@link #RPC_STALE_PROBE_TIMEOUT_SEC}s) that at least one
     *  connected snap peer serves {@code stateRoot} right now — used before handing a
     *  STALE head to a state callView so a doomed read fails fast instead of timing out.
     *  Verdict cached for {@link #STALE_PROBE_CACHE_MS} keyed by root so a confirm-screen
     *  burst on one root shares a single probe rather than hammering every peer N times. */
    private record ProbeVerdict(byte[] root, boolean servable, long atMs) {}
    /** One immutable unit behind a single volatile so root, verdict and timestamp are
     *  read/written atomically together — a reader can't pair a fresh root with a stale
     *  timestamp/verdict (same pattern as {@link HeadWithTimestamp} / {@code FeeSnapshot}). */
    private volatile ProbeVerdict lastRootProbe;
    /** Serializes the probe itself: a confirm-screen burst of ~20 state reads hitting an
     *  expired verdict at once must run ONE network probe, not 20 concurrent ones that
     *  hammer every peer with duplicate requests (a thundering herd on exactly the
     *  degraded path). Losers block on the lock and reuse the winner's fresh verdict. */
    private final Object rootProbeLock = new Object();

    private boolean anyPeerServesRoot(byte[] stateRoot) {
        if (stateRoot == null) return false;
        ProbeVerdict v = lastRootProbe;
        if (v != null && java.util.Arrays.equals(v.root(), stateRoot)
                && clock.elapsedMillis() - v.atMs() < STALE_PROBE_CACHE_MS) {
            return v.servable();
        }
        synchronized (rootProbeLock) {
            // Re-check under the lock: the thread that held it before us probably just
            // probed this exact root — reuse its verdict instead of re-probing.
            v = lastRootProbe;
            if (v != null && java.util.Arrays.equals(v.root(), stateRoot)
                    && clock.elapsedMillis() - v.atMs() < STALE_PROBE_CACHE_MS) {
                return v.servable();
            }
            RLPxConnector c = connector;
            List<EthHandler> peers = (c == null) ? List.of() : c.activeSnapHandlers();
            boolean ok = !peers.isEmpty()
                    && firstPeerServing(peers, Bytes32.wrap(stateRoot), RPC_STALE_PROBE_TIMEOUT_SEC) != null;
            lastRootProbe = new ProbeVerdict(stateRoot.clone(), ok, clock.elapsedMillis());
            return ok;
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
    private byte[] rpcCall(byte[] from, byte[] to, byte[] data,
                           java.math.BigInteger value, String block) {
        // Keep the early-rejection logs correlatable with the wallet call that triggered
        // them: include target + 4-byte selector, matching the richer `desc` logging below.
        String callCtx = " to=" + (to != null && to.length == 20 ? Bytes.wrap(to).toHexString() : "?")
                + " sel=" + (data != null && data.length >= 4 ? Bytes.wrap(data, 0, 4).toHexString() : "0x");
        if (from != null && from.length != 20) {
            log.info("[rpc] eth_call -> malformed from (len=" + from.length + ")" + callCtx);
            return null;
        }
        // Defence in depth (the router already screens this): wei is non-negative, and a
        // negative value would throw IllegalArgumentException in Wei.of down in the executor.
        // Return null so the router centrally manages the fallback instead.
        if (value != null && value.signum() < 0) {
            log.info("[rpc] eth_call -> negative value (" + value + ")" + callCtx);
            return null;
        }
        // Identify the call up front: caller + target + 4-byte selector + calldata size
        // + block tag. eth_call failures were undiagnosable as "eth_call -> proxy:
        // Timeout" — with hundreds of MetaMask poll variants we need to know WHICH
        // contract/method is being asked for (e.g. its confirm-screen simulation
        // multicall), and by WHOM (a from-gated transfer/approve simulation differs
        // from an anonymous read).
        String desc = "from=" + (from != null && from.length == 20 ? Bytes.wrap(from).toHexString() : "0x0")
                + " to=" + (to != null && to.length == 20 ? Bytes.wrap(to).toHexString() : "?")
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
        // SINGLE-FLIGHT identical calls. MetaMask fires the same eth_call 4-6x
        // concurrently (observed live: its ~32KB BalanceChecker token sweep, and the
        // confirm screen's Multicall3 simulation retries) — each copy independently
        // re-running the same EVM execution and, far worse, the same snap fetch waves
        // against the few mobile peers. On a phone that multiplies hundreds of
        // account/storage round-trips by N for ONE answer, starving the gating calls
        // (fee simulation, estimateGas) into 30s timeouts. Key the in-flight execution
        // by (stateRoot, to, calldata): identical inputs against the same verified
        // context compute the identical verified result, so duplicates can safely
        // share one execution — this changes scheduling, never verification. Each
        // waiter keeps its own 30s deadline; the entry is removed when the execution
        // completes so a later retry re-executes fresh.
        // Key by (stateRoot, from, to, value, calldata): the sender and value are now
        // part of the input — a transfer simulated by vitalik vs by the zero address
        // computes a DIFFERENT verified result, so they must not share an execution.
        String flightKey = Bytes.wrap(h.blockCtx().stateRoot()).toHexString()
                + ":" + (from == null ? "0x0" : Bytes.wrap(from).toHexString())
                + ":" + Bytes.wrap(to).toHexString()
                + ":" + (value == null ? "0" : value.toString())
                + ":" + (data == null ? "0x" : Hash.keccak256(Bytes.wrap(data)).toHexString());
        // Warm-result replay: a prior execution for this exact (root, target, calldata)
        // already produced a verified answer — possibly one whose original waiter timed
        // out but whose background leader finished and populated the cache. Replay it; the
        // result is deterministic given the anchored stateRoot, so this skips the whole
        // EVM + snap-fetch round entirely (the retried-confirm-screen fast path).
        byte[] cached = callResultCache.get(flightKey, clock.elapsedMillis());
        if (cached != null) {
            log.info("[rpc] eth_call " + desc + " ok in "
                    + (clock.elapsedMillis() - t0) + "ms (cached)");
            return cached.clone();   // hand each reader its own copy; never expose the cached array
        }
        // Route small calls onto the reserved EVM lane so a confirm screen's tiny
        // probes/simulations never queue behind a ~32KB token-sweep storm. The hint
        // is read synchronously by evmPool when callView's supplyAsync submits on
        // this thread; cleared in finally so the handler thread doesn't leak it.
        boolean smallLane = (data == null || data.length <= EVM_SMALL_CALLDATA_MAX);
        if (smallLane) EVM_SMALL_LANE.set(Boolean.TRUE);
        boolean leader = false;
        CompletableFuture<byte[]> flight;
        try {
            CompletableFuture<byte[]> mine = new CompletableFuture<>();
            CompletableFuture<byte[]> existing = inflightCalls.putIfAbsent(flightKey, mine);
            if (existing != null) {
                flight = existing;   // duplicate: ride the leader's execution
            } else {
                leader = true;
                flight = mine;
                // callView can throw SYNCHRONOUSLY (e.g. RejectedExecutionException from
                // a saturated/shutting-down pool) — without this guard, `mine` would stay
                // forever-incomplete AND forever-registered, poisoning every later
                // identical call into a guaranteed timeout. On a sync throw, deregister
                // and complete exceptionally so waiters fail fast and a retry re-executes.
                try {
                    h.offchainExecutor()
                            .callView(from == null ? null : io.myotis.evm.Address.of(from),
                                    io.myotis.evm.Address.of(to),
                                    data == null ? new byte[0] : data,
                                    value, h.blockCtx())
                            .whenComplete((out, ex) -> {
                                try {
                                    if (ex != null) {
                                        mine.completeExceptionally(ex);
                                    } else {
                                        // Populate the replay cache from the LEADER's completion,
                                        // which fires even if our waiter already timed out and gave
                                        // up — so a call the wallet abandoned still lands warm for
                                        // the retry. Verified before insertion (proven against this
                                        // root by the oracle during execution). Store a clone: `out`
                                        // is handed to the waiter below, so caching the same reference
                                        // would let the waiter mutate the cached value.
                                        callResultCache.put(flightKey,
                                                out != null ? out.clone() : null, clock.elapsedMillis());
                                        mine.complete(out);
                                    }
                                } finally {
                                    // Release the dedup guard only AFTER the cache is warm, so a
                                    // concurrent identical call falls through to the warm result
                                    // instead of racing into a redundant execution in the gap
                                    // between guard-release and cache-fill.
                                    inflightCalls.remove(flightKey, mine);
                                }
                            });
                } catch (Throwable t) {
                    inflightCalls.remove(flightKey, mine);
                    mine.completeExceptionally(t);
                }
            }
            byte[] out = flight.get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            log.info("[rpc] eth_call " + desc + " ok in "
                    + (clock.elapsedMillis() - t0) + "ms" + (leader ? "" : " (deduped)"));
            return out;
        } catch (Exception e) {
            log.info("[rpc] eth_call " + desc + " -> error after "
                    + (clock.elapsedMillis() - t0) + "ms"
                    + (leader ? "" : " (deduped)") + ": " + describeEvmError(e));
            if (isStateUnavailable(e)) evictUnservableHead(h);
            return null;
        } finally {
            if (smallLane) EVM_SMALL_LANE.remove();
        }
    }

    /** In-flight eth_call executions keyed by (stateRoot, to, keccak(calldata)) so
     *  concurrent identical calls share ONE EVM execution + snap fetch wave. Entries
     *  remove themselves on completion (see rpcCall); bounded by the number of
     *  distinct concurrent calls a wallet makes (~tens). */
    private final Map<String, CompletableFuture<byte[]>> inflightCalls =
            new java.util.concurrent.ConcurrentHashMap<>();

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
        // Don't collapse the head on a TRANSIENT failure. A single StateUnavailable can
        // come from the oracle's rotation denying peers that merely timed out (slow /
        // overloaded under a confirm-screen fetch burst), not peers that truly lack the
        // root. Nulling lastGoodHead on that strands the nonce (eth_getTransactionCount)
        // and every state read until a full rebuild — observed on-device: the head went
        // to Long.MAX_VALUE-stale mid-send and the Confirm button did nothing. Re-probe
        // first: if ANY connected peer still serves this root, KEEP the head — the pool
        // dipped but the head is alive. Only evict when the root is genuinely unservable
        // by the whole pool (the real pruned-root case eviction exists for). The probe
        // verdict is cached (STALE_PROBE_CACHE_MS), so a burst of failures shares one.
        if (anyPeerServesRoot(doomed.blockCtx().stateRoot())) {
            log.info("[rpc] StateUnavailable on head #" + doomed.blockNumber()
                    + " but a peer still serves its root — keeping head (transient)");
            return;
        }
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
            recordPendingNonce(rawTx);
            // Watch for this hash to come back over gossip (propagation confirmation), and record
            // the head block at broadcast so a late receipt poll can deep-scan back to where the
            // tx could first have been mined (see locateMinedTx) instead of only the recent window.
            Long broadcastHead = headBlockNumber();
            sentTxWatch.watch(Bytes32.wrap(txHash), clock.elapsedMillis(),
                    broadcastHead != null ? broadcastHead : -1L);
            log.info("[rpc] eth_sendRawTransaction broadcast to " + sent
                    + " peer(s), hash=" + Bytes.wrap(txHash).toHexString());
            return txHash;
        } catch (Exception e) {
            log.info("[rpc] eth_sendRawTransaction failed: " + unwrap(e));
            return null;
        }
    }

    /** Re-broadcast still-pending, not-yet-propagated txs of ours to ALL currently-READY peers.
     *  Called on a cadence from the warmer (see {@link #TX_REBROADCAST_INTERVAL_MS}). Only txs
     *  we have NOT yet seen echo back on gossip are re-pushed — once one propagates, the network
     *  has it and re-pushing won't change whether it mines. Re-sending to a peer that already
     *  holds the tx is harmless (it dedupes); the point is to reach peers that connected after
     *  the original one-shot send, which on Gnosis may have reached almost no one. */
    private void rebroadcastPendingTxs() {
        SentTxTracker watch = sentTxWatch;
        if (!watch.watchingAny()) return;
        RLPxConnector conn = connector;
        if (conn == null) return;
        for (Bytes32 h : watch.unseen()) {
            byte[] raw = sentTxCache.get(h.toHexString());
            if (raw == null) continue; // bytes aged out of the LRU — can't re-push
            int sent = conn.broadcastTransaction(raw);
            if (sent > 0) {
                log.info("[rpc] re-broadcast pending tx " + h.toHexString()
                        + " to " + sent + " peer(s)");
            }
        }
    }

    /** Record the (sender, nonce) of a tx we just broadcast so a follow-up
     *  eth_getTransactionCount("pending") from that sender reports next = nonce + 1
     *  instead of reusing this still-pending nonce. Decodes the sender from the signed
     *  bytes (ECDSA recovery — our own tx, no trust involved). Keeps only the highest
     *  nonce per sender; a malformed/undecodable tx is silently skipped (we already
     *  broadcast it — the overlay is best-effort, not a gate). */
    // ---------------------------------------------------------------------
    // TxGossipObserver: watch our own broadcast txs propagate over gossip
    // ---------------------------------------------------------------------

    /** Hot-path guard read by every peer's gossip handler — true only while we hold an
     *  unconfirmed broadcast of our own, so the firehose is otherwise dropped untouched. */
    @Override
    public boolean watchingAny() {
        return sentTxWatch.watchingAny();
    }

    /** A tx hash observed on the network. We only act when it's one of OUR broadcasts
     *  (cheap miss otherwise), logging the first sighting as propagation confirmation. */
    @Override
    public void onTxHashSeen(Bytes32 txHash) {
        long ms = sentTxWatch.markSeen(txHash, clock.elapsedMillis());
        if (ms >= 0) {
            log.info("[mini-mempool] our tx " + txHash.toHexString()
                    + " seen propagating on the network " + ms + "ms after broadcast");
        }
    }

    private void recordPendingNonce(byte[] rawTx) {
        try {
            var t = com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.decode(Bytes.wrap(rawTx));
            if (t == null || t.from() == null) return;
            String key = t.from().toHexString().toLowerCase();
            pendingNonces.record(key, t.nonce(), clock.elapsedMillis());
            log.info("[rpc] pending-nonce: " + key + " -> " + t.nonce() + " (broadcast)");
        } catch (Exception e) {
            // best-effort overlay; never fail the send over bookkeeping
        }
    }

    /** Overlay our own broadcast-but-unmined nonce onto a freshly-read mined count.
     *  Returns {@code max(minedCount, ourPendingNonce + 1)} while the chain hasn't yet
     *  reflected our send, so a second back-to-back send from the same account gets the
     *  next nonce instead of colliding. Only consulted for the "pending" tag. */
    private long pendingNonceOverlay(byte[] address, long minedCount) {
        String key = Bytes.wrap(address).toHexString().toLowerCase();
        long now = clock.elapsedMillis();
        long pending = pendingNonces.pendingNonce(key);
        long next = pendingNonces.overlay(key, minedCount, now);
        if (next != minedCount) {
            log.info("[rpc] pending-nonce: " + key + " overlay mined=" + minedCount
                    + " -> " + next + " (our nonce " + pending + " still pending)");
        }
        return next;
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
            TxLocation loc = locateMinedTx(conn, want);
            if (loc != null) {
                // Verified inclusion: stop watching it for gossip propagation.
                sentTxWatch.confirmMined(want);
                log.info("[rpc] eth_getTransactionByHash found in block #"
                        + loc.header().number + " index " + loc.index());
                return buildTxJson(loc.txBytes(), want, loc.blockHash(),
                        loc.header().number, loc.index());
            }
            // Not located in the verified scan. If it's our own just-sent tx we can honestly
            // answer "pending" from the signed bytes we hold.
            byte[] ourRaw = sentTxCache.get(want.toHexString());
            if (ourRaw != null) return buildTxJson(ourRaw, want, null, -1, -1);
            // Otherwise: "null" (verified-unknown) when we have an anchor, Java null (can't
            // verify → router error) when we don't.
            return headerAnchor() == null ? null : "null";
        } catch (Exception e) {
            // Restore interrupt status if a wrapped Future.get() was interrupted, so
            // cancellation propagates instead of being swallowed by the generic catch.
            if (e instanceof InterruptedException || e.getCause() instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.info("[rpc] eth_getTransactionByHash failed: " + unwrap(e));
            return null;
        }
    }

    /**
     * Incrementally scan beacon-anchored blocks for {@code want}, remembering per-tx how far
     * we have already scanned so each poll fetches only the blocks that appeared since the
     * previous one. Returns the verified {@link TxLocation} once found (cached thereafter), or
     * {@code null} if the tx has not been seen in the coverage scanned so far (or no header
     * anchor is available yet).
     *
     * <p>This replaces the old flat {@code RECEIPT_LOOKBACK_BLOCKS} window, which made a mined
     * tx discoverable for only ~8 blocks before the moving head scrolled it out of view for
     * good. Coverage now grows to span the whole time a tx is watched while keeping per-poll
     * cost to roughly the number of new blocks (usually one), capped at
     * {@link #RECEIPT_MAX_SCAN_BLOCKS_PER_POLL} so a long polling gap can't trigger a huge
     * fetch. Bodies are still verified against {@code transactionsRoot}; nothing is trusted.
     */
    private TxLocation locateMinedTx(RLPxConnector conn, Bytes32 want) throws Exception {
        String key = want.toHexString();
        long now = clock.elapsedMillis();
        TxScanState st = txScanStates.computeIfAbsent(key, k -> new TxScanState());
        synchronized (st) {
            st.lastTouchedMs = now;

            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return st.found; // can't re-check now; prior verification stands
            long head = anchor.number();

            if (st.found != null) {
                // A finalized block is immutable — trust the cache. While the tx's block is
                // still near head it can be reorged out (the old flat-window code re-scanned
                // live every poll, so it never went stale); re-confirm canonicality cheaply.
                long finalizedNum = finalizedExecBlockNumber();
                if (finalizedNum >= 0 && st.found.header().number <= finalizedNum) return st.found;
                if (stillCanonical(conn, anchor, st.found)) return st.found;
                // Reorged out: drop the cache and rescan the recent region from scratch.
                st.found = null;
                st.highScanned = Long.MIN_VALUE;
            }
            long from = (st.highScanned == Long.MIN_VALUE)
                    ? head - RECEIPT_INITIAL_LOOKBACK_BLOCKS + 1
                    : st.highScanned + 1;
            // For our OWN sent txs, the first scan reaches back to the head block recorded at
            // broadcast — otherwise the forward-only window misses a tx mined >INITIAL_LOOKBACK
            // blocks before the first SUCCESSFUL poll (e.g. peers were flaky for a minute, then
            // the tx's block already scrolled out of the small window). Bounded by capFloor below;
            // the sent-tx watch TTL keeps the broadcast head recent (well within the cap).
            if (st.highScanned == Long.MIN_VALUE) {
                long bcHead = sentTxWatch.broadcastHead(want);
                if (bcHead >= 0 && bcHead < from) from = bcHead;
            }
            // Cap catch-up after a gap; blocks below this are skipped (better than the old
            // 8-block ceiling, and the tx is usually long-confirmed by then anyway).
            long capFloor = head - RECEIPT_MAX_SCAN_BLOCKS_PER_POLL + 1;
            if (from < capFloor) {
                log.info("[rpc] tx scan: catch-up gap, skipping blocks #" + from + "..#"
                        + (capFloor - 1) + " (cap " + RECEIPT_MAX_SCAN_BLOCKS_PER_POLL + ")");
                from = capFloor;
            }
            if (from < 0) from = 0;
            if (from > head) return null; // head hasn't advanced since last scan

            int count = (int) (head - from + 1);
            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(from, count)
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            // The window ends at the verified head and must hash-link back; if it can't be
            // anchored, don't advance the cursor — retry the same range next poll.
            if (!anchor.anchors(window)) {
                log.info("[rpc] tx scan: header window failed to anchor");
                return null;
            }
            st.highScanned = head;

            List<CompletableFuture<List<BlockBodiesMessage.BlockBody>>> bodyFutures =
                    new ArrayList<>(window.size());
            for (BlockHeadersMessage.VerifiedHeader vh : window) {
                bodyFutures.add(conn.requestBlockBodies(vh.hash()));
            }
            // Newest-first: a just-mined tx is found on the first body checked.
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
                if (!OrderedTrieRoot.verify(txs, h.transactionsRoot)) {
                    log.info("[rpc] block #" + h.number + " body failed transactionsRoot verify");
                    continue;
                }
                for (int i = 0; i < txs.size(); i++) {
                    if (Hash.keccak256(txs.get(i)).equals(want)) {
                        TxLocation loc = new TxLocation(h, blockHash, i, txs.get(i).toArrayUnsafe());
                        st.found = loc;
                        // Pre-populate for the eth_getBlockByHash the wallet issues next.
                        blockHashToNumber.put(blockHash.toHexString(), h.number);
                        return loc;
                    }
                }
            }
            return null;
        }
    }

    /** Beacon-finalized execution block number, or -1 if the light client has no finalized
     *  header yet. A tx in a block at/below this height is immutable — its cached location can
     *  be trusted without re-checking for reorgs. */
    private long finalizedExecBlockNumber() {
        BeaconLightClient blc = beaconLightClient;
        if (blc == null) return -1;
        try {
            com.jaeckel.ethp2p.consensus.types.LightClientHeader fin =
                    blc.getStore().getFinalizedHeader();
            return fin != null ? fin.execution().blockNumber() : -1;
        } catch (Exception e) {
            return -1;
        }
    }

    /** True if {@code loc}'s block is still on the canonical chain under {@code anchor}: re-fetch
     *  the headers from that block up to the verified head, anchor them, and confirm the hash at
     *  loc's height still matches. Conservatively returns true when it can't disprove canonicality
     *  (transient peer hiccup, implausibly large range) so a glitch never flips a real receipt to
     *  "unknown"; returns false only on a proven hash mismatch / head dropping below the block. */
    private boolean stillCanonical(RLPxConnector conn, HeaderAnchor anchor, TxLocation loc)
            throws Exception {
        long head = anchor.number();
        long blockNum = loc.header().number;
        if (blockNum > head) return false; // head sits below it — deep reorg
        long count = head - blockNum + 1;
        if (count <= 0 || count > RECEIPT_MAX_SCAN_BLOCKS_PER_POLL) return true; // too far to recheck
        List<BlockHeadersMessage.VerifiedHeader> window = conn
                .requestBlockHeadersBatched(blockNum, (int) count)
                .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
        if (window.isEmpty() || !anchor.anchors(window)) return true; // can't disprove → keep
        return window.get(0).hash().equals(loc.blockHash());
    }

    /** Effective gas price actually paid per the receipt convention: the legacy/2930 gasPrice,
     *  or for EIP-1559 txs {@code baseFee + min(maxPriorityFee, maxFee - baseFee)} using this
     *  block's base fee. Null if the tx carries neither (shouldn't happen for a decoded tx). */
    private static java.math.BigInteger effectiveGasPrice(
            com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.DecodedTx tx, BlockHeader h) {
        if (tx.gasPrice() != null) return tx.gasPrice();
        if (tx.maxFeePerGas() == null) return null;
        java.math.BigInteger base = h.baseFeePerGas != null ? h.baseFeePerGas : java.math.BigInteger.ZERO;
        java.math.BigInteger prio = tx.maxPriorityFeePerGas() != null
                ? tx.maxPriorityFeePerGas() : java.math.BigInteger.ZERO;
        java.math.BigInteger room = tx.maxFeePerGas().subtract(base);
        if (room.signum() < 0) room = java.math.BigInteger.ZERO;
        return base.add(prio.min(room));
    }

    /** Contract address created by a {@code to == null} (creation) tx: {@code keccak256(rlp([from,
     *  nonce]))[12:]}. Null for ordinary calls or if the sender couldn't be recovered. */
    private static String contractAddressFor(
            com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.DecodedTx tx) {
        if (tx.from() == null) return null;
        try {
            Bytes rlp = org.apache.tuweni.rlp.RLP.encodeList(w -> {
                w.writeValue(Bytes.wrap(tx.from().toArrayUnsafe()));
                w.writeLong(tx.nonce());
            });
            Bytes32 hash = org.apache.tuweni.crypto.Hash.keccak256(rlp);
            return hash.slice(12, 20).toHexString();
        } catch (Exception e) {
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
            Bytes32 want = Bytes32.wrap(txHash);
            // Incremental beacon-anchored scan (snap head preferred, beacon optimistic
            // fallback): receipts need verified headers + bodies, not snap state, so this
            // path keeps working through snap-peer outages — see headerAnchor()/locateMinedTx.
            TxLocation loc = locateMinedTx(conn, want);
            if (loc == null) {
                // No anchor → couldn't verify (Java null → router error). Anchored but not
                // seen yet → a VERIFIED "not seen": JSON-null literal (eth's pending/unknown).
                return headerAnchor() == null ? null : "null";
            }
            BlockHeader h = loc.header();
            // Fetch + verify the block's receipts against the (beacon-anchored) receiptsRoot.
            List<List<Bytes>> rcptBlocks = conn
                    .requestReceipts(loc.blockHash())
                    // Future.get(timeout) kept (over CompletableFuture.orTimeout) so the
                    // same code runs unmodified on Android API 29 hosts.
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (rcptBlocks.isEmpty()) return null;
            List<Bytes> receipts = rcptBlocks.get(0);
            if (!OrderedTrieRoot.verify(receipts, h.receiptsRoot)) {
                log.info("[rpc] block #" + h.number + " receipts failed receiptsRoot verify");
                return null;
            }
            if (loc.index() >= receipts.size()) return null;
            // Verified inclusion: stop watching/re-broadcasting it (mirrors getTransactionByHash).
            sentTxWatch.confirmMined(want);
            log.info("[rpc] eth_getTransactionReceipt verified tx in block #"
                    + h.number + " index " + loc.index());
            return buildReceiptJson(receipts, loc.index(), h, loc.blockHash(), want, loc.txBytes());
        } catch (Exception e) {
            if (e instanceof InterruptedException || e.getCause() instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.info("[rpc] eth_getTransactionReceipt failed: " + unwrap(e));
            return null; // couldn't verify → router errors (not a misleading "pending")
        }
    }

    /** Build the eth_getTransactionReceipt JSON object from VERIFIED receipt bytes.
     *  {@code txHash} is the body's tx hash (already confirmed == the requested hash).
     *  This single-receipt entry computes the running accumulators with a one-shot
     *  pass over the preceding receipts; the batch path (eth_getBlockReceipts)
     *  accumulates them across its loop instead, calling the shared
     *  {@link #buildReceiptJsonAt} so a full block stays O(n). */
    private static String buildReceiptJson(List<Bytes> receipts, int idx,
                                           BlockHeader h, Bytes32 blockHash, Bytes32 txHash,
                                           byte[] rawTx) {
        // Single pass over the preceding receipts: gasUsed needs receipt[idx-1]'s
        // cumulative, logIndex needs the running log count — decode each only once.
        long prevCum = 0L;
        int logBase = 0;
        for (int j = 0; j < idx; j++) {
            Receipt prev = Receipt.decode(receipts.get(j));
            logBase += prev.logs().size();
            if (j == idx - 1) prevCum = prev.cumulativeGasUsed();
        }
        return buildReceiptJsonAt(Receipt.decode(receipts.get(idx)), idx, h, blockHash, txHash,
                rawTx, prevCum, logBase);
    }

    /** The per-element receipt serializer both entries share: the caller supplies
     *  the ALREADY-DECODED receipt and the running accumulators (previous
     *  cumulative gas, block-global log-index base). */
    private static String buildReceiptJsonAt(Receipt r, int idx,
                                             BlockHeader h, Bytes32 blockHash, Bytes32 txHash,
                                             byte[] rawTx, long prevCum, int logBase) {
        // Decode the (block-verified) tx so the receipt can carry from / to / contractAddress /
        // effectiveGasPrice. Without these MetaMask won't reconcile the receipt with its pending
        // tx and leaves it stuck "pending/submitted" even though we verified its inclusion.
        // Decode defensively: rawTx is on-chain-verified, but a future/unknown tx type could
        // make the decoder throw — fall back to null and emit a partial receipt (omitting the
        // optional from/to/effectiveGasPrice fields) rather than failing the whole receipt.
        com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.DecodedTx tx = null;
        if (rawTx != null) {
            try {
                tx = com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.decode(Bytes.wrap(rawTx));
            } catch (Exception decodeEx) {
                tx = null;
            }
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
        // from / to / contractAddress / effectiveGasPrice — required by MetaMask et al. to mark
        // the tx confirmed. Derived from the verified tx bytes + this block's base fee.
        if (tx != null) {
            if (tx.from() != null) {
                sb.append(",\"from\":\"").append(tx.from().toHexString()).append("\"");
            }
            if (!tx.to().isEmpty()) {
                sb.append(",\"to\":\"").append(tx.to().toHexString()).append("\"");
                sb.append(",\"contractAddress\":null");
            } else {
                sb.append(",\"to\":null");
                String created = contractAddressFor(tx);
                sb.append(",\"contractAddress\":")
                  .append(created == null ? "null" : "\"" + created + "\"");
            }
            java.math.BigInteger eff = effectiveGasPrice(tx, h);
            if (eff != null) {
                sb.append(",\"effectiveGasPrice\":\"0x").append(eff.toString(16)).append("\"");
            }
        }
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
            if (target > headNum) {
                HeaderAnchor reanchored = reAnchorForPin(target);
                if (reanchored == null) {
                    return "null";          // beyond the verified chain tip → eth null
                }
                anchor = reanchored;
                headNum = reanchored.number();
            }
            long back = headNum - target;
            if (back >= BLOCK_LOOKBACK_MAX) return null;     // too far to verify cheaply → error

            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(target, (int) (back + 1))
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!anchor.anchors(window)) return serveStaleBlock(isTag, pinned);
            BlockHeadersMessage.VerifiedHeader vh = window.get(0); // target is first in [target..head]
            // Remember this verified hash↔number so eth_getBlockByHash can resolve it.
            blockHashToNumber.put(vh.hash().toHexString(), vh.header().number);

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

    /** eth_getBlockByHash. Wallets call this immediately after a receipt to finalize a tx as
     *  confirmed, so it must work or the tx stays "submitted"/"pending". We resolve the hash →
     *  number from blocks we've already verified (receipt scan / getBlockByNumber), serve via
     *  the verified by-number path, then confirm the block actually served still carries the
     *  requested hash (guards a stale cache entry across a reorg). A hash we've never verified
     *  → "null" (eth's unknown-block); the live confirm flow always pre-populates it via the
     *  preceding eth_getTransactionReceipt. */
    private String rpcGetBlockByHash(String blockHash, boolean fullTx) {
        if (blockHash == null || fullTx) return null; // fullTx not served verified (mirrors by-number)
        String key = blockHash.toLowerCase(java.util.Locale.ROOT);
        Long number = blockHashToNumber.get(key);
        if (number == null) return "null"; // not a block we've verified — unknown to us
        String json = rpcGetBlockByNumber("0x" + Long.toHexString(number), false);
        if (json == null || "null".equals(json)) return json;
        // The verified by-number serve returns the CURRENTLY-canonical block at that height;
        // make sure it's still the one asked for (else a reorg remapped number → hash).
        return json.contains("\"hash\":\"" + key + "\"") ? json : "null";
    }

    /**
     * Re-anchor for a number pin AHEAD of the preferred (snap-built) anchor. This is
     * the NORMAL state on mobile, not an unknown block: eth_blockNumber advertises the
     * CL optimistic number (advances every slot), while the snap-built / lastGood
     * anchor trails it by the head build time (30-60s on a phone, i.e. several
     * blocks). MetaMask pins reads to the number we just advertised, so denying it
     * wedges the wallet's block tracker — observed live as eth_getBlockByNumber
     * returning the "null" literal for 96% of polls (778 of 806), stalling tx
     * tracking and the confirm screen. The beacon OPTIMISTIC payload is itself a
     * light-client-verified anchor at/past the pin — re-anchor on it (its exec
     * blockHash, via windowAnchoredToHash) and serve fully verified. Returns null
     * only when the pin is past even the optimistic number — genuinely
     * future/unknown, the caller's eth "null". Shared by every by-number serve
     * (blocks, block receipts) so the tuned rule can never diverge between them.
     * beaconSyncState is non-null (constructor requireNonNull).
     */
    private HeaderAnchor reAnchorForPin(long target) {
        long optimisticNum = beaconSyncState.getOptimisticBlockNumber();
        byte[] optimisticHash = beaconSyncState.getOptimisticBlockHash();
        if (optimisticNum >= target && optimisticHash != null) {
            return new HeaderAnchor(optimisticNum, null, optimisticHash);
        }
        return null;
    }

    /**
     * eth_getBlockReceipts — every receipt of one block as a JSON array, verified.
     * The block resolves through the same anchored path as eth_getBlockByNumber
     * (a 0x-32-byte hash first resolves via the verified hash→number map, like
     * eth_getBlockByHash, with the same reorg re-check); the body is verified
     * against transactionsRoot (the receipts' txHash/from/to/effectiveGasPrice
     * derive from it) and the receipt list against receiptsRoot before anything
     * is served. Returns the array JSON, the "null" literal for a verified
     * unknown/future block or a never-verified hash, or Java null (→ error)
     * when it can't verify right now.
     */
    private String rpcGetBlockReceipts(String blockSelector) {
        RLPxConnector conn = connector;
        if (conn == null) return null;
        String b = (blockSelector == null || blockSelector.isBlank())
                ? "latest" : blockSelector.trim();
        // A 32-byte 0x hash (unambiguous: a block NUMBER is at most 18 hex chars)
        // resolves to its number from blocks we've already verified; unknown → the
        // eth "null" (mirrors rpcGetBlockByHash).
        String expectHash = null;
        if (b.length() == 66 && (b.startsWith("0x") || b.startsWith("0X"))) {
            String key = b.toLowerCase(java.util.Locale.ROOT);
            Long number = blockHashToNumber.get(key);
            if (number == null) return "null";
            expectHash = key;
            b = "0x" + Long.toHexString(number);
        }
        boolean isTag;
        switch (b) {
            case "latest": case "pending": case "safe": case "finalized":
                isTag = true; break;
            case "earliest":
                return null; // genesis not served verified (mirrors getBlockByNumber)
            default:
                isTag = false;
        }
        long pinned = -1;
        if (!isTag) {
            try { pinned = Long.decode(b); } catch (Exception e) { return null; }
            // Genesis by number is rejected like the "earliest" tag above (and like
            // the Rust engine's selector parser) — the two engines must answer the
            // same request identically.
            if (pinned <= 0) return null;
        }
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            long headNum = anchor.number();
            long target = isTag ? headNum : pinned;
            if (target > headNum) {
                // Same near-head re-anchor as getBlockByNumber: a pin just past the
                // preferred anchor is the normal mobile state, and the beacon
                // OPTIMISTIC payload is itself a verified anchor at/past it.
                HeaderAnchor reanchored = reAnchorForPin(target);
                if (reanchored == null) {
                    return "null"; // beyond the verified chain tip → eth null
                }
                anchor = reanchored;
                headNum = reanchored.number();
            }
            long back = headNum - target;
            if (back >= BLOCK_LOOKBACK_MAX) return null; // too far to verify cheaply

            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(target, (int) (back + 1))
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!anchor.anchors(window)) return null;
            BlockHeadersMessage.VerifiedHeader vh = window.get(0);
            // A hash-form request must still name the block served at that height
            // (a reorg can remap the number under a stale map entry).
            if (expectHash != null && !vh.hash().toHexString().equals(expectHash)) return "null";
            blockHashToNumber.put(vh.hash().toHexString(), vh.header().number);

            // Body + receipts in flight together, ONE shared deadline for the pair
            // (sequential .get calls would each start a fresh timeout — worst case
            // twice the budget, not the "one round of wall-clock" this is for).
            CompletableFuture<List<BlockBodiesMessage.BlockBody>> bodiesF =
                    conn.requestBlockBodies(vh.hash());
            CompletableFuture<List<List<Bytes>>> rcptF = conn.requestReceipts(vh.hash());
            CompletableFuture.allOf(bodiesF, rcptF).get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            List<BlockBodiesMessage.BlockBody> bodies = bodiesF.join();
            List<List<Bytes>> rcptBlocks = rcptF.join();
            if (bodies.isEmpty() || rcptBlocks.isEmpty()) return null;
            List<Bytes> txs = bodies.get(0).transactions();
            List<Bytes> receipts = rcptBlocks.get(0);
            if (!OrderedTrieRoot.verify(txs, vh.header().transactionsRoot)) return null;
            if (receipts.size() != txs.size()
                    || !OrderedTrieRoot.verify(receipts, vh.header().receiptsRoot)) {
                return null;
            }

            // One O(n) pass: each receipt decodes exactly once, the previous
            // cumulative gas and the block-global log-index base accumulate
            // across the loop (the Rust build_block_receipts twin).
            StringBuilder sb = new StringBuilder(256 * Math.max(1, receipts.size()));
            sb.append("[");
            long prevCum = 0L;
            int logBase = 0;
            for (int i = 0; i < receipts.size(); i++) {
                if (i > 0) sb.append(",");
                Receipt r = Receipt.decode(receipts.get(i));
                Bytes32 txHash = Hash.keccak256(txs.get(i));
                sb.append(buildReceiptJsonAt(r, i, vh.header(), vh.hash(), txHash,
                        txs.get(i).toArrayUnsafe(), prevCum, logBase));
                prevCum = r.cumulativeGasUsed();
                logBase += r.logs().size();
            }
            return sb.append("]").toString();
        } catch (Exception e) {
            if (e instanceof InterruptedException || e.getCause() instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.info("[rpc] eth_getBlockReceipts failed: " + unwrap(e));
            return null;
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
            RpcCallContext ctx = anchoredHeadOrWait(RPC_HEAD_SERVE_STALE_MAX_MS, false);
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

    /** Network-aware floor for the suggested tip (see NetworkConfig#minSuggestedTipWei).
     *  Falls back to the {@link #MIN_SUGGESTED_TIP} default only before the connector/network
     *  is available. */
    private java.math.BigInteger minSuggestedTip() {
        RLPxConnector conn = connector;
        if (conn != null && conn.getNetwork() != null) {
            return conn.getNetwork().minSuggestedTipWei();
        }
        return MIN_SUGGESTED_TIP;
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
            // Network-aware floor: a hardcoded 0.1 gwei over-suggests by orders of magnitude
            // on cheap chains like Gnosis (~10 wei base fee). See NetworkConfig#minSuggestedTipWei.
            java.math.BigInteger minTip = minSuggestedTip();
            java.math.BigInteger tip;
            if (tips.isEmpty()) {
                tip = minTip;
            } else {
                java.util.Collections.sort(tips);
                tip = tips.get(tips.size() / 2).max(minTip);
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
        RpcCallContext h = anchoredHeadOrWait(stateHeadStaleCapMs, true);
        if (h == null) return null;
        // Replay a verified estimate for this exact (root, from, to, data, value): an
        // estimate is deterministic given the anchored state, so a retried confirm screen
        // hitting the same pinned head skips the binary-search EVM run entirely.
        String estKey = Bytes.wrap(h.blockCtx().stateRoot()).toHexString()
                + ":" + (from == null ? "0x" : Bytes.wrap(from).toHexString())
                + ":" + Bytes.wrap(to).toHexString()
                + ":" + (data == null || data.length == 0
                        ? "0x" : Hash.keccak256(Bytes.wrap(data)).toHexString())
                + ":" + (value == null ? "0" : value.toString(16));
        Long cachedGas = estimateCache.get(estKey, clock.elapsedMillis());
        if (cachedGas != null) return java.math.BigInteger.valueOf(cachedGas);
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
                    estimateCache.put(estKey, 21_000L, clock.elapsedMillis());
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
            java.util.concurrent.CompletableFuture<Long> est =
                    h.offchainExecutor().estimateGas(tx, h.blockCtx());
            // Warm the replay cache from the async completion, not just the returning
            // thread: if the wallet's blocking get() below times out but the binary-search
            // estimate finishes in the background, the result still lands warm for the
            // retry — same rationale as the eth_call leader populating callResultCache
            // after its waiter gave up.
            est.whenComplete((g, ex) -> {
                if (ex == null && g != null) estimateCache.put(estKey, g, clock.elapsedMillis());
            });
            Long gas = est.get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (gas == null) return null;
            return java.math.BigInteger.valueOf(gas);
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
