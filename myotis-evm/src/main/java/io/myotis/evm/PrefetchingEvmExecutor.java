package io.myotis.evm;

import io.myotis.evm.prefetch.ConvergenceTracker;
import io.myotis.evm.prefetch.PrefetchingTracer;
import io.myotis.evm.world.AccessTracker;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.SnapStateOracle;
import io.myotis.evm.world.SyncStateView;
import org.apache.tuweni.units.bigints.UInt256;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * {@link EvmExecutor} that wraps {@link DefaultEvmExecutor} with a
 * speculative-prefetch convergence loop using the <em>sentinel-return</em>
 * approach.
 *
 * <p>Iteration 0 runs the EVM with {@link SyncStateView#setSentinelOnMiss}
 * enabled: cache misses return zero-shaped placeholders without blocking
 * on the oracle. The {@link PrefetchingTracer} records every (account, slot)
 * touched. The result of iteration 0 is <em>discarded</em> (the placeholders
 * may have produced wrong values, divergent paths, or even reverts) — only
 * the access list survives.
 *
 * <p>Between iterations the loop parallel-fetches all recorded misses
 * through the {@link SnapStateOracle}, populating the {@link SyncStateView}
 * cache.
 *
 * <p>Iteration 1 runs with sentinel mode <em>cleared</em>. Cache hits return
 * real values; any newly-discovered misses (slots iteration 0's wrong path
 * never reached, but the real path needs) block on the oracle. The tracer
 * records the real-path access list.
 *
 * <p>If iteration 1's access list is a subset of what iteration 0 saw, the
 * call converges and the result is returned. Otherwise iteration 2+ repeats
 * with sentinel mode off — each subsequent iteration relies on cache hits
 * for previously-seen accesses and only blocks on data-dependent new ones.
 *
 * <p><strong>The bytecode-and-account-of-target trick.</strong> Sentinel
 * mode for the very-first lookup would return an empty account record
 * (codeHash = keccak("")) and the EVM would find no code to execute,
 * defeating the whole iteration. The executor pre-populates the target
 * contract's account and bytecode synchronously before iteration 0 so the
 * sentinel run reaches actual contract logic. This adds two RTTs upfront
 * but they would be paid in iteration 0 anyway.
 *
 * <p><strong>Where this design wins:</strong> contracts with multiple
 * data-independent state reads. Iteration 0 records all of them at memory
 * speed; the parallel batch fetch covers them in one network round trip;
 * iteration 1 produces the real result. For a contract that does N
 * independent SLOADs, the latency drops from {@code N · RTT} (serial) to
 * roughly {@code 2 · RTT} (one parallel batch + one verify run).
 *
 * <p><strong>Where it doesn't:</strong> chained data-dependent reads
 * (proxy → impl → balance) require one round trip per chain link, so
 * sentinel-return offers little advantage over the previous trace-based
 * design. The convergence loop still verifies stability, which is the
 * correctness guarantee.
 */
public final class PrefetchingEvmExecutor implements EvmExecutor {

    private static final Logger log = LoggerFactory.getLogger(PrefetchingEvmExecutor.class);

    /** Plan-mandated default iteration cap. */
    public static final int DEFAULT_ITERATION_CAP = 4;

    private final DefaultEvmExecutor delegate;
    private final int iterationCap;
    private final ConvergenceTracker convergenceTracker;

    public PrefetchingEvmExecutor(DefaultEvmExecutor delegate) {
        this(delegate, DEFAULT_ITERATION_CAP, new ConvergenceTracker());
    }

    public PrefetchingEvmExecutor(DefaultEvmExecutor delegate, int iterationCap,
                                  ConvergenceTracker convergenceTracker) {
        this.delegate = delegate;
        this.iterationCap = iterationCap;
        this.convergenceTracker = convergenceTracker;
    }

    public ConvergenceTracker convergenceTracker() {
        return convergenceTracker;
    }

    @Override
    public CompletableFuture<byte[]> callView(Address target, byte[] calldata, BlockContext blockContext) {
        Executor executor = delegate.executor();
        return CompletableFuture.supplyAsync(
                () -> runConvergent(target, calldata, blockContext), executor);
    }

    /** Estimation delegates directly: the prefetch/convergence loop exists to batch
     *  oracle round-trips for reads; the estimator already runs against the same
     *  snap-backed view and its gas accounting must not be re-run to convergence. */
    @Override
    public CompletableFuture<Long> estimateGas(UnsignedTransaction tx, BlockContext blockContext) {
        return delegate.estimateGas(tx, blockContext);
    }

    private byte[] runConvergent(Address target, byte[] calldata, BlockContext blockContext) {
        SnapStateOracle oracle = delegate.oracle();
        BytecodeCache bytecodeCache = delegate.bytecodeCache();

        // One view across all iterations so cache hits accumulate. The
        // accessTracker is null during prime — pre-populating the target
        // shouldn't show up as an "iteration 0 access" because primeTarget
        // pulls real values, not sentinels, and we don't want it to inflate
        // the per-iteration access set we use to drive parallel batches.
        SyncStateView view = new SyncStateView(
                oracle, blockContext.stateRoot(), bytecodeCache, /* tracker */ null);

        // Pre-populate the target contract's account + bytecode synchronously
        // so iteration 0's sentinel run actually executes meaningful bytecode.
        // Without this, the very-first lookup would get a sentinel empty
        // account, find no code, and return immediately.
        primeTarget(view, target);

        // Track every (address, slot) we've ever seen so we can recognise the
        // "no new misses" stable state across iterations.
        Set<AccessTracker.SlotKey> seenSlots = new HashSet<>();
        Set<Address> seenAccounts = new HashSet<>();

        // Sentinel mode stays ON while each iteration still DISCOVERS new accesses,
        // so multi-hop access patterns get one parallel prefetch wave per hop instead
        // of falling into serial blocking reads. The motivating case is MetaMask's
        // SingleCallBalances sweep — balances(users[], tokens[]) over ~1000 tokens:
        // iteration 0 (sentinel) discovers the 1000 token ACCOUNTS (their code isn't
        // loaded yet, so no balanceOf executes); with iteration 1 forced real, the
        // 1000 balance SLOTS were then fetched one blocking read at a time (~minutes,
        // i.e. a guaranteed 30s RPC timeout — the wallet showed no balances at all).
        // Sentinel iteration 1 instead RECORDS all 1000 slots and batch-fetches them
        // in one wave; the real run then executes against a fully-warm cache.
        // The last two iterations are always real, preserving the old convergence
        // budget for paths the sentinel zeros diverged away from; results returned to
        // the caller still come only from a real, fully-converged run.
        boolean discovering = true;
        for (int iter = 0; iter < iterationCap; iter++) {
            boolean sentinelMode = discovering && iter < iterationCap - 2;
            view.setSentinelOnMiss(sentinelMode);

            // Per-iteration tracker, wired into both the tracer (records SLOAD
            // / EXTCODE* stack args before opcode dispatch) AND the view
            // (records every account/storage/bytecode lookup the world
            // updater performs — including the implicit lookups Besu does
            // when entering a child frame for CALL / STATICCALL / DELEGATECALL,
            // which the tracer alone wouldn't capture). The two sources
            // overlap by design; HashSet de-dupes.
            AccessTracker iterationTracker = new AccessTracker();
            view.setAccessTracker(iterationTracker);
            PrefetchingTracer tracer = new PrefetchingTracer(iterationTracker);

            long missesBefore = view.sentinelMissCount();
            byte[] result;
            try {
                result = delegate.runOnTracedView(target, calldata, blockContext, view, tracer);
            } catch (EvmExecutionException e) {
                if (!sentinelMode) {
                    // Real iteration produced an actual revert / halt — propagate.
                    throw e;
                }
                // A sentinel iteration may revert because zero-valued state
                // tripped a require()/divide-by-zero/etc. That's expected;
                // we still have whatever access list was recorded up to the
                // point of the revert. Continue to the prefetch wave.
                log.debug("[prefetch] sentinel iteration {} halted ({}); continuing with recorded access list",
                        iter, e.error());
                result = null;
            }

            AccessTracker.Snapshot snap = iterationTracker.snapshot();

            if (sentinelMode) {
                Set<AccessTracker.SlotKey> sentinelNewSlots = new HashSet<>(snap.storage());
                sentinelNewSlots.removeAll(seenSlots);
                Set<Address> sentinelNewAccounts = new HashSet<>(snap.accounts());
                sentinelNewAccounts.removeAll(seenAccounts);
                if (sentinelNewAccounts.isEmpty() && sentinelNewSlots.isEmpty()) {
                    if (result != null && view.sentinelMissCount() == missesBefore) {
                        // No new accesses AND no sentinel value was handed out: every
                        // read hit the (verified) cache, so this run is byte-identical
                        // to a real run — converged, no extra iteration needed.
                        convergenceTracker.record(iter + 1);
                        log.debug("[prefetch] converged after {} iteration(s) (hit-only sentinel run)",
                                iter + 1);
                        return result;
                    }
                    // Nothing new to prefetch, but a sentinel placeholder leaked into
                    // (or reverted) this run — e.g. a prior wave's fetch failed. Run
                    // real next so misses block-fetch serially and the result is true.
                    discovering = false;
                    continue;
                }
                // A sentinel iteration's result may be bogus by construction. Discard;
                // batch-prefetch what it newly discovered and go discover the next hop.
                seenAccounts.addAll(sentinelNewAccounts);
                seenSlots.addAll(sentinelNewSlots);
                prefetchInParallel(view, blockContext.stateRoot(), sentinelNewAccounts, sentinelNewSlots);
                continue;
            }

            // Real iteration: check whether the access set has stabilised.
            Set<AccessTracker.SlotKey> newSlots = new HashSet<>(snap.storage());
            newSlots.removeAll(seenSlots);
            Set<Address> newAccounts = new HashSet<>(snap.accounts());
            newAccounts.removeAll(seenAccounts);

            if (newSlots.isEmpty() && newAccounts.isEmpty()) {
                convergenceTracker.record(iter + 1);
                log.debug("[prefetch] converged after {} iteration(s)", iter + 1);
                return result;
            }

            seenAccounts.addAll(newAccounts);
            seenSlots.addAll(newSlots);
            // The new misses were already block-fetched by this iteration's
            // serial reads (sentinel mode is OFF here), so the prefetchInParallel
            // call below mostly skips via view.hasAccount / view.hasStorage. It
            // remains as a safety net for any future code path that records an
            // access without populating the cache — e.g. an EXTCODESIZE that
            // doesn't trigger a getCode() in the EVM.
            prefetchInParallel(view, blockContext.stateRoot(), newAccounts, newSlots);
        }

        log.warn("[prefetch] iteration cap {} exceeded", iterationCap);
        throw new EvmExecutionException(new EvmExecutionError.IterationLimitExceeded(iterationCap));
    }

    /**
     * Synchronously fetch the target contract's account and bytecode so the
     * sentinel-mode iteration 0 has real code to execute at the top level.
     * Does nothing if the target is already cached (e.g. a repeat call from
     * the same wallet session).
     */
    private void primeTarget(SyncStateView view, Address target) {
        if (view.hasAccount(target)) return;
        // Sentinel mode is OFF at this point; account() blocks on the oracle.
        AccountState targetAccount = view.account(target);
        // Force bytecode fetch into the BytecodeCache (also blocks).
        view.bytecode(targetAccount.codeHash());
    }

    /**
     * Parallel-fetch the accounts and storage slots that just got recorded as
     * cache misses. Population is via {@link SyncStateView#putAccount} /
     * {@link SyncStateView#putStorage}, so the next iteration's reads hit the
     * cache and don't issue any oracle calls.
     */
    /** Max prefetch requests in flight at once. A wallet balance sweep can record
     *  ~1000 misses in one wave; firing them all concurrently floods the single
     *  pinned snap peer (request-queue overflow / disconnects). Chunking keeps the
     *  peer responsive while still collapsing a wave to ~(N/chunk) round trips. */
    private static final int PREFETCH_CHUNK = 128;

    private void prefetchInParallel(SyncStateView view, byte[] stateRoot,
                                    Set<Address> accounts,
                                    Set<AccessTracker.SlotKey> slots) {
        SnapStateOracle oracle = delegate.oracle();
        List<java.util.function.Supplier<CompletableFuture<?>>> work =
                new ArrayList<>(accounts.size() + slots.size());

        for (Address address : accounts) {
            if (view.hasAccount(address)) continue;
            work.add(() -> oracle.fetchAccount(stateRoot, address)
                    .thenAccept(state -> view.putAccount(address, state))
                    .exceptionally(t -> {
                        log.debug("[prefetch] account fetch for {} failed: {}", address, t.getMessage());
                        return null;
                    }));
        }
        for (AccessTracker.SlotKey key : slots) {
            if (view.hasStorage(key.address(), UInt256.valueOf(key.slot()))) continue;
            work.add(() -> oracle.fetchStorage(stateRoot, key.address(), key.slot())
                    .thenAccept(value -> view.putStorage(
                            key.address(),
                            UInt256.valueOf(key.slot()),
                            UInt256.valueOf(value)))
                    .exceptionally(t -> {
                        log.debug("[prefetch] storage fetch for {} slot {} failed: {}",
                                key.address(), key.slot(), t.getMessage());
                        return null;
                    }));
        }

        // Best-effort, chunked: wait for each chunk before firing the next, but don't
        // propagate individual failures — if a prefetch failed, the next EVM run will
        // hit the (still-uncached) miss and either succeed via the oracle's serial
        // path or surface a clean error from there.
        for (int from = 0; from < work.size(); from += PREFETCH_CHUNK) {
            List<CompletableFuture<?>> chunk = new ArrayList<>(PREFETCH_CHUNK);
            for (int i = from; i < Math.min(from + PREFETCH_CHUNK, work.size()); i++) {
                chunk.add(work.get(i).get());
            }
            try {
                CompletableFuture.allOf(chunk.toArray(CompletableFuture[]::new))
                        .get(30, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception e) {
                log.debug("[prefetch] chunk fetch timed out / failed: {}", e.getMessage());
                for (CompletableFuture<?> f : chunk) {
                    if (!f.isDone()) f.cancel(false);
                }
            }
        }
    }
}
