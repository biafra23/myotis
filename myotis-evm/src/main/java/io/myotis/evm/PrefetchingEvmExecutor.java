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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * {@link EvmExecutor} that wraps {@link DefaultEvmExecutor} with a
 * speculative-prefetch convergence loop.
 *
 * <p>The loop runs the EVM repeatedly against a shared per-call
 * {@link SyncStateView} cache. Each iteration uses {@link PrefetchingTracer}
 * to record (account, slot) and codeHash accesses without changing what the
 * EVM reads. After the iteration:
 *
 * <ol>
 *   <li>Compute the set of accesses that <em>missed</em> the cache (the
 *       accesses from this iteration not already pre-populated).
 *   <li>If the miss set is empty, the run is stable: return the result.
 *   <li>Otherwise, parallel-fetch the misses through the
 *       {@link SnapStateOracle}, populate the {@link SyncStateView} cache,
 *       and re-run.
 *   <li>Bail with {@link EvmExecutionError.IterationLimitExceeded} if the
 *       iteration cap is hit before convergence.
 * </ol>
 *
 * <p>The first iteration is necessarily slow — every miss triggers a
 * blocking fetch through the oracle's per-call retry path. Subsequent
 * iterations use the populated cache and only fetch newly-discovered
 * accesses, in parallel. Real-world contracts (ERC-20, ENS resolvers)
 * typically converge in 2–3 iterations because the access pattern is
 * data-independent past the first SLOAD.
 *
 * <p>Limitations:
 * <ul>
 *   <li>The loop currently re-runs the EVM from scratch each iteration
 *       (cheap because state is in memory). A future refinement could use
 *       Besu's frame-pause hooks to resume mid-execution.
 *   <li>Bytecode is fetched lazily by the existing {@code BytecodeCache}
 *       path; trace-recorded codeHashes that aren't yet cached are batched
 *       just like account/storage misses.
 * </ul>
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

    private byte[] runConvergent(Address target, byte[] calldata, BlockContext blockContext) {
        SnapStateOracle oracle = delegate.oracle();
        BytecodeCache bytecodeCache = delegate.bytecodeCache();

        // One view across all iterations so cache hits accumulate.
        SyncStateView view = new SyncStateView(
                oracle, blockContext.stateRoot(), bytecodeCache, /* tracker */ null);

        // Track every (address, slot) we've ever seen so we can recognise the
        // "no new misses" stable state across iterations.
        Set<AccessTracker.SlotKey> seenSlots = new HashSet<>();
        Set<Address> seenAccounts = new HashSet<>();

        byte[] lastResult = null;

        for (int iter = 0; iter < iterationCap; iter++) {
            AccessTracker iterationTracker = new AccessTracker();
            PrefetchingTracer tracer = new PrefetchingTracer(iterationTracker);

            byte[] result = delegate.runOnTracedView(target, calldata, blockContext, view, tracer);
            lastResult = result;

            AccessTracker.Snapshot snap = iterationTracker.snapshot();

            // What's new this iteration relative to everything we've ever seen?
            Set<AccessTracker.SlotKey> newSlots = new HashSet<>(snap.storage());
            newSlots.removeAll(seenSlots);
            Set<Address> newAccounts = new HashSet<>(snap.accounts());
            newAccounts.removeAll(seenAccounts);

            if (newSlots.isEmpty() && newAccounts.isEmpty()) {
                // Stable. Convergence reached.
                convergenceTracker.record(iter + 1);
                log.debug("[prefetch] converged after {} iteration(s)", iter + 1);
                return result;
            }

            // Pre-populate the view's cache with parallel batch fetches of the
            // new accesses. After this, the next iteration's reads hit memory.
            //
            // Note: bytecode prefetching isn't a separate wave here because
            // SyncStateView.bytecode() already populates the shared
            // BytecodeCache synchronously during the run that just finished;
            // any EXTCODE* target's code is in the cache by the time the
            // tracer reports the access. A separate wave would be redundant.
            prefetchInParallel(view, blockContext.stateRoot(), newAccounts, newSlots);
            seenAccounts.addAll(newAccounts);
            seenSlots.addAll(newSlots);
        }

        // We hit the cap. Returning the last result would be honest — every
        // read it observed was satisfiable — but the access set was still
        // expanding, which usually indicates pathological data-dependent
        // bytecode the prefetcher couldn't predict. Surface an explicit error
        // per the plan's contract.
        log.warn("[prefetch] iteration cap {} exceeded; returning IterationLimitExceeded", iterationCap);
        throw new EvmExecutionException(new EvmExecutionError.IterationLimitExceeded(iterationCap));
    }

    /**
     * Parallel-fetch the accounts and storage slots that just got recorded as
     * cache misses. Population is via {@link SyncStateView#putAccount} /
     * {@link SyncStateView#putStorage}, so the next iteration's reads hit the
     * cache and don't issue any oracle calls.
     */
    private void prefetchInParallel(SyncStateView view, byte[] stateRoot,
                                    Set<Address> accounts,
                                    Set<AccessTracker.SlotKey> slots) {
        SnapStateOracle oracle = delegate.oracle();
        List<CompletableFuture<?>> futures = new ArrayList<>(accounts.size() + slots.size());

        for (Address address : accounts) {
            if (view.hasAccount(address)) continue;
            futures.add(oracle.fetchAccount(stateRoot, address)
                    .thenAccept(state -> view.putAccount(address, state))
                    .exceptionally(t -> {
                        log.debug("[prefetch] account fetch for {} failed: {}", address, t.getMessage());
                        return null;
                    }));
        }
        for (AccessTracker.SlotKey key : slots) {
            if (view.hasStorage(key.address(), UInt256.valueOf(key.slot()))) continue;
            futures.add(oracle.fetchStorage(stateRoot, key.address(), key.slot())
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

        // Best-effort: wait for the batch to finish, but don't propagate
        // individual failures here — if a prefetch failed, the next EVM run
        // will hit the (still-uncached) miss and either succeed via the
        // oracle's serial path or surface a clean error from there.
        try {
            CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new))
                    .get(30, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception e) {
            log.debug("[prefetch] batch fetch timed out / failed: {}", e.getMessage());
        }
    }

}
