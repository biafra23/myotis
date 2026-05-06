package io.myotis.evm.prefetch;

/**
 * Speculative prefetcher: runs the EVM, collects state misses, batch-fetches
 * them in parallel, then re-runs until convergence (no new misses) or the
 * iteration cap is hit.
 *
 * <p><strong>Phase 2 — not yet implemented.</strong> The Phase 0 deliverable
 * uses synchronous {@code SnapStateOracle} fetches inside the EVM's read path
 * via {@code SyncStateView}. Phase 2 wraps that with this loop:
 * <pre>
 *   1. Run with sentinel-on-miss (or a trace-based access list — see open Q1)
 *   2. Collect AccessTracker.Snapshot
 *   3. Parallel-fetch all misses
 *   4. Re-run; if AccessTracker emits any new misses, loop
 *   5. Bail with IterationLimitExceeded when the cap is reached
 * </pre>
 *
 * <p>The cap defaults to 4 (per the plan); workloads that don't converge in
 * three iterations on the benchmark corpus are treated as bugs.
 */
public final class PrefetchLoop {

    /** Plan-mandated default. Override only with intent. */
    public static final int DEFAULT_ITERATION_CAP = 4;

    private final ConvergenceTracker tracker;
    private final int iterationCap;

    public PrefetchLoop(ConvergenceTracker tracker, int iterationCap) {
        this.tracker = tracker;
        this.iterationCap = iterationCap;
    }

    public PrefetchLoop() {
        this(new ConvergenceTracker(), DEFAULT_ITERATION_CAP);
    }

    public int iterationCap() { return iterationCap; }
    public ConvergenceTracker tracker() { return tracker; }
}
