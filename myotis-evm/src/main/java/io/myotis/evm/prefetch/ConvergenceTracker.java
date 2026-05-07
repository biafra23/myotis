package io.myotis.evm.prefetch;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Records iteration-count statistics for the prefetch loop, used for tuning
 * the iteration cap and detecting access-pattern regressions.
 *
 * <p>Phase 2 deliverable. Exposed via the {@link io.myotis.evm.EvmExecutor}'s
 * telemetry channel; never exfiltrated.
 */
public final class ConvergenceTracker {

    private final List<Integer> iterations = Collections.synchronizedList(new ArrayList<>());

    public void record(int iterationCount) {
        iterations.add(iterationCount);
    }

    public List<Integer> snapshot() {
        synchronized (iterations) {
            return List.copyOf(iterations);
        }
    }

    public int max() {
        synchronized (iterations) {
            return iterations.stream().mapToInt(Integer::intValue).max().orElse(0);
        }
    }

    /**
     * Discard all recorded iteration counts. Used by the benchmark IT after
     * warm-up runs so the reported stats reflect only the timed measurements.
     */
    public void clear() {
        synchronized (iterations) {
            iterations.clear();
        }
    }
}
