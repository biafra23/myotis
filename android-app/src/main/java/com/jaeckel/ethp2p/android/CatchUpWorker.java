package com.jaeckel.ethp2p.android;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

/**
 * The ~daily maintenance pass while the node sleeps: resume each idle-paused
 * stack, let the beacon light client catch up the sync-committee periods missed
 * since the last run (a period is ~27 h — staying current keeps a wake at zero
 * BLS catch-up), persist a fresh snapshot, and pause again. Scheduled by
 * {@link EthP2PApplication} as a network-constrained periodic job.
 *
 * <p>Never boots a stopped node — if the user stopped the service, there is
 * nothing to maintain and the job is a no-op success.
 */
public final class CatchUpWorker extends Worker {

    /** WorkManager stops workers at ~10 min; leave margin for the final pause+persist. */
    private static final long BUDGET_MS = 8 * 60_000L;

    public CatchUpWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        if (!NodeService.isRunning()) return Result.success();
        try {
            NodeService.dailyCatchUp(BUDGET_MS);
        } catch (Throwable t) {
            // Maintenance must never crash the process; the next daily run retries.
            return Result.success();
        }
        return Result.success();
    }
}
