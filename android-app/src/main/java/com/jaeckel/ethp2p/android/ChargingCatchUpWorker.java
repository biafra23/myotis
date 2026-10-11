package com.jaeckel.ethp2p.android;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

/**
 * The catch-up pass while the device is charging on an unmetered network: resume
 * each idle-paused stack and let it close the gap the paused hours opened — the
 * beacon light client AND the log index's head gap, which the daily
 * {@link CatchUpWorker} leaves alone. Scheduled by {@link EthP2PApplication} as a
 * periodic job constrained to charging + unmetered, so a phone left on the charger
 * overnight starts the day at the head instead of thousands of blocks behind.
 * See {@link NodeService#chargingCatchUp} for what a pass does.
 *
 * <p>Never boots a stopped node — if the user stopped the service, there is
 * nothing to maintain and the job is a no-op success.
 */
public final class ChargingCatchUpWorker extends Worker {

    public ChargingCatchUpWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        if (!NodeService.isRunning()) return Result.success();
        try {
            NodeService.chargingCatchUp(getApplicationContext(), CatchUpWorker.BUDGET_MS);
        } catch (Throwable t) {
            // Maintenance must never crash the process; the next run retries.
            return Result.success();
        }
        return Result.success();
    }
}
