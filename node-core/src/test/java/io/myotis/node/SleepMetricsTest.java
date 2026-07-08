package io.myotis.node;

import io.myotis.api.WakeReason;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Hermetic tests for the idle-sleep accounting, including the load-bearing
 * observer-effect rule: a foreground (observation) wake still accrues into the
 * pause count / total, but must not overwrite the recorded last-wake reason/time.
 */
class SleepMetricsTest {

    private static final long MS = 1_000_000L; // nanos per ms

    @Test
    void freshMetricsAreZero() {
        SleepMetrics m = new SleepMetrics();
        assertEquals(0, m.pauseCount());
        assertEquals(0L, m.totalPausedMs());
        assertEquals(0L, m.lastPauseEpochMs());
        assertEquals(0L, m.lastResumeEpochMs());
        assertNull(m.lastWakeReason());
    }

    @Test
    void countsPausesAndAccumulatesTotal() {
        SleepMetrics m = new SleepMetrics();
        // Pause at t=1000ms, wake 5s later.
        m.onPause(1_000L, 1_000L * MS);
        m.onResume(6_000L, 6_000L * MS, WakeReason.REQUEST, true);
        // Pause again at t=10s, wake 3s later.
        m.onPause(10_000L, 10_000L * MS);
        m.onResume(13_000L, 13_000L * MS, WakeReason.CATCH_UP, true);

        assertEquals(2, m.pauseCount());
        assertEquals(8_000L, m.totalPausedMs());          // 5s + 3s
        assertEquals(10_000L, m.lastPauseEpochMs());
        assertEquals(13_000L, m.lastResumeEpochMs());
        assertEquals(WakeReason.CATCH_UP, m.lastWakeReason());
    }

    @Test
    void foregroundWakeCountsButDoesNotClobberLastReason() {
        SleepMetrics m = new SleepMetrics();
        // A real demand wake (request) at t=6s.
        m.onPause(1_000L, 1_000L * MS);
        m.onResume(6_000L, 6_000L * MS, WakeReason.REQUEST, /*recordAsWake*/ true);
        // Then the user opens the app: a foreground observation wake at t=13s.
        m.onPause(10_000L, 10_000L * MS);
        m.onResume(13_000L, 13_000L * MS, WakeReason.FOREGROUND, /*recordAsWake*/ false);

        // Both sleeps counted (the node genuinely slept + woke both times)...
        assertEquals(2, m.pauseCount());
        assertEquals(8_000L, m.totalPausedMs());          // 5s + 3s
        // ...but the last-wake display still shows the REQUEST wake, not foreground —
        // opening the status page did not hide the reason being debugged.
        assertEquals(WakeReason.REQUEST, m.lastWakeReason());
        assertEquals(6_000L, m.lastResumeEpochMs());
    }
}
