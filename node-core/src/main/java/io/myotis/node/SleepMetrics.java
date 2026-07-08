package io.myotis.node;

/**
 * Idle-sleep bookkeeping for one {@link ChainStack}: how many times it paused, how
 * long it spent paused in total, and when/why it last woke — surfaced on the status
 * screens to make the pause/resume cycle debuggable. Extracted from ChainStack so
 * the accounting (especially the observer-effect rule below) is unit-testable
 * without standing up a network.
 *
 * <p>Durations use the caller's monotonic clock (nanos) so an NTP/wall-clock step
 * can't distort the total; the display timestamps use the caller's wall clock
 * (epoch ms) because the UI renders them as clock times.
 *
 * <p><b>Observer effect:</b> {@link #onResume} takes a {@code recordAsWake} flag.
 * A foreground/observation wake (the user opened the app, which resumes a sleeping
 * stack) passes {@code false}: it still accrues into the pause count / total, but
 * must not overwrite the last-wake reason/time, or simply viewing the status page
 * would hide the request/catch-up wake you're trying to observe.
 *
 * <p>Not thread-safe on its own; ChainStack only mutates it under its lifecycle
 * monitor (pause/resume are {@code synchronized}), and the volatile-free reads are
 * fine for the status snapshot (a torn read at worst shows a value one transition
 * stale, which is harmless for a diagnostic display).
 */
final class SleepMetrics {

    private int pauseCount;
    private long totalPausedNanos;
    private long lastPauseNanos;          // 0 = not currently timing a pause
    private long lastPauseEpochMs;        // 0 = never paused
    private long lastResumeEpochMs;       // 0 = never woken by a demand wake
    private String lastWakeReason;        // null = never woken by a demand wake

    /** Record entry into idle sleep. */
    void onPause(long nowEpochMs, long nowNanos) {
        pauseCount++;
        lastPauseEpochMs = nowEpochMs;
        lastPauseNanos = nowNanos;
    }

    /**
     * Record a wake. Always closes the current pause interval into {@link #totalPausedMs};
     * only records the reason/time as the "last wake" when {@code recordAsWake} (i.e. a
     * demand wake, not a foreground observation).
     */
    void onResume(long nowEpochMs, long nowNanos, String reason, boolean recordAsWake) {
        if (lastPauseNanos != 0) {
            totalPausedNanos += nowNanos - lastPauseNanos;
            lastPauseNanos = 0;
        }
        if (recordAsWake) {
            lastResumeEpochMs = nowEpochMs;
            lastWakeReason = reason;
        }
    }

    int pauseCount() { return pauseCount; }
    long totalPausedMs() { return totalPausedNanos / 1_000_000L; }
    long lastPauseEpochMs() { return lastPauseEpochMs; }
    long lastResumeEpochMs() { return lastResumeEpochMs; }
    String lastWakeReason() { return lastWakeReason; }
}
