package com.jaeckel.ethp2p.android;

/**
 * When the balance watch (the Watch tab; {@code io.myotis.ui.BalanceWatch}) checks on its
 * own. Pure (no Android imports) so the rule is unit-testable on the JVM, like
 * {@link StayAwakePolicy}; {@link NodeService} feeds it the live state.
 *
 * <ul>
 *   <li><b>App in the foreground</b>: every {@link #FOREGROUND_INTERVAL_MS}, on any network —
 *       the user is looking, and one proof per address is a few KB.</li>
 *   <li><b>Plugged in on an unmetered network</b> ({@link #backgroundApplies}): once right
 *       before the idle controller puts a stack to sleep, and once when a catch-up pass has
 *       woken one and brought it to the head. Independent of "Stay awake while charging" —
 *       that setting decides whether the node sleeps, not whether a sleep is preceded by a
 *       check.</li>
 *   <li><b>Kept awake on the charger</b> (the stay-awake rule holds, so the node never
 *       sleeps and the two moments above never come): every {@link #AWAKE_INTERVAL_MS}.
 *       Only then: on battery, or with the setting off, a periodic check would itself count
 *       as activity and keep a node awake that the user lets sleep.</li>
 * </ul>
 */
final class WatchPolicy {

    private WatchPolicy() {}

    /** Between scheduled checks while the app is in the foreground. */
    static final long FOREGROUND_INTERVAL_MS = 5 * 60_000L;
    /** Between scheduled checks while the stay-awake rule keeps the node running. */
    static final long AWAKE_INTERVAL_MS = 10 * 60_000L;
    /** A network whose last attempt found no verified answer waits this long before the next. */
    static final long RETRY_MS = 2 * 60_000L;
    /** Before a sleep or after a wake, a check younger than this is fresh enough to skip. */
    static final long FRESH_MS = 60_000L;
    /** Cause-search window: blocks scanned newest first when a balance changed. A mainnet
     *  block with its transactions is ~100–200 KB, so a metered network gets a short one. */
    static final int SCAN_BLOCKS_UNMETERED = 64;
    static final int SCAN_BLOCKS_METERED = 16;

    /** Plugged in, and the active network has Internet and is unmetered. */
    static boolean backgroundApplies(boolean pluggedIn, boolean internet, boolean unmetered) {
        return pluggedIn && internet && unmetered;
    }

    /**
     * The interval of the scheduled check, or 0 when none is scheduled.
     *
     * @param foreground the app is in the foreground
     * @param stayAwake  the stay-awake rule holds ({@link StayAwakePolicy#applies})
     */
    static long scheduledIntervalMs(boolean foreground, boolean stayAwake) {
        if (foreground) return FOREGROUND_INTERVAL_MS;
        if (stayAwake) return AWAKE_INTERVAL_MS;
        return 0;
    }

    static int scanBlocks(boolean unmetered) {
        return unmetered ? SCAN_BLOCKS_UNMETERED : SCAN_BLOCKS_METERED;
    }
}
