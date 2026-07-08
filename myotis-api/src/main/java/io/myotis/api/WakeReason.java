package io.myotis.api;

/**
 * The shared vocabulary of reasons a paused stack was resumed, recorded for the
 * status screens' "last wake" line. Defined here (not in the engine) so hosts and
 * the engine agree on the exact strings without a host importing engine internals.
 *
 * <p>{@link #FOREGROUND} is an <em>observation</em> wake — the user opened the app,
 * which proactively resumes a sleeping stack. It still counts toward the pause
 * count / total-slept accounting (the node genuinely slept and woke), but it must
 * NOT be recorded as the "last wake reason": otherwise merely viewing the status
 * page would overwrite the interesting reason (a request / catch-up wake) every
 * time. The other reasons are <em>demand</em> wakes and are recorded.
 */
public final class WakeReason {

    /** Engine self-wake: a verified read / operator query / ENS lookup hit the wake gate. */
    public static final String REQUEST = "request";

    /** Observation wake: the app came to the foreground and proactively resumed. Not recorded. */
    public static final String FOREGROUND = "foreground";

    /** The daily WorkManager maintenance pass resumed the stack to catch up + persist. */
    public static final String CATCH_UP = "catch-up";

    /** The daemon's {@code resume} IPC command. */
    public static final String IPC = "ipc";

    /** A plain {@link ChainHandle#resume()} with no reason given. */
    public static final String MANUAL = "manual";

    private WakeReason() {}
}
