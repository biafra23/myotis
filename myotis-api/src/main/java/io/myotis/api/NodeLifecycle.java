package io.myotis.api;

/**
 * Narrow lifecycle-control seam the JSON-RPC server consumes to answer the local
 * {@code myotis_pause} / {@code myotis_wakeup} methods — the JSON-RPC counterpart
 * of the daemon's {@code pause} / {@code resume} IPC commands and of what the
 * Android {@code NodeService} idle controller does directly in-process when the
 * app goes idle / comes to the foreground.
 *
 * <p>Kept separate from {@link ChainHandle} (like {@link NodeStatusReads}) so the
 * RPC layer depends only on this two-verb control surface plus the lifecycle name,
 * not the full engine surface. Both engine hosts already own
 * {@link ChainHandle#pause()} / {@link ChainHandle#resume(String)} /
 * {@link ChainHandle#lifecycle()}; the implementations here delegate to those, so
 * the RPC methods perform exactly the same transitions as the IPC commands.
 *
 * <p>Like the status reads, these are local control that bypasses the verified
 * backend: a Myotis-aware wallet pauses the node when its UI backgrounds and wakes
 * it (then polls {@code myotis_status} / {@code myotis_beaconStatus} until ready)
 * before the next burst of queries. FFI-portable: booleans + a String only; every
 * method BLOCKS.
 */
public interface NodeLifecycle {

    /**
     * Idle-pause: quiesce all P2P — every socket and every periodic timer, so the
     * radio can sleep — while keeping the JSON-RPC listener up and the warm
     * verified state in memory. Exactly the transition the daemon's {@code pause}
     * command and the Android idle controller perform. Blocking (a few seconds).
     * Idempotent; a no-op unless {@code RUNNING}.
     *
     * @return {@code true} when {@code PAUSED} on return
     */
    boolean pause();

    /**
     * Rebuild P2P after {@link #pause()}, recorded as {@link WakeReason#IPC} (the
     * IPC/RPC wake). Blocking (seconds; skips the cold DNS walk). A verified read
     * arriving while paused already wakes the stack on its own, so an explicit
     * wakeup is the optimization a Myotis-aware wallet issues — alongside polling
     * {@code myotis_status} / {@code myotis_beaconStatus} — to overlap the rebuild
     * with its UI coming to the foreground. A no-op returning {@code true} when
     * already {@code RUNNING}; on a failed rebuild returns {@code false} and the
     * stack stays {@code PAUSED} (retryable).
     *
     * @return {@code true} when {@code RUNNING} on return
     */
    boolean wakeUp();

    /** Coarse lifecycle name — {@link LifecycleState#name()}: {@code RUNNING} |
     *  {@code PAUSED} | {@code STOPPED}. */
    String lifecycleName();
}
