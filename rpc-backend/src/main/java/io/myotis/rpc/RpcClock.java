package io.myotis.rpc;

/**
 * Monotonic millisecond clock seam. The backend's TTLs and staleness windows
 * (head-context freshness, fee-snapshot age, frozen-pin age) need a monotonic
 * source unaffected by wall-clock jumps. {@code :android-app} backs this with
 * {@code android.os.SystemClock.elapsedRealtime()}; the daemon with
 * {@link System#nanoTime()}. Kept as a seam so the shared module pulls in no
 * Android API.
 */
@FunctionalInterface
public interface RpcClock {

    /** A monotonically non-decreasing time in milliseconds (arbitrary epoch). */
    long elapsedMillis();

    /** Default monotonic clock from {@link System#nanoTime()} (daemon/tests). */
    static RpcClock monotonic() {
        return () -> System.nanoTime() / 1_000_000L;
    }
}
