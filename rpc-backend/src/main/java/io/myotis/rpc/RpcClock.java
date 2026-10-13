package io.myotis.rpc;

/**
 * Monotonic millisecond clock seam. The backend's TTLs and staleness windows
 * (head-context freshness, fee-snapshot age, frozen-pin age) need a monotonic
 * source unaffected by wall-clock jumps. Every host runs on {@link #monotonic()}
 * ({@link System#nanoTime()}): {@code ChainStack} builds the backend with it, on
 * Android as everywhere else. On Android that clock stops while the device is in
 * deep sleep (unlike {@code SystemClock.elapsedRealtime()}), so these windows
 * do not age across a suspend. Kept as a seam so the shared module pulls in no
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
