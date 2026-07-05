package io.myotis.api.ports;

/**
 * A monotonic clock (never wall-clock) for the engine's elapsed-time decisions —
 * head-context TTLs, cache expiry. Android supplies elapsedRealtime(); the JVM
 * default is System.nanoTime()/1e6.
 */
public interface EngineClock {

    long elapsedMillis();
}
