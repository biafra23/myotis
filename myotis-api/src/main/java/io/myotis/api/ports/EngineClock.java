package io.myotis.api.ports;

/**
 * A monotonic clock (never wall-clock) for the engine's elapsed-time decisions —
 * head-context TTLs, cache expiry. Not consumed yet: every host passes null for
 * {@link EnginePorts#clock()}, and neither engine reads it — the Java engine's RPC
 * backend runs on {@code RpcClock.monotonic()} (System.nanoTime()/1e6) on every
 * host, Android included.
 */
public interface EngineClock {

    long elapsedMillis();
}
