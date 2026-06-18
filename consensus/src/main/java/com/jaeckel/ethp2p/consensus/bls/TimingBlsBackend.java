package com.jaeckel.ethp2p.consensus.bls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Wraps any {@link BlsBackend} to time every {@code fastAggregateVerify} and keep
 * running stats, so the cost of the active backend is visible on whatever platform it
 * runs (desktop daemon or Android device). Switch the backend (see {@link BlsBackends})
 * and compare the logged numbers to evaluate native vs pure-Java.
 *
 * <p>Each verify logs at DEBUG; every {@value #SUMMARY_EVERY} verifies it logs an INFO
 * summary (count / avg / max ms). {@link #snapshot()} exposes the same for an IPC/UI
 * surface.
 */
public final class TimingBlsBackend implements BlsBackend {

    private static final Logger log = LoggerFactory.getLogger(TimingBlsBackend.class);
    private static final int SUMMARY_EVERY = 16;

    private final BlsBackend delegate;
    private final AtomicLong count = new AtomicLong();
    private final AtomicLong totalNanos = new AtomicLong();
    private final AtomicLong maxNanos = new AtomicLong();

    public TimingBlsBackend(BlsBackend delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean fastAggregateVerify(List<byte[]> pubkeys, byte[] message, byte[] signature) {
        long t0 = System.nanoTime();
        boolean ok = delegate.fastAggregateVerify(pubkeys, message, signature);
        long dt = System.nanoTime() - t0;

        long n = count.incrementAndGet();
        totalNanos.addAndGet(dt);
        maxNanos.accumulateAndGet(dt, Math::max);

        int pk = pubkeys == null ? 0 : pubkeys.size();
        log.debug("[bls-timing] backend={} pubkeys={} took={}ms ok={}",
                delegate.name(), pk, dt / 1_000_000.0, ok);
        if (n % SUMMARY_EVERY == 0) {
            log.info("[bls-timing] {}", snapshot());
        }
        return ok;
    }

    @Override
    public void warmPubkeyCache(List<byte[]> pubkeys) {
        delegate.warmPubkeyCache(pubkeys);
    }

    @Override
    public String name() { return delegate.name(); }

    /** Wrapped backend (for selection logic that needs the real name/type). */
    public BlsBackend delegate() { return delegate; }

    /** Immutable timing snapshot for logs / IPC. */
    public Stats snapshot() {
        long n = count.get();
        long total = totalNanos.get();
        return new Stats(delegate.name(), n,
                n == 0 ? 0.0 : total / 1e6 / n,
                maxNanos.get() / 1e6);
    }

    public record Stats(String backend, long verifies, double avgMs, double maxMs) {
        @Override public String toString() {
            return String.format("backend=%s verifies=%d avg=%.2fms max=%.2fms",
                    backend, verifies, avgMs, maxMs);
        }
    }
}
