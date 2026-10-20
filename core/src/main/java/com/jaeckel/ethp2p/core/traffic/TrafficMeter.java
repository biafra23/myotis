package com.jaeckel.ethp2p.core.traffic;

import java.util.concurrent.atomic.AtomicLong;

/**
 * One network stack's bytes on the wire, by layer — the Java engine's twin of the
 * Rust engine's {@code myotis_net::traffic::TrafficMeter} (docs/data-usage.md).
 * Monotonic: the counts only ever grow.
 */
public final class TrafficMeter {

    /** One direction pair. */
    public static final class Counter {
        private final AtomicLong in = new AtomicLong();
        private final AtomicLong out = new AtomicLong();

        public void addIn(long n) { if (n > 0) in.addAndGet(n); }
        public void addOut(long n) { if (n > 0) out.addAndGet(n); }
        public long in() { return in.get(); }
        public long out() { return out.get(); }
    }

    /** Execution layer: RLPx sessions and discv4. */
    public final Counter el = new Counter();
    /** Consensus layer: libp2p. */
    public final Counter cl = new Counter();
}
