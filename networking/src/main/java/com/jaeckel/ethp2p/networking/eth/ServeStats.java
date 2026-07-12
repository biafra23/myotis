package com.jaeckel.ethp2p.networking.eth;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Counters for what OTHER clients ask us to serve over the eth sub-protocol, and how
 * often we could actually answer. One instance per network stack, shared across all
 * peer connections and across pause/resume cycles (the connector and its handlers are
 * rebuilt on resume; these numbers must not reset with them — they answer the operator
 * question "does anyone actually ask us for data?", which needs the whole run).
 *
 * <p>"Served" means the response carried at least one item. We answer header requests
 * from the {@link ServedHeaderWindow}; body requests always get an empty (but prompt)
 * response today — a light client holds no bodies — so {@code bodyRequestsServed}
 * stays 0 until that ever changes. Thread-safe; incremented from Netty event-loop
 * threads.
 */
public final class ServeStats {

    private final AtomicLong headerRequests = new AtomicLong();
    private final AtomicLong headerRequestsServed = new AtomicLong();
    private final AtomicLong bodyRequests = new AtomicLong();
    private final AtomicLong bodyRequestsServed = new AtomicLong();

    /** An inbound GetBlockHeaders arrived. Counted BEFORE parsing/answering so malformed
     *  requests and failed sends still register as demand. */
    public void headerAsked() { headerRequests.incrementAndGet(); }

    /** We answered a GetBlockHeaders with ≥1 header. */
    public void headerServed() { headerRequestsServed.incrementAndGet(); }

    /** An inbound GetBlockBodies arrived (counted before parsing/answering, as above). */
    public void bodyAsked() { bodyRequests.incrementAndGet(); }

    /** We answered a GetBlockBodies with ≥1 body (never happens today). */
    public void bodyServed() { bodyRequestsServed.incrementAndGet(); }

    /** Zero all counters. Called where the stack re-anchors uptime (a fresh start
     *  after shutdown) so the status page's counters and uptime share one epoch;
     *  deliberately NOT called on pause/resume (a pause is not a restart). */
    public void reset() {
        headerRequests.set(0);
        headerRequestsServed.set(0);
        bodyRequests.set(0);
        bodyRequestsServed.set(0);
    }

    public long headerRequests() { return headerRequests.get(); }
    public long headerRequestsServed() { return headerRequestsServed.get(); }
    public long bodyRequests() { return bodyRequests.get(); }
    public long bodyRequestsServed() { return bodyRequestsServed.get(); }
}
