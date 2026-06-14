package io.myotis.rpc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SnapLaneGateTest {

    @AfterEach
    void clearLane() {
        SnapLaneGate.clearLane();   // never leak the heavy flag to another test
    }

    @Test
    void smallLaneNeverAcquires() {
        SnapLaneGate g = new SnapLaneGate(() -> 10, 1000);
        // not a heavy thread -> no permit, no throttle
        assertFalse(g.acquireIfHeavy());
        assertEquals(0, g.inFlight());
        SnapLaneGate.enterLane(false);   // explicit small lane
        assertFalse(g.acquireIfHeavy());
    }

    @Test
    void heavyLaneCapsAtHalfThePeers_thenSoftProceeds() {
        SnapLaneGate g = new SnapLaneGate(() -> 4, 60);   // limit = 4/2 = 2
        SnapLaneGate.enterLane(true);
        assertTrue(g.acquireIfHeavy());   // 1
        assertTrue(g.acquireIfHeavy());   // 2 (at limit)
        assertEquals(2, g.inFlight());
        // 3rd is over the limit: blocks for ~maxWaitMs, then soft-proceeds (never stalls forever)
        long t0 = System.nanoTime();
        assertTrue(g.acquireIfHeavy());
        long waitedMs = (System.nanoTime() - t0) / 1_000_000L;
        assertTrue(waitedMs >= 40, "should have waited ~maxWaitMs, waited " + waitedMs);
        assertEquals(3, g.inFlight());
        g.release(); g.release(); g.release();
        assertEquals(0, g.inFlight());
    }

    @Test
    void releaseUnblocksWaiterWellBeforeTimeout() throws Exception {
        SnapLaneGate g = new SnapLaneGate(() -> 2, 5000);   // limit = 1, long timeout
        SnapLaneGate.enterLane(true);
        assertTrue(g.acquireIfHeavy());   // holds the only permit
        Thread releaser = new Thread(() -> {
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            g.release();
        });
        releaser.start();
        long t0 = System.nanoTime();
        assertTrue(g.acquireIfHeavy());   // blocks until the release (~100ms), not the 5s timeout
        long waitedMs = (System.nanoTime() - t0) / 1_000_000L;
        assertTrue(waitedMs < 2500, "should unblock on release, waited " + waitedMs);
        releaser.join();
        g.release();
    }

    @Test
    void limitTracksLivePeerCountDynamically() {
        int[] peers = {2};                                  // limit = 1
        SnapLaneGate g = new SnapLaneGate(() -> peers[0], 40);
        SnapLaneGate.enterLane(true);
        assertTrue(g.acquireIfHeavy());                     // inFlight=1, at limit
        // grow the pool -> limit rises to 4, so the next acquire is immediate (no soft wait)
        peers[0] = 8;
        long t0 = System.nanoTime();
        assertTrue(g.acquireIfHeavy());
        long waitedMs = (System.nanoTime() - t0) / 1_000_000L;
        assertTrue(waitedMs < 25, "limit grew, acquire should be immediate, waited " + waitedMs);
        g.release(); g.release();
    }

    @Test
    void neverCapsBelowOneEvenWithNoPeers() {
        SnapLaneGate g = new SnapLaneGate(() -> 0, 30);     // 0/2 -> floored to 1
        SnapLaneGate.enterLane(true);
        assertTrue(g.acquireIfHeavy());                     // the single allowed permit
        assertEquals(1, g.inFlight());
        g.release();
    }
}
