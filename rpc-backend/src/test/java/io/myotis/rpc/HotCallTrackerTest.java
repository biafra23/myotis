package io.myotis.rpc;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HotCallTrackerTest {

    private static final byte[] TO_A = addr(0xAA);
    private static final byte[] TO_B = addr(0xBB);
    private static final byte[] FROM = addr(0x01);
    private static final byte[] DATA = new byte[]{1, 2, 3, 4, 5};

    private static byte[] addr(int fill) {
        byte[] a = new byte[20];
        java.util.Arrays.fill(a, (byte) fill);
        return a;
    }

    private static HotCallTracker tracker() {
        // maxTracked=4, minHits=2, ttl=10s, maxCalldata=1KB, warmTimeout=5s, backoff=3s
        return new HotCallTracker(4, 2, 10_000, 1024, 5_000, 3_000);
    }

    @Test
    void singleSightingIsNeverWarmable() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        assertTrue(t.beginWarmables(1_001, 10).isEmpty(),
                "a one-off call must not be replayed");
    }

    @Test
    void secondSightingMakesShapeWarmable() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        List<HotCallTracker.HotCall> hot = t.beginWarmables(2_001, 10);
        assertEquals(1, hot.size());
        assertArrayEquals(TO_A, hot.get(0).to());
        assertArrayEquals(DATA, hot.get(0).data());
        assertArrayEquals(FROM, hot.get(0).from());
        assertNull(hot.get(0).value());
    }

    @Test
    void distinctShapesTrackIndependently() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_B, null, DATA, 1_100);   // different target = different shape
        t.record(FROM, TO_A, BigInteger.ONE, DATA, 1_200);   // different value = different shape
        t.record(FROM, TO_A, null, new byte[]{9}, 1_300);    // different calldata = different shape
        assertTrue(t.beginWarmables(1_400, 10).isEmpty(),
                "four distinct single-sighting shapes — none warmable");
        assertEquals(4, t.size());
    }

    @Test
    void staleShapeIsNotWarmable() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        assertTrue(t.beginWarmables(13_000, 10).isEmpty(),
                "not seen within the TTL -> wallet moved on, stop warming");
    }

    @Test
    void hitsResetAfterShapeGoesCold() {
        // Two sightings separated by more than the TTL must NOT qualify the shape:
        // the counter restarts when a cold shape resumes.
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 20_000);   // > ttl after the first
        assertTrue(t.beginWarmables(20_001, 10).isEmpty());
        t.record(FROM, TO_A, null, DATA, 21_000);   // second fresh sighting
        assertEquals(1, t.beginWarmables(21_001, 10).size());
    }

    @Test
    void warmInFlightBlocksReWarmUntilEnded() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        List<HotCallTracker.HotCall> first = t.beginWarmables(2_001, 10);
        assertEquals(1, first.size());
        assertTrue(t.beginWarmables(2_002, 10).isEmpty(),
                "the same shape must not be double-warmed while one is in flight");
        t.endWarm(first.get(0), true, 3_000);
        assertEquals(1, t.beginWarmables(3_001, 10).size(),
                "after endWarm the next head build may warm it again");
    }

    @Test
    void deadWarmExpiresAndShapeBecomesWarmableAgain() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        assertEquals(1, t.beginWarmables(2_001, 10).size());
        // No endWarm (the warm's queue slot was dropped). Past warmTimeout the mark
        // is considered dead; the shape needs to still be fresh, so re-record.
        t.record(FROM, TO_A, null, DATA, 8_000);
        assertEquals(1, t.beginWarmables(8_001, 10).size(),
                "a warm mark older than warmTimeout must not block warming forever");
    }

    @Test
    void failedWarmBacksOff() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        List<HotCallTracker.HotCall> first = t.beginWarmables(2_001, 10);
        t.endWarm(first.get(0), false, 2_500);
        t.record(FROM, TO_A, null, DATA, 3_000);
        assertTrue(t.beginWarmables(3_001, 10).isEmpty(),
                "inside the failure backoff the shape must be left alone");
        assertEquals(1, t.beginWarmables(6_000, 10).size(),
                "after the backoff the shape is retried");
    }

    @Test
    void mostRecentlySeenShapesWinTheWarmBudget() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        t.record(FROM, TO_B, null, DATA, 1_500);
        t.record(FROM, TO_B, null, DATA, 2_500);   // B seen more recently
        List<HotCallTracker.HotCall> hot = t.beginWarmables(3_000, 1);
        assertEquals(1, hot.size(), "budget of 1 must yield exactly one shape");
        assertArrayEquals(TO_B, hot.get(0).to(), "the most recently seen shape wins");
        // Only the RETURNED shape may be marked in-flight: the shape that lost on
        // budget must still be warmable — an implementation that marks every
        // candidate would silently starve everything beyond the budget.
        List<HotCallTracker.HotCall> next = t.beginWarmables(3_001, 10);
        assertEquals(1, next.size(), "the budget loser must still be warmable");
        assertArrayEquals(TO_A, next.get(0).to());
    }

    @Test
    void lruEvictsOldestShapeBeyondCapacity() {
        var t = tracker();   // capacity 4
        byte[][] tos = new byte[5][];
        for (int i = 0; i < 5; i++) {
            tos[i] = addr(0x10 + i);
            t.record(FROM, tos[i], null, DATA, 1_000 + i);
        }
        assertEquals(4, t.size(), "capacity must hold");
        // Pin WHICH shape was evicted — the oldest (tos[0]), not the newest: a
        // second sighting of a survivor reaches minHits=2 and becomes warmable,
        // while the evicted shape restarts at one sighting and stays cold.
        t.record(FROM, tos[1], null, DATA, 2_000);   // survivor: 2nd sighting
        t.record(FROM, tos[0], null, DATA, 2_001);   // evicted: back at 1st sighting
        List<HotCallTracker.HotCall> hot = t.beginWarmables(2_002, 10);
        assertEquals(1, hot.size(), "only the survivor may have accumulated hits");
        assertArrayEquals(tos[1], hot.get(0).to());
    }

    @Test
    void malformedFromIsNotTracked() {
        // A wrong-length from would make Address.of throw during every replay of the
        // shape — it must never enter the tracker.
        var t = tracker();
        byte[] badFrom = new byte[]{1, 2, 3};
        t.record(badFrom, TO_A, null, DATA, 1_000);
        t.record(badFrom, TO_A, null, DATA, 2_000);
        assertTrue(t.beginWarmables(2_001, 10).isEmpty());
        assertEquals(0, t.size());
    }

    @Test
    void clearDropsAllShapes() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        t.clear();
        assertEquals(0, t.size());
        assertTrue(t.beginWarmables(2_001, 10).isEmpty(),
                "purge must also reset warm-worthiness, not just memory");
    }

    @Test
    void oversizedCalldataIsNotTracked() {
        var t = tracker();   // 1KB cap
        byte[] big = new byte[2048];
        t.record(FROM, TO_A, null, big, 1_000);
        t.record(FROM, TO_A, null, big, 2_000);
        assertTrue(t.beginWarmables(2_001, 10).isEmpty());
        assertEquals(0, t.size());
    }

    @Test
    void endWarmForEvictedShapeIsHarmless() {
        var t = tracker();
        t.record(FROM, TO_A, null, DATA, 1_000);
        t.record(FROM, TO_A, null, DATA, 2_000);
        List<HotCallTracker.HotCall> hot = t.beginWarmables(2_001, 10);
        for (int i = 0; i < 5; i++) {   // push the shape out of the LRU
            t.record(FROM, addr(0x30 + i), null, DATA, 3_000 + i);
        }
        t.endWarm(hot.get(0), true, 4_000);   // must not throw
    }

    @Test
    void nullFromAndValueAreValidShapeComponents() {
        var t = tracker();
        t.record(null, TO_A, null, null, 1_000);
        t.record(null, TO_A, null, null, 2_000);
        List<HotCallTracker.HotCall> hot = t.beginWarmables(2_001, 10);
        assertEquals(1, hot.size());
        assertNull(hot.get(0).from());
        assertNull(hot.get(0).value());
        assertEquals(0, hot.get(0).data().length, "null calldata normalizes to empty");
    }

    @Test
    void recordedArraysAreDefensiveCopies() {
        var t = tracker();
        byte[] mutableTo = TO_A.clone();
        byte[] mutableData = DATA.clone();
        t.record(FROM, mutableTo, null, mutableData, 1_000);
        mutableTo[0] = 0;
        mutableData[0] = 0;
        t.record(FROM, TO_A, null, DATA, 2_000);   // original bytes: same shape
        List<HotCallTracker.HotCall> hot = t.beginWarmables(2_001, 10);
        assertEquals(1, hot.size(), "caller mutation must not have corrupted the stored shape");
        assertArrayEquals(TO_A, hot.get(0).to());
        assertArrayEquals(DATA, hot.get(0).data());
    }
}
