package io.myotis.rpc;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SentTxTrackerTest {

    private static final Bytes32 H1 = Bytes32.fromHexString(
            "0x1111111111111111111111111111111111111111111111111111111111111111");
    private static final Bytes32 H2 = Bytes32.fromHexString(
            "0x2222222222222222222222222222222222222222222222222222222222222222");
    private static final long TTL = 180_000;

    @Test
    void notWatchingWhenEmpty() {
        SentTxTracker t = new SentTxTracker(TTL);
        assertFalse(t.watchingAny());
        // a gossip hit for something we never sent is a cheap miss.
        assertEquals(-1, t.markSeen(H1, 1_000));
    }

    @Test
    void firstSightingReportsLatencyThenStopsCounting() {
        SentTxTracker t = new SentTxTracker(TTL);
        t.watch(H1, 1_000, -1L);
        assertTrue(t.watchingAny());
        assertFalse(t.wasSeen(H1));
        // first time the hash comes back: ms since broadcast.
        assertEquals(500, t.markSeen(H1, 1_500));
        assertTrue(t.wasSeen(H1));
        // every subsequent sighting is a no-op (already counted).
        assertEquals(-1, t.markSeen(H1, 1_800));
        assertEquals(-1, t.markSeen(H1, 9_999));
    }

    @Test
    void watchesAreIndependentPerHash() {
        SentTxTracker t = new SentTxTracker(TTL);
        t.watch(H1, 1_000, -1L);
        t.watch(H2, 1_000, -1L);
        assertEquals(2, t.size());
        assertEquals(200, t.markSeen(H1, 1_200));
        // H2 never seen; an unrelated hash is still a miss.
        assertEquals(-1, t.markSeen(
                Bytes32.fromHexString("0x3333333333333333333333333333333333333333333333333333333333333333"),
                1_300));
        assertTrue(t.wasSeen(H1));
        assertFalse(t.wasSeen(H2));
    }

    @Test
    void confirmMinedStopsWatching() {
        SentTxTracker t = new SentTxTracker(TTL);
        t.watch(H1, 1_000, -1L);
        t.confirmMined(H1);
        assertFalse(t.watchingAny());
        assertEquals(-1, t.markSeen(H1, 1_500));
    }

    @Test
    void recordsBroadcastHeadAndPreservesItAcrossSighting() {
        SentTxTracker t = new SentTxTracker(TTL);
        // unknown hash -> -1
        assertEquals(-1, t.broadcastHead(H1));
        t.watch(H1, 1_000, 46_726_900L);
        assertEquals(46_726_900L, t.broadcastHead(H1));
        // a gossip sighting must not clobber the recorded broadcast head.
        t.markSeen(H1, 1_500);
        assertEquals(46_726_900L, t.broadcastHead(H1));
        // a tx watched without a known head reports -1.
        t.watch(H2, 1_000, -1L);
        assertEquals(-1, t.broadcastHead(H2));
    }

    @Test
    void ttlEvictionClearsStaleWatchesAndQuietsTheGuard() {
        SentTxTracker t = new SentTxTracker(TTL);
        t.watch(H1, 1_000, -1L);
        // within TTL: nothing evicted, still watching.
        assertEquals(0, t.evictExpired(1_000 + TTL));
        assertTrue(t.watchingAny());
        // past TTL with no mining: evicted, guard goes quiet.
        assertEquals(1, t.evictExpired(1_001 + TTL));
        assertFalse(t.watchingAny());
    }
}
