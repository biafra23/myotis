package io.myotis.rpc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class VerifiedResultCacheTest {

    private static final long TTL = 120_000;

    @Test
    void missOnEmpty() {
        VerifiedResultCache<byte[]> c = new VerifiedResultCache<>(8, TTL);
        assertNull(c.get("k", 0));
        assertEquals(0, c.size());
    }

    @Test
    void putThenGetReturnsValue() {
        VerifiedResultCache<byte[]> c = new VerifiedResultCache<>(8, TTL);
        byte[] v = {1, 2, 3};
        c.put("k", v, 1_000);
        assertArrayEquals(v, c.get("k", 1_000));
        // still warm just under the TTL boundary
        assertArrayEquals(v, c.get("k", 1_000 + TTL - 1));
        assertEquals(1, c.size());
    }

    @Test
    void expiresAtTtlBoundaryAndPrunesOnRead() {
        VerifiedResultCache<byte[]> c = new VerifiedResultCache<>(8, TTL);
        c.put("k", new byte[]{9}, 1_000);
        // exactly TTL ms later is expired (>=), and the read evicts it.
        assertNull(c.get("k", 1_000 + TTL));
        assertEquals(0, c.size(), "expired entry should be pruned lazily on read");
    }

    @Test
    void nullValueIsNotCached() {
        VerifiedResultCache<byte[]> c = new VerifiedResultCache<>(8, TTL);
        c.put("k", null, 1_000);
        assertNull(c.get("k", 1_000));
        assertEquals(0, c.size(), "errors/reverts must never pin a cache entry");
    }

    @Test
    void reInsertRefreshesTimestamp() {
        VerifiedResultCache<byte[]> c = new VerifiedResultCache<>(8, TTL);
        c.put("k", new byte[]{1}, 1_000);
        // a fresh execution against the same key re-stamps it, extending its life.
        c.put("k", new byte[]{2}, 1_000 + TTL - 1);
        assertArrayEquals(new byte[]{2}, c.get("k", 1_000 + TTL));
    }

    @Test
    void lruEvictsLeastRecentlyUsedBeyondBound() {
        VerifiedResultCache<Long> c = new VerifiedResultCache<>(2, TTL);
        c.put("a", 1L, 0);
        c.put("b", 2L, 0);
        // touch "a" so "b" becomes least-recently-used (access-order LRU)
        assertEquals(1L, c.get("a", 0));
        c.put("c", 3L, 0);   // exceeds bound of 2 -> evicts "b"
        assertEquals(2, c.size());
        assertNull(c.get("b", 0));
        assertEquals(1L, c.get("a", 0));
        assertEquals(3L, c.get("c", 0));
    }

    @Test
    void distinctKeysAreIndependent() {
        VerifiedResultCache<Long> c = new VerifiedResultCache<>(8, TTL);
        c.put("root1:to:data", 21_000L, 0);
        c.put("root2:to:data", 50_000L, 0);
        assertEquals(21_000L, c.get("root1:to:data", 0));
        assertEquals(50_000L, c.get("root2:to:data", 0));
    }

    @Test
    void clearEmpties() {
        VerifiedResultCache<Long> c = new VerifiedResultCache<>(8, TTL);
        c.put("a", 1L, 0);
        c.put("b", 2L, 0);
        c.clear();
        assertEquals(0, c.size());
        assertNull(c.get("a", 0));
    }
}
