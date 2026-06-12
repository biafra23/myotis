package io.myotis.rpc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PendingNonceTrackerTest {

    private static final String A = "0x00000000000000000000000000000000000000aa";
    private static final long TTL = 90_000;

    @Test
    void noPendingEntryServesMinedCountUnchanged() {
        PendingNonceTracker t = new PendingNonceTracker(TTL);
        assertEquals(5, t.overlay(A, 5, 1_000));
        assertFalse(t.has(A));
        assertEquals(-1, t.pendingNonce(A));
    }

    @Test
    void pendingSendRaisesNextNonceUntilMined() {
        PendingNonceTracker t = new PendingNonceTracker(TTL);
        // account has sent nonces 0..4 -> mined count 5; we broadcast nonce 5.
        t.record(A, 5, 1_000);
        // chain hasn't reflected our send yet (still 5) -> next must be 6, not 5.
        assertEquals(6, t.overlay(A, 5, 2_000));
        // a second back-to-back send takes nonce 6; broadcast it.
        t.record(A, 6, 2_500);
        assertEquals(7, t.overlay(A, 5, 3_000));
    }

    @Test
    void overlayNeverLowersTheMinedCount() {
        PendingNonceTracker t = new PendingNonceTracker(TTL);
        t.record(A, 5, 1_000);
        // chain advanced past our pending nonce by other means -> trust the chain.
        assertEquals(9, t.overlay(A, 9, 2_000));
    }

    @Test
    void entryClearsOnceTheChainReflectsOurSend() {
        PendingNonceTracker t = new PendingNonceTracker(TTL);
        t.record(A, 5, 1_000);
        assertEquals(6, t.overlay(A, 5, 2_000));
        assertTrue(t.has(A));
        // our tx mined -> mined count is now 6 (> our nonce 5): entry expires.
        assertEquals(6, t.overlay(A, 6, 3_000));
        assertFalse(t.has(A));
        // and a later read is the plain mined count.
        assertEquals(6, t.overlay(A, 6, 4_000));
    }

    @Test
    void entryExpiresAfterTtlWhenNeverMined() {
        PendingNonceTracker t = new PendingNonceTracker(TTL);
        t.record(A, 5, 1_000);
        // within TTL the overlay still holds.
        assertEquals(6, t.overlay(A, 5, 1_000 + TTL));
        assertTrue(t.has(A));
        // past TTL with the chain never reflecting it (tx dropped) -> stop wedging.
        assertEquals(5, t.overlay(A, 5, 1_001 + TTL));
        assertFalse(t.has(A));
    }

    @Test
    void recordKeepsHighestNoncePerSender() {
        PendingNonceTracker t = new PendingNonceTracker(TTL);
        t.record(A, 5, 1_000);
        // an out-of-order/replacement record with a lower nonce must not lower it.
        t.record(A, 3, 1_500);
        assertEquals(5, t.pendingNonce(A));
        assertEquals(6, t.overlay(A, 5, 2_000));
    }
}
