package com.jaeckel.ethp2p.networking.eth;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The window-poisoning admission filter: a peer answering OUR GetBlockHeaders can
 * only feed the serve caches / chainHead with headers matching what we asked for.
 * A fabricated far-future number (or a header we never requested) must be rejected,
 * so it cannot pin the served-window eviction floor or inflate the announced head.
 * Twin of the Rust EL's remember_served guard (PR #229).
 */
class HeaderReqTest {

    private static Bytes32 hash(long n) {
        return Bytes32.rightPad(Bytes.ofUnsignedLong(0xC0FFEE0000000000L | n));
    }

    @Test
    void byNumberAdmitsOnlyTheRequestedContiguousRange() {
        EthHandler.HeaderReq req = EthHandler.HeaderReq.byNumber(21_000_000L, 8);
        assertTrue(req.admits(hash(21_000_000L), 21_000_000L), "start of range");
        assertTrue(req.admits(hash(21_000_007L), 21_000_007L), "last of range");
        assertFalse(req.admits(hash(20_999_999L), 20_999_999L), "just below range");
        assertFalse(req.admits(hash(21_000_008L), 21_000_008L), "just above range");
        // The poisoning payload: a fabricated far-future number a hostile peer
        // would use to pin the eviction floor / inflate the head.
        assertFalse(req.admits(hash(Long.MAX_VALUE), Long.MAX_VALUE), "far-future fabrication");
    }

    @Test
    void byNumberCountOfOneAdmitsExactlyThatBlock() {
        EthHandler.HeaderReq req = EthHandler.HeaderReq.byNumber(500L, 1);
        assertTrue(req.admits(hash(500L), 500L));
        assertFalse(req.admits(hash(501L), 501L));
    }

    @Test
    void byNumberDoesNotOverflowNearMaxCount() {
        // start + count must not wrap negative and admit everything.
        EthHandler.HeaderReq req = EthHandler.HeaderReq.byNumber(Long.MAX_VALUE - 2, Integer.MAX_VALUE);
        assertTrue(req.admits(hash(Long.MAX_VALUE - 2), Long.MAX_VALUE - 2));
        assertFalse(req.admits(hash(0L), 0L), "low number must not be admitted via overflow");
    }

    @Test
    void byHashAdmitsOnlyTheExactRequestedHash() {
        EthHandler.HeaderReq req = EthHandler.HeaderReq.byHash(hash(42L));
        assertTrue(req.admits(hash(42L), 999L), "matching hash, any number");
        assertFalse(req.admits(hash(43L), 42L), "wrong hash, even with a plausible number");
    }
}
