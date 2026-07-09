package io.myotis.engines;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The block-selector window ({@link RustVerifiedReads#blockInWindow}) that lets a
 * number-pinned read (MetaMask pins to the just-fetched latest number) resolve to
 * the anchored head, while rejecting genuinely-historical blocks.
 */
class RustBlockWindowTest {

    private static final long HEAD = 25_000_000L;

    private static boolean at(String block) {
        return RustVerifiedReads.blockInWindow(block, () -> HEAD);
    }

    @Test
    void headTagsAndDefaultAreServable() {
        assertTrue(at("latest"));
        assertTrue(at("pending"));
        assertTrue(at("safe"));
        assertTrue(at("finalized"));
        assertTrue(at(null));
        assertTrue(at(""));
    }

    @Test
    void numberPinAtOrNearHeadIsServable() {
        assertTrue(at("0x17d7840"));                          // == HEAD (25_000_000)
        assertTrue(at(Long.toString(HEAD)));                  // decimal form too
        assertTrue(at("0x" + Long.toHexString(HEAD - 64)));   // lag bound
        assertTrue(at("0x" + Long.toHexString(HEAD + 16)));   // ahead bound
    }

    @Test
    void olderOrTooFarAheadNumberIsRejected() {
        assertFalse(at("0x" + Long.toHexString(HEAD - 65)));  // just past the lag bound
        assertFalse(at("0x" + Long.toHexString(HEAD + 17)));  // just past the ahead bound
        assertFalse(at("0x1"));                               // ancient block
        assertFalse(at("earliest"));                          // genesis
    }

    @Test
    void malformedOrNotSyncedIsRejected() {
        assertFalse(at("0xzz"));                              // not a number
        assertFalse(at("garbage"));
        assertFalse(RustVerifiedReads.blockInWindow("0x17d7840", () -> null)); // head unknown
    }
}
