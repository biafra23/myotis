package com.jaeckel.ethp2p.networking.eth;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The eth/69 served-block window only ever advertises blocks it actually holds — the
 * whole point being to never promise a peer history we can't serve.
 */
class ServedHeaderWindowTest {

    private static Bytes32 hash(long n) {
        return Bytes32.rightPad(Bytes.ofUnsignedLong(0xA000000000000000L | n));
    }

    private static byte[] rlp(long n) {
        return ("header-" + n).getBytes();
    }

    @Test
    void advertisesOnlyTheContiguousRunItHolds() {
        ServedHeaderWindow w = new ServedHeaderWindow(32, hash(0), rlp(0));
        for (long n = 100; n <= 110; n++) w.put(n, hash(n), rlp(n));

        // Head is 110; we hold 100..110 contiguously → advertise [100, 110].
        ServedHeaderWindow.Range r = w.advertise(110, hash(110));
        assertEquals(100, r.earliest());
        assertEquals(110, r.latest());
        assertEquals(hash(110), r.latestHash());
    }

    @Test
    void aGapBreaksTheAdvertisedRunAtTheHead() {
        ServedHeaderWindow w = new ServedHeaderWindow(32, hash(0), rlp(0));
        for (long n = 100; n <= 110; n++) {
            if (n == 107) continue; // hole
            w.put(n, hash(n), rlp(n));
        }
        // Contiguous run ending at 110 is 108..110 — the hole at 107 stops it.
        ServedHeaderWindow.Range r = w.advertise(110, hash(110));
        assertEquals(108, r.earliest());
        assertEquals(110, r.latest());
    }

    @Test
    void emptyWindowAdvertisesGenesisNotHead() {
        ServedHeaderWindow w = new ServedHeaderWindow(32, hash(0), rlp(0));
        ServedHeaderWindow.Range r = w.advertise(21_000_000L, hash(21_000_000L));
        assertEquals(0, r.earliest());
        assertEquals(0, r.latest(), "nothing held near head → advertise genesis (held), never the head");
        assertEquals(hash(0), r.latestHash());
    }

    @Test
    void latestNeverExceedsWhatWeHoldEvenWithAFarAheadHead() {
        // Regression: the chain head is the NETWORK head (from peers / the sensible-head
        // probe), which a light client does not hold. advertise() must clamp latest to the
        // highest header we actually have — never the head.
        ServedHeaderWindow w = new ServedHeaderWindow(32, hash(0), rlp(0));
        for (long n = 20_000_000L; n <= 20_000_010L; n++) w.put(n, hash(n), rlp(n));

        ServedHeaderWindow.Range r = w.advertise(25_000_000L, hash(25_000_000L));
        assertEquals(20_000_010L, r.latest(), "latest must be the highest HELD block, not the head");
        assertEquals(hash(20_000_010L), r.latestHash());
        assertEquals(20_000_000L, r.earliest());
        // And the block we serve at `latest` is really present.
        org.junit.jupiter.api.Assertions.assertArrayEquals(rlp(20_000_010L), w.getByNumber(r.latest()));
    }

    @Test
    void windowCapBoundsHowFarBackWeClaim() {
        ServedHeaderWindow w = new ServedHeaderWindow(5, hash(0), rlp(0));
        for (long n = 100; n <= 120; n++) w.put(n, hash(n), rlp(n));
        // Only the last 5 numbers are retained → advertise [116, 120].
        ServedHeaderWindow.Range r = w.advertise(120, hash(120));
        assertEquals(116, r.earliest());
        assertEquals(120, r.latest());
        assertNull(w.getByNumber(115), "blocks below the cap are evicted");
    }

    @Test
    void liveShrinkEvictsAndLiveGrowRefills() {
        // The Settings knob calls setMaxWindow on a live window: shrinking must evict the
        // tail immediately (the advertised range must never exceed the new cap), growing
        // widens the cap and the window refills as new headers arrive.
        ServedHeaderWindow w = new ServedHeaderWindow(10, hash(0), rlp(0));
        for (long n = 100; n <= 109; n++) w.put(n, hash(n), rlp(n));

        w.setMaxWindow(3);
        ServedHeaderWindow.Range shrunk = w.advertise(109, hash(109));
        assertEquals(107, shrunk.earliest());
        assertEquals(109, shrunk.latest());
        assertNull(w.getByNumber(106), "shrink evicts below the new cap");

        w.setMaxWindow(5);
        for (long n = 110; n <= 111; n++) w.put(n, hash(n), rlp(n));
        ServedHeaderWindow.Range grown = w.advertise(111, hash(111));
        assertEquals(107, grown.earliest(), "grow keeps survivors and refills forward");
        assertEquals(111, grown.latest());
    }

    @Test
    void servesHeldHeadersByNumberAndHashAndAlwaysGenesis() {
        ServedHeaderWindow w = new ServedHeaderWindow(32, hash(0), rlp(0));
        w.put(105, hash(105), rlp(105));

        assertArrayEquals(rlp(105), w.getByNumber(105));
        assertArrayEquals(rlp(105), w.getByHash(hash(105).toHexString()));
        // Genesis is always servable even though it's outside the head window.
        assertArrayEquals(rlp(0), w.getByNumber(0));
        assertArrayEquals(rlp(0), w.getByHash(hash(0).toHexString()));
        // A block we don't hold is null (never a fabricated answer).
        assertNull(w.getByNumber(999));
        assertNull(w.getByHash(hash(999).toHexString()));
    }
}
