package com.jaeckel.ethp2p.consensus.lightclient;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The steady-state finality poll's schedule ({@link BeaconChainSpec#millisUntilNextPoll}):
 * a third of the way into every slot, twin of the Rust
 * {@code sync.rs the_finality_poll_fires_a_third_into_every_slot}.
 */
class BeaconChainSpecPollScheduleTest {

    private static final long G = 1_606_824_023L; // mainnet genesis (s)

    private static long at(long slot, long ms) {
        return G * 1000 + slot * 12_000 + ms;
    }

    @Test
    void theOffsetIsAThirdOfTheSlot() {
        assertEquals(3_999, BeaconChainSpec.finalityPollOffsetMillis(12));
        assertEquals(1_666, BeaconChainSpec.finalityPollOffsetMillis(5));
        assertEquals(333, BeaconChainSpec.finalityPollOffsetMillis(0)); // non-positive → 1 s
    }

    @Test
    void thePollFiresAtTheNextPointAndNeverTwiceInASlot() {
        long off = 3_999;
        assertEquals(2_999, BeaconChainSpec.millisUntilNextPoll(at(100, 1_000), G, 12, off));
        assertEquals(12_000, BeaconChainSpec.millisUntilNextPoll(at(100, 3_999), G, 12, off));
        assertEquals(11_999, BeaconChainSpec.millisUntilNextPoll(at(100, 4_000), G, 12, off));
        // A round that overran a whole slot skips to the next point.
        assertEquals(11_000, BeaconChainSpec.millisUntilNextPoll(at(101, 4_999), G, 12, off));
        // Gnosis: 5 s slots, the point at 1_666 ms.
        assertEquals(666, BeaconChainSpec.millisUntilNextPoll(G * 1000 + 5_000 * 7 + 1_000, G, 5, 1_666));
        // An offset past the slot wraps.
        assertEquals(500, BeaconChainSpec.millisUntilNextPoll(at(5, 0), G, 12, 12_500));
    }

    @Test
    void aClockBeforeGenesisWaitsAtMostOneSlot() {
        assertEquals(12_000, BeaconChainSpec.millisUntilNextPoll(0, G, 12, 3_999));
        assertEquals(10, BeaconChainSpec.millisUntilNextPoll(G * 1000 + 3_989, G, 12, 3_999));
    }

    @Test
    void everyDelayLandsOnTheGrid() {
        long off = 3_999;
        for (long ms = 0; ms < 24_000; ms += 37) {
            long now = at(200, 0) + ms;
            long wait = BeaconChainSpec.millisUntilNextPoll(now, G, 12, off);
            assertTrue(wait > 0 && wait <= 12_000, "wait " + wait);
            assertEquals(off, (now + wait - G * 1000) % 12_000, "at +" + ms);
        }
    }
}
