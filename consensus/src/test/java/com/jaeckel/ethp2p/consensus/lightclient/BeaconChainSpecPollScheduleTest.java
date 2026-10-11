package com.jaeckel.ethp2p.consensus.lightclient;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The steady-state finality poll's schedule: just past a third of the way into every slot,
 * twin of the Rust {@code sync.rs the_finality_poll_fires_just_past_a_third_into_every_slot}.
 */
class BeaconChainSpecPollScheduleTest {

    private static final long G = 1_606_824_023L; // mainnet genesis (s)

    private static long at(long slot, long ms) {
        return G * 1000 + slot * 12_000 + ms;
    }

    @Test
    void thePollPointIsJustPastAThirdOfTheSlot() {
        // The 1/3 mark + 500 ms margin + a draw from a quarter-slot window.
        assertEquals(4_499, BeaconChainSpec.finalityPollOffsetMillis(12, 0));
        assertEquals(7_499, BeaconChainSpec.finalityPollOffsetMillis(12, 3_000));
        assertEquals(4_499, BeaconChainSpec.finalityPollOffsetMillis(12, 3_001)); // wraps
        assertEquals(2_166, BeaconChainSpec.finalityPollOffsetMillis(5, 0)); // gnosis
        assertEquals(433, BeaconChainSpec.finalityPollOffsetMillis(1, 0)); // margin capped at a tenth
        assertEquals(433, BeaconChainSpec.finalityPollOffsetMillis(0, 0)); // non-positive → 1 s
        for (long r : new long[] {0, 1, 999, -1, Long.MIN_VALUE, Long.MAX_VALUE}) {
            long mainnet = BeaconChainSpec.finalityPollOffsetMillis(12, r);
            long gnosis = BeaconChainSpec.finalityPollOffsetMillis(5, r);
            assertTrue(mainnet >= 4_499 && mainnet <= 7_499, "mainnet " + mainnet);
            assertTrue(gnosis >= 2_166 && gnosis <= 3_416, "gnosis " + gnosis);
        }
    }

    @Test
    void theNextPollLeavesAQuarterSlotOfRestAndNeverRefires() {
        long off = 4_499;
        assertEquals(3_499, BeaconChainSpec.millisUntilNextPoll(at(100, 1_000), G, 12, off));
        assertEquals(15_000, BeaconChainSpec.millisUntilNextPoll(at(100, 1_499), G, 12, off));
        assertEquals(12_000, BeaconChainSpec.millisUntilNextPoll(at(100, 4_499), G, 12, off));
        assertEquals(10_499, BeaconChainSpec.millisUntilNextPoll(at(100, 6_000), G, 12, off));
        // A round that overran into the next point skips ahead.
        assertEquals(12_499, BeaconChainSpec.millisUntilNextPoll(at(101, 4_000), G, 12, off));
        // Gnosis: 5 s slots, 1.25 s rest.
        assertEquals(1_666, BeaconChainSpec.millisUntilNextPoll(G * 1000 + 5_000 * 7 + 500, G, 5, 2_166));
    }

    @Test
    void aClockBeforeGenesisWaitsAtMostRestPlusASlot() {
        assertEquals(15_000, BeaconChainSpec.millisUntilNextPoll(0, G, 12, 4_499));
    }

    @Test
    void everyDelayLeavesTheRestAndLandsOnTheGrid() {
        long off = 4_499;
        for (long ms = 0; ms < 24_000; ms += 37) {
            long now = at(200, 0) + ms;
            long wait = BeaconChainSpec.millisUntilNextPoll(now, G, 12, off);
            assertTrue(wait > 3_000 && wait <= 15_000, "wait " + wait);
            assertEquals(off, (now + wait - G * 1000) % 12_000, "at +" + ms);
        }
    }
}
