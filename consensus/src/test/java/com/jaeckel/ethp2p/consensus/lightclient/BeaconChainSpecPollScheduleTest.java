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
        // The 1/3 mark + 500 ms margin + a draw from a quarter-slot window, capped at 2/3.
        assertEquals(4_499, BeaconChainSpec.finalityPollOffsetMillis(12, 0));
        assertEquals(7_499, BeaconChainSpec.finalityPollOffsetMillis(12, 3_000));
        assertEquals(4_499, BeaconChainSpec.finalityPollOffsetMillis(12, 3_001)); // wraps
        assertEquals(2_166, BeaconChainSpec.finalityPollOffsetMillis(5, 0)); // gnosis
        assertEquals(3_333, BeaconChainSpec.finalityPollOffsetMillis(5, 1_167)); // capped at 2/3
        assertEquals(2_166, BeaconChainSpec.finalityPollOffsetMillis(5, 1_168)); // wraps
        assertEquals(433, BeaconChainSpec.finalityPollOffsetMillis(1, 0)); // margin capped at a tenth
        assertEquals(433, BeaconChainSpec.finalityPollOffsetMillis(0, 0)); // non-positive → 1 s
        long[][] cases = {{12, 4_499, 7_499, 3_000}, {5, 2_166, 3_333, 1_167}, {1, 433, 666, 233}};
        for (long[] c : cases) {
            int sps = (int) c[0];
            long lo = c[1], hi = c[2], window = c[3];
            for (long r : new long[] {0, 1, 999, -1, Long.MIN_VALUE, Long.MAX_VALUE, window - 1, window}) {
                long o = BeaconChainSpec.finalityPollOffsetMillis(sps, r);
                assertTrue(o >= lo && o <= hi && o <= sps * 1000L * 2 / 3, sps + "/" + r + ": " + o);
            }
            assertEquals(hi, BeaconChainSpec.finalityPollOffsetMillis(sps, window), sps + ": the window's top");
        }
    }

    /** A poll long ago: only the rest applies. */
    private static long untilNext(long now, long off) {
        return BeaconChainSpec.millisUntilNextPoll(now, 60_000, G, 12, off);
    }

    @Test
    void theNextPollLeavesAQuarterSlotOfRestAndNeverRefires() {
        long off = 4_499;
        assertEquals(3_499, untilNext(at(100, 1_000), off));
        assertEquals(15_000, untilNext(at(100, 1_499), off));
        assertEquals(12_000, untilNext(at(100, 4_499), off));
        assertEquals(10_499, untilNext(at(100, 6_000), off));
        // A round that overran into the next point skips ahead.
        assertEquals(12_499, untilNext(at(101, 4_000), off));
        // Gnosis: 5 s slots, 1.25 s rest, and no quota floor (its slot is shorter).
        assertEquals(1_666, BeaconChainSpec.millisUntilNextPoll(G * 1000 + 5_000 * 7 + 500, 0, G, 5, 2_166));
    }

    @Test
    void aClockBeforeGenesisWaitsAtMostTheLeastWaitPlusASlot() {
        assertEquals(15_000, untilNext(0, 4_499));
        assertEquals(23_000, BeaconChainSpec.millisUntilNextPoll(0, 0, G, 12, 4_499));
    }

    @Test
    void everyDelayLeavesTheRestAndLandsOnTheGrid() {
        long off = 4_499;
        for (long ms = 0; ms < 24_000; ms += 37) {
            long now = at(200, 0) + ms;
            long wait = untilNext(now, off);
            assertTrue(wait > 3_000 && wait <= 15_000, "wait " + wait);
            assertEquals(off, (now + wait - G * 1000) % 12_000, "at +" + ms);
        }
    }

    @Test
    void aGridPollIsFollowedASlotLaterWhateverItsRound() {
        long off = 4_499;
        long p = at(300, off);
        for (long round = 0; round < 9_000; round += 250) {
            long wait = BeaconChainSpec.millisUntilNextPoll(p + round, round, G, 12, off);
            assertEquals(p + 12_000, p + round + wait, "round " + round);
        }
    }

    @Test
    void thePollAfterAnOffGridOneKeepsLighthousesQuota() {
        long off = 4_499;
        // Without the floor, a poll at the slot's start would be followed 4.5 s later.
        assertEquals(15_499, BeaconChainSpec.millisUntilNextPoll(at(300, 1_000), 1_000, G, 12, off));
        for (long startMs = 0; startMs < 12_000; startMs += 37) {
            for (long round : new long[] {0, 200, 1_000, 5_000, 8_000}) {
                long start = at(400, startMs);
                long now = start + round;
                long wait = BeaconChainSpec.millisUntilNextPoll(now, round, G, 12, off);
                long next = now + wait;
                String label = startMs + "+" + round;
                assertTrue(next - start >= 11_000, label + ": " + (next - start));
                assertTrue(wait > 3_000, label + ": " + wait);
                assertEquals(off, (next - G * 1000) % 12_000, label);
                assertTrue(next - start <= Math.max(round + 3_000, 11_000) + 12_000, label);
            }
        }
    }
}
