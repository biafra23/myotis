package com.jaeckel.ethp2p.consensus.lightclient;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The wall-clock period estimate must honor the network's slot time. Gnosis uses
 * 5s slots vs mainnet's 12; using the wrong value makes catch-up target a period
 * ~2.4x too small and the light client never reaches SYNCED.
 */
class BeaconChainSpecPeriodTest {

    private static final long GNOSIS_GENESIS = 1638993340L;

    @Test
    void slotsPerSyncCommitteePeriodIsEqualAcrossPresets() {
        // 32*256 (mainnet) == 16*512 (gnosis) == 8192, which is why
        // computeSyncCommitteePeriod needs no per-network variant.
        assertEquals(8192, BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD);
    }

    @Test
    void currentPeriodHonorsSecondsPerSlot() {
        long nowSec = System.currentTimeMillis() / 1000;
        long expected5 = ((nowSec - GNOSIS_GENESIS) / 5) / 8192;
        long actual5 = BeaconChainSpec.currentPeriod(GNOSIS_GENESIS, 5);
        // Allow ±1 for the second that may tick between the two reads.
        assertTrue(Math.abs(actual5 - expected5) <= 1,
                "expected ~" + expected5 + " got " + actual5);

        // The 5s estimate must exceed the (wrong) 12s estimate for the same genesis,
        // by roughly the 12/5 ratio — this is exactly the bug a hardcoded 12 caused.
        long actual12 = BeaconChainSpec.currentPeriod(GNOSIS_GENESIS, 12);
        assertTrue(actual5 > actual12, "5s period (" + actual5 + ") must exceed 12s period (" + actual12 + ")");
    }

    @Test
    void singleArgOverloadMatchesMainnetSlotTime() {
        assertEquals(
                BeaconChainSpec.currentPeriod(GNOSIS_GENESIS, BeaconChainSpec.SECONDS_PER_SLOT),
                BeaconChainSpec.currentPeriod(GNOSIS_GENESIS));
    }
}
