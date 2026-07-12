package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the LC-hunt trigger conditions ({@link BeaconLightClient#huntDue}) —
 * the mirror of the Rust engine's {@code hunt_due} test in sync.rs, so both
 * engines engage the hunt in the same states:
 * <ul>
 *   <li>bootstrap stall: store uninitialized past the stall window</li>
 *   <li>finality starvation: committee period current, finalized head aged
 *       past the freshness slack (the "CATCHING_UP at period X/X" state)</li>
 * </ul>
 */
class BeaconLightClientHuntTest {

    private static final int MAINNET_EPOCH = 32;
    private static final int GNOSIS_EPOCH = 16;

    @Test
    void bootstrapStallTriggersOnlyAfterWindow() {
        long wall = 10_000_000L;
        assertFalse(BeaconLightClient.huntDue(false, 10_000, wall, 0, 0, MAINNET_EPOCH),
                "10s into a failing bootstrap is not a stall yet");
        assertTrue(BeaconLightClient.huntDue(false,
                        BeaconLightClient.HUNT_BOOTSTRAP_STALL_MS, wall, 0, 0, MAINNET_EPOCH),
                "unbootstrapped past the window must hunt");
    }

    @Test
    void finalityStarvationTriggersWhenPeriodCurrentButFinalityStale() {
        long wall = 10_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        long slack = (long) BeaconLightClient.HUNT_SLACK_EPOCHS * MAINNET_EPOCH;

        assertTrue(BeaconLightClient.huntDue(true, 0, wall, period, wall - slack - 1, MAINNET_EPOCH),
                "period current + finality past the slack must hunt");
        assertFalse(BeaconLightClient.huntDue(true, 0, wall, period, wall - 64, MAINNET_EPOCH),
                "fresh finality (normal ~2-epoch lag) must not hunt");
    }

    @Test
    void catchUpTerritoryDoesNotHunt() {
        // Committee period behind wall clock is catch-up's job (its own wide
        // fan-out); hunting there would double-dial the same peers.
        long wall = 10_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        long slack = (long) BeaconLightClient.HUNT_SLACK_EPOCHS * MAINNET_EPOCH;
        assertFalse(BeaconLightClient.huntDue(true, 0, wall, period - 1, wall - slack - 1, MAINNET_EPOCH));
    }

    @Test
    void slackScalesWithEpochLength() {
        // Gnosis: 16-slot epochs → the slack window is half as many slots.
        long wall = 28_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        long gnosisSlack = (long) BeaconLightClient.HUNT_SLACK_EPOCHS * GNOSIS_EPOCH; // 80 slots
        assertTrue(BeaconLightClient.huntDue(true, 0, wall, period, wall - gnosisSlack - 1, GNOSIS_EPOCH));
        assertFalse(BeaconLightClient.huntDue(true, 0, wall, period, wall - gnosisSlack + 1, GNOSIS_EPOCH));
    }
}
