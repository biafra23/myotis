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
 *   <li>starved catch-up: period behind wall clock with zero store progress
 *       past the stall window (a progressing catch-up never hunts)</li>
 *   <li>finality starvation: committee period current, finalized head aged
 *       past the freshness slack (the "CATCHING_UP at period X/X" state),
 *       with engage/disengage hysteresis</li>
 * </ul>
 */
class BeaconLightClientHuntTest {

    private static final int MAINNET_EPOCH = 32;
    private static final int GNOSIS_EPOCH = 16;

    @Test
    void bootstrapStallTriggersOnlyAfterWindow() {
        long wall = 10_000_000L;
        assertFalse(BeaconLightClient.huntDue(false, false, 10_000, 0, wall, 0, 0, MAINNET_EPOCH),
                "10s into a failing bootstrap is not a stall yet");
        assertTrue(BeaconLightClient.huntDue(false, false,
                        BeaconLightClient.HUNT_BOOTSTRAP_STALL_MS, 0, wall, 0, 0, MAINNET_EPOCH),
                "unbootstrapped past the window must hunt");
    }

    @Test
    void finalityStarvationTriggersWhenPeriodCurrentButFinalityStale() {
        long wall = 10_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        long slack = (long) BeaconLightClient.HUNT_SLACK_EPOCHS * MAINNET_EPOCH;

        assertTrue(BeaconLightClient.huntDue(false, true, 0, 0, wall, period,
                        wall - slack - 1, MAINNET_EPOCH),
                "period current + finality past the slack must hunt");
        assertFalse(BeaconLightClient.huntDue(false, true, 0, 0, wall, period,
                        wall - 64, MAINNET_EPOCH),
                "fresh finality (normal ~2-epoch lag) must not hunt");
    }

    @Test
    void progressingCatchUpDoesNotHuntButStarvedCatchUpDoes() {
        long wall = 10_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        long slack = (long) BeaconLightClient.HUNT_SLACK_EPOCHS * MAINNET_EPOCH;

        // Period behind + recent store progress: catch-up's own wide fan-out
        // covers the pool; hunting there would double-dial it.
        assertFalse(BeaconLightClient.huntDue(false, true, 0, 0, wall, period - 1,
                wall - slack - 1, MAINNET_EPOCH));
        // Period behind + zero progress past the stall window: the catch-up
        // fan-out itself is starved — hunt.
        assertTrue(BeaconLightClient.huntDue(false, true, 0,
                BeaconLightClient.HUNT_CATCHUP_STALL_MS, wall, period - 1,
                wall - slack - 1, MAINNET_EPOCH));
        // An ENGAGED hunt survives the period boundary the same way (finality
        // starvation rotating into catch-up must not disengage the boost).
        assertTrue(BeaconLightClient.huntDue(true, true, 0,
                BeaconLightClient.HUNT_CATCHUP_STALL_MS, wall, period - 1,
                wall - slack - 1, MAINNET_EPOCH));
    }

    @Test
    void finalityTriggerHasHysteresis() {
        long wall = 10_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        long slack = (long) BeaconLightClient.HUNT_SLACK_EPOCHS * MAINNET_EPOCH;
        // Staleness between the engaged (slack-1 epochs) and disengaged
        // (slack epochs) thresholds: an engaged hunt stays on, a disengaged
        // one stays off — no flapping at the boundary.
        long between = wall - slack + MAINNET_EPOCH - 1;
        assertTrue(BeaconLightClient.huntDue(true, true, 0, 0, wall, period, between, MAINNET_EPOCH));
        assertFalse(BeaconLightClient.huntDue(false, true, 0, 0, wall, period, between, MAINNET_EPOCH));
    }

    @Test
    void slackScalesWithEpochLength() {
        // Gnosis: 16-slot epochs → the slack window is half as many slots.
        long wall = 28_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        long gnosisSlack = (long) BeaconLightClient.HUNT_SLACK_EPOCHS * GNOSIS_EPOCH; // 80 slots
        assertTrue(BeaconLightClient.huntDue(false, true, 0, 0, wall, period,
                wall - gnosisSlack - 1, GNOSIS_EPOCH));
        assertFalse(BeaconLightClient.huntDue(false, true, 0, 0, wall, period,
                wall - gnosisSlack + 1, GNOSIS_EPOCH));
    }
}
