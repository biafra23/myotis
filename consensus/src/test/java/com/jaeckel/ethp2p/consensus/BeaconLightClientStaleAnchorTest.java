package com.jaeckel.ethp2p.consensus;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Behavioral test of the weak-subjectivity gate: a cold start whose best anchor
 * is ancient must PARK (STALE_ANCHOR, fail closed, before any peer contact), and
 * {@link BeaconLightClient#acceptStaleAnchor()} must release the park. No peers
 * are configured, so the only network activity is the local libp2p host bind.
 */
class BeaconLightClientStaleAnchorTest {

    private static final long MAINNET_GENESIS = 1_606_824_023L;

    private static BeaconSyncState.State stateOf(BeaconSyncState s) {
        return s.getSyncState(MAINNET_GENESIS, 12);
    }

    private static void awaitState(BeaconSyncState s, boolean wantStale) throws InterruptedException {
        long deadline = System.nanoTime() + 15_000_000_000L;
        while ((stateOf(s) == BeaconSyncState.State.STALE_ANCHOR) != wantStale
                && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
    }

    @Test
    @Timeout(60)
    void ancientAnchorParksColdStart_andAcceptReleasesIt() throws Exception {
        BeaconSyncState syncState = new BeaconSyncState();
        // Checkpoint at period 10 — decades of periods behind the real mainnet
        // wall clock derived from the genuine genesis time.
        BeaconLightClient blc = new BeaconLightClient(
                List.of(),
                new byte[32],
                8192L * 10,
                new byte[]{0x06, 0x00, 0x00, 0x00},
                new byte[32],
                syncState,
                null,
                null,
                null,
                MAINNET_GENESIS);
        try {
            blc.start();
            awaitState(syncState, true);
            assertEquals(BeaconSyncState.State.STALE_ANCHOR, stateOf(syncState),
                    "an anchor thousands of periods old must park the cold start");
            assertEquals(10L, syncState.getStaleAnchorPeriod(),
                    "the refused anchor's period is surfaced for status displays");
            assertEquals(com.jaeckel.ethp2p.consensus.lightclient.WeakSubjectivity.DEFAULT_BOUND_PERIODS,
                    syncState.getWsBoundPeriods(),
                    "with no network default configured, the fallback bound applies");

            // The user's consent releases the park (this run only).
            blc.acceptStaleAnchor();
            awaitState(syncState, false);
            assertNotEquals(BeaconSyncState.State.STALE_ANCHOR, stateOf(syncState),
                    "acceptStaleAnchor must release the park within the 1 s re-evaluation");
        } finally {
            blc.close();
        }
    }
}
