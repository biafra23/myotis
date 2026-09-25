package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import org.junit.jupiter.api.Test;

import static com.jaeckel.ethp2p.consensus.BeaconSyncState.State.CATCHING_UP;
import static com.jaeckel.ethp2p.consensus.BeaconSyncState.State.STALE_ANCHOR;
import static com.jaeckel.ethp2p.consensus.BeaconSyncState.State.SYNCED;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pins the SYNCED gate ({@link BeaconSyncState#syncStateAt}), in particular its finality
 * freshness condition: SYNCED only while the finalized slot is within
 * {@link BeaconSyncState#SYNCED_SLOT_SLACK_EPOCHS} epochs of the wall clock, on the
 * network's own epoch length. The mirror of the Rust engine's
 * {@code sync_state_marks_only_a_current_finality_as_synced} (sync.rs), so both engines
 * leave SYNCED at the same staleness.
 */
class BeaconSyncStateSyncedGateTest {

    private static final int MAINNET_EPOCH = 32;
    private static final int GNOSIS_EPOCH = 16;
    private static final int GNOSIS_SECONDS_PER_SLOT = 5;
    private static final long SLACK_EPOCHS = BeaconSyncState.SYNCED_SLOT_SLACK_EPOCHS;

    private static byte[] root(int seed) {
        byte[] r = new byte[32];
        for (int i = 0; i < 32; i++) r[i] = (byte) (seed + i);
        return r;
    }

    /** A state that passes every gate except, possibly, finality freshness: a finalized
     *  execution root at {@code finalizedSlot}, a full roots window, and the committee of
     *  {@code wallSlot}'s period. */
    private static BeaconSyncState heldAt(long finalizedSlot, long wallSlot) {
        BeaconSyncState s = new BeaconSyncState();
        for (int i = 0; i < BeaconSyncState.FILL_THRESHOLD; i++) {
            s.recordStateRoot(finalizedSlot - i, root(i), true);
        }
        s.update(finalizedSlot, root(0xA0), finalizedSlot + 64);
        s.setCurrentSyncCommitteePeriod(BeaconChainSpec.computeSyncCommitteePeriod(wallSlot));
        return s;
    }

    @Test
    void finalityWithinTheSlackIsSynced_oneSlotPastItIsNot() {
        long wall = 10_000_000L; // mid-period: period 1220 spans 9_994_240..10_002_431
        long fin = wall - 64;    // the normal ~2-epoch finality lag
        BeaconSyncState s = heldAt(fin, wall);
        assertEquals(SYNCED, s.syncStateAt(wall, MAINNET_EPOCH));

        long slack = SLACK_EPOCHS * MAINNET_EPOCH; // 160 slots = 32 min
        assertEquals(SYNCED, s.syncStateAt(fin + slack, MAINNET_EPOCH), "the slack is inclusive");
        assertEquals(CATCHING_UP, s.syncStateAt(fin + slack + 1, MAINNET_EPOCH),
                "one slot past the slack, with the committee still current");
    }

    @Test
    void gnosisGeometryUsesItsOwnEpochLength() {
        long wall = 28_000_000L; // period 3417 spans 27_992_064..28_000_255
        long fin = wall - 32;    // ~2 Gnosis epochs
        BeaconSyncState s = heldAt(fin, wall);
        long slack = SLACK_EPOCHS * GNOSIS_EPOCH; // 80 slots = 400 s
        assertEquals(SYNCED, s.syncStateAt(fin + slack, GNOSIS_EPOCH));
        assertEquals(CATCHING_UP, s.syncStateAt(fin + slack + 1, GNOSIS_EPOCH));

        // The same staleness is fresh on the mainnet preset and stale on Gnosis: the gate
        // must be fed the network's epoch, not BeaconChainSpec.SLOTS_PER_EPOCH.
        BeaconSyncState behind100 = heldAt(wall - 100, wall);
        assertEquals(SYNCED, behind100.syncStateAt(wall, MAINNET_EPOCH));
        assertEquals(CATCHING_UP, behind100.syncStateAt(wall, GNOSIS_EPOCH));
    }

    @Test
    void stalledFinalityRegressesAndRecovers() {
        long wall = 10_000_000L;
        BeaconSyncState s = heldAt(wall - 64, wall);
        assertEquals(SYNCED, s.syncStateAt(wall, MAINNET_EPOCH));

        // The feed stalls (withheld, or a fork this build can't follow): no finality update
        // for two hours. The committee period is still current, which alone used to keep
        // this SYNCED until the period ended.
        long later = wall + 600;
        assertEquals(CATCHING_UP, s.syncStateAt(later, MAINNET_EPOCH));

        // Finality lands again: SYNCED is not latched in either direction.
        s.update(later - 64, root(0xB0), later - 1);
        assertEquals(SYNCED, s.syncStateAt(later, MAINNET_EPOCH));
    }

    @Test
    void aResumedSnapshotsOldFinalityIsNotSynced() {
        // Resumed from a snapshot written at this period's start: the committee is current
        // and the sidecar refilled the roots window, but the finality is hours old. That is
        // catch-up, not SYNCED, until the first fresh finality update lands.
        long wall = 10_000_000L;
        long periodStart = wall - wall % BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        BeaconSyncState s = heldAt(periodStart, wall);
        assertEquals(CATCHING_UP, s.syncStateAt(wall, MAINNET_EPOCH));

        s.update(wall - 64, root(0xC0), wall - 1);
        assertEquals(SYNCED, s.syncStateAt(wall, MAINNET_EPOCH));
    }

    @Test
    void theOtherGatesStillApplyToFreshFinality() {
        long periodStart = 1221L * BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        long wall = periodStart + 10;
        long fin = wall - 64; // fresh, but still in period 1220

        // Committee behind the wall clock's period: CATCHING_UP until the rotation.
        BeaconSyncState s = heldAt(fin, wall);
        s.setCurrentSyncCommitteePeriod(1220L);
        assertEquals(CATCHING_UP, s.syncStateAt(wall, MAINNET_EPOCH));
        s.setCurrentSyncCommitteePeriod(1221L);
        assertEquals(SYNCED, s.syncStateAt(wall, MAINNET_EPOCH));

        // A stale-anchor park overrides everything.
        s.markStaleAnchor(1221L);
        assertEquals(STALE_ANCHOR, s.syncStateAt(wall, MAINNET_EPOCH));
        s.clearStaleAnchor();

        // A sparse roots window is not SYNCED either.
        BeaconSyncState sparse = new BeaconSyncState();
        for (int i = 0; i < BeaconSyncState.FILL_THRESHOLD - 1; i++) {
            sparse.recordStateRoot(fin - i, root(i), true);
        }
        sparse.update(fin, root(0xA0), fin + 64);
        sparse.setCurrentSyncCommitteePeriod(1221L);
        assertEquals(CATCHING_UP, sparse.syncStateAt(wall, MAINNET_EPOCH));
    }

    @Test
    void getSyncStateReadsTheWallClockInTheNetworksOwnSlots() {
        // Genesis placed so the real clock sits mid-period on a 5-second-slot chain.
        long nowSec = System.currentTimeMillis() / 1000L;
        long wallSlot = 1000L * BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD + 4096;
        long genesis = nowSec - wallSlot * GNOSIS_SECONDS_PER_SLOT;
        long slack = SLACK_EPOCHS * GNOSIS_EPOCH;

        // A few slots either side of the slack, so a slow test can't cross it.
        assertEquals(SYNCED, heldAt(wallSlot - slack + 3, wallSlot)
                .getSyncState(genesis, GNOSIS_SECONDS_PER_SLOT, GNOSIS_EPOCH));
        assertEquals(CATCHING_UP, heldAt(wallSlot - slack - 3, wallSlot)
                .getSyncState(genesis, GNOSIS_SECONDS_PER_SLOT, GNOSIS_EPOCH));
    }

    @Test
    void huntEngagesAtTheSameStalenessThatEndsSynced() {
        long wall = 10_000_000L;
        long period = BeaconChainSpec.computeSyncCommitteePeriod(wall);
        for (int epoch : new int[] {MAINNET_EPOCH, GNOSIS_EPOCH}) {
            long slack = SLACK_EPOCHS * epoch;
            for (long fin : new long[] {wall - slack, wall - slack - 1}) {
                boolean synced = heldAt(fin, wall).syncStateAt(wall, epoch) == SYNCED;
                boolean hunt = BeaconLightClient.huntDue(false, true, 0, 0, wall, period, fin, epoch);
                assertEquals(!synced, hunt,
                        "epoch " + epoch + ", finality " + (wall - fin) + " slots behind");
            }
        }
    }
}
