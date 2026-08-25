package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The weak-subjectivity anchor-age gate: pure math + the state-machine surfacing. */
class WeakSubjectivityTest {

    @Test
    void staleness_isExclusiveAtTheBound_andSkewSafe() {
        // age == bound is NOT stale (inclusive headroom)…
        assertFalse(WeakSubjectivity.isStale(1800, 1813, 13));
        // …one period past it is.
        assertTrue(WeakSubjectivity.isStale(1800, 1814, 13));
        // A wall clock BEHIND the anchor (skew) reads as fresh — a backwards clock
        // can only make the check more permissive; the device clock is out of scope.
        assertFalse(WeakSubjectivity.isStale(1800, 1700, 13));
    }

    @Test
    void effectiveBound_overrideWinsThenNetworkDefaultThenFallback() {
        assertEquals(40, WeakSubjectivity.effectiveBound(40, 13));
        assertEquals(13, WeakSubjectivity.effectiveBound(0, 13));
        assertEquals(3, WeakSubjectivity.effectiveBound(0, 3));
        assertEquals(WeakSubjectivity.DEFAULT_BOUND_PERIODS, WeakSubjectivity.effectiveBound(0, 0));
    }

    @Test
    void mainnetDefault_matchesTheSpecPlateauFloor() {
        // 3532 epochs (the spec plateau) / 256 epochs-per-period = 13.79… → floor 13,
        // rounded DOWN so the bound never exceeds the spec window.
        assertEquals(13L, WeakSubjectivity.DEFAULT_BOUND_PERIODS);
    }

    @Test
    void staleAnchorPark_dominatesTheSyncStateMachine_untilCleared() {
        BeaconSyncState state = new BeaconSyncState();
        // Pre-bootstrap a fresh state reports SYNCING…
        assertEquals(BeaconSyncState.State.SYNCING,
                state.getSyncState(1_606_824_023L, 12));
        // …a marked park reports STALE_ANCHOR and remembers the refused anchor…
        state.markStaleAnchor(1825L);
        state.setWsBoundPeriods(13L);
        assertEquals(BeaconSyncState.State.STALE_ANCHOR,
                state.getSyncState(1_606_824_023L, 12));
        assertEquals(1825L, state.getStaleAnchorPeriod());
        assertEquals(13L, state.getWsBoundPeriods());
        // …and clearing it (bound raised / risk accepted / anchor fresh) returns
        // the machine to its normal derivation.
        state.clearStaleAnchor();
        assertEquals(BeaconSyncState.State.SYNCING,
                state.getSyncState(1_606_824_023L, 12));
        assertEquals(-1L, state.getStaleAnchorPeriod());
    }
}
