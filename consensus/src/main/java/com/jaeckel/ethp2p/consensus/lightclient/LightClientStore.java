package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;

/**
 * Thread-safe store for the light client state.
 *
 * <p>Holds the finalized and optimistic headers, the current and next sync committees,
 * and associated slot numbers. All access is synchronized on {@code this}.
 */
public class LightClientStore {

    private LightClientHeader finalizedHeader;
    private LightClientHeader optimisticHeader;
    private SyncCommittee currentSyncCommittee;
    private SyncCommittee nextSyncCommittee; // may be null
    private long finalizedSlot;
    private long optimisticSlot;

    /**
     * Initialize the store from a bootstrap.
     *
     * @param header    the trusted light client header
     * @param committee the current sync committee at the header's slot
     */
    public synchronized void initialize(LightClientHeader header, SyncCommittee committee) {
        this.finalizedHeader = header;
        this.optimisticHeader = header;
        this.currentSyncCommittee = committee;
        this.nextSyncCommittee = null;
        this.finalizedSlot = header.beacon().slot();
        this.optimisticSlot = header.beacon().slot();
    }

    /**
     * Update the finalized header and slot.
     *
     * @param header the new finalized header
     * @param slot   the finalized slot
     */
    public synchronized void updateFinalized(LightClientHeader header, long slot) {
        if (slot > this.finalizedSlot) {
            this.finalizedHeader = header;
            this.finalizedSlot = slot;
        }
    }

    /**
     * Update the optimistic header and slot.
     *
     * @param header the new optimistic header (attested header)
     * @param slot   the slot associated with the new optimistic tip
     */
    public synchronized void updateOptimistic(LightClientHeader header, long slot) {
        if (slot > this.optimisticSlot) {
            this.optimisticHeader = header;
            this.optimisticSlot = slot;
        }
    }

    /**
     * Store the next sync committee.
     *
     * @param next the next sync committee
     */
    public synchronized void updateNextSyncCommittee(SyncCommittee next) {
        this.nextSyncCommittee = next;
    }

    /**
     * If {@code newFinalizedSlot} crosses a sync committee period boundary relative to
     * {@code oldFinalizedSlot}, rotate nextSyncCommittee → currentSyncCommittee.
     *
     * <p>The caller must pass the finalized slot <b>before</b> {@link #updateFinalized}
     * was called, so the period comparison is correct.
     *
     * @param oldFinalizedSlot the finalized slot before the current update
     * @param newFinalizedSlot the newly finalized slot
     */
    public synchronized void applyNextSyncCommitteeWhenPeriodChanges(long oldFinalizedSlot, long newFinalizedSlot) {
        if (nextSyncCommittee == null) {
            return;
        }
        long oldPeriod = BeaconChainSpec.computeSyncCommitteePeriod(oldFinalizedSlot);
        long newPeriod = BeaconChainSpec.computeSyncCommitteePeriod(newFinalizedSlot);
        if (newPeriod > oldPeriod) {
            currentSyncCommittee = nextSyncCommittee;
            nextSyncCommittee = null;
        }
    }

    /**
     * Force-rotate the sync committee if the wall clock indicates we are past the
     * boundary. Used during catch-up when finality hasn't crossed the boundary yet
     * but we know from wall clock that the next period's committee should be active.
     *
     * @param currentSlotEstimate estimated current slot from wall clock
     */
    public synchronized void forceRotateIfPastPeriod(long currentSlotEstimate) {
        if (nextSyncCommittee == null) {
            return;
        }
        long storePeriod = BeaconChainSpec.computeSyncCommitteePeriod(finalizedSlot);
        long wallPeriod = BeaconChainSpec.computeSyncCommitteePeriod(currentSlotEstimate);
        if (wallPeriod > storePeriod) {
            currentSyncCommittee = nextSyncCommittee;
            nextSyncCommittee = null;
        }
    }

    public synchronized LightClientHeader getFinalizedHeader() {
        return finalizedHeader;
    }

    public synchronized LightClientHeader getOptimisticHeader() {
        return optimisticHeader;
    }

    public synchronized SyncCommittee getCurrentSyncCommittee() {
        return currentSyncCommittee;
    }

    public synchronized SyncCommittee getNextSyncCommittee() {
        return nextSyncCommittee;
    }

    public synchronized long getFinalizedSlot() {
        return finalizedSlot;
    }

    public synchronized long getOptimisticSlot() {
        return optimisticSlot;
    }

    public synchronized boolean isInitialized() {
        return currentSyncCommittee != null;
    }
}
