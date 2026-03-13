package com.jaeckel.ethp2p.consensus.lightclient;

/**
 * Ethereum consensus-layer constants for the light client protocol.
 */
public final class BeaconChainSpec {

    public static final int SLOTS_PER_EPOCH = 32;
    public static final int EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256;
    public static final int SLOTS_PER_SYNC_COMMITTEE_PERIOD =
            SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD; // 8192
    public static final int SYNC_COMMITTEE_SIZE = 512;
    public static final int MIN_SYNC_COMMITTEE_PARTICIPANTS = 1;
    public static final int UPDATE_TIMEOUT = SLOTS_PER_SYNC_COMMITTEE_PERIOD;

    // Domain types (4 bytes each)
    public static final byte[] DOMAIN_SYNC_COMMITTEE = {0x07, 0x00, 0x00, 0x00};

    // Generalized index for execution payload in BeaconBlockBody (Capella+)
    // Body tree: depth 4 from body root, index 25 in the generalized tree
    public static final int EXECUTION_PAYLOAD_GINDEX = 25;
    public static final int EXECUTION_PAYLOAD_DEPTH = 4;

    // Generalized index for current sync committee in BeaconState.
    // Field index 22 in BeaconState container.
    // Pre-Electra (≤28 fields): depth 5, gindex = 32 + 22 = 54
    // Post-Electra (37 fields): depth 6, gindex = 64 + 22 = 86
    public static final int CURRENT_SYNC_COMMITTEE_GINDEX = 54;
    public static final int CURRENT_SYNC_COMMITTEE_DEPTH = 5;
    public static final int CURRENT_SYNC_COMMITTEE_FIELD_INDEX = 22;

    // Generalized index for finalized checkpoint root in BeaconState.
    // finalized_checkpoint is field 20; root is the 2nd child (index 1) within Checkpoint.
    // Pre-Electra: depth 6, gindex = (32+20)*2+1 = 105
    // Post-Electra: depth 7, gindex = (64+20)*2+1 = 169
    public static final int FINALIZED_ROOT_GINDEX = 105;
    public static final int FINALIZED_ROOT_DEPTH = 6;
    public static final int FINALIZED_CHECKPOINT_FIELD_INDEX = 20;

    /**
     * Compute the generalized index for current_sync_committee given the branch depth.
     * This handles fork-dependent tree structure changes (e.g. Electra adds fields).
     */
    public static int syncCommitteeGindex(int branchDepth) {
        return (1 << branchDepth) + CURRENT_SYNC_COMMITTEE_FIELD_INDEX;
    }

    /**
     * Compute the generalized index for finalized_checkpoint.root given the branch depth.
     * The finalized_checkpoint is a Checkpoint container; root is its second field (index 1).
     */
    public static int finalizedRootGindex(int branchDepth) {
        // branchDepth includes the extra level into the Checkpoint container
        int checkpointGindex = (1 << (branchDepth - 1)) + FINALIZED_CHECKPOINT_FIELD_INDEX;
        return checkpointGindex * 2 + 1; // root is at index 1 within Checkpoint
    }

    private BeaconChainSpec() {}

    /**
     * Compute the sync committee period for a given slot.
     */
    public static long computeSyncCommitteePeriod(long slot) {
        return slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD;
    }
}
