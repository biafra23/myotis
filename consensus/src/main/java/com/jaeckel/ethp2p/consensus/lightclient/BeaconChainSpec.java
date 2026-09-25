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
    public static final int SECONDS_PER_SLOT = 12;
    public static final long MAINNET_GENESIS_TIME = 1606824023L;

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

    // Generalized index for next sync committee in BeaconState.
    // Field index 23 (one past current_sync_committee).
    // Pre-Electra: depth 5, gindex = 32 + 23 = 55
    // Post-Electra: depth 6, gindex = 64 + 23 = 87
    public static final int NEXT_SYNC_COMMITTEE_FIELD_INDEX = 23;

    // Generalized index for finalized checkpoint root in BeaconState.
    // finalized_checkpoint is field 20; root is the 2nd child (index 1) within Checkpoint.
    // Pre-Electra: depth 6, gindex = (32+20)*2+1 = 105
    // Post-Electra: depth 7, gindex = (64+20)*2+1 = 169
    public static final int FINALIZED_ROOT_GINDEX = 105;
    public static final int FINALIZED_ROOT_DEPTH = 6;
    public static final int FINALIZED_CHECKPOINT_FIELD_INDEX = 20;

    // Gloas (EIP-7732 ePBS + EIP-7688 progressive containers), consensus-specs
    // v1.7.0-beta.2 specs/gloas/light-client/sync-protocol.md. The body carries a
    // payload BID instead of the payload, so a header proves only the execution
    // block hash — signed_execution_payload_bid.message.parent_block_hash — and the
    // Gloas BeaconState is a progressive container, so the state gindices move even
    // though the field indices (20, 22, 23) do not. They are NOT derivable from a
    // branch length the way the pre-Gloas ones are (the depth-derived helpers below
    // give 553/2070/2071 for depths 9/11/11): select them by the fork of the attested
    // slot, as the spec's *_gindex_at_slot helpers do. Rust twin: spec.rs.

    /** {@code get_generalized_index(BeaconState, 'finalized_checkpoint', 'root')} (Gloas). */
    public static final int FINALIZED_ROOT_GINDEX_GLOAS = 735;
    /** {@code get_generalized_index(BeaconState, 'current_sync_committee')} (Gloas). */
    public static final int CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS = 2945;
    /** {@code get_generalized_index(BeaconState, 'next_sync_committee')} (Gloas). */
    public static final int NEXT_SYNC_COMMITTEE_GINDEX_GLOAS = 2946;
    /** {@code get_generalized_index(BeaconBlockBody, 'signed_execution_payload_bid',
     *  'message', 'parent_block_hash')} (Gloas). */
    public static final int EXECUTION_BLOCK_HASH_GINDEX_GLOAS = 2856;
    /** {@code get_generalized_index(deneb.BeaconBlockBody, 'execution_payload', 'block_hash')}:
     *  where a pre-Gloas header carried in the Gloas shape proves its block hash
     *  (normalized to the Gloas branch length with leading zeros). */
    public static final int EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812;

    /** Gloas branch lengths — the SSZ vector lengths on the wire, all fixed. */
    public static final int GLOAS_EXECUTION_BRANCH_LEN = gindexDepth(EXECUTION_BLOCK_HASH_GINDEX_GLOAS); // 11
    public static final int GLOAS_SYNC_COMMITTEE_BRANCH_LEN = gindexDepth(CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS); // 11
    public static final int GLOAS_FINALITY_BRANCH_LEN = gindexDepth(FINALIZED_ROOT_GINDEX_GLOAS); // 9

    /** {@code floorlog2} of a generalized index: the depth of the node it names. */
    public static int gindexDepth(int gindex) {
        return 31 - Integer.numberOfLeadingZeros(gindex);
    }

    /**
     * Compute the generalized index for current_sync_committee given the branch depth.
     * This handles fork-dependent tree structure changes (e.g. Electra adds fields).
     */
    public static int syncCommitteeGindex(int branchDepth) {
        return (1 << branchDepth) + CURRENT_SYNC_COMMITTEE_FIELD_INDEX;
    }

    /**
     * Compute the generalized index for next_sync_committee given the branch depth.
     * One field past current_sync_committee in the BeaconState SSZ container.
     */
    public static int nextSyncCommitteeGindex(int branchDepth) {
        return (1 << branchDepth) + NEXT_SYNC_COMMITTEE_FIELD_INDEX;
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

    /**
     * Estimate the current wall-clock sync committee period for mainnet.
     *
     * @deprecated prefer {@link #currentPeriod(long)} with the network-specific CL
     * genesis time, so the estimate is correct on testnets too.
     */
    @Deprecated
    public static long currentMainnetPeriod() {
        return currentPeriod(MAINNET_GENESIS_TIME);
    }

    /**
     * Estimate the current wall-clock sync committee period from a beacon chain
     * genesis time (seconds since epoch), assuming the mainnet 12s slot time.
     * Prefer {@link #currentPeriod(long, int)} on networks whose slot time differs
     * (e.g. Gnosis Beacon Chain at 5s).
     */
    public static long currentPeriod(long genesisTimeSec) {
        return currentPeriod(genesisTimeSec, SECONDS_PER_SLOT);
    }

    /**
     * Estimate the current wall-clock sync committee period for a network with the
     * given seconds-per-slot. Gnosis Beacon Chain uses 5s slots vs mainnet's 12, so
     * the wall-clock → slot conversion must use the network value or catch-up targets
     * the wrong period.
     *
     * <p>Note: {@link #SLOTS_PER_SYNC_COMMITTEE_PERIOD} is 8192 on both presets
     * ({@code 32*256 == 16*512}), so {@link #computeSyncCommitteePeriod(long)} needs
     * no per-network variant — only this slot-time conversion does.
     */
    public static long currentPeriod(long genesisTimeSec, int secondsPerSlot) {
        return computeSyncCommitteePeriod(wallClockSlot(genesisTimeSec, secondsPerSlot));
    }

    /**
     * The wall-clock slot of a chain with this genesis time and slot length — the one
     * clock read behind the period estimate, the SYNCED gate and the LC hunt. Clamped at
     * 0 for a clock set before genesis, and a non-positive slot length counts as 1 s, so
     * a bad clock or preset degrades to "slot 0" rather than a negative slot or a throw
     * (Rust twin: {@code ChainConfig::current_slot_estimate}, saturating).
     */
    public static long wallClockSlot(long genesisTimeSec, int secondsPerSlot) {
        long nowSec = System.currentTimeMillis() / 1000;
        return Math.max(0L, nowSec - genesisTimeSec) / Math.max(1, secondsPerSlot);
    }
}
