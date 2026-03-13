package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Processes light client updates against a {@link LightClientStore}.
 *
 * <p>Validates sync aggregate signatures and Merkle inclusion proofs before
 * advancing the finalized and optimistic headers in the store.
 */
public class LightClientProcessor {

    private static final Logger log = LoggerFactory.getLogger(LightClientProcessor.class);

    private final LightClientStore store;
    private final byte[] forkVersion;
    private final byte[] genesisValidatorsRoot;

    public LightClientProcessor(LightClientStore store, byte[] forkVersion, byte[] genesisValidatorsRoot) {
        this.store = store;
        this.forkVersion = forkVersion;
        this.genesisValidatorsRoot = genesisValidatorsRoot;
    }

    /**
     * Process a {@link LightClientFinalityUpdate}.
     *
     * <ol>
     *   <li>Verify sync aggregate over the attested header.</li>
     *   <li>Verify the finality branch (proves finalizedHeader is finalized in attested state).</li>
     *   <li>Update the store's finalized and optimistic headers.</li>
     *   <li>Rotate the sync committee if a period boundary was crossed.</li>
     * </ol>
     *
     * @param update the finality update to process
     * @return true if the update was successfully applied
     */
    public boolean processFinalityUpdate(LightClientFinalityUpdate update) {
        SyncCommittee committee = store.getCurrentSyncCommittee();
        if (committee == null) {
            log.debug("[lc-processor] Finality update rejected: no current sync committee");
            return false;
        }

        long attestedSlot = update.attestedHeader().beacon().slot();
        long finalizedSlot = update.finalizedHeader().beacon().slot();
        int participation = update.syncAggregate().countParticipants();
        log.debug("[lc-processor] Processing finality update: attestedSlot={}, finalizedSlot={}, " +
                "signatureSlot={}, participation={}/512, finalityBranchLen={}",
                attestedSlot, finalizedSlot, update.signatureSlot(),
                participation, update.finalityBranch().length);

        // Verify sync aggregate over attested header
        if (!SyncCommitteeVerifier.verify(
                update.syncAggregate(),
                committee,
                update.attestedHeader().beacon(),
                forkVersion,
                genesisValidatorsRoot)) {
            log.debug("[lc-processor] Finality update rejected: BLS verification failed " +
                    "(attestedSlot={}, forkVersion={}, participation={})",
                    attestedSlot, bytesToHex(forkVersion), participation);
            return false;
        }

        // Verify finality branch: proves finalizedHeader.beacon is finalized in attestedHeader's state.
        // Branch length is fork-dependent (6 pre-Electra, 7 post-Electra).
        int finalityDepth = update.finalityBranch().length;
        int finalityGindex = BeaconChainSpec.finalizedRootGindex(finalityDepth);
        if (!SszUtil.verifyMerkleBranch(
                update.finalizedHeader().beacon().hashTreeRoot(),
                update.finalityBranch(),
                finalityDepth,
                finalityGindex,
                update.attestedHeader().beacon().stateRoot())) {
            log.debug("[lc-processor] Finality update rejected: Merkle branch invalid " +
                    "(depth={}, gindex={}, finalizedSlot={})",
                    finalityDepth, finalityGindex, finalizedSlot);
            return false;
        }

        long oldFinalizedSlot = store.getFinalizedSlot();
        store.updateFinalized(update.finalizedHeader(), finalizedSlot);
        store.updateOptimistic(update.attestedHeader(), update.signatureSlot());

        // Rotate sync committee if we crossed a period boundary.
        // Pass the OLD finalized slot so the period comparison is correct
        // (updateFinalized may have already advanced this.finalizedSlot).
        store.applyNextSyncCommitteeWhenPeriodChanges(oldFinalizedSlot, finalizedSlot);

        log.debug("[lc-processor] Finality update applied: finalizedSlot {} → {}", oldFinalizedSlot, finalizedSlot);
        return true;
    }

    /**
     * Process a {@link LightClientUpdate} (which may carry the next sync committee).
     *
     * <ol>
     *   <li>Verify sync aggregate over the attested header.</li>
     *   <li>Verify the finality branch.</li>
     *   <li>If a next sync committee is provided, verify its branch and store it.</li>
     *   <li>Update the store's finalized and optimistic headers.</li>
     *   <li>Rotate the sync committee if a period boundary was crossed.</li>
     * </ol>
     *
     * @param update the update to process
     * @return true if the update was successfully applied
     */
    public boolean processUpdate(LightClientUpdate update) {
        SyncCommittee committee = store.getCurrentSyncCommittee();
        if (committee == null) {
            return false;
        }

        // Verify sync aggregate over attested header
        if (!SyncCommitteeVerifier.verify(
                update.syncAggregate(),
                committee,
                update.attestedHeader().beacon(),
                forkVersion,
                genesisValidatorsRoot)) {
            return false;
        }

        // Verify finality branch (depth is fork-dependent)
        int finalityDepth = update.finalityBranch().length;
        int finalityGindex = BeaconChainSpec.finalizedRootGindex(finalityDepth);
        if (!SszUtil.verifyMerkleBranch(
                update.finalizedHeader().beacon().hashTreeRoot(),
                update.finalityBranch(),
                finalityDepth,
                finalityGindex,
                update.attestedHeader().beacon().stateRoot())) {
            return false;
        }

        // Verify and store next sync committee if present
        SyncCommittee nextSyncCommittee = update.nextSyncCommittee();
        if (nextSyncCommittee != null && store.getNextSyncCommittee() == null) {
            // Verify the next sync committee branch against the attested state
            // Branch depth is fork-dependent (5 pre-Electra, 6 post-Electra)
            int scDepth = update.nextSyncCommitteeBranch().length;
            int scGindex = BeaconChainSpec.syncCommitteeGindex(scDepth);
            if (!SszUtil.verifyMerkleBranch(
                    nextSyncCommittee.hashTreeRoot(),
                    update.nextSyncCommitteeBranch(),
                    scDepth,
                    scGindex,
                    update.attestedHeader().beacon().stateRoot())) {
                return false;
            }
            store.updateNextSyncCommittee(nextSyncCommittee);
        }

        long oldFinalizedSlot = store.getFinalizedSlot();
        long finalizedSlot = update.finalizedHeader().beacon().slot();
        store.updateFinalized(update.finalizedHeader(), finalizedSlot);
        store.updateOptimistic(update.attestedHeader(), update.signatureSlot());

        // Rotate sync committee if we crossed a period boundary.
        // Pass the OLD finalized slot so the period comparison is correct.
        store.applyNextSyncCommitteeWhenPeriodChanges(oldFinalizedSlot, finalizedSlot);

        return true;
    }

    public LightClientStore getStore() {
        return store;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
