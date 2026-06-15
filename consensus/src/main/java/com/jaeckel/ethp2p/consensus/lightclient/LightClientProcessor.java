package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
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

    /** Aggregate signature of the last successfully applied finality update. The
     *  signature commits to the attested header root (whose state root in turn commits
     *  the finality branch), so a byte-identical signature is the same already-applied
     *  update: any variant with different contents would fail verification anyway.
     *  Lets the 12s poll loop skip re-verifying an unchanged head — each BLS verify
     *  costs ~18s on Android/ART, so without this the steady-state loop burns a full
     *  core re-proving the same update. */
    private volatile byte[] lastAppliedFinalitySig;

    public LightClientProcessor(LightClientStore store, byte[] forkVersion, byte[] genesisValidatorsRoot) {
        this.store = store;
        this.forkVersion = forkVersion.clone();
        this.genesisValidatorsRoot = genesisValidatorsRoot.clone();
        log.info("[lc-processor] Initialized with forkVersion={}, fv[0]={}, id={}",
                bytesToHex(this.forkVersion), this.forkVersion[0], System.identityHashCode(this.forkVersion));
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

        byte[] sig = update.syncAggregate().syncCommitteeSignature();
        byte[] lastSig = lastAppliedFinalitySig;
        if (lastSig != null && java.util.Arrays.equals(lastSig, sig)) {
            log.debug("[lc-processor] Finality update is a duplicate of the already-applied one "
                    + "(attestedSlot={}) — skipping re-verify", attestedSlot);
            return true;
        }

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
                    "(attestedSlot={}, forkVersion={}, fv[0]={}, id={}, participation={})",
                    attestedSlot, bytesToHex(forkVersion), forkVersion[0],
                    System.identityHashCode(forkVersion), participation);
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

        // Bind each header's execution payload to its beacon body. The headers we store
        // here feed the execution-layer verification chain (EL state root / block hash),
        // and the sync-committee signature does NOT cover the execution payload — only
        // this branch does.
        if (!verifyExecutionBranch(update.attestedHeader())
                || !verifyExecutionBranch(update.finalizedHeader())) {
            log.debug("[lc-processor] Finality update rejected (attestedSlot={}): execution branch Merkle proof failed",
                    attestedSlot);
            return false;
        }

        long oldFinalizedSlot = store.getFinalizedSlot();
        store.updateFinalized(update.finalizedHeader(), finalizedSlot);
        store.updateOptimistic(update.attestedHeader(), update.signatureSlot());

        // Rotate sync committee if we crossed a period boundary.
        // Pass the OLD finalized slot so the period comparison is correct
        // (updateFinalized may have already advanced this.finalizedSlot).
        store.applyNextSyncCommitteeWhenPeriodChanges(oldFinalizedSlot, finalizedSlot);

        lastAppliedFinalitySig = sig.clone();
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
        long attestedSlot = update.attestedHeader().beacon().slot();
        long finalizedSlot = update.finalizedHeader().beacon().slot();

        SyncCommittee committee = store.getCurrentSyncCommittee();
        if (committee == null) {
            log.info("[lc-processor] Update rejected (attestedSlot={}): no current sync committee",
                    attestedSlot);
            return false;
        }

        // Cheap applicability gate BEFORE the expensive BLS verify. An update's
        // sync aggregate is signed by the committee of signature_slot's period,
        // so it can only verify against our current committee when that period
        // matches store_period (or store_period+1 once we already hold the next
        // committee) — per spec validate_light_client_update. This is critical
        // on Android: each BLS sync-aggregate verify costs ~17-30s on ART, and a
        // catch-up updates_by_range response routinely contains far-future
        // periods (e.g. period 1766 while the store is at 1728). Without this
        // gate every such update burns a full verify only to fail the committee
        // check, so catch-up from an old checkpoint never makes progress.
        long storePeriod = store.getCurrentSyncCommitteePeriod();
        long sigPeriod = BeaconChainSpec.computeSyncCommitteePeriod(update.signatureSlot());
        boolean haveNext = store.getNextSyncCommittee() != null;
        boolean applicable = haveNext
                ? (sigPeriod == storePeriod || sigPeriod == storePeriod + 1)
                : (sigPeriod == storePeriod);
        if (!applicable) {
            log.debug("[lc-processor] Update skipped pre-verify: signaturePeriod={} not applicable to "
                            + "storePeriod={} (haveNext={}, attestedSlot={})",
                    sigPeriod, storePeriod, haveNext, attestedSlot);
            return false;
        }

        // Verify sync aggregate over attested header
        if (!SyncCommitteeVerifier.verify(
                update.syncAggregate(),
                committee,
                update.attestedHeader().beacon(),
                forkVersion,
                genesisValidatorsRoot)) {
            log.info("[lc-processor] Update rejected (attestedSlot={}, finalizedSlot={}): BLS sync-aggregate verify failed",
                    attestedSlot, finalizedSlot);
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
            log.info("[lc-processor] Update rejected (attestedSlot={}): finality branch Merkle proof failed (depth={}, gindex={})",
                    attestedSlot, finalityDepth, finalityGindex);
            return false;
        }

        // Bind each header's execution payload to its beacon body (see
        // verifyExecutionBranch): the sync-committee signature covers only the beacon
        // header, so without this an attacker could swap in a forged execution payload.
        if (!verifyExecutionBranch(update.attestedHeader())
                || !verifyExecutionBranch(update.finalizedHeader())) {
            log.info("[lc-processor] Update rejected (attestedSlot={}): execution branch Merkle proof failed",
                    attestedSlot);
            return false;
        }

        // Verify and store next sync committee if present.
        // Always verify and store when the store has no next committee (e.g. after rotation).
        SyncCommittee nextSyncCommittee = update.nextSyncCommittee();
        if (nextSyncCommittee != null && store.getNextSyncCommittee() == null) {
            // Verify the next sync committee branch against the attested state.
            // Branch depth is fork-dependent (5 pre-Electra, 6 post-Electra).
            // NEXT sync committee lives at field index 23, not 22 — using the
            // CURRENT gindex here (as we did before) silently rejected every
            // valid update because the Merkle proof path from field 23 doesn't
            // reconcile when verified as if it came from field 22.
            int scDepth = update.nextSyncCommitteeBranch().length;
            int scGindex = BeaconChainSpec.nextSyncCommitteeGindex(scDepth);
            if (!SszUtil.verifyMerkleBranch(
                    nextSyncCommittee.hashTreeRoot(),
                    update.nextSyncCommitteeBranch(),
                    scDepth,
                    scGindex,
                    update.attestedHeader().beacon().stateRoot())) {
                log.info("[lc-processor] Update rejected (attestedSlot={}): nextSyncCommittee branch Merkle proof failed (depth={}, gindex={})",
                        attestedSlot, scDepth, scGindex);
                return false;
            }
            store.updateNextSyncCommittee(nextSyncCommittee);
        }

        long oldFinalizedSlot = store.getFinalizedSlot();
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

    /**
     * Verify that a light client header's {@code execution} payload header is the one
     * committed to its beacon block body — i.e. {@code is_valid_light_client_header}
     * from the consensus spec (Capella+).
     *
     * <p>The sync-committee BLS signature only covers the <i>beacon</i> header; the
     * execution payload (carrying the EL state root and block hash that the whole
     * execution-layer verification chain anchors to) is bound to the beacon header
     * solely through this Merkle branch. Without checking it, a peer can forward a
     * genuine, correctly-signed beacon header while swapping in a forged
     * {@link com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader} with an
     * attacker-chosen state root / block hash, and every downstream account/storage
     * proof would verify against forged state.
     *
     * @param header the light client header whose execution payload must be proven
     * @return true if {@code header.execution} is proven to live at the
     *         execution_payload field of {@code header.beacon.body}
     */
    public static boolean verifyExecutionBranch(LightClientHeader header) {
        if (header == null
                || header.beacon() == null
                || header.execution() == null
                || header.executionBranch() == null) {
            return false;
        }
        return SszUtil.verifyMerkleBranch(
                header.execution().hashTreeRoot(),
                header.executionBranch(),
                BeaconChainSpec.EXECUTION_PAYLOAD_DEPTH,
                BeaconChainSpec.EXECUTION_PAYLOAD_GINDEX,
                header.beacon().bodyRoot());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
