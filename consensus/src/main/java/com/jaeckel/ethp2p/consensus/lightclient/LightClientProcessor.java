package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
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
    /** Per-slot signing-domain selector. Every update is verified under the fork
     *  active at its {@code signatureSlot} (spec {@code validate_light_client_update}),
     *  so the store can walk updates across a fork boundary — a single fixed version
     *  rejects everything signed on the other side of it (#295). */
    private final ForkSchedule forkSchedule;
    private final byte[] genesisValidatorsRoot;

    /** Aggregate signature of the last successfully applied finality update. The
     *  signature commits to the attested header root (whose state root in turn commits
     *  the finality branch), so a byte-identical signature is the same already-applied
     *  update: any variant with different contents would fail verification anyway.
     *  Lets the 12s poll loop skip re-verifying an unchanged head — each BLS verify
     *  costs ~18s on Android/ART, so without this the steady-state loop burns a full
     *  core re-proving the same update. */
    private volatile byte[] lastAppliedFinalitySig;
    /** The signature slot that {@link #lastAppliedFinalitySig} was applied under. The slot is not
     *  covered by the signature, so the memo must key on both: the same aggregate relabelled into
     *  another period is a different update that has to face the period gate and the next
     *  committee's keys (#423), not the memo — and a memo hit must never be a verdict that
     *  re-verification would not reach. */
    private volatile long lastAppliedFinalitySigSlot = -1;

    public LightClientProcessor(LightClientStore store, ForkSchedule forkSchedule, byte[] genesisValidatorsRoot) {
        this.store = store;
        this.forkSchedule = java.util.Objects.requireNonNull(forkSchedule, "forkSchedule");
        this.genesisValidatorsRoot = genesisValidatorsRoot.clone();
        log.info("[lc-processor] Initialized with forkSchedule={}", forkSchedule);
    }

    /**
     * The committee that signs {@code sigPeriod}: the store's current committee for its own
     * period, the held next committee for the period after, {@code null} otherwise (spec
     * validate_light_client_update's applicability + key selection in one place).
     */
    private SyncCommittee committeeFor(long sigPeriod) {
        long storePeriod = store.getCurrentSyncCommitteePeriod();
        if (sigPeriod == storePeriod) return store.getCurrentSyncCommittee();
        if (sigPeriod == storePeriod + 1) return store.getNextSyncCommittee();
        return null;
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

        // Same period rule as processUpdate, and BEFORE the duplicate memo, so a memo hit
        // can never be a verdict that re-verification would not reach. This path had no
        // gate at all and always
        // used the current keys, so with the store at P holding next and a P+1-signed
        // finality update in hand (a local clock lagging the chain; the Rust engine's
        // hunt path while catch-up is starved) the update was rejected until a
        // catch-up round happened to force-rotate.
        long storePeriod = store.getCurrentSyncCommitteePeriod();
        long sigPeriod = BeaconChainSpec.computeSyncCommitteePeriod(update.signatureSlot());
        committee = committeeFor(sigPeriod);
        if (committee == null) {
            log.debug("[lc-processor] Finality update rejected: signaturePeriod={} not applicable to "
                    + "storePeriod={} (attestedSlot={})", sigPeriod, storePeriod, attestedSlot);
            return false;
        }

        byte[] sig = update.syncAggregate().syncCommitteeSignature();
        byte[] lastSig = lastAppliedFinalitySig;
        if (lastSig != null && java.util.Arrays.equals(lastSig, sig)
                && lastAppliedFinalitySigSlot == update.signatureSlot()) {
            log.debug("[lc-processor] Finality update is a duplicate of the already-applied one "
                    + "(attestedSlot={}) — skipping re-verify", attestedSlot);
            return true;
        }

        log.debug("[lc-processor] Processing finality update: attestedSlot={}, finalizedSlot={}, " +
                "signatureSlot={}, participation={}/512, finalityBranchLen={}",
                attestedSlot, finalizedSlot, update.signatureSlot(),
                participation, update.finalityBranch().length);

        // Verify sync aggregate over attested header, under the fork active at
        // the signature slot (spec: compute_fork_version(epoch(max(sig_slot,1)-1))).
        byte[] forkVersion = forkSchedule.versionForSignatureSlot(update.signatureSlot());
        if (!SyncCommitteeVerifier.verify(
                update.syncAggregate(),
                committee,
                update.attestedHeader().beacon(),
                forkVersion,
                genesisValidatorsRoot)) {
            log.debug("[lc-processor] Finality update rejected: BLS verification failed " +
                    "(attestedSlot={}, signatureSlot={}, usedNext={}, forkVersion={}, participation={})",
                    attestedSlot, update.signatureSlot(), sigPeriod != storePeriod,
                    bytesToHex(forkVersion), participation);
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

        // The three store mutations must be one atomic transaction w.r.t. readers:
        // store.snapshot() (persistence) interleaving between updateFinalized and the
        // rotation would capture finalizedSlot in the new period with the OLD committee
        // still current — restored after a restart, that state can't rotate via the
        // slot-crossing path anymore. Verification above runs without the monitor;
        // only these fast memory writes hold it.
        final long oldFinalizedSlot;
        synchronized (store) {
            oldFinalizedSlot = store.getFinalizedSlot();
            store.updateFinalized(update.finalizedHeader(), finalizedSlot);
            store.updateOptimistic(update.attestedHeader(), update.signatureSlot());
            // Rotate sync committee if we crossed a period boundary.
            // Pass the OLD finalized slot so the period comparison is correct
            // (updateFinalized may have already advanced this.finalizedSlot).
            store.applyNextSyncCommitteeWhenPeriodChanges(oldFinalizedSlot, finalizedSlot);
        }

        lastAppliedFinalitySig = sig.clone();
        lastAppliedFinalitySigSlot = update.signatureSlot();
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
        // so it can only verify against the committee of THAT period: ours for
        // store_period, the held next one for store_period+1 — per spec
        // validate_light_client_update. This is critical
        // on Android: each BLS sync-aggregate verify costs ~17-30s on ART, and a
        // catch-up updates_by_range response routinely contains far-future
        // periods (e.g. period 1766 while the store is at 1728). Without this
        // gate every such update burns a full verify only to fail the committee
        // check, so catch-up from an old checkpoint never makes progress.
        long storePeriod = store.getCurrentSyncCommitteePeriod();
        long sigPeriod = BeaconChainSpec.computeSyncCommitteePeriod(update.signatureSlot());
        // Selecting the keys IS the gate. Verifying both admitted periods with the
        // current keys rejected genuine next-committee updates before rotation and
        // accepted a current-committee signature whose unsigned signatureSlot had
        // been relabelled into the next period (#423).
        committee = committeeFor(sigPeriod);
        if (committee == null) {
            log.debug("[lc-processor] Update skipped pre-verify: signaturePeriod={} not applicable to "
                            + "storePeriod={} (haveNext={}, attestedSlot={})",
                    sigPeriod, storePeriod, store.getNextSyncCommittee() != null, attestedSlot);
            return false;
        }

        // Verify sync aggregate over attested header, under the fork active at
        // the signature slot (see processFinalityUpdate).
        byte[] forkVersion = forkSchedule.versionForSignatureSlot(update.signatureSlot());
        if (!SyncCommitteeVerifier.verify(
                update.syncAggregate(),
                committee,
                update.attestedHeader().beacon(),
                forkVersion,
                genesisValidatorsRoot)) {
            log.info("[lc-processor] Update rejected (attestedSlot={}, finalizedSlot={}, signatureSlot={}, "
                            + "usedNext={}, forkVersion={}): BLS sync-aggregate verify failed",
                    attestedSlot, finalizedSlot, update.signatureSlot(), sigPeriod != storePeriod,
                    bytesToHex(forkVersion));
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

        // Atomic w.r.t. store.snapshot() — see the matching block in
        // processFinalityUpdate for why a torn snapshot here wedges a restart.
        synchronized (store) {
            long oldFinalizedSlot = store.getFinalizedSlot();
            store.updateFinalized(update.finalizedHeader(), finalizedSlot);
            store.updateOptimistic(update.attestedHeader(), update.signatureSlot());
            // Rotate sync committee if we crossed a period boundary.
            // Pass the OLD finalized slot so the period comparison is correct.
            store.applyNextSyncCommitteeWhenPeriodChanges(oldFinalizedSlot, finalizedSlot);
        }

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
