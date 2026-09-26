package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import com.jaeckel.ethp2p.core.consensus.LcFork;
import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
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
 * advancing the finalized and optimistic headers in the store. The fork schedule
 * picks both the signing domain (by signature slot) and, from Gloas on, the wire
 * shape and proof indices (by attested slot — {@link ForkSchedule#lcForkAtSlot}).
 */
public class LightClientProcessor {

    private static final Logger log = LoggerFactory.getLogger(LightClientProcessor.class);

    private final LightClientStore store;
    /** Per-slot signing-domain selector. Every update is verified under the fork
     *  active at its {@code signatureSlot} (spec {@code validate_light_client_update}),
     *  so the store can walk updates across a fork boundary — a single fixed version
     *  rejects everything signed on the other side of it (#295). Its Gloas epoch
     *  also selects each object's wire shape and state-proof indices. */
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

        // Shape gate, also ahead of the memo: a memo hit is never granted to an update
        // whose shape re-verification would refuse (see updateShapeOk).
        if (!updateShapeOk(update.attestedHeader(), update.finalizedHeader())) {
            log.debug("[lc-processor] Finality update rejected: wire shape is not the attested slot's fork's "
                    + "(attestedSlot={}, attestedShape={}, finalizedShape={})", attestedSlot,
                    update.attestedHeader().shape(), update.finalizedHeader().shape());
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
        // The attested slot's fork picks the proof: depth-derived before Gloas (6 pre-Electra,
        // 7 post-Electra), fixed from Gloas on (see finalityGindex).
        int finalityDepth = finalityDepth(attestedSlot, update.finalityBranch().length);
        int finalityGindex = finalityGindex(attestedSlot, finalityDepth);
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

        // Bind each header's execution payload (from Gloas on: block hash) to its beacon
        // body. The headers we store here feed the execution-layer verification chain (EL
        // state root / block hash), and the sync-committee signature does NOT cover the
        // execution data — only this branch does, selected by each header's own slot.
        if (!verifyHeader(update.attestedHeader())
                || !verifyHeader(update.finalizedHeader())) {
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
     *   <li>If the store holds no next sync committee, verify the update's branch and store
     *       it — only from an update attested in the store's period, whose next committee
     *       is the store's next period's.</li>
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

        // A store holding no next committee adopts the one this update carries (below):
        // the next committee of the ATTESTED state, i.e. of period(attested) + 1. So only
        // an update attested in the store's own period can supply it (spec
        // validate_light_client_update counts it only when update_attested_period ==
        // store_period). The last block of P-1 signed at the first slot of P passes the
        // gate above and verifies, and its genuine next committee is committee(P) — ours:
        // the rotation would install it for P+1, and every P+1 update would then fail BLS.
        // Honest servers send that update without a committee (spec
        // create_light_client_update), which the branch check below would refuse anyway,
        // so this changes no honest verdict. Not required: the spec's
        // apply_light_client_update also wants the FINALIZED header in the store period.
        // This client adopts from the attested state, as the spec's force-update path
        // does, having no best-valid-update timeout: requiring finality would stall
        // catch-up at a period that never finalized. Rust twin: store.rs process_update.
        if (store.getNextSyncCommittee() == null) {
            long attestedPeriod = BeaconChainSpec.computeSyncCommitteePeriod(attestedSlot);
            if (attestedPeriod != storePeriod) {
                log.info("[lc-processor] Update rejected (attestedSlot={}): attested in period {}, not the "
                                + "store's {}, so its next committee is not the store's next (signaturePeriod={})",
                        attestedSlot, attestedPeriod, storePeriod, sigPeriod);
                return false;
            }
        }

        if (!updateShapeOk(update.attestedHeader(), update.finalizedHeader())) {
            log.info("[lc-processor] Update rejected (attestedSlot={}): wire shape is not the attested slot's "
                            + "fork's (attestedShape={}, finalizedShape={})", attestedSlot,
                    update.attestedHeader().shape(), update.finalizedHeader().shape());
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

        // Verify finality branch (depth and gindex are fork-dependent, see finalityGindex)
        int finalityDepth = finalityDepth(attestedSlot, update.finalityBranch().length);
        int finalityGindex = finalityGindex(attestedSlot, finalityDepth);
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

        // Bind each header's execution payload (block hash) to its beacon body (see
        // verifyExecutionBranchAt): the sync-committee signature covers only the beacon
        // header, so without this an attacker could swap in forged execution data.
        if (!verifyHeader(update.attestedHeader())
                || !verifyHeader(update.finalizedHeader())) {
            log.info("[lc-processor] Update rejected (attestedSlot={}): execution branch Merkle proof failed",
                    attestedSlot);
            return false;
        }

        // Verify and store next sync committee if present.
        // Always verify and store when the store has no next committee (e.g. after rotation).
        SyncCommittee nextSyncCommittee = update.nextSyncCommittee();
        if (nextSyncCommittee != null && store.getNextSyncCommittee() == null) {
            // Verify the next sync committee branch against the attested state.
            // Branch depth is fork-dependent (5 pre-Electra, 6 post-Electra); from
            // Gloas on the attested slot's fork fixes it at 11, gindex 2946 (a
            // progressive BeaconState — the depth-derived 2071 is not it).
            // NEXT sync committee lives at field index 23, not 22 — using the
            // CURRENT gindex here (as we did before) silently rejected every
            // valid update because the Merkle proof path from field 23 doesn't
            // reconcile when verified as if it came from field 22.
            boolean gloas = lcForkAtSlot(attestedSlot) == LcFork.GLOAS;
            int scDepth = gloas ? BeaconChainSpec.GLOAS_SYNC_COMMITTEE_BRANCH_LEN
                    : update.nextSyncCommitteeBranch().length;
            int scGindex = gloas ? BeaconChainSpec.NEXT_SYNC_COMMITTEE_GINDEX_GLOAS
                    : BeaconChainSpec.nextSyncCommitteeGindex(scDepth);
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
     * The fork whose wire format and proof indices an object with this attested (or
     * bootstrap header) slot uses.
     */
    public LcFork lcForkAtSlot(long slot) {
        return forkSchedule.lcForkAtSlot(slot);
    }

    /**
     * Cheap structural gate for an update, BEFORE any BLS work: every header in it must
     * be in the shape of its ATTESTED slot's fork (a Gloas-format update carries even a
     * pre-Gloas finalized header in the Gloas shape), since that fork also picks the
     * state-proof indices. A mismatch is a misrouted or forged object, never a genuine
     * one.
     */
    private boolean updateShapeOk(LightClientHeader attested, LightClientHeader finalized) {
        LcFork fork = lcForkAtSlot(attested.beacon().slot());
        return attested.shape() == fork && finalized.shape() == fork;
    }

    /**
     * Finality branch depth for an update attested at {@code attestedSlot}: the fixed
     * Gloas vector length from Gloas on, the branch's own (fork-sniffed) length before.
     */
    private int finalityDepth(long attestedSlot, int branchLength) {
        return lcForkAtSlot(attestedSlot) == LcFork.GLOAS ? BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN : branchLength;
    }

    /**
     * Finality gindex (against the attested state root) at the attested slot's fork:
     * fixed for Gloas (735 — a progressive {@code BeaconState}, not derivable from the
     * depth), depth-derived before it (6 → 105, 7 → 169).
     */
    private int finalityGindex(long attestedSlot, int depth) {
        return lcForkAtSlot(attestedSlot) == LcFork.GLOAS
                ? BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS
                : BeaconChainSpec.finalizedRootGindex(depth);
    }

    /**
     * {@code is_valid_light_client_header} against this chain's schedule: the proof is
     * selected by the fork of the header's OWN slot ({@link #verifyExecutionBranchAt}).
     */
    public boolean verifyHeader(LightClientHeader header) {
        if (header == null || header.beacon() == null) return false;
        return verifyExecutionBranchAt(header, lcForkAtSlot(header.beacon().slot()));
    }

    /** Why {@link #verifyBootstrap} refused a bootstrap. Rust twin: {@code store::BootstrapReject}. */
    public enum BootstrapReject {
        /** The header's wire shape is not its slot's fork's. */
        SHAPE_NOT_ITS_FORKS("wire shape is not its slot's fork's"),
        /** The current sync committee is not in the header's state. */
        SYNC_COMMITTEE_BRANCH("sync committee branch invalid"),
        /** The header's execution data is not bound to its body. */
        EXECUTION_BRANCH("execution branch invalid");

        private final String reason;

        BootstrapReject(String reason) {
            this.reason = reason;
        }

        /** The human-readable reason (the Rust {@code Display} text). */
        public String reason() {
            return reason;
        }
    }

    /**
     * The checks a bootstrap must pass besides the checkpoint pin (which the caller
     * owns — it chose the root): its shape matches its slot's fork, the current sync
     * committee is in the header's state at that fork's gindex (Gloas: 2945 at depth 11;
     * before: depth-derived from the branch length), and the execution branch binds the
     * header's execution data to its body.
     *
     * @return {@code null} when the bootstrap verifies, otherwise why it was refused
     */
    public BootstrapReject verifyBootstrap(LightClientBootstrap bootstrap) {
        LightClientHeader header = bootstrap.header();
        LcFork fork = lcForkAtSlot(header.beacon().slot());
        if (header.shape() != fork) {
            return BootstrapReject.SHAPE_NOT_ITS_FORKS;
        }
        byte[][] branch = bootstrap.currentSyncCommitteeBranch();
        boolean gloas = fork == LcFork.GLOAS;
        int depth = gloas ? BeaconChainSpec.GLOAS_SYNC_COMMITTEE_BRANCH_LEN : branch.length;
        int gindex = gloas ? BeaconChainSpec.CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS
                : BeaconChainSpec.syncCommitteeGindex(depth);
        if (!SszUtil.verifyMerkleBranch(
                bootstrap.currentSyncCommittee().hashTreeRoot(),
                branch,
                depth,
                gindex,
                header.beacon().stateRoot())) {
            return BootstrapReject.SYNC_COMMITTEE_BRANCH;
        }
        if (!verifyHeader(header)) {
            return BootstrapReject.EXECUTION_BRANCH;
        }
        return null;
    }

    /**
     * Verify that a light client header's {@code execution} payload header is the one
     * committed to its beacon block body — i.e. {@code is_valid_light_client_header}
     * from the consensus spec (Capella+) — for a PRE-GLOAS-shaped header at a pre-Gloas
     * slot (Capella..Fulu). Kept for callers that hold no fork schedule and only ever
     * see that shape; Gloas-aware callers use {@link #verifyHeader}, which selects the
     * proof by the header's own slot. A Gloas-shaped header is refused outright rather
     * than checked under a guessed slot fork, so a call site that should have moved to
     * {@link #verifyHeader} (or {@link #verifyBootstrap}) fails loudly.
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
        return header != null
                && header.shape() == LcFork.PRE_GLOAS
                && verifyExecutionBranchAt(header, LcFork.PRE_GLOAS);
    }

    /**
     * {@code is_valid_light_client_header} for a header whose OWN slot is in
     * {@code slotFork}. Rust twin: {@code store::verify_execution_branch_at}.
     *
     * <p>This is the whole binding between the sync-committee-signed beacon header and
     * the execution layer: the signature covers only {@code beacon}, so without it a peer
     * could pair a genuine signed header with an execution payload or block hash of its
     * choosing, and every state proof downstream would verify against it.
     *
     * <ul>
     *   <li>Pre-Gloas shape at a pre-Gloas slot: the payload header's root at gindex 25.</li>
     *   <li>Gloas shape at a Gloas slot: the block hash at 2856 — the payload bid's
     *       {@code parent_block_hash}.</li>
     *   <li>Gloas shape at a pre-Gloas slot (a Gloas update's finalized header in the
     *       first epochs after the fork): the payload's block hash at 812 (Deneb+),
     *       normalized to 11 nodes with zero padding. Capella's 412 is not accepted: no
     *       header this client meets is pre-Deneb (every network's checkpoint and every
     *       Gloas update's finalized header are far past it), and a Capella header's
     *       genuine proof simply fails here — a rejection, never an acceptance.</li>
     *   <li>A pre-Gloas shape at a Gloas slot is never genuine: rejected.</li>
     * </ul>
     *
     * @param header   the light client header whose execution data must be proven
     * @param slotFork the fork of {@code header.beacon().slot()} — not its wire shape
     * @return true if the header's execution payload (or block hash) is proven to live
     *         in {@code header.beacon.body} at that fork's gindex
     */
    public static boolean verifyExecutionBranchAt(LightClientHeader header, LcFork slotFork) {
        if (header == null
                || header.beacon() == null
                || header.executionBranch() == null
                || slotFork == null) {
            return false;
        }
        byte[] bodyRoot = header.beacon().bodyRoot();
        if (header.shape() == LcFork.PRE_GLOAS) {
            if (slotFork != LcFork.PRE_GLOAS || header.execution() == null) {
                return false;
            }
            return SszUtil.verifyMerkleBranch(
                    header.execution().hashTreeRoot(),
                    header.executionBranch(),
                    BeaconChainSpec.EXECUTION_PAYLOAD_DEPTH,
                    BeaconChainSpec.EXECUTION_PAYLOAD_GINDEX,
                    bodyRoot);
        }
        int gindex = slotFork == LcFork.GLOAS
                ? BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_GLOAS
                : BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_DENEB;
        return header.executionBranch().length == BeaconChainSpec.GLOAS_EXECUTION_BRANCH_LEN
                && SszUtil.verifyNormalizedMerkleBranch(
                        header.executionBlockHash(), header.executionBranch(), gindex, bodyRoot);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
