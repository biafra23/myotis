package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.core.consensus.LcFork;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: LightClientUpdate
 *
 * Fields (in order):
 *   attestedHeader           — LightClientHeader (variable)
 *   nextSyncCommittee        — SyncCommittee (24624B, fixed inline)
 *   nextSyncCommitteeBranch  — Vector[Bytes32, 5 or 6] (fork-dependent)
 *   finalizedHeader          — LightClientHeader (variable)
 *   finalityBranch           — Vector[Bytes32, 6 or 7] (fork-dependent)
 *   syncAggregate            — SyncAggregate (160B, fixed inline)
 *   signatureSlot            — uint64 (8B, fixed inline)
 *
 * SSZ fixed part (variable fields contribute 4B offsets):
 *   4B  offset to attestedHeader
 *   24624B  nextSyncCommittee
 *   N*32B  nextSyncCommitteeBranch (N=5 pre-Electra, 6 post-Electra)
 *   4B  offset to finalizedHeader
 *   M*32B  finalityBranch (M=6 pre-Electra, 7 post-Electra)
 *   160B  syncAggregate
 *   8B  signatureSlot
 *
 * Gloas: every field fixed-size, no offsets — attestedHeader 496 (Gloas shape) +
 * nextSyncCommittee 24624 + nextSyncCommitteeBranch 11 x 32 + finalizedHeader 496
 * (Gloas shape) + finalityBranch 9 x 32 + syncAggregate 160 + signatureSlot 8.
 */
public final class LightClientUpdate {

    /** Minimum fixed size (pre-Electra). */
    public static final int FIXED_SIZE =
            4                           // attestedHeader offset
            + SyncCommittee.ENCODED_SIZE  // nextSyncCommittee = 24624
            + 5 * 32                    // nextSyncCommitteeBranch = 160
            + 4                         // finalizedHeader offset
            + 6 * 32                    // finalityBranch = 192
            + 160                       // syncAggregate
            + 8;                        // signatureSlot

    /** Gloas: attested 496 + committee 24624 + 11 x 32 + finalized 496 + 9 x 32 + aggregate 160 + slot 8, fixed.
     *  The branches are {@code floorlog2(NEXT_SYNC_COMMITTEE_GINDEX_GLOAS)} and
     *  {@code floorlog2(FINALIZED_ROOT_GINDEX_GLOAS)} nodes long. */
    public static final int GLOAS_SIZE =
            LightClientHeader.GLOAS_SIZE
            + SyncCommittee.ENCODED_SIZE
            + BeaconChainSpec.GLOAS_SYNC_COMMITTEE_BRANCH_LEN * 32
            + LightClientHeader.GLOAS_SIZE
            + BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN * 32
            + 160
            + 8; // 26424

    private final LightClientHeader attestedHeader;
    private final SyncCommittee nextSyncCommittee;
    private final byte[][] nextSyncCommitteeBranch;
    private final LightClientHeader finalizedHeader;
    private final byte[][] finalityBranch;
    private final SyncAggregate syncAggregate;
    private final long signatureSlot;

    public LightClientUpdate(
            LightClientHeader attestedHeader,
            SyncCommittee nextSyncCommittee,
            byte[][] nextSyncCommitteeBranch,
            LightClientHeader finalizedHeader,
            byte[][] finalityBranch,
            SyncAggregate syncAggregate,
            long signatureSlot
    ) {
        this.attestedHeader = attestedHeader;
        this.nextSyncCommittee = nextSyncCommittee;
        this.nextSyncCommitteeBranch = nextSyncCommitteeBranch;
        this.finalizedHeader = finalizedHeader;
        this.finalityBranch = finalityBranch;
        this.syncAggregate = syncAggregate;
        this.signatureSlot = signatureSlot;
    }

    /**
     * Decode a LightClientUpdate from SSZ bytes.
     *
     * The branch lengths are fork-dependent. We derive them from the
     * attestedHeaderOffset (which equals the fixed part size).
     */
    public static LightClientUpdate decode(byte[] ssz) {
        if (ssz.length < FIXED_SIZE) {
            throw new IllegalArgumentException(
                    "LightClientUpdate requires at least " + FIXED_SIZE + " bytes, got " + ssz.length);
        }

        ByteBuffer buf = ByteBuffer.wrap(ssz).order(ByteOrder.LITTLE_ENDIAN);

        // Read attestedHeaderOffset to determine the actual fixed part size
        int attestedHeaderOffset = buf.getInt();  // pos 4

        // Derive branch sizes from the fixed part.
        // fixedSize = 4 + 24624 + scBranch + 4 + finBranch + 160 + 8
        // where scBranch = scNodes*32, finBranch = finNodes*32
        // Pre-Electra: scNodes=5, finNodes=6 → fixed=25152
        // Post-Electra: scNodes=6, finNodes=7 → fixed=25216
        int totalBranchBytes = attestedHeaderOffset - 4 - SyncCommittee.ENCODED_SIZE - 4 - 160 - 8;
        int scBranchNodes, finBranchNodes;
        if (totalBranchBytes == 5 * 32 + 6 * 32) {
            scBranchNodes = 5; finBranchNodes = 6;  // pre-Electra
        } else if (totalBranchBytes == 6 * 32 + 7 * 32) {
            scBranchNodes = 6; finBranchNodes = 7;  // post-Electra
        } else {
            // Fall back to pre-Electra
            scBranchNodes = 5; finBranchNodes = 6;
        }

        // nextSyncCommittee (24624B)
        byte[] nextSyncCommitteeBytes = new byte[SyncCommittee.ENCODED_SIZE];
        buf.get(nextSyncCommitteeBytes);
        SyncCommittee nextSyncCommittee = SyncCommittee.decode(nextSyncCommitteeBytes);

        // nextSyncCommitteeBranch
        byte[][] nextSyncCommitteeBranch = new byte[scBranchNodes][32];
        for (int i = 0; i < scBranchNodes; i++) {
            buf.get(nextSyncCommitteeBranch[i]);
        }

        // offset to finalizedHeader
        int finalizedHeaderOffset = buf.getInt();

        // finalityBranch
        byte[][] finalityBranch = new byte[finBranchNodes][32];
        for (int i = 0; i < finBranchNodes; i++) {
            buf.get(finalityBranch[i]);
        }

        // syncAggregate (160B)
        byte[] syncAggregateBytes = new byte[160];
        buf.get(syncAggregateBytes);
        SyncAggregate syncAggregate = SyncAggregate.decode(syncAggregateBytes);

        // signatureSlot (8B)
        long signatureSlot = buf.getLong();

        // Decode variable-length attestedHeader
        if (attestedHeaderOffset > ssz.length) {
            throw new IllegalArgumentException("Invalid attestedHeader offset: " + attestedHeaderOffset);
        }
        byte[] attestedHeaderBytes;
        if (finalizedHeaderOffset > attestedHeaderOffset && finalizedHeaderOffset <= ssz.length) {
            attestedHeaderBytes = Arrays.copyOfRange(ssz, attestedHeaderOffset, finalizedHeaderOffset);
        } else {
            attestedHeaderBytes = Arrays.copyOfRange(ssz, attestedHeaderOffset, ssz.length);
        }
        LightClientHeader attestedHeader = LightClientHeader.decode(attestedHeaderBytes);

        // Decode variable-length finalizedHeader
        if (finalizedHeaderOffset > ssz.length) {
            throw new IllegalArgumentException("Invalid finalizedHeader offset: " + finalizedHeaderOffset);
        }
        byte[] finalizedHeaderBytes = Arrays.copyOfRange(ssz, finalizedHeaderOffset, ssz.length);
        LightClientHeader finalizedHeader = LightClientHeader.decode(finalizedHeaderBytes);

        return new LightClientUpdate(
                attestedHeader,
                nextSyncCommittee,
                nextSyncCommitteeBranch,
                finalizedHeader,
                finalityBranch,
                syncAggregate,
                signatureSlot
        );
    }

    /**
     * Decode the Gloas format: exactly {@link #GLOAS_SIZE} bytes.
     *
     * @throws IllegalArgumentException on any other length
     */
    public static LightClientUpdate decodeGloas(byte[] ssz) {
        if (ssz == null || ssz.length != GLOAS_SIZE) {
            throw new IllegalArgumentException("Gloas LightClientUpdate requires " + GLOAS_SIZE
                    + " bytes, got " + (ssz == null ? "null" : ssz.length));
        }
        int h = LightClientHeader.GLOAS_SIZE;
        int nsc = h;
        int nscBranch = nsc + SyncCommittee.ENCODED_SIZE;
        int finalized = nscBranch + BeaconChainSpec.GLOAS_SYNC_COMMITTEE_BRANCH_LEN * 32;
        int finBranch = finalized + h;
        int agg = finBranch + BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN * 32;
        int slot = agg + 160;
        return new LightClientUpdate(
                LightClientHeader.decodeGloas(Arrays.copyOfRange(ssz, 0, h)),
                SyncCommittee.decode(Arrays.copyOfRange(ssz, nsc, nscBranch)),
                LightClientHeader.readNodes(ssz, nscBranch, BeaconChainSpec.GLOAS_SYNC_COMMITTEE_BRANCH_LEN),
                LightClientHeader.decodeGloas(Arrays.copyOfRange(ssz, finalized, finBranch)),
                LightClientHeader.readNodes(ssz, finBranch, BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN),
                SyncAggregate.decode(Arrays.copyOfRange(ssz, agg, slot)),
                ByteBuffer.wrap(ssz, slot, 8).order(ByteOrder.LITTLE_ENDIAN).getLong());
    }

    /** Decode in the wire format of {@code fork} (the fork of the attested slot). */
    public static LightClientUpdate decodeFor(LcFork fork, byte[] ssz) {
        if (fork == null) throw new IllegalArgumentException("LightClientUpdate: fork is required");
        return fork == LcFork.GLOAS ? decodeGloas(ssz) : decode(ssz);
    }

    public LightClientHeader attestedHeader() { return attestedHeader; }
    public SyncCommittee nextSyncCommittee() { return nextSyncCommittee; }
    public byte[][] nextSyncCommitteeBranch() { return nextSyncCommitteeBranch; }
    public LightClientHeader finalizedHeader() { return finalizedHeader; }
    public byte[][] finalityBranch() { return finalityBranch; }
    public SyncAggregate syncAggregate() { return syncAggregate; }
    public long signatureSlot() { return signatureSlot; }
}
