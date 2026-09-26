package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.core.consensus.LcFork;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: LightClientFinalityUpdate
 *
 * Fields (in order):
 *   attestedHeader   — LightClientHeader (variable)
 *   finalizedHeader  — LightClientHeader (variable)
 *   finalityBranch   — Vector[Bytes32, 6] (192B, fixed inline)
 *   syncAggregate    — SyncAggregate (160B, fixed inline)
 *   signatureSlot    — uint64 (8B, fixed inline)
 *
 * SSZ fixed part:
 *   4B  offset to attestedHeader
 *   4B  offset to finalizedHeader
 *   192B  finalityBranch
 *   160B  syncAggregate
 *   8B  signatureSlot
 *   Total fixed: 4 + 4 + 192 + 160 + 8 = 368 bytes
 *
 * Gloas: every field fixed-size, no offsets — attestedHeader 496 + finalizedHeader
 * 496 (both Gloas shape) + finalityBranch 9 x 32 + syncAggregate 160 + signatureSlot 8.
 */
public final class LightClientFinalityUpdate {

    /** Minimum fixed size (pre-Electra, 6-node finality branch). */
    public static final int FIXED_SIZE = 4 + 4 + 6 * 32 + 160 + 8; // 368
    /** Gloas: attested 496 + finalized 496 + the finality branch, {@code Vector[Bytes32,
     *  floorlog2(FINALIZED_ROOT_GINDEX_GLOAS)]} (9 x 32) + aggregate 160 + slot 8, fixed. */
    public static final int GLOAS_SIZE =
            2 * LightClientHeader.GLOAS_SIZE + BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN * 32 + 160 + 8; // 1448

    private final LightClientHeader attestedHeader;
    private final LightClientHeader finalizedHeader;
    private final byte[][] finalityBranch; // 6 or 7 x 32 (fork-dependent); 9 (Gloas)
    private final SyncAggregate syncAggregate;
    private final long signatureSlot;

    public LightClientFinalityUpdate(
            LightClientHeader attestedHeader,
            LightClientHeader finalizedHeader,
            byte[][] finalityBranch,
            SyncAggregate syncAggregate,
            long signatureSlot
    ) {
        int nodes = finalityBranch.length;
        if ((nodes < 6 || nodes > 7) && nodes != BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN) {
            throw new IllegalArgumentException("finalityBranch must have 6 or 7 nodes ("
                    + BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN + " for Gloas), got " + nodes);
        }
        this.attestedHeader = attestedHeader;
        this.finalizedHeader = finalizedHeader;
        this.finalityBranch = finalityBranch;
        this.syncAggregate = syncAggregate;
        this.signatureSlot = signatureSlot;
    }

    /**
     * Decode a LightClientFinalityUpdate from SSZ bytes.
     *
     * The finality branch length is fork-dependent:
     *   Pre-Electra:  6 nodes, fixed size = 368
     *   Post-Electra: 7 nodes, fixed size = 400
     *
     * We detect the branch count from the first variable offset (attestedHeaderOffset),
     * which equals the fixed part size.
     */
    public static LightClientFinalityUpdate decode(byte[] ssz) {
        if (ssz.length < FIXED_SIZE) {
            throw new IllegalArgumentException(
                    "LightClientFinalityUpdate requires at least " + FIXED_SIZE + " bytes, got " + ssz.length);
        }

        ByteBuffer buf = ByteBuffer.wrap(ssz).order(ByteOrder.LITTLE_ENDIAN);

        int attestedHeaderOffset = buf.getInt();   // pos 4
        int finalizedHeaderOffset = buf.getInt();  // pos 8

        // Derive finality branch node count from fixed part size.
        // fixedSize = 4 + 4 + (branchNodes * 32) + 160 + 8
        // branchBytes = fixedSize - 176
        int branchBytes = attestedHeaderOffset - 4 - 4 - 160 - 8;
        if (branchBytes % 32 != 0) {
            throw new IllegalArgumentException(
                    "Finality branch region is not a multiple of 32 bytes: " + branchBytes);
        }
        int branchNodeCount = branchBytes / 32;
        if (branchNodeCount != 6 && branchNodeCount != 7) {
            throw new IllegalArgumentException(
                    "Unexpected finality branch node count: " + branchNodeCount
                            + " (expected 6 for pre-Electra or 7 for post-Electra)");
        }

        byte[][] finalityBranch = new byte[branchNodeCount][32];
        for (int i = 0; i < branchNodeCount; i++) {
            buf.get(finalityBranch[i]);
        }

        byte[] syncAggregateBytes = new byte[160];
        buf.get(syncAggregateBytes);
        SyncAggregate syncAggregate = SyncAggregate.decode(syncAggregateBytes);

        long signatureSlot = buf.getLong();

        int actualFixedSize = 4 + 4 + branchNodeCount * 32 + 160 + 8;
        // Validate offsets
        if (attestedHeaderOffset < actualFixedSize || attestedHeaderOffset > ssz.length) {
            throw new IllegalArgumentException("Invalid attestedHeader offset: " + attestedHeaderOffset);
        }
        if (finalizedHeaderOffset < actualFixedSize || finalizedHeaderOffset > ssz.length) {
            throw new IllegalArgumentException("Invalid finalizedHeader offset: " + finalizedHeaderOffset);
        }

        // Determine the end boundary for each variable field
        // They are ordered: attestedHeader first, then finalizedHeader (by convention of offset order)
        int attestedEnd;
        int finalizedEnd;
        if (attestedHeaderOffset < finalizedHeaderOffset) {
            attestedEnd = finalizedHeaderOffset;
            finalizedEnd = ssz.length;
        } else {
            finalizedEnd = attestedHeaderOffset;
            attestedEnd = ssz.length;
        }

        byte[] attestedBytes = Arrays.copyOfRange(ssz, attestedHeaderOffset, attestedEnd);
        LightClientHeader attestedHeader = LightClientHeader.decode(attestedBytes);

        byte[] finalizedBytes = Arrays.copyOfRange(ssz, finalizedHeaderOffset, finalizedEnd);
        LightClientHeader finalizedHeader = LightClientHeader.decode(finalizedBytes);

        return new LightClientFinalityUpdate(attestedHeader, finalizedHeader, finalityBranch, syncAggregate, signatureSlot);
    }

    /**
     * Decode the Gloas format: exactly {@link #GLOAS_SIZE} bytes.
     *
     * @throws IllegalArgumentException on any other length
     */
    public static LightClientFinalityUpdate decodeGloas(byte[] ssz) {
        if (ssz == null || ssz.length != GLOAS_SIZE) {
            throw new IllegalArgumentException("Gloas LightClientFinalityUpdate requires " + GLOAS_SIZE
                    + " bytes, got " + (ssz == null ? "null" : ssz.length));
        }
        int h = LightClientHeader.GLOAS_SIZE;
        int finBranch = 2 * h;
        int agg = finBranch + BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN * 32;
        int slot = agg + 160;
        return new LightClientFinalityUpdate(
                LightClientHeader.decodeGloas(Arrays.copyOfRange(ssz, 0, h)),
                LightClientHeader.decodeGloas(Arrays.copyOfRange(ssz, h, finBranch)),
                LightClientHeader.readNodes(ssz, finBranch, BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN),
                SyncAggregate.decode(Arrays.copyOfRange(ssz, agg, slot)),
                ByteBuffer.wrap(ssz, slot, 8).order(ByteOrder.LITTLE_ENDIAN).getLong());
    }

    /** Decode in the wire format of {@code fork} (the fork of the attested slot). */
    public static LightClientFinalityUpdate decodeFor(LcFork fork, byte[] ssz) {
        if (fork == null) throw new IllegalArgumentException("LightClientFinalityUpdate: fork is required");
        return fork == LcFork.GLOAS ? decodeGloas(ssz) : decode(ssz);
    }

    public LightClientHeader attestedHeader() { return attestedHeader; }
    public LightClientHeader finalizedHeader() { return finalizedHeader; }
    public byte[][] finalityBranch() { return finalityBranch; }
    public SyncAggregate syncAggregate() { return syncAggregate; }
    public long signatureSlot() { return signatureSlot; }
}
