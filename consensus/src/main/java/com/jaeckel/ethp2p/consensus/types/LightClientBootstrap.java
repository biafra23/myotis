package com.jaeckel.ethp2p.consensus.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: LightClientBootstrap
 *
 * Fields:
 *   header                    — LightClientHeader (variable)
 *   currentSyncCommittee      — SyncCommittee (24624 bytes, fixed)
 *   currentSyncCommitteeBranch — Vector[Bytes32, 5] (5 * 32 = 160 bytes, fixed)
 *
 * SSZ layout (header is variable, so fixed part contains its offset):
 *   [0..4)       offset to header (4B LE uint32)
 *   [4..24628)   currentSyncCommittee (24624B inline)
 *   [24628..24788) currentSyncCommitteeBranch (160B inline)
 *   [offset..)   header bytes (variable)
 *
 * Total fixed part: 4 + 24624 + 160 = 24788 bytes
 */
public final class LightClientBootstrap {

    /** Minimum fixed size (pre-Electra, 5 branch nodes). */
    public static final int FIXED_SIZE = 4 + SyncCommittee.ENCODED_SIZE + 5 * 32; // 24788

    private final LightClientHeader header;
    private final SyncCommittee currentSyncCommittee;
    private final byte[][] currentSyncCommitteeBranch; // 5 or 6 x 32 bytes (fork-dependent)

    public LightClientBootstrap(
            LightClientHeader header,
            SyncCommittee currentSyncCommittee,
            byte[][] currentSyncCommitteeBranch
    ) {
        if (currentSyncCommitteeBranch.length < 5 || currentSyncCommitteeBranch.length > 6) {
            throw new IllegalArgumentException("currentSyncCommitteeBranch must have 5 or 6 nodes, got "
                    + currentSyncCommitteeBranch.length);
        }
        for (byte[] node : currentSyncCommitteeBranch) {
            if (node.length != 32) throw new IllegalArgumentException("each branch node must be 32 bytes");
        }
        this.header = header;
        this.currentSyncCommittee = currentSyncCommittee;
        this.currentSyncCommitteeBranch = currentSyncCommitteeBranch;
    }

    /**
     * Decode a LightClientBootstrap from SSZ bytes.
     *
     * The branch length is fork-dependent:
     *   Pre-Electra:  5 nodes (160B), fixed size = 24788
     *   Post-Electra: 6 nodes (192B), fixed size = 24820
     *
     * The header offset at [0..4) tells us the fixed size, from which
     * we derive the branch node count.
     */
    public static LightClientBootstrap decode(byte[] ssz) {
        if (ssz.length < FIXED_SIZE) {
            throw new IllegalArgumentException(
                    "LightClientBootstrap requires at least " + FIXED_SIZE + " bytes, got " + ssz.length);
        }

        // Read header offset at byte 0 — this equals the fixed part size
        ByteBuffer buf = ByteBuffer.wrap(ssz, 0, 4).order(ByteOrder.LITTLE_ENDIAN);
        int headerOffset = buf.getInt();

        // Derive branch node count from the fixed part layout
        int branchBytes = headerOffset - 4 - SyncCommittee.ENCODED_SIZE;
        int branchNodeCount = branchBytes / 32;
        if (branchNodeCount < 5 || branchNodeCount > 6 || branchBytes % 32 != 0) {
            throw new IllegalArgumentException(
                    "Invalid branch size: " + branchBytes + " bytes (expected 160 or 192) in LightClientBootstrap");
        }

        // Read currentSyncCommittee at bytes 4..24628
        byte[] syncCommitteeBytes = Arrays.copyOfRange(ssz, 4, 4 + SyncCommittee.ENCODED_SIZE);
        SyncCommittee currentSyncCommittee = SyncCommittee.decode(syncCommitteeBytes);

        // Read currentSyncCommitteeBranch
        int branchStart = 4 + SyncCommittee.ENCODED_SIZE;
        byte[][] branch = new byte[branchNodeCount][32];
        for (int i = 0; i < branchNodeCount; i++) {
            branch[i] = Arrays.copyOfRange(ssz, branchStart + i * 32, branchStart + (i + 1) * 32);
        }

        // Decode variable header
        if (headerOffset > ssz.length) {
            throw new IllegalArgumentException(
                    "Invalid header offset " + headerOffset + " in LightClientBootstrap");
        }
        byte[] headerBytes = Arrays.copyOfRange(ssz, headerOffset, ssz.length);
        LightClientHeader header = LightClientHeader.decode(headerBytes);

        return new LightClientBootstrap(header, currentSyncCommittee, branch);
    }

    public LightClientHeader header() { return header; }
    public SyncCommittee currentSyncCommittee() { return currentSyncCommittee; }
    public byte[][] currentSyncCommitteeBranch() { return currentSyncCommitteeBranch; }
}
