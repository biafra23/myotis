package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: SyncAggregate
 * syncCommitteeBits (bitvector[512] = bytes64) | syncCommitteeSignature (BLS G2 = bytes96)
 * Total: 160 bytes
 */
public record SyncAggregate(
        byte[] syncCommitteeBits,
        byte[] syncCommitteeSignature
) {

    public SyncAggregate {
        if (syncCommitteeBits.length != 64) throw new IllegalArgumentException("syncCommitteeBits must be 64 bytes");
        if (syncCommitteeSignature.length != 96) throw new IllegalArgumentException("syncCommitteeSignature must be 96 bytes");
    }

    /**
     * Decode a SyncAggregate from 160 bytes of SSZ.
     */
    public static SyncAggregate decode(byte[] ssz) {
        if (ssz.length < 160) {
            throw new IllegalArgumentException("SyncAggregate requires 160 bytes, got " + ssz.length);
        }
        byte[] bits = Arrays.copyOfRange(ssz, 0, 64);
        byte[] sig = Arrays.copyOfRange(ssz, 64, 160);
        return new SyncAggregate(bits, sig);
    }

    /**
     * hash_tree_root of this SyncAggregate container.
     * Fields: syncCommitteeBits (Bitvector[512] = 64B → 2 chunks), syncCommitteeSignature (Bytes96)
     */
    public byte[] hashTreeRoot() {
        byte[][] bitChunks = {
                Arrays.copyOfRange(syncCommitteeBits, 0, 32),
                Arrays.copyOfRange(syncCommitteeBits, 32, 64)
        };
        byte[] bitsRoot = SszUtil.merkleize(bitChunks);
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(syncCommitteeSignature);
        return SszUtil.hashTreeRootContainer(bitsRoot, sigRoot);
    }

    /**
     * hash_tree_root computed from raw body bytes at a given offset (avoids object allocation).
     */
    public static byte[] hashTreeRootAt(byte[] data, int off) {
        byte[][] bitChunks = {
                Arrays.copyOfRange(data, off, off + 32),
                Arrays.copyOfRange(data, off + 32, off + 64)
        };
        byte[] bitsRoot = SszUtil.merkleize(bitChunks);
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 64, off + 160));
        return SszUtil.hashTreeRootContainer(bitsRoot, sigRoot);
    }

    /**
     * Count the number of participating validators (popcount of all 64 bytes).
     */
    public int countParticipants() {
        int count = 0;
        for (byte b : syncCommitteeBits) {
            count += Integer.bitCount(b & 0xFF);
        }
        return count;
    }

    /**
     * Get bit i from the bitvector (0-indexed).
     * Bit i is at byte i/8, bit position i%8 (LSB first).
     */
    public boolean getBit(int i) {
        if (i < 0 || i >= 512) throw new IndexOutOfBoundsException("bit index out of range: " + i);
        int byteIndex = i / 8;
        int bitIndex = i % 8;
        return ((syncCommitteeBits[byteIndex] >>> bitIndex) & 1) == 1;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof SyncAggregate other)) return false;
        return Arrays.equals(syncCommitteeBits, other.syncCommitteeBits)
                && Arrays.equals(syncCommitteeSignature, other.syncCommitteeSignature);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(syncCommitteeBits) + Arrays.hashCode(syncCommitteeSignature);
    }
}
