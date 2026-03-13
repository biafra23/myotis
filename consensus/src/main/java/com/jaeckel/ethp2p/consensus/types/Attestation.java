package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: Attestation (Electra, variable-length)
 * aggregation_bits(Bitlist[MAX_VALIDATORS * MAX_COMMITTEES]) + data(AttestationData = 128B)
 * + signature(Bytes96) + committee_bits(Bitvector[64] = 8B)
 * SSZ fixed part: agg_bits_offset(4) + data(128) + sig(96) + committee_bits(8) = 236 bytes
 */
public record Attestation(
        byte[] aggregationBits,
        AttestationData data,
        byte[] signature,
        byte[] committeeBits
) {

    private static final int MAX_AGGREGATION_BITS = 131072; // MAX_VALIDATORS * MAX_COMMITTEES

    public static byte[] hashTreeRootAt(byte[] data, int off, int end) {
        int aggBitsOffset = SszUtil.readUint32(data, off);
        int absAggBits = off + aggBitsOffset;
        byte[] aggBitsBytes = Arrays.copyOfRange(data, absAggBits, end);

        byte[] aggBitsRoot = SszUtil.hashBitlist(aggBitsBytes, MAX_AGGREGATION_BITS);
        byte[] dataRoot = AttestationData.decode(data, off + 4).hashTreeRoot();
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 132, off + 228));

        // committee_bits: Bitvector[64] = 8 bytes → 1 chunk (padded to 32)
        byte[] committeeBitsChunk = new byte[32];
        System.arraycopy(data, off + 228, committeeBitsChunk, 0, 8);

        return SszUtil.hashTreeRootContainer(aggBitsRoot, dataRoot, sigRoot, committeeBitsChunk);
    }
}
