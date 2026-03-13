package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: IndexedAttestation (variable-length)
 * attesting_indices(List[uint64, 131072]) + data(AttestationData = 128B) + signature(Bytes96)
 * SSZ fixed part: indices_offset(4) + data(128) + sig(96) = 228 bytes
 */
public record IndexedAttestation(
        byte[] attestingIndicesRaw,
        AttestationData data,
        byte[] signature
) {

    private static final int MAX_VALIDATORS_PER_COMMITTEE = 131072;

    public static byte[] hashTreeRootAt(byte[] data, int off, int end) {
        int indicesOffset = SszUtil.readUint32(data, off);
        int absIndices = off + indicesOffset;
        byte[] indicesBytes = Arrays.copyOfRange(data, absIndices, end);

        byte[] indicesRoot = SszUtil.hashUint64List(indicesBytes, MAX_VALIDATORS_PER_COMMITTEE);
        byte[] dataRoot = AttestationData.decode(data, off + 4).hashTreeRoot();
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 132, off + 228));

        return SszUtil.hashTreeRootContainer(indicesRoot, dataRoot, sigRoot);
    }
}
