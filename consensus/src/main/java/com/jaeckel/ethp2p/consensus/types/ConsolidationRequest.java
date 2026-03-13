package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: ConsolidationRequest
 * source_address (Bytes20) | source_pubkey (Bytes48) | target_pubkey (Bytes48)
 * Total fixed size: 20 + 48 + 48 = 116 bytes
 */
public record ConsolidationRequest(byte[] sourceAddress, byte[] sourcePubkey, byte[] targetPubkey) {

    public static final int SSZ_SIZE = 116;

    public ConsolidationRequest {
        if (sourceAddress.length != 20) throw new IllegalArgumentException("sourceAddress must be 20 bytes");
        if (sourcePubkey.length != 48) throw new IllegalArgumentException("sourcePubkey must be 48 bytes");
        if (targetPubkey.length != 48) throw new IllegalArgumentException("targetPubkey must be 48 bytes");
    }

    public static ConsolidationRequest decode(byte[] data, int offset) {
        byte[] sourceAddress = Arrays.copyOfRange(data, offset, offset + 20);
        byte[] sourcePubkey = Arrays.copyOfRange(data, offset + 20, offset + 68);
        byte[] targetPubkey = Arrays.copyOfRange(data, offset + 68, offset + 116);
        return new ConsolidationRequest(sourceAddress, sourcePubkey, targetPubkey);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes20(sourceAddress),
                SszUtil.hashTreeRootByteVector(sourcePubkey),
                SszUtil.hashTreeRootByteVector(targetPubkey)
        );
    }

    /** Hash from raw bytes at offset without constructing the record. */
    public static byte[] hashTreeRootAt(byte[] data, int offset) {
        return decode(data, offset).hashTreeRoot();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof ConsolidationRequest other)) return false;
        return Arrays.equals(sourceAddress, other.sourceAddress)
                && Arrays.equals(sourcePubkey, other.sourcePubkey)
                && Arrays.equals(targetPubkey, other.targetPubkey);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(sourceAddress);
        result = 31 * result + Arrays.hashCode(sourcePubkey);
        result = 31 * result + Arrays.hashCode(targetPubkey);
        return result;
    }
}
