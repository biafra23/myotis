package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: WithdrawalRequest
 * source_address (Bytes20) | validator_pubkey (Bytes48) | amount (uint64)
 * Total fixed size: 20 + 48 + 8 = 76 bytes
 */
public record WithdrawalRequest(byte[] sourceAddress, byte[] validatorPubkey, long amount) {

    public static final int SSZ_SIZE = 76;

    public WithdrawalRequest {
        if (sourceAddress.length != 20) throw new IllegalArgumentException("sourceAddress must be 20 bytes");
        if (validatorPubkey.length != 48) throw new IllegalArgumentException("validatorPubkey must be 48 bytes");
    }

    public static WithdrawalRequest decode(byte[] data, int offset) {
        byte[] sourceAddress = Arrays.copyOfRange(data, offset, offset + 20);
        byte[] validatorPubkey = Arrays.copyOfRange(data, offset + 20, offset + 68);
        long amount = SszUtil.readUint64(data, offset + 68);
        return new WithdrawalRequest(sourceAddress, validatorPubkey, amount);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes20(sourceAddress),
                SszUtil.hashTreeRootByteVector(validatorPubkey),
                SszUtil.hashTreeRootUint64(amount)
        );
    }

    /** Hash from raw bytes at offset without constructing the record. */
    public static byte[] hashTreeRootAt(byte[] data, int offset) {
        return decode(data, offset).hashTreeRoot();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof WithdrawalRequest other)) return false;
        return Arrays.equals(sourceAddress, other.sourceAddress)
                && Arrays.equals(validatorPubkey, other.validatorPubkey)
                && amount == other.amount;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(sourceAddress);
        result = 31 * result + Arrays.hashCode(validatorPubkey);
        result = 31 * result + Long.hashCode(amount);
        return result;
    }
}
