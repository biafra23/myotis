package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: DepositRequest
 * pubkey (Bytes48) | withdrawal_credentials (Bytes32) | amount (uint64) | signature (Bytes96) | index (uint64)
 * Total fixed size: 48 + 32 + 8 + 96 + 8 = 192 bytes
 */
public record DepositRequest(byte[] pubkey, byte[] withdrawalCredentials, long amount, byte[] signature, long index) {

    public static final int SSZ_SIZE = 192;

    public DepositRequest {
        if (pubkey.length != 48) throw new IllegalArgumentException("pubkey must be 48 bytes");
        if (withdrawalCredentials.length != 32) throw new IllegalArgumentException("withdrawalCredentials must be 32 bytes");
        if (signature.length != 96) throw new IllegalArgumentException("signature must be 96 bytes");
    }

    public static DepositRequest decode(byte[] data, int offset) {
        byte[] pubkey = Arrays.copyOfRange(data, offset, offset + 48);
        byte[] withdrawalCredentials = Arrays.copyOfRange(data, offset + 48, offset + 80);
        long amount = SszUtil.readUint64(data, offset + 80);
        byte[] signature = Arrays.copyOfRange(data, offset + 88, offset + 184);
        long index = SszUtil.readUint64(data, offset + 184);
        return new DepositRequest(pubkey, withdrawalCredentials, amount, signature, index);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootByteVector(pubkey),
                SszUtil.hashTreeRootBytes32(withdrawalCredentials),
                SszUtil.hashTreeRootUint64(amount),
                SszUtil.hashTreeRootByteVector(signature),
                SszUtil.hashTreeRootUint64(index)
        );
    }

    /** Hash from raw bytes at offset without constructing the record. */
    public static byte[] hashTreeRootAt(byte[] data, int offset) {
        return decode(data, offset).hashTreeRoot();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof DepositRequest other)) return false;
        return Arrays.equals(pubkey, other.pubkey)
                && Arrays.equals(withdrawalCredentials, other.withdrawalCredentials)
                && amount == other.amount
                && Arrays.equals(signature, other.signature)
                && index == other.index;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(pubkey);
        result = 31 * result + Arrays.hashCode(withdrawalCredentials);
        result = 31 * result + Long.hashCode(amount);
        result = 31 * result + Arrays.hashCode(signature);
        result = 31 * result + Long.hashCode(index);
        return result;
    }
}
