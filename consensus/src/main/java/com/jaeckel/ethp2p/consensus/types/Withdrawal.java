package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: Withdrawal
 * index (uint64) | validator_index (uint64) | address (Bytes20) | amount (uint64)
 * Total fixed size: 8 + 8 + 20 + 8 = 44 bytes
 */
public record Withdrawal(long index, long validatorIndex, byte[] address, long amount) {

    public static final int SSZ_SIZE = 44;

    public Withdrawal {
        if (address.length != 20) throw new IllegalArgumentException("address must be 20 bytes");
    }

    public static Withdrawal decode(byte[] data, int offset) {
        long index = SszUtil.readUint64(data, offset);
        long validatorIndex = SszUtil.readUint64(data, offset + 8);
        byte[] address = Arrays.copyOfRange(data, offset + 16, offset + 36);
        long amount = SszUtil.readUint64(data, offset + 36);
        return new Withdrawal(index, validatorIndex, address, amount);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(index),
                SszUtil.hashTreeRootUint64(validatorIndex),
                SszUtil.hashTreeRootBytes20(address),
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
        if (!(obj instanceof Withdrawal other)) return false;
        return index == other.index
                && validatorIndex == other.validatorIndex
                && Arrays.equals(address, other.address)
                && amount == other.amount;
    }

    @Override
    public int hashCode() {
        int result = Long.hashCode(index);
        result = 31 * result + Long.hashCode(validatorIndex);
        result = 31 * result + Arrays.hashCode(address);
        result = 31 * result + Long.hashCode(amount);
        return result;
    }
}
