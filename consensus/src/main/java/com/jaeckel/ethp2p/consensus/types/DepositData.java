package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: DepositData
 * pubkey (bytes48) | withdrawal_credentials (bytes32) | amount (uint64) | signature (bytes96)
 * Total fixed size: 48 + 32 + 8 + 96 = 184 bytes
 */
public record DepositData(byte[] pubkey, byte[] withdrawalCredentials, long amount, byte[] signature) {

    public static final int SSZ_SIZE = 184;

    public static DepositData decode(byte[] data, int offset) {
        byte[] pubkey = Arrays.copyOfRange(data, offset, offset + 48);
        byte[] withdrawalCredentials = Arrays.copyOfRange(data, offset + 48, offset + 80);
        long amount = SszUtil.readUint64(data, offset + 80);
        byte[] signature = Arrays.copyOfRange(data, offset + 88, offset + 184);
        return new DepositData(pubkey, withdrawalCredentials, amount, signature);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootByteVector(pubkey),
                SszUtil.hashTreeRootBytes32(withdrawalCredentials),
                SszUtil.hashTreeRootUint64(amount),
                SszUtil.hashTreeRootByteVector(signature)
        );
    }
}
