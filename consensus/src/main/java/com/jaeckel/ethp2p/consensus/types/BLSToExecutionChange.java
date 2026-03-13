package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: BLSToExecutionChange
 * validator_index (uint64) | from_bls_pubkey (bytes48) | to_execution_address (bytes20)
 * Total fixed size: 8 + 48 + 20 = 76 bytes
 */
public record BLSToExecutionChange(long validatorIndex, byte[] fromBlsPubkey, byte[] toAddress) {

    public static final int SSZ_SIZE = 76;

    public static BLSToExecutionChange decode(byte[] data, int offset) {
        long validatorIndex = SszUtil.readUint64(data, offset);
        byte[] fromBlsPubkey = Arrays.copyOfRange(data, offset + 8, offset + 56);
        byte[] toAddress = Arrays.copyOfRange(data, offset + 56, offset + 76);
        return new BLSToExecutionChange(validatorIndex, fromBlsPubkey, toAddress);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(validatorIndex),
                SszUtil.hashTreeRootByteVector(fromBlsPubkey),
                SszUtil.hashTreeRootBytes20(toAddress)
        );
    }
}
