package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: SignedBLSToExecutionChange
 * message(BLSToExecutionChange = 76B) + signature(Bytes96)
 * Total fixed size: 172 bytes
 */
public record SignedBLSToExecutionChange(
        BLSToExecutionChange message,
        byte[] signature
) {

    public static final int SSZ_SIZE = 172;

    public static SignedBLSToExecutionChange decode(byte[] data, int offset) {
        BLSToExecutionChange change = BLSToExecutionChange.decode(data, offset);
        byte[] signature = Arrays.copyOfRange(data, offset + 76, offset + 172);
        return new SignedBLSToExecutionChange(change, signature);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                message.hashTreeRoot(),
                SszUtil.hashTreeRootByteVector(signature)
        );
    }

    /** Hash from raw bytes at offset without constructing the record. */
    public static byte[] hashTreeRootAt(byte[] data, int offset) {
        return decode(data, offset).hashTreeRoot();
    }
}
