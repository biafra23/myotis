package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: SignedVoluntaryExit
 * message(VoluntaryExit = 16B) + signature(Bytes96)
 * Total fixed size: 112 bytes
 */
public record SignedVoluntaryExit(
        VoluntaryExit message,
        byte[] signature
) {

    public static final int SSZ_SIZE = 112;

    public static SignedVoluntaryExit decode(byte[] data, int offset) {
        VoluntaryExit exit = VoluntaryExit.decode(data, offset);
        byte[] signature = Arrays.copyOfRange(data, offset + 16, offset + 112);
        return new SignedVoluntaryExit(exit, signature);
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
