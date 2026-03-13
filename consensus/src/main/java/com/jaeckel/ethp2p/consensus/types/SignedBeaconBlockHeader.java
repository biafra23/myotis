package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: SignedBeaconBlockHeader
 * message(BeaconBlockHeader = 112B) + signature(Bytes96)
 * Total fixed size: 208 bytes
 */
public record SignedBeaconBlockHeader(
        BeaconBlockHeader message,
        byte[] signature
) {

    public static final int SSZ_SIZE = 208;

    public static SignedBeaconBlockHeader decode(byte[] data, int offset) {
        BeaconBlockHeader header = BeaconBlockHeader.decode(Arrays.copyOfRange(data, offset, offset + 112));
        byte[] signature = Arrays.copyOfRange(data, offset + 112, offset + 208);
        return new SignedBeaconBlockHeader(header, signature);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                message.hashTreeRoot(),
                SszUtil.hashTreeRootByteVector(signature)
        );
    }
}
