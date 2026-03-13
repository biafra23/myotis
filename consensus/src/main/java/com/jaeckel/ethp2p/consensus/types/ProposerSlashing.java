package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

/**
 * SSZ container: ProposerSlashing
 * signed_header_1(SignedBeaconBlockHeader = 208B) + signed_header_2(SignedBeaconBlockHeader = 208B)
 * Total fixed size: 416 bytes
 */
public record ProposerSlashing(
        SignedBeaconBlockHeader signedHeader1,
        SignedBeaconBlockHeader signedHeader2
) {

    public static final int SSZ_SIZE = 416;

    public static ProposerSlashing decode(byte[] data, int offset) {
        SignedBeaconBlockHeader h1 = SignedBeaconBlockHeader.decode(data, offset);
        SignedBeaconBlockHeader h2 = SignedBeaconBlockHeader.decode(data, offset + 208);
        return new ProposerSlashing(h1, h2);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                signedHeader1.hashTreeRoot(),
                signedHeader2.hashTreeRoot()
        );
    }

    /** Hash from raw bytes at offset without constructing the record. */
    public static byte[] hashTreeRootAt(byte[] data, int offset) {
        return decode(data, offset).hashTreeRoot();
    }
}
