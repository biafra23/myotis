package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

/**
 * SSZ container: AttesterSlashing (variable-length)
 * attestation_1(IndexedAttestation) + attestation_2(IndexedAttestation)
 * SSZ fixed part: 2 offsets = 8 bytes
 */
public record AttesterSlashing() {

    public static byte[] hashTreeRootAt(byte[] data, int off, int end) {
        int att1Off = off + SszUtil.readUint32(data, off);
        int att2Off = off + SszUtil.readUint32(data, off + 4);
        return SszUtil.hashTreeRootContainer(
                IndexedAttestation.hashTreeRootAt(data, att1Off, att2Off),
                IndexedAttestation.hashTreeRootAt(data, att2Off, end)
        );
    }
}
