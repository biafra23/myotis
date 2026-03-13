package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

/**
 * SSZ container: VoluntaryExit
 * epoch (uint64) | validator_index (uint64)
 * Total fixed size: 8 + 8 = 16 bytes
 */
public record VoluntaryExit(long epoch, long validatorIndex) {

    public static final int SSZ_SIZE = 16;

    public static VoluntaryExit decode(byte[] data, int offset) {
        long epoch = SszUtil.readUint64(data, offset);
        long validatorIndex = SszUtil.readUint64(data, offset + 8);
        return new VoluntaryExit(epoch, validatorIndex);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(epoch),
                SszUtil.hashTreeRootUint64(validatorIndex)
        );
    }
}
