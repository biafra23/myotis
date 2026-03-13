package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: Checkpoint
 * epoch (uint64) | root (bytes32)
 * Total fixed size: 8 + 32 = 40 bytes
 */
public record Checkpoint(long epoch, byte[] root) {

    public static final int SSZ_SIZE = 40;

    public static Checkpoint decode(byte[] data, int offset) {
        long epoch = SszUtil.readUint64(data, offset);
        byte[] root = Arrays.copyOfRange(data, offset + 8, offset + 40);
        return new Checkpoint(epoch, root);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(epoch),
                SszUtil.hashTreeRootBytes32(root)
        );
    }
}
