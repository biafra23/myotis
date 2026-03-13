package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: Eth1Data
 * deposit_root (bytes32) | deposit_count (uint64) | block_hash (bytes32)
 * Total fixed size: 32 + 8 + 32 = 72 bytes
 */
public record Eth1Data(byte[] depositRoot, long depositCount, byte[] blockHash) {

    public static final int SSZ_SIZE = 72;

    public static Eth1Data decode(byte[] data, int offset) {
        byte[] depositRoot = Arrays.copyOfRange(data, offset, offset + 32);
        long depositCount = SszUtil.readUint64(data, offset + 32);
        byte[] blockHash = Arrays.copyOfRange(data, offset + 40, offset + 72);
        return new Eth1Data(depositRoot, depositCount, blockHash);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes32(depositRoot),
                SszUtil.hashTreeRootUint64(depositCount),
                SszUtil.hashTreeRootBytes32(blockHash)
        );
    }
}
