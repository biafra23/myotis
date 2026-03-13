package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: AttestationData
 * slot(uint64) + index(uint64) + beacon_block_root(Bytes32) + source(Checkpoint) + target(Checkpoint)
 * Total fixed size: 8 + 8 + 32 + 40 + 40 = 128 bytes
 */
public record AttestationData(
        long slot,
        long index,
        byte[] beaconBlockRoot,
        Checkpoint source,
        Checkpoint target
) {

    public static final int SSZ_SIZE = 128;

    public static AttestationData decode(byte[] data, int offset) {
        long slot = SszUtil.readUint64(data, offset);
        long index = SszUtil.readUint64(data, offset + 8);
        byte[] beaconBlockRoot = Arrays.copyOfRange(data, offset + 16, offset + 48);
        Checkpoint source = Checkpoint.decode(data, offset + 48);
        Checkpoint target = Checkpoint.decode(data, offset + 88);
        return new AttestationData(slot, index, beaconBlockRoot, source, target);
    }

    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(slot),
                SszUtil.hashTreeRootUint64(index),
                SszUtil.hashTreeRootBytes32(beaconBlockRoot),
                source.hashTreeRoot(),
                target.hashTreeRoot()
        );
    }
}
