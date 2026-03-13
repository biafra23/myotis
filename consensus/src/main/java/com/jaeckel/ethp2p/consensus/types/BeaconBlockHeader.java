package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: BeaconBlockHeader
 * slot (uint64) | proposerIndex (uint64) | parentRoot (bytes32) | stateRoot (bytes32) | bodyRoot (bytes32)
 * Total fixed size: 8 + 8 + 32 + 32 + 32 = 112 bytes
 */
public record BeaconBlockHeader(
        long slot,
        long proposerIndex,
        byte[] parentRoot,
        byte[] stateRoot,
        byte[] bodyRoot
) {

    public BeaconBlockHeader {
        if (parentRoot.length != 32) throw new IllegalArgumentException("parentRoot must be 32 bytes");
        if (stateRoot.length != 32) throw new IllegalArgumentException("stateRoot must be 32 bytes");
        if (bodyRoot.length != 32) throw new IllegalArgumentException("bodyRoot must be 32 bytes");
    }

    /**
     * Decode a BeaconBlockHeader from 112 bytes of SSZ.
     */
    public static BeaconBlockHeader decode(byte[] ssz) {
        if (ssz.length < 112) {
            throw new IllegalArgumentException("BeaconBlockHeader requires 112 bytes, got " + ssz.length);
        }
        ByteBuffer buf = ByteBuffer.wrap(ssz).order(ByteOrder.LITTLE_ENDIAN);
        long slot = buf.getLong();
        long proposerIndex = buf.getLong();
        byte[] parentRoot = new byte[32];
        byte[] stateRoot = new byte[32];
        byte[] bodyRoot = new byte[32];
        buf.get(parentRoot);
        buf.get(stateRoot);
        buf.get(bodyRoot);
        return new BeaconBlockHeader(slot, proposerIndex, parentRoot, stateRoot, bodyRoot);
    }

    /**
     * Serialize to 112 bytes of SSZ.
     */
    public byte[] encode() {
        ByteBuffer buf = ByteBuffer.allocate(112).order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(slot);
        buf.putLong(proposerIndex);
        buf.put(parentRoot);
        buf.put(stateRoot);
        buf.put(bodyRoot);
        return buf.array();
    }

    /**
     * hash_tree_root of this container.
     * Fields: slot (uint64), proposerIndex (uint64), parentRoot (bytes32), stateRoot (bytes32), bodyRoot (bytes32)
     */
    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(slot),
                SszUtil.hashTreeRootUint64(proposerIndex),
                SszUtil.hashTreeRootBytes32(parentRoot),
                SszUtil.hashTreeRootBytes32(stateRoot),
                SszUtil.hashTreeRootBytes32(bodyRoot)
        );
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof BeaconBlockHeader other)) return false;
        return slot == other.slot
                && proposerIndex == other.proposerIndex
                && Arrays.equals(parentRoot, other.parentRoot)
                && Arrays.equals(stateRoot, other.stateRoot)
                && Arrays.equals(bodyRoot, other.bodyRoot);
    }

    @Override
    public int hashCode() {
        int result = Long.hashCode(slot);
        result = 31 * result + Long.hashCode(proposerIndex);
        result = 31 * result + Arrays.hashCode(parentRoot);
        result = 31 * result + Arrays.hashCode(stateRoot);
        result = 31 * result + Arrays.hashCode(bodyRoot);
        return result;
    }

    @Override
    public String toString() {
        return "BeaconBlockHeader{slot=" + slot + ", proposerIndex=" + proposerIndex + "}";
    }
}
