package com.jaeckel.ethp2p.consensus.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: LightClientHeader (Capella+)
 *
 * Fields:
 *   beacon           — BeaconBlockHeader (112 bytes, fixed-size)
 *   execution        — ExecutionPayloadHeader (variable-length)
 *   executionBranch  — Vector[Bytes32, 4] (4 * 32 = 128 bytes, fixed-size)
 *
 * SSZ layout:
 *   The container has one variable-length field (execution), so the fixed part is:
 *     - beacon:          112 bytes (inline, fixed)
 *     - execution offset: 4 bytes (uint32 LE, points to start of execution data)
 *     - executionBranch: 128 bytes (inline, fixed)
 *   Total fixed: 112 + 4 + 128 = 244 bytes
 *   Then variable: execution payload header bytes starting at given offset
 */
public final class LightClientHeader {

    public static final int FIXED_SIZE = 244; // 112 + 4 + 128

    private final BeaconBlockHeader beacon;
    private final ExecutionPayloadHeader execution;
    private final byte[][] executionBranch; // 4 x 32 bytes

    public LightClientHeader(BeaconBlockHeader beacon, ExecutionPayloadHeader execution, byte[][] executionBranch) {
        if (executionBranch.length != 4) throw new IllegalArgumentException("executionBranch must have 4 nodes");
        for (byte[] node : executionBranch) {
            if (node.length != 32) throw new IllegalArgumentException("each executionBranch node must be 32 bytes");
        }
        this.beacon = beacon;
        this.execution = execution;
        this.executionBranch = executionBranch;
    }

    /**
     * Decode a LightClientHeader from SSZ bytes.
     *
     * Layout:
     *   [0..112)   beacon (fixed inline)
     *   [112..116) execution offset (4B LE uint32)
     *   [116..244) executionBranch (4 * 32B)
     *   [offset..] execution payload header bytes
     */
    public static LightClientHeader decode(byte[] ssz) {
        if (ssz.length < FIXED_SIZE) {
            throw new IllegalArgumentException(
                    "LightClientHeader requires at least " + FIXED_SIZE + " bytes, got " + ssz.length);
        }

        // Decode beacon header from first 112 bytes
        BeaconBlockHeader beacon = BeaconBlockHeader.decode(Arrays.copyOfRange(ssz, 0, 112));

        // Read execution offset at byte 112
        ByteBuffer buf = ByteBuffer.wrap(ssz, 112, 4).order(ByteOrder.LITTLE_ENDIAN);
        int executionOffset = buf.getInt();

        // Read execution branch at bytes 116..244
        byte[][] executionBranch = new byte[4][32];
        for (int i = 0; i < 4; i++) {
            executionBranch[i] = Arrays.copyOfRange(ssz, 116 + i * 32, 116 + (i + 1) * 32);
        }

        // Decode execution payload header from the variable part
        if (executionOffset < FIXED_SIZE || executionOffset > ssz.length) {
            throw new IllegalArgumentException(
                    "Invalid execution offset " + executionOffset + " in LightClientHeader");
        }
        byte[] executionBytes = Arrays.copyOfRange(ssz, executionOffset, ssz.length);
        ExecutionPayloadHeader execution = ExecutionPayloadHeader.decode(executionBytes);

        return new LightClientHeader(beacon, execution, executionBranch);
    }

    public BeaconBlockHeader beacon() { return beacon; }
    public ExecutionPayloadHeader execution() { return execution; }
    public byte[][] executionBranch() { return executionBranch; }

    /**
     * Convenience accessor: the body root from the beacon header.
     */
    public byte[] beaconBodyRoot() {
        return beacon.bodyRoot();
    }
}
