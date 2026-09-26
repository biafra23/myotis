package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.core.consensus.LcFork;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: LightClientHeader, in the wire shape of its fork ({@link LcFork}).
 *
 * Pre-Gloas shape (Capella..Fulu) fields:
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
 *
 * Gloas shape (EIP-7732: the body carries a payload bid, not a payload) fields:
 *   beacon             — BeaconBlockHeader (112 bytes)
 *   executionBlockHash — Bytes32 (32 bytes)
 *   executionBranch    — Vector[Bytes32, 11] (352 bytes)
 *   All fixed: 112 + 32 + 352 = 496 bytes ({@link #GLOAS_SIZE}).
 *
 * Gloas objects are NOT sniffed: with no variable part every Gloas container is
 * fixed-size, and the only honest way to tell the format is the fork of the object's
 * slot — the req/resp context bytes. {@link #decodeFor} dispatches on it; the
 * pre-Gloas {@link #decode} path is unchanged. Rust twin: {@code types.rs}.
 */
public final class LightClientHeader {

    public static final int FIXED_SIZE = 244; // 112 + 4 + 128
    /** The whole Gloas shape: beacon 112 + block hash 32 + the execution branch,
     *  {@code Vector[Bytes32, floorlog2(EXECUTION_BLOCK_HASH_GINDEX_GLOAS)]} (11 x 32). */
    public static final int GLOAS_SIZE = 112 + 32 + BeaconChainSpec.GLOAS_EXECUTION_BRANCH_LEN * 32; // 496

    private final BeaconBlockHeader beacon;
    private final ExecutionPayloadHeader execution; // pre-Gloas shape; null in the Gloas shape
    private final byte[] executionBlockHash;        // Gloas shape; null in the pre-Gloas shape
    private final byte[][] executionBranch; // 4 x 32 bytes (pre-Gloas), 11 x 32 bytes (Gloas)

    /** The pre-Gloas shape: the whole execution payload header, bound by a 4-node branch. */
    public LightClientHeader(BeaconBlockHeader beacon, ExecutionPayloadHeader execution, byte[][] executionBranch) {
        if (executionBranch.length != 4) throw new IllegalArgumentException("executionBranch must have 4 nodes");
        for (byte[] node : executionBranch) {
            if (node.length != 32) throw new IllegalArgumentException("each executionBranch node must be 32 bytes");
        }
        this.beacon = beacon;
        this.execution = execution;
        this.executionBlockHash = null;
        this.executionBranch = executionBranch;
    }

    private LightClientHeader(BeaconBlockHeader beacon, byte[][] executionBranch, byte[] executionBlockHash) {
        this.beacon = beacon;
        this.execution = null;
        this.executionBlockHash = executionBlockHash;
        this.executionBranch = executionBranch;
    }

    /**
     * The Gloas shape: the execution block hash alone, bound to the beacon body at
     * {@code EXECUTION_BLOCK_HASH_GINDEX_GLOAS} (2856) by an 11-node branch — or, for a
     * pre-Gloas header carried in the Gloas shape (a Gloas update's finalized header in
     * the first epochs after the fork), at {@code EXECUTION_BLOCK_HASH_GINDEX_DENEB}
     * (812) normalized to 11 nodes. Which proof applies is the verifier's call, by the
     * fork of the header's own slot ({@code LightClientProcessor.verifyExecutionBranchAt}).
     *
     * @throws IllegalArgumentException unless the hash is 32 bytes and the branch is
     *                                  exactly 11 nodes of 32 bytes
     */
    public static LightClientHeader gloas(BeaconBlockHeader beacon, byte[] executionBlockHash, byte[][] executionBranch) {
        if (executionBlockHash == null || executionBlockHash.length != 32)
            throw new IllegalArgumentException("executionBlockHash must be 32 bytes");
        if (executionBranch == null || executionBranch.length != BeaconChainSpec.GLOAS_EXECUTION_BRANCH_LEN)
            throw new IllegalArgumentException("Gloas executionBranch must have "
                    + BeaconChainSpec.GLOAS_EXECUTION_BRANCH_LEN + " nodes");
        for (byte[] node : executionBranch) {
            if (node == null || node.length != 32)
                throw new IllegalArgumentException("each executionBranch node must be 32 bytes");
        }
        return new LightClientHeader(beacon, executionBranch, executionBlockHash);
    }

    /**
     * Decode a pre-Gloas (payload-carrying) LightClientHeader from SSZ bytes.
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

    /**
     * Decode the Gloas shape: exactly {@link #GLOAS_SIZE} bytes.
     *
     * Layout:
     *   [0..112)   beacon
     *   [112..144) executionBlockHash
     *   [144..496) executionBranch (11 * 32B)
     *
     * @throws IllegalArgumentException on any other length — one short or one long is
     *                                  a rejection, never a silently ignored tail
     */
    public static LightClientHeader decodeGloas(byte[] ssz) {
        if (ssz == null || ssz.length != GLOAS_SIZE) {
            throw new IllegalArgumentException("Gloas LightClientHeader requires " + GLOAS_SIZE
                    + " bytes, got " + (ssz == null ? "null" : ssz.length));
        }
        BeaconBlockHeader beacon = BeaconBlockHeader.decode(Arrays.copyOfRange(ssz, 0, 112));
        byte[] executionBlockHash = Arrays.copyOfRange(ssz, 112, 144);
        return gloas(beacon, executionBlockHash, readNodes(ssz, 144, BeaconChainSpec.GLOAS_EXECUTION_BRANCH_LEN));
    }

    /**
     * Decode in the wire format of {@code fork} — the fork of the object's slot (for a
     * header inside an update: its attested slot's), never sniffed from the bytes.
     */
    public static LightClientHeader decodeFor(LcFork fork, byte[] ssz) {
        if (fork == null) throw new IllegalArgumentException("LightClientHeader: fork is required");
        return fork == LcFork.GLOAS ? decodeGloas(ssz) : decode(ssz);
    }

    /** {@code n} consecutive 32-byte nodes from {@code offset}; the caller has checked the bounds. */
    static byte[][] readNodes(byte[] ssz, int offset, int n) {
        byte[][] nodes = new byte[n][];
        for (int i = 0; i < n; i++) {
            nodes[i] = Arrays.copyOfRange(ssz, offset + i * 32, offset + (i + 1) * 32);
        }
        return nodes;
    }

    public BeaconBlockHeader beacon() { return beacon; }

    /**
     * The execution payload header, when this is the pre-Gloas shape; {@code null} in
     * the Gloas shape, which carries only {@link #executionBlockHash()}.
     */
    public ExecutionPayloadHeader execution() { return execution; }

    public byte[][] executionBranch() { return executionBranch; }

    /**
     * The execution block hash this header proves, in either shape. At a Gloas slot it
     * is the PARENT payload's hash ({@code bid.parent_block_hash}): the slot's own
     * payload is revealed separately and may be withheld, the parent is one the chain
     * has imported. The Gloas shape has no state root, number or timestamp: those come
     * from the execution header this hash pins.
     */
    public byte[] executionBlockHash() {
        if (executionBlockHash != null) return executionBlockHash;
        return execution != null ? execution.blockHash() : null;
    }

    /**
     * Which wire shape this header was decoded from (or built in) — NOT the fork of its
     * slot: a Gloas update carries a pre-Gloas finalized header in the Gloas shape.
     */
    public LcFork shape() {
        return executionBlockHash != null ? LcFork.GLOAS : LcFork.PRE_GLOAS;
    }

    /**
     * Convenience accessor: the body root from the beacon header.
     */
    public byte[] beaconBodyRoot() {
        return beacon.bodyRoot();
    }
}
