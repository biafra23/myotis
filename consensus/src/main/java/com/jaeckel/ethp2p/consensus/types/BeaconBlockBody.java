package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: BeaconBlockBody (Deneb: 12 fields, Electra: 13 fields)
 *
 * <p>Fixed-part layout:
 * <pre>
 *   0:   randao_reveal (96B)
 *  96:   eth1_data (72B)
 * 168:   graffiti (32B)
 * 200:   proposer_slashings offset (4B)
 * 204:   attester_slashings offset (4B)
 * 208:   attestations offset (4B)
 * 212:   deposits offset (4B)
 * 216:   voluntary_exits offset (4B)
 * 220:   sync_aggregate (160B)
 * 380:   execution_payload offset (4B)
 * 384:   bls_to_execution_changes offset (4B)
 * 388:   blob_kzg_commitments offset (4B)
 * [392:  execution_requests offset (4B)] — Electra only
 * </pre>
 * Deneb fixed = 392 bytes, Electra fixed = 396 bytes.
 */
public final class BeaconBlockBody {

    // Consensus-spec list limits
    private static final int MAX_PROPOSER_SLASHINGS = 16;
    private static final int MAX_ATTESTER_SLASHINGS_ELECTRA = 1;
    private static final int MAX_ATTESTER_SLASHINGS_DENEB = 2;
    private static final int MAX_ATTESTATIONS_ELECTRA = 8;
    private static final int MAX_ATTESTATIONS_DENEB = 128;
    private static final int MAX_DEPOSITS = 16;
    private static final int MAX_VOLUNTARY_EXITS = 16;
    private static final int MAX_BLS_TO_EXECUTION_CHANGES = 16;
    private static final int MAX_BLOB_COMMITMENTS = 4096;
    private static final int KZG_COMMITMENT_SIZE = 48;

    private final byte[] randaoReveal;
    private final Eth1Data eth1Data;
    private final byte[] graffiti;
    private final ExecutionPayload executionPayload;
    private final boolean electra;

    // Raw body bytes retained for variable-length list hashing
    private final byte[] raw;
    private final int[] varOffsets;
    private final int blobKzgOffset;

    private BeaconBlockBody(
            byte[] randaoReveal, Eth1Data eth1Data, byte[] graffiti,
            ExecutionPayload executionPayload, boolean electra,
            byte[] raw, int[] varOffsets, int blobKzgOffset
    ) {
        this.randaoReveal = randaoReveal;
        this.eth1Data = eth1Data;
        this.graffiti = graffiti;
        this.executionPayload = executionPayload;
        this.electra = electra;
        this.raw = raw;
        this.varOffsets = varOffsets;
        this.blobKzgOffset = blobKzgOffset;
    }

    /**
     * Decode a BeaconBlockBody from raw bytes between [offset, end).
     */
    public static BeaconBlockBody decode(byte[] data, int offset, int end) {
        byte[] b = Arrays.copyOfRange(data, offset, end);

        // Fixed fields
        byte[] randaoReveal = Arrays.copyOfRange(b, 0, 96);
        Eth1Data eth1Data = Eth1Data.decode(b, 96);
        byte[] graffiti = Arrays.copyOfRange(b, 168, 200);

        // Detect fork: Electra has firstVarOffset >= 396
        int firstVarOffset = SszUtil.readUint32(b, 200);
        boolean electra = firstVarOffset >= 396;

        // Variable field offsets
        int[] varOffsets = new int[electra ? 8 : 7];
        varOffsets[0] = SszUtil.readUint32(b, 200); // proposer_slashings
        varOffsets[1] = SszUtil.readUint32(b, 204); // attester_slashings
        varOffsets[2] = SszUtil.readUint32(b, 208); // attestations
        varOffsets[3] = SszUtil.readUint32(b, 212); // deposits
        varOffsets[4] = SszUtil.readUint32(b, 216); // voluntary_exits
        varOffsets[5] = SszUtil.readUint32(b, 380); // execution_payload
        varOffsets[6] = SszUtil.readUint32(b, 384); // bls_to_execution_changes
        if (electra) {
            varOffsets[7] = SszUtil.readUint32(b, 392); // execution_requests
        }
        int blobKzgOffset = SszUtil.readUint32(b, 388); // blob_kzg_commitments

        // Decode execution payload
        ExecutionPayload ep = ExecutionPayload.decode(b, varOffsets[5], varOffsets[6]);

        return new BeaconBlockBody(
                randaoReveal, eth1Data, graffiti, ep, electra,
                b, varOffsets, blobKzgOffset
        );
    }

    public ExecutionPayload executionPayload() { return executionPayload; }

    public byte[] hashTreeRoot() {
        int fieldCount = electra ? 13 : 12;
        byte[][] fieldRoots = new byte[fieldCount][];

        // 0: randao_reveal (Bytes96)
        fieldRoots[0] = SszUtil.hashTreeRootByteVector(randaoReveal);
        // 1: eth1_data
        fieldRoots[1] = eth1Data.hashTreeRoot();
        // 2: graffiti (Bytes32)
        fieldRoots[2] = SszUtil.hashTreeRootBytes32(graffiti);

        // 3: proposer_slashings
        fieldRoots[3] = SszUtil.hashFixedElementList(raw, varOffsets[0], varOffsets[1],
                ProposerSlashing.SSZ_SIZE, MAX_PROPOSER_SLASHINGS, ProposerSlashing::hashTreeRootAt);
        // 4: attester_slashings
        fieldRoots[4] = SszUtil.hashVariableElementList(raw, varOffsets[1], varOffsets[2],
                electra ? MAX_ATTESTER_SLASHINGS_ELECTRA : MAX_ATTESTER_SLASHINGS_DENEB,
                AttesterSlashing::hashTreeRootAt);
        // 5: attestations
        fieldRoots[5] = SszUtil.hashVariableElementList(raw, varOffsets[2], varOffsets[3],
                electra ? MAX_ATTESTATIONS_ELECTRA : MAX_ATTESTATIONS_DENEB,
                Attestation::hashTreeRootAt);
        // 6: deposits
        fieldRoots[6] = SszUtil.hashFixedElementList(raw, varOffsets[3], varOffsets[4],
                Deposit.SSZ_SIZE, MAX_DEPOSITS, Deposit::hashTreeRootAt);
        // 7: voluntary_exits
        fieldRoots[7] = SszUtil.hashFixedElementList(raw, varOffsets[4], varOffsets[5],
                SignedVoluntaryExit.SSZ_SIZE, MAX_VOLUNTARY_EXITS, SignedVoluntaryExit::hashTreeRootAt);

        // 8: sync_aggregate (fixed at offset 220)
        fieldRoots[8] = SyncAggregate.hashTreeRootAt(raw, 220);

        // 9: execution_payload
        fieldRoots[9] = executionPayload.hashTreeRoot();

        // 10: bls_to_execution_changes
        fieldRoots[10] = SszUtil.hashFixedElementList(raw, varOffsets[6], blobKzgOffset,
                SignedBLSToExecutionChange.SSZ_SIZE, MAX_BLS_TO_EXECUTION_CHANGES,
                SignedBLSToExecutionChange::hashTreeRootAt);

        // 11: blob_kzg_commitments
        int blobEnd = electra ? varOffsets[7] : raw.length;
        fieldRoots[11] = hashKzgCommitments(raw, blobKzgOffset, blobEnd);

        // 12: execution_requests (Electra only)
        if (electra) {
            fieldRoots[12] = ExecutionRequests.hashTreeRoot(raw, varOffsets[7], raw.length);
        }

        return SszUtil.merkleize(fieldRoots);
    }

    private static byte[] hashKzgCommitments(byte[] body, int start, int end) {
        int len = end - start;
        int count = len / KZG_COMMITMENT_SIZE;
        byte[][] roots = new byte[count][];
        for (int i = 0; i < count; i++) {
            int off = start + i * KZG_COMMITMENT_SIZE;
            roots[i] = SszUtil.hashTreeRootByteVector(
                    Arrays.copyOfRange(body, off, off + KZG_COMMITMENT_SIZE));
        }
        byte[] root = SszUtil.merkleizeSparse(roots, MAX_BLOB_COMMITMENTS);
        return SszUtil.mixInLength(root, count);
    }
}
