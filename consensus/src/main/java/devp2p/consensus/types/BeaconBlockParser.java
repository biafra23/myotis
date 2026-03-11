package devp2p.consensus.types;

import devp2p.consensus.ssz.SszUtil;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Parses SSZ-encoded {@code SignedBeaconBlock} payloads from the
 * {@code beacon_blocks_by_range/2} P2P protocol and computes each block's
 * header hash ({@code hash_tree_root(BeaconBlockHeader)}).
 *
 * <p>Computing the header hash requires {@code body_root = hash_tree_root(BeaconBlockBody)},
 * which in turn requires hashing every field of the block body — including the
 * full transactions list, attestations, and (for Electra) execution requests.
 *
 * <p>Supports both Deneb (12-field body) and Electra (13-field body) forks.
 */
public final class BeaconBlockParser {

    private BeaconBlockParser() {}

    /** Result of parsing a SignedBeaconBlock. */
    public record ParsedBlock(
            long slot,
            long proposerIndex,
            byte[] parentRoot,
            byte[] stateRoot,
            byte[] bodyRoot,
            byte[] executionStateRoot,
            byte[] blockHeaderRoot
    ) {}

    // =========================================================================
    // Consensus-spec limits (used for merkleize tree depths)
    // =========================================================================

    // BeaconBlockBody list limits
    private static final int MAX_PROPOSER_SLASHINGS       = 16;
    private static final int MAX_ATTESTER_SLASHINGS_ELECTRA = 1;
    private static final int MAX_ATTESTATIONS_ELECTRA      = 8;
    private static final int MAX_DEPOSITS                  = 16;
    private static final int MAX_VOLUNTARY_EXITS           = 16;
    private static final int MAX_BLS_TO_EXECUTION_CHANGES  = 16;
    private static final int MAX_BLOB_COMMITMENTS          = 4096;

    // ExecutionPayload limits
    private static final int MAX_EXTRA_DATA_BYTES        = 32;
    private static final int MAX_TRANSACTIONS_PER_PAYLOAD = 1_048_576;
    private static final int MAX_BYTES_PER_TRANSACTION    = 1_073_741_824;
    private static final int MAX_WITHDRAWALS              = 16;

    // Electra ExecutionRequests limits
    private static final int MAX_DEPOSIT_REQUESTS    = 8192;
    private static final int MAX_WITHDRAWAL_REQUESTS = 16;
    private static final int MAX_CONSOLIDATION_REQUESTS = 2;

    // Fixed sizes of various types
    private static final int PROPOSER_SLASHING_SIZE = 416;   // 2 * SignedBeaconBlockHeader(208)
    private static final int SIGNED_VOLUNTARY_EXIT_SIZE = 112; // VoluntaryExit(16) + BLSSignature(96)
    private static final int SIGNED_BLS_CHANGE_SIZE = 172;    // BLSToExecutionChange(76) + BLSSignature(96)
    private static final int KZG_COMMITMENT_SIZE = 48;
    private static final int WITHDRAWAL_SIZE = 44;            // 8+8+20+8 (index, validatorIdx, address, amount)
    private static final int DEPOSIT_REQUEST_SIZE = 192;      // 48+32+8+96+8
    private static final int WITHDRAWAL_REQUEST_SIZE = 76;    // 20+48+8
    private static final int CONSOLIDATION_REQUEST_SIZE = 116; // 20+48+48

    // =========================================================================
    // Main parse entry point
    // =========================================================================

    /**
     * Parse a SSZ-encoded {@code SignedBeaconBlock} and compute its header hash.
     *
     * @param ssz the full SSZ bytes of the SignedBeaconBlock
     * @return parsed block with slot, roots, and computed header hash
     * @throws IllegalArgumentException if the SSZ is malformed
     */
    public static ParsedBlock parse(byte[] ssz) {
        // SignedBeaconBlock: [message_offset(4)] [signature(96)] [message...]
        if (ssz.length < 100) throw new IllegalArgumentException("SignedBeaconBlock too short: " + ssz.length);
        int messageOffset = readUint32(ssz, 0);
        if (messageOffset < 100 || messageOffset > ssz.length) {
            throw new IllegalArgumentException("Invalid message offset: " + messageOffset);
        }
        byte[] blockBytes = Arrays.copyOfRange(ssz, messageOffset, ssz.length);

        // BeaconBlock: [slot(8)] [proposer_index(8)] [parent_root(32)] [state_root(32)] [body_offset(4)]
        if (blockBytes.length < 84) throw new IllegalArgumentException("BeaconBlock too short: " + blockBytes.length);
        long slot = readUint64(blockBytes, 0);
        long proposerIndex = readUint64(blockBytes, 8);
        byte[] parentRoot = Arrays.copyOfRange(blockBytes, 16, 48);
        byte[] stateRoot = Arrays.copyOfRange(blockBytes, 48, 80);
        int bodyOffset = readUint32(blockBytes, 80);
        if (bodyOffset < 84 || bodyOffset > blockBytes.length) {
            throw new IllegalArgumentException("Invalid body offset: " + bodyOffset);
        }

        byte[] bodyBytes = Arrays.copyOfRange(blockBytes, bodyOffset, blockBytes.length);

        // Determine fork from body fixed part size
        int firstVarOffset = readUint32(bodyBytes, 200); // proposer_slashings offset
        boolean electra = firstVarOffset >= 396;

        byte[] bodyRoot = computeBodyRoot(bodyBytes, electra);
        byte[] executionStateRoot = extractExecutionStateRoot(bodyBytes, electra);

        // BeaconBlockHeader = hash_tree_root(slot, proposerIndex, parentRoot, stateRoot, bodyRoot)
        byte[] blockHeaderRoot = SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(slot),
                SszUtil.hashTreeRootUint64(proposerIndex),
                SszUtil.hashTreeRootBytes32(parentRoot),
                SszUtil.hashTreeRootBytes32(stateRoot),
                SszUtil.hashTreeRootBytes32(bodyRoot)
        );

        return new ParsedBlock(slot, proposerIndex, parentRoot, stateRoot,
                bodyRoot, executionStateRoot, blockHeaderRoot);
    }

    // =========================================================================
    // Body root: hash_tree_root(BeaconBlockBody)
    // =========================================================================

    private static byte[] computeBodyRoot(byte[] b, boolean electra) {
        int fieldCount = electra ? 13 : 12;
        byte[][] fieldRoots = new byte[fieldCount][];

        // --- Fixed fields ---
        // 0: randao_reveal (Bytes96, offset 0)
        fieldRoots[0] = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(b, 0, 96));
        // 1: eth1_data (Eth1Data container, offset 96, 72 bytes)
        fieldRoots[1] = hashEth1Data(b, 96);
        // 2: graffiti (Bytes32, offset 168)
        fieldRoots[2] = SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(b, 168, 200));
        // 9: sync_aggregate (SyncAggregate, offset 220, 160 bytes)
        // (computed here because it's at a fixed position before the variable offsets)

        // --- Variable field offsets (each 4 bytes) ---
        // offsets at: 200, 204, 208, 212, 216 (before sync_aggregate gap)
        // sync_aggregate at 220-380
        // offsets at: 380, 384, 388 [, 392 for Electra]
        int[] varOffsets = new int[electra ? 8 : 7];
        varOffsets[0] = readUint32(b, 200); // proposer_slashings
        varOffsets[1] = readUint32(b, 204); // attester_slashings
        varOffsets[2] = readUint32(b, 208); // attestations
        varOffsets[3] = readUint32(b, 212); // deposits
        varOffsets[4] = readUint32(b, 216); // voluntary_exits
        varOffsets[5] = readUint32(b, 380); // execution_payload
        varOffsets[6] = readUint32(b, 384); // bls_to_execution_changes
        if (electra) {
            varOffsets[7] = readUint32(b, 392); // execution_requests
        }
        int blobKzgOffset = readUint32(b, 388); // blob_kzg_commitments

        // Build end-offset array for slicing: each field ends where the next begins
        // Variable fields in body order: proposer_slashings(3), attester_slashings(4),
        // attestations(5), deposits(6), voluntary_exits(7), execution_payload(9),
        // bls_to_execution_changes(10), blob_kzg_commitments(11) [, execution_requests(12)]
        // Their offsets in varOffsets: 0..7, blobKzg is separate

        // 3: proposer_slashings
        fieldRoots[3] = hashFixedElementList(b, varOffsets[0], varOffsets[1],
                PROPOSER_SLASHING_SIZE, MAX_PROPOSER_SLASHINGS, BeaconBlockParser::hashProposerSlashing);
        // 4: attester_slashings
        fieldRoots[4] = hashVariableElementList(b, varOffsets[1], varOffsets[2],
                electra ? MAX_ATTESTER_SLASHINGS_ELECTRA : 2, BeaconBlockParser::hashAttesterSlashing);
        // 5: attestations
        fieldRoots[5] = hashVariableElementList(b, varOffsets[2], varOffsets[3],
                electra ? MAX_ATTESTATIONS_ELECTRA : 128, BeaconBlockParser::hashAttestation);
        // 6: deposits
        fieldRoots[6] = hashFixedElementList(b, varOffsets[3], varOffsets[4],
                1240, MAX_DEPOSITS, BeaconBlockParser::hashDeposit); // Deposit = 1056 + 184
        // 7: voluntary_exits
        fieldRoots[7] = hashFixedElementList(b, varOffsets[4], varOffsets[5],
                SIGNED_VOLUNTARY_EXIT_SIZE, MAX_VOLUNTARY_EXITS, BeaconBlockParser::hashSignedVoluntaryExit);

        // 8: sync_aggregate (fixed at offset 220, 160 bytes)
        fieldRoots[8] = hashSyncAggregate(b, 220);

        // 9: execution_payload
        fieldRoots[9] = hashExecutionPayload(b, varOffsets[5], varOffsets[6]);

        // 10: bls_to_execution_changes
        fieldRoots[10] = hashFixedElementList(b, varOffsets[6], blobKzgOffset,
                SIGNED_BLS_CHANGE_SIZE, MAX_BLS_TO_EXECUTION_CHANGES, BeaconBlockParser::hashSignedBLSChange);

        // 11: blob_kzg_commitments
        int blobEnd = electra ? varOffsets[7] : b.length;
        fieldRoots[11] = hashKzgCommitments(b, blobKzgOffset, blobEnd);

        // 12: execution_requests (Electra only)
        if (electra) {
            fieldRoots[12] = hashExecutionRequests(b, varOffsets[7], b.length);
        }

        return SszUtil.merkleize(fieldRoots);
    }

    // =========================================================================
    // Execution state root extraction (without full body parse)
    // =========================================================================

    private static byte[] extractExecutionStateRoot(byte[] body, boolean electra) {
        int epOffset = readUint32(body, 380); // execution_payload offset
        // ExecutionPayload fixed layout: parent_hash(32) + fee_recipient(20) + state_root(32)
        int stateRootStart = epOffset + 32 + 20;
        return Arrays.copyOfRange(body, stateRootStart, stateRootStart + 32);
    }

    // =========================================================================
    // Individual type hashers
    // =========================================================================

    /** Eth1Data: deposit_root(32) + deposit_count(8) + block_hash(32) = 72 bytes */
    private static byte[] hashEth1Data(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off, off + 32)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 32)),
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off + 40, off + 72))
        );
    }

    /** SyncAggregate: sync_committee_bits(Bitvector[512]=64B) + signature(Bytes96) */
    private static byte[] hashSyncAggregate(byte[] data, int off) {
        // Bitvector[512] = 64 bytes → 2 chunks
        byte[][] bitChunks = {
                Arrays.copyOfRange(data, off, off + 32),
                Arrays.copyOfRange(data, off + 32, off + 64)
        };
        byte[] bitsRoot = SszUtil.merkleize(bitChunks);
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 64, off + 160));
        return SszUtil.hashTreeRootContainer(bitsRoot, sigRoot);
    }

    /** ProposerSlashing: signed_header_1 + signed_header_2 (each 208 bytes) */
    private static byte[] hashProposerSlashing(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                hashSignedBeaconBlockHeader(data, off),
                hashSignedBeaconBlockHeader(data, off + 208)
        );
    }

    /** SignedBeaconBlockHeader: message(BeaconBlockHeader=112B) + signature(96B) */
    private static byte[] hashSignedBeaconBlockHeader(byte[] data, int off) {
        byte[] headerRoot = hashBeaconBlockHeaderAt(data, off);
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 112, off + 208));
        return SszUtil.hashTreeRootContainer(headerRoot, sigRoot);
    }

    /** BeaconBlockHeader at offset: slot(8) + proposer(8) + parent(32) + state(32) + body(32) */
    private static byte[] hashBeaconBlockHeaderAt(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(readUint64(data, off)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 8)),
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off + 16, off + 48)),
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off + 48, off + 80)),
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off + 80, off + 112))
        );
    }

    /** SignedVoluntaryExit: VoluntaryExit(epoch[8]+validator[8]) + sig(96) = 112 bytes */
    private static byte[] hashSignedVoluntaryExit(byte[] data, int off) {
        byte[] exitRoot = SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(readUint64(data, off)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 8))
        );
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 16, off + 112));
        return SszUtil.hashTreeRootContainer(exitRoot, sigRoot);
    }

    /** SignedBLSToExecutionChange: message(76B) + sig(96B) = 172 bytes */
    private static byte[] hashSignedBLSChange(byte[] data, int off) {
        // BLSToExecutionChange: validator_index(8) + from_bls_pubkey(48) + to_address(20)
        byte[] msgRoot = SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(readUint64(data, off)),
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 8, off + 56)),
                SszUtil.hashTreeRootBytes20(Arrays.copyOfRange(data, off + 56, off + 76))
        );
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 76, off + 172));
        return SszUtil.hashTreeRootContainer(msgRoot, sigRoot);
    }

    /**
     * Deposit: proof(Vector[Bytes32, 33]=1056B) + data(DepositData=184B) = 1240 bytes.
     * DepositData: pubkey(48) + withdrawal_creds(32) + amount(8) + sig(96)
     */
    private static byte[] hashDeposit(byte[] data, int off) {
        // proof: Vector[Bytes32, 33] — 33 chunks, merkleize with next_pow2(33)=64
        byte[][] proofChunks = new byte[33][];
        for (int i = 0; i < 33; i++) {
            proofChunks[i] = Arrays.copyOfRange(data, off + i * 32, off + i * 32 + 32);
        }
        byte[] proofRoot = SszUtil.merkleize(proofChunks);

        int dOff = off + 1056;
        byte[] dataRoot = SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, dOff, dOff + 48)),
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, dOff + 48, dOff + 80)),
                SszUtil.hashTreeRootUint64(readUint64(data, dOff + 80)),
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, dOff + 88, dOff + 184))
        );
        return SszUtil.hashTreeRootContainer(proofRoot, dataRoot);
    }

    // =========================================================================
    // Attestation / AttesterSlashing (variable-length, most complex types)
    // =========================================================================

    /**
     * Attestation (Electra): aggregation_bits(Bitlist) + data(128B) + sig(96B) + committee_bits(Bitvector[64]=8B)
     * SSZ fixed: offset(4) + data(128) + sig(96) + committee_bits(8) = 236
     */
    private static byte[] hashAttestation(byte[] data, int off, int end) {
        int aggBitsOffset = readUint32(data, off); // relative to container start
        int absAggBits = off + aggBitsOffset;
        byte[] aggBitsBytes = Arrays.copyOfRange(data, absAggBits, end);

        byte[] aggBitsRoot = hashBitlist(aggBitsBytes, 131072); // MAX_VALIDATORS * MAX_COMMITTEES

        byte[] dataRoot = hashAttestationData(data, off + 4);
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 132, off + 228));

        // committee_bits: Bitvector[64] = 8 bytes → 1 chunk (padded to 32)
        byte[] committeeBitsChunk = new byte[32];
        System.arraycopy(data, off + 228, committeeBitsChunk, 0, 8);

        return SszUtil.hashTreeRootContainer(aggBitsRoot, dataRoot, sigRoot, committeeBitsChunk);
    }

    /**
     * AttestationData: slot(8) + index(8) + beacon_block_root(32) + source(Checkpoint=40) + target(Checkpoint=40) = 128B
     */
    private static byte[] hashAttestationData(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(readUint64(data, off)),       // slot
                SszUtil.hashTreeRootUint64(readUint64(data, off + 8)),   // index
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off + 16, off + 48)), // beacon_block_root
                hashCheckpoint(data, off + 48),                           // source
                hashCheckpoint(data, off + 88)                            // target
        );
    }

    /** Checkpoint: epoch(8) + root(32) = 40 bytes */
    private static byte[] hashCheckpoint(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(readUint64(data, off)),
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off + 8, off + 40))
        );
    }

    /**
     * AttesterSlashing: attestation_1 + attestation_2 (both IndexedAttestation, variable).
     * IndexedAttestation SSZ fixed: offset(4) + data(128) + sig(96) = 228B
     */
    private static byte[] hashAttesterSlashing(byte[] data, int off, int end) {
        // SSZ container with 2 variable fields → 2 offsets
        int att1Off = off + readUint32(data, off);
        int att2Off = off + readUint32(data, off + 4);
        return SszUtil.hashTreeRootContainer(
                hashIndexedAttestation(data, att1Off, att2Off),
                hashIndexedAttestation(data, att2Off, end)
        );
    }

    /**
     * IndexedAttestation: attesting_indices(List[uint64, 131072]) + data(128B) + sig(96B)
     * SSZ fixed: indices_offset(4) + data(128) + sig(96) = 228B
     */
    private static byte[] hashIndexedAttestation(byte[] data, int off, int end) {
        int indicesOffset = readUint32(data, off);
        int absIndices = off + indicesOffset;
        byte[] indicesBytes = Arrays.copyOfRange(data, absIndices, end);

        byte[] indicesRoot = hashUint64List(indicesBytes, 131072);
        byte[] dataRoot = hashAttestationData(data, off + 4);
        byte[] sigRoot = SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 132, off + 228));

        return SszUtil.hashTreeRootContainer(indicesRoot, dataRoot, sigRoot);
    }

    // =========================================================================
    // ExecutionPayload (17 fields for Deneb/Electra)
    // =========================================================================

    /**
     * Hash the execution payload from body bytes.
     *
     * <p>ExecutionPayload fixed layout (528 bytes):
     * parent_hash(32) fee_recipient(20) state_root(32) receipts_root(32) logs_bloom(256)
     * prev_randao(32) block_number(8) gas_limit(8) gas_used(8) timestamp(8)
     * extra_data_offset(4) base_fee_per_gas(32) block_hash(32)
     * transactions_offset(4) withdrawals_offset(4) blob_gas_used(8) excess_blob_gas(8)
     */
    private static byte[] hashExecutionPayload(byte[] body, int start, int end) {
        byte[] ep = Arrays.copyOfRange(body, start, end);
        byte[][] fr = new byte[17][];

        int p = 0;
        fr[0]  = SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(ep, p, p + 32)); p += 32; // parent_hash
        fr[1]  = SszUtil.hashTreeRootBytes20(Arrays.copyOfRange(ep, p, p + 20)); p += 20; // fee_recipient
        fr[2]  = SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(ep, p, p + 32)); p += 32; // state_root
        fr[3]  = SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(ep, p, p + 32)); p += 32; // receipts_root
        fr[4]  = SszUtil.hashTreeRootBytes256(Arrays.copyOfRange(ep, p, p + 256)); p += 256; // logs_bloom
        fr[5]  = SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(ep, p, p + 32)); p += 32; // prev_randao
        fr[6]  = SszUtil.hashTreeRootUint64(readUint64(ep, p)); p += 8;  // block_number
        fr[7]  = SszUtil.hashTreeRootUint64(readUint64(ep, p)); p += 8;  // gas_limit
        fr[8]  = SszUtil.hashTreeRootUint64(readUint64(ep, p)); p += 8;  // gas_used
        fr[9]  = SszUtil.hashTreeRootUint64(readUint64(ep, p)); p += 8;  // timestamp
        int extraDataOffset = readUint32(ep, p); p += 4;                  // extra_data offset
        fr[11] = SszUtil.hashTreeRootUint256(Arrays.copyOfRange(ep, p, p + 32)); p += 32; // base_fee_per_gas
        fr[12] = SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(ep, p, p + 32)); p += 32; // block_hash
        int txOffset = readUint32(ep, p); p += 4;                         // transactions offset
        int wdOffset = readUint32(ep, p); p += 4;                         // withdrawals offset
        fr[15] = SszUtil.hashTreeRootUint64(readUint64(ep, p)); p += 8;  // blob_gas_used
        fr[16] = SszUtil.hashTreeRootUint64(readUint64(ep, p));           // excess_blob_gas

        // Variable fields
        // 10: extra_data (ByteList[32])
        byte[] extraData = Arrays.copyOfRange(ep, extraDataOffset, txOffset);
        fr[10] = SszUtil.hashTreeRootByteList(extraData, (MAX_EXTRA_DATA_BYTES + 31) / 32);

        // 13: transactions (List[Transaction, 1048576] — each Transaction is ByteList)
        fr[13] = hashTransactionList(ep, txOffset, wdOffset);

        // 14: withdrawals (List[Withdrawal, 16])
        fr[14] = hashWithdrawalList(ep, wdOffset, ep.length);

        return SszUtil.merkleize(fr);
    }

    /**
     * Hash transactions list: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].
     * Each transaction is a variable-length ByteList. SSZ encoding uses offsets.
     */
    private static byte[] hashTransactionList(byte[] ep, int start, int end) {
        int len = end - start;
        if (len == 0) {
            // Empty list
            byte[] emptyRoot = SszUtil.merkleizeSparse(new byte[0][], MAX_TRANSACTIONS_PER_PAYLOAD);
            return SszUtil.mixInLength(emptyRoot, 0);
        }

        // Read offsets to determine transaction boundaries
        // First offset value / 4 = number of transactions
        int firstOffset = readUint32(ep, start);
        int txCount = firstOffset / 4;

        int[] offsets = new int[txCount];
        for (int i = 0; i < txCount; i++) {
            offsets[i] = readUint32(ep, start + i * 4);
        }

        // Hash each transaction as ByteList[MAX_BYTES_PER_TRANSACTION]
        int chunkLimit = (MAX_BYTES_PER_TRANSACTION + 31) / 32;
        byte[][] txRoots = new byte[txCount][];
        for (int i = 0; i < txCount; i++) {
            int txStart = start + offsets[i];
            int txEnd = (i + 1 < txCount) ? start + offsets[i + 1] : end;
            byte[] txBytes = Arrays.copyOfRange(ep, txStart, txEnd);
            txRoots[i] = SszUtil.hashTreeRootByteList(txBytes, chunkLimit);
        }

        byte[] root = SszUtil.merkleizeSparse(txRoots, MAX_TRANSACTIONS_PER_PAYLOAD);
        return SszUtil.mixInLength(root, txCount);
    }

    /**
     * Withdrawal: index(8) + validator_index(8) + address(20) + amount(8) = 44 bytes.
     */
    private static byte[] hashWithdrawalList(byte[] ep, int start, int end) {
        return hashFixedElementList(ep, start, end,
                WITHDRAWAL_SIZE, MAX_WITHDRAWALS, BeaconBlockParser::hashWithdrawal);
    }

    private static byte[] hashWithdrawal(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(readUint64(data, off)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 8)),
                SszUtil.hashTreeRootBytes20(Arrays.copyOfRange(data, off + 16, off + 36)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 36))
        );
    }

    // =========================================================================
    // KZG commitments
    // =========================================================================

    /** List[KZGCommitment, 4096] where KZGCommitment = Bytes48 */
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

    // =========================================================================
    // Electra: ExecutionRequests
    // =========================================================================

    /**
     * ExecutionRequests container: deposits(List) + withdrawals(List) + consolidations(List).
     * SSZ fixed part: 3 offsets = 12 bytes.
     */
    private static byte[] hashExecutionRequests(byte[] body, int start, int end) {
        byte[] er = Arrays.copyOfRange(body, start, end);
        if (er.length < 12) {
            // Empty or malformed — return hash of empty container
            return SszUtil.hashTreeRootContainer(
                    emptyListRoot(MAX_DEPOSIT_REQUESTS),
                    emptyListRoot(MAX_WITHDRAWAL_REQUESTS),
                    emptyListRoot(MAX_CONSOLIDATION_REQUESTS)
            );
        }
        int depOff = readUint32(er, 0);
        int wdOff = readUint32(er, 4);
        int conOff = readUint32(er, 8);

        byte[] depRoot = hashFixedElementList(er, depOff, wdOff,
                DEPOSIT_REQUEST_SIZE, MAX_DEPOSIT_REQUESTS, BeaconBlockParser::hashDepositRequest);
        byte[] wdRoot = hashFixedElementList(er, wdOff, conOff,
                WITHDRAWAL_REQUEST_SIZE, MAX_WITHDRAWAL_REQUESTS, BeaconBlockParser::hashWithdrawalRequest);
        byte[] conRoot = hashFixedElementList(er, conOff, er.length,
                CONSOLIDATION_REQUEST_SIZE, MAX_CONSOLIDATION_REQUESTS, BeaconBlockParser::hashConsolidationRequest);

        return SszUtil.hashTreeRootContainer(depRoot, wdRoot, conRoot);
    }

    /** DepositRequest: pubkey(48) + withdrawal_creds(32) + amount(8) + sig(96) + index(8) = 192B */
    private static byte[] hashDepositRequest(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off, off + 48)),
                SszUtil.hashTreeRootBytes32(Arrays.copyOfRange(data, off + 48, off + 80)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 80)),
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 88, off + 184)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 184))
        );
    }

    /** WithdrawalRequest: source_address(20) + validator_pubkey(48) + amount(8) = 76B */
    private static byte[] hashWithdrawalRequest(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes20(Arrays.copyOfRange(data, off, off + 20)),
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 20, off + 68)),
                SszUtil.hashTreeRootUint64(readUint64(data, off + 68))
        );
    }

    /** ConsolidationRequest: source_address(20) + source_pubkey(48) + target_pubkey(48) = 116B */
    private static byte[] hashConsolidationRequest(byte[] data, int off) {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes20(Arrays.copyOfRange(data, off, off + 20)),
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 20, off + 68)),
                SszUtil.hashTreeRootByteVector(Arrays.copyOfRange(data, off + 68, off + 116))
        );
    }

    // =========================================================================
    // Generic list hashers
    // =========================================================================

    @FunctionalInterface
    private interface FixedElementHasher {
        byte[] hash(byte[] data, int offset);
    }

    @FunctionalInterface
    private interface VariableElementHasher {
        byte[] hash(byte[] data, int offset, int end);
    }

    /**
     * Hash a list of fixed-size composite elements.
     * hash_tree_root(List[T, limit]) = mixInLength(merkleize(element_roots, limit), count)
     */
    private static byte[] hashFixedElementList(byte[] data, int start, int end,
                                                int elementSize, int limit,
                                                FixedElementHasher hasher) {
        int len = end - start;
        int count = elementSize > 0 ? len / elementSize : 0;
        byte[][] roots = new byte[count][];
        for (int i = 0; i < count; i++) {
            roots[i] = hasher.hash(data, start + i * elementSize);
        }
        byte[] root = limit > 256
                ? SszUtil.merkleizeSparse(roots, limit)
                : SszUtil.merkleize(roots, limit);
        return SszUtil.mixInLength(root, count);
    }

    /**
     * Hash a list of variable-size composite elements (uses SSZ offsets).
     */
    private static byte[] hashVariableElementList(byte[] data, int start, int end,
                                                   int limit, VariableElementHasher hasher) {
        int len = end - start;
        if (len == 0) return SszUtil.mixInLength(emptyListRoot(limit), 0);

        // First offset / 4 = number of elements
        int firstOffset = readUint32(data, start);
        int count = firstOffset / 4;
        if (count == 0) return SszUtil.mixInLength(emptyListRoot(limit), 0);

        int[] offsets = new int[count];
        for (int i = 0; i < count; i++) {
            offsets[i] = readUint32(data, start + i * 4);
        }

        byte[][] roots = new byte[count][];
        for (int i = 0; i < count; i++) {
            int elemStart = start + offsets[i];
            int elemEnd = (i + 1 < count) ? start + offsets[i + 1] : end;
            roots[i] = hasher.hash(data, elemStart, elemEnd);
        }

        byte[] root = limit > 256
                ? SszUtil.merkleizeSparse(roots, limit)
                : SszUtil.merkleize(roots, limit);
        return SszUtil.mixInLength(root, count);
    }

    // =========================================================================
    // Bitlist hashing
    // =========================================================================

    /**
     * hash_tree_root of a Bitlist[N]: remove delimiter bit, pack into chunks,
     * merkleize with limit, mix in length.
     */
    private static byte[] hashBitlist(byte[] serialized, int maxBits) {
        if (serialized.length == 0) {
            int chunkLimit = (maxBits + 255) / 256;
            return SszUtil.mixInLength(emptyListRoot(chunkLimit), 0);
        }
        // Find delimiter bit (highest set bit in last byte)
        byte lastByte = serialized[serialized.length - 1];
        int delimPos = 7;
        while (delimPos >= 0 && ((lastByte >> delimPos) & 1) == 0) delimPos--;
        int bitLength = (serialized.length - 1) * 8 + delimPos;

        // Copy bytes and clear delimiter bit
        byte[] bits = Arrays.copyOf(serialized, serialized.length);
        bits[bits.length - 1] = (byte) (bits[bits.length - 1] & ~(1 << delimPos));
        // Remove trailing zero bytes beyond what's needed
        int neededBytes = (bitLength + 7) / 8;

        // Pack into 32-byte chunks
        int numChunks = Math.max(1, (neededBytes + 31) / 32);
        byte[][] chunks = new byte[numChunks][];
        for (int i = 0; i < numChunks; i++) {
            chunks[i] = new byte[32];
            int copyStart = i * 32;
            int copyLen = Math.min(32, Math.min(bits.length - copyStart, neededBytes - copyStart));
            if (copyLen > 0) System.arraycopy(bits, copyStart, chunks[i], 0, copyLen);
        }

        int chunkLimit = (maxBits + 255) / 256;
        byte[] root = chunkLimit > 256
                ? SszUtil.merkleizeSparse(chunks, chunkLimit)
                : SszUtil.merkleize(chunks, chunkLimit);
        return SszUtil.mixInLength(root, bitLength);
    }

    /**
     * hash_tree_root of a List[uint64, limit]: pack uint64s into 32-byte chunks (4 per chunk).
     */
    private static byte[] hashUint64List(byte[] data, int limit) {
        int count = data.length / 8;
        int numChunks = (count + 3) / 4;
        byte[][] chunks = new byte[numChunks][];
        for (int i = 0; i < numChunks; i++) {
            chunks[i] = new byte[32];
            int base = i * 4;
            for (int j = 0; j < 4 && base + j < count; j++) {
                System.arraycopy(data, (base + j) * 8, chunks[i], j * 8, 8);
            }
        }
        // chunk_count for List[uint64, N] = ceil(N * 8 / 32) = ceil(N / 4)
        int chunkLimit = (limit + 3) / 4;
        byte[] root = chunkLimit > 256
                ? SszUtil.merkleizeSparse(chunks, chunkLimit)
                : SszUtil.merkleize(chunks, chunkLimit);
        return SszUtil.mixInLength(root, count);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static byte[] emptyListRoot(int limit) {
        if (limit <= 0) return SszUtil.ZERO_HASHES[0];
        int depth = 0;
        int n = 1;
        while (n < limit) { n <<= 1; depth++; }
        return SszUtil.ZERO_HASHES[depth];
    }

    private static int readUint32(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    private static long readUint64(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }
}
