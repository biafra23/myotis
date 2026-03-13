package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BeaconBlockParser} that capture current parsing and
 * hash_tree_root behavior so the implementation can be safely rewritten
 * to use a declarative SSZ library.
 *
 * <p>Each test constructs raw SSZ bytes by hand (matching the consensus-spec
 * encoding) and asserts the parser produces the correct field values and roots.
 */
class BeaconBlockParserTest {

    // -----------------------------------------------------------------------
    // Helpers: little-endian writers
    // -----------------------------------------------------------------------

    private static void writeUint32(byte[] buf, int offset, int value) {
        buf[offset]     = (byte) (value);
        buf[offset + 1] = (byte) (value >>> 8);
        buf[offset + 2] = (byte) (value >>> 16);
        buf[offset + 3] = (byte) (value >>> 24);
    }

    private static void writeUint64(byte[] buf, int offset, long value) {
        ByteBuffer.wrap(buf, offset, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(value);
    }

    private static byte[] fillBytes(int length, byte fillValue) {
        byte[] b = new byte[length];
        Arrays.fill(b, fillValue);
        return b;
    }

    private static byte[] hexBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // -----------------------------------------------------------------------
    // Build a minimal Electra-fork SignedBeaconBlock with empty variable lists
    // -----------------------------------------------------------------------

    /**
     * Builds a minimal SSZ-encoded SignedBeaconBlock (Electra fork) where every
     * variable-length list is empty. This lets us test field extraction and root
     * computation without needing real attestations/transactions.
     */
    private static byte[] buildMinimalElectraBlock(
            long slot, long proposerIndex, byte[] parentRoot, byte[] stateRoot,
            byte[] randaoReveal, byte[] eth1DepositRoot, long eth1DepositCount,
            byte[] eth1BlockHash, byte[] graffiti,
            byte[] syncCommitteeBits, byte[] syncCommitteeSig,
            byte[] executionParentHash, byte[] executionFeeRecipient,
            byte[] executionStateRoot, byte[] executionReceiptsRoot,
            byte[] executionLogsBloom, byte[] executionPrevRandao,
            long executionBlockNumber, long executionGasLimit,
            long executionGasUsed, long executionTimestamp,
            byte[] executionExtraData, byte[] executionBaseFeePerGas,
            byte[] executionBlockHash, long executionBlobGasUsed,
            long executionExcessBlobGas
    ) {
        // --- BeaconBlockBody (Electra) ---
        // Fixed part layout (396 bytes):
        //   0:   randao_reveal (96)
        //   96:  eth1_data (72) = deposit_root(32) + deposit_count(8) + block_hash(32)
        //   168: graffiti (32)
        //   200: proposer_slashings offset (4)
        //   204: attester_slashings offset (4)
        //   208: attestations offset (4)
        //   212: deposits offset (4)
        //   216: voluntary_exits offset (4)
        //   220: sync_aggregate (160) = bits(64) + sig(96)
        //   380: execution_payload offset (4)
        //   384: bls_to_execution_changes offset (4)
        //   388: blob_kzg_commitments offset (4)
        //   392: execution_requests offset (4)
        // Total fixed = 396 bytes

        // ExecutionPayload fixed part = 528 bytes (see parser doc)
        // ExecutionPayload variable: extra_data + transactions + withdrawals
        // We use a small extra_data and empty tx/withdrawals lists.

        int bodyFixedSize = 396;

        // All empty variable body lists point to the same offset (= bodyFixedSize)
        // except execution_payload which starts at bodyFixedSize
        // But actually, variable offsets in order come after the fixed area. Since
        // proposer_slashings..voluntary_exits are all empty, their offset = start of
        // execution_payload section. execution_payload is variable too (has its own
        // variable fields). Let's compute carefully:

        // Body variable fields order:
        //   proposer_slashings, attester_slashings, attestations, deposits,
        //   voluntary_exits, execution_payload, bls_to_execution_changes,
        //   blob_kzg_commitments, execution_requests

        // Since empty lists have zero bytes, the first 5 variable fields all point
        // to the start of the variable area = bodyFixedSize.
        // execution_payload offset also = bodyFixedSize (since those 5 are empty).

        // ExecutionPayload SSZ:
        //   Fixed part (528 bytes):
        //     parent_hash(32) fee_recipient(20) state_root(32) receipts_root(32)
        //     logs_bloom(256) prev_randao(32) block_number(8) gas_limit(8) gas_used(8)
        //     timestamp(8) extra_data_offset(4) base_fee_per_gas(32) block_hash(32)
        //     transactions_offset(4) withdrawals_offset(4) blob_gas_used(8) excess_blob_gas(8)
        //   Variable: extra_data, transactions, withdrawals
        int epFixedSize = 528;
        int extraDataLen = executionExtraData.length;
        int epVarSize = extraDataLen; // empty tx and withdrawals = 0 additional bytes
        int epTotalSize = epFixedSize + epVarSize;

        // ExecutionRequests (empty) = 12 bytes (3 offsets pointing to offset 12)
        int erSize = 12;

        // Build body
        int bodyTotalSize = bodyFixedSize + epTotalSize + erSize; // +0 for other empty var lists
        byte[] body = new byte[bodyTotalSize];

        // Fill fixed fields
        System.arraycopy(randaoReveal, 0, body, 0, 96);
        System.arraycopy(eth1DepositRoot, 0, body, 96, 32);
        writeUint64(body, 128, eth1DepositCount);
        System.arraycopy(eth1BlockHash, 0, body, 136, 32);
        System.arraycopy(graffiti, 0, body, 168, 32);

        // Variable field offsets (all empty lists + EP + bls_changes + kzg + requests)
        int epStart = bodyFixedSize; // proposer_slashings..voluntary_exits all empty
        int blsChangesStart = epStart + epTotalSize;
        int kzgStart = blsChangesStart; // bls_to_execution_changes is empty
        int erStart = kzgStart; // blob_kzg_commitments is empty

        writeUint32(body, 200, bodyFixedSize); // proposer_slashings
        writeUint32(body, 204, bodyFixedSize); // attester_slashings
        writeUint32(body, 208, bodyFixedSize); // attestations
        writeUint32(body, 212, bodyFixedSize); // deposits
        writeUint32(body, 216, bodyFixedSize); // voluntary_exits

        // sync_aggregate at 220
        System.arraycopy(syncCommitteeBits, 0, body, 220, 64);
        System.arraycopy(syncCommitteeSig, 0, body, 284, 96);

        writeUint32(body, 380, epStart);          // execution_payload
        writeUint32(body, 384, blsChangesStart);  // bls_to_execution_changes
        writeUint32(body, 388, kzgStart);         // blob_kzg_commitments
        writeUint32(body, 392, erStart);          // execution_requests

        // --- ExecutionPayload at epStart ---
        int ep = epStart;
        System.arraycopy(executionParentHash, 0, body, ep, 32);       ep += 32;
        System.arraycopy(executionFeeRecipient, 0, body, ep, 20);     ep += 20;
        System.arraycopy(executionStateRoot, 0, body, ep, 32);        ep += 32;
        System.arraycopy(executionReceiptsRoot, 0, body, ep, 32);     ep += 32;
        System.arraycopy(executionLogsBloom, 0, body, ep, 256);       ep += 256;
        System.arraycopy(executionPrevRandao, 0, body, ep, 32);       ep += 32;
        writeUint64(body, ep, executionBlockNumber);                   ep += 8;
        writeUint64(body, ep, executionGasLimit);                      ep += 8;
        writeUint64(body, ep, executionGasUsed);                       ep += 8;
        writeUint64(body, ep, executionTimestamp);                     ep += 8;
        // extra_data offset (relative to EP start)
        writeUint32(body, ep, epFixedSize);                            ep += 4;
        System.arraycopy(executionBaseFeePerGas, 0, body, ep, 32);    ep += 32;
        System.arraycopy(executionBlockHash, 0, body, ep, 32);        ep += 32;
        // transactions offset = epFixedSize + extraDataLen (empty tx list follows extra_data)
        writeUint32(body, ep, epFixedSize + extraDataLen);             ep += 4;
        // withdrawals offset = same (empty tx)
        writeUint32(body, ep, epFixedSize + extraDataLen);             ep += 4;
        writeUint64(body, ep, executionBlobGasUsed);                   ep += 8;
        writeUint64(body, ep, executionExcessBlobGas);                 ep += 8;
        // assert ep == epStart + epFixedSize
        // extra_data
        System.arraycopy(executionExtraData, 0, body, ep, extraDataLen);

        // --- ExecutionRequests at erStart (3 offsets, all pointing to 12 = past offsets) ---
        writeUint32(body, erStart, 12);
        writeUint32(body, erStart + 4, 12);
        writeUint32(body, erStart + 8, 12);

        // --- BeaconBlock ---
        // Fixed: slot(8) + proposerIndex(8) + parentRoot(32) + stateRoot(32) + bodyOffset(4) = 84
        int blockFixedSize = 84;
        byte[] block = new byte[blockFixedSize + bodyTotalSize];
        writeUint64(block, 0, slot);
        writeUint64(block, 8, proposerIndex);
        System.arraycopy(parentRoot, 0, block, 16, 32);
        System.arraycopy(stateRoot, 0, block, 48, 32);
        writeUint32(block, 80, blockFixedSize); // body offset
        System.arraycopy(body, 0, block, blockFixedSize, bodyTotalSize);

        // --- SignedBeaconBlock ---
        // Fixed: messageOffset(4) + signature(96) + message...
        int signedFixedSize = 100; // offset(4) + signature(96)
        byte[] signed = new byte[signedFixedSize + block.length];
        writeUint32(signed, 0, signedFixedSize); // message offset
        // signature = 96 bytes of zeros (we don't verify it here)
        System.arraycopy(block, 0, signed, signedFixedSize, block.length);

        return signed;
    }

    // Similarly for Deneb (12-field body, no execution_requests)
    private static byte[] buildMinimalDenebBlock(
            long slot, long proposerIndex, byte[] parentRoot, byte[] stateRoot
    ) {
        // Deneb body has 12 fields. Fixed part = 392 bytes (no execution_requests offset)
        // Offsets at: 200(4), 204(4), 208(4), 212(4), 216(4)
        //             sync_aggregate at 220 (160 bytes)
        //             380: execution_payload offset(4), 384: bls_changes offset(4),
        //             388: kzg offset(4) → total fixed = 392
        int bodyFixedSize = 392;
        int epFixedSize = 528;
        int epTotalSize = epFixedSize; // no extra_data (offset points to end)
        int bodyTotalSize = bodyFixedSize + epTotalSize;
        byte[] body = new byte[bodyTotalSize];

        // randao_reveal (96 zeros)
        // eth1_data (72 zeros)
        // graffiti (32 zeros)

        int epStart = bodyFixedSize;
        int blsStart = epStart + epTotalSize;
        int kzgStart = blsStart;

        writeUint32(body, 200, bodyFixedSize);
        writeUint32(body, 204, bodyFixedSize);
        writeUint32(body, 208, bodyFixedSize);
        writeUint32(body, 212, bodyFixedSize);
        writeUint32(body, 216, bodyFixedSize);
        // sync_aggregate at 220: 160 zeros
        writeUint32(body, 380, epStart);
        writeUint32(body, 384, blsStart);
        writeUint32(body, 388, kzgStart);

        // ExecutionPayload: all zeros except offsets
        int ep = epStart;
        ep += 32 + 20 + 32 + 32 + 256 + 32 + 8 + 8 + 8 + 8; // skip to extra_data offset
        writeUint32(body, ep, epFixedSize); ep += 4; // extra_data → end of EP fixed
        ep += 32 + 32; // base_fee_per_gas + block_hash
        writeUint32(body, ep, epFixedSize); ep += 4; // transactions → end
        writeUint32(body, ep, epFixedSize); ep += 4; // withdrawals → end
        // blob_gas_used + excess_blob_gas remain 0

        // BeaconBlock
        int blockFixedSize = 84;
        byte[] block = new byte[blockFixedSize + bodyTotalSize];
        writeUint64(block, 0, slot);
        writeUint64(block, 8, proposerIndex);
        System.arraycopy(parentRoot, 0, block, 16, 32);
        System.arraycopy(stateRoot, 0, block, 48, 32);
        writeUint32(block, 80, blockFixedSize);
        System.arraycopy(body, 0, block, blockFixedSize, bodyTotalSize);

        // SignedBeaconBlock
        int signedFixedSize = 100;
        byte[] signed = new byte[signedFixedSize + block.length];
        writeUint32(signed, 0, signedFixedSize);
        System.arraycopy(block, 0, signed, signedFixedSize, block.length);
        return signed;
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    @Test
    void parseExtractsSlotAndProposerIndex() {
        long slot = 12345678L;
        long proposerIndex = 42L;
        byte[] parentRoot = fillBytes(32, (byte) 0xAA);
        byte[] stateRoot = fillBytes(32, (byte) 0xBB);

        byte[] ssz = buildMinimalElectraBlock(
                slot, proposerIndex, parentRoot, stateRoot,
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);

        assertEquals(slot, parsed.slot());
        assertEquals(proposerIndex, parsed.proposerIndex());
        assertArrayEquals(parentRoot, parsed.parentRoot());
        assertArrayEquals(stateRoot, parsed.stateRoot());
    }

    @Test
    void parseExtractsExecutionStateRoot() {
        byte[] executionStateRoot = fillBytes(32, (byte) 0xCC);

        byte[] ssz = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], executionStateRoot, new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);
        assertArrayEquals(executionStateRoot, parsed.executionStateRoot());
    }

    @Test
    void blockHeaderRootMatchesManualComputation() {
        long slot = 9999L;
        long proposerIndex = 7L;
        byte[] parentRoot = fillBytes(32, (byte) 0x11);
        byte[] stateRoot = fillBytes(32, (byte) 0x22);

        byte[] ssz = buildMinimalElectraBlock(
                slot, proposerIndex, parentRoot, stateRoot,
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);

        // Independently compute header root: hash_tree_root(slot, proposerIndex, parentRoot, stateRoot, bodyRoot)
        byte[] expectedHeaderRoot = SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootUint64(slot),
                SszUtil.hashTreeRootUint64(proposerIndex),
                SszUtil.hashTreeRootBytes32(parentRoot),
                SszUtil.hashTreeRootBytes32(stateRoot),
                SszUtil.hashTreeRootBytes32(parsed.bodyRoot())
        );

        assertArrayEquals(expectedHeaderRoot, parsed.blockHeaderRoot());
    }

    @Test
    void bodyRootIsNonZero() {
        byte[] ssz = buildMinimalElectraBlock(
                1L, 0L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);
        assertFalse(Arrays.equals(new byte[32], parsed.bodyRoot()),
                "Body root should not be all zeros for a valid block");
    }

    @Test
    void bodyRootIsDeterministic() {
        byte[] ssz1 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );
        byte[] ssz2 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock p1 = BeaconBlockParser.parse(ssz1);
        BeaconBlockParser.ParsedBlock p2 = BeaconBlockParser.parse(ssz2);

        assertArrayEquals(p1.bodyRoot(), p2.bodyRoot());
        assertArrayEquals(p1.blockHeaderRoot(), p2.blockHeaderRoot());
    }

    @Test
    void differentBodyFieldsProduceDifferentBodyRoots() {
        // Block with graffiti = 0x33...
        byte[] graffiti1 = fillBytes(32, (byte) 0x33);
        byte[] ssz1 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], graffiti1,
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        // Block with graffiti = 0x44...
        byte[] graffiti2 = fillBytes(32, (byte) 0x44);
        byte[] ssz2 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], graffiti2,
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock p1 = BeaconBlockParser.parse(ssz1);
        BeaconBlockParser.ParsedBlock p2 = BeaconBlockParser.parse(ssz2);

        assertFalse(Arrays.equals(p1.bodyRoot(), p2.bodyRoot()),
                "Different graffiti should produce different body roots");
    }

    @Test
    void differentExecutionFieldsProduceDifferentBodyRoots() {
        byte[] ssz1 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                1000L, 30000000L, 21000L, 1700000000L,
                new byte[]{0x01, 0x02}, new byte[32], new byte[32], 0, 0
        );

        byte[] ssz2 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                2000L, 30000000L, 21000L, 1700000000L,
                new byte[]{0x01, 0x02}, new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock p1 = BeaconBlockParser.parse(ssz1);
        BeaconBlockParser.ParsedBlock p2 = BeaconBlockParser.parse(ssz2);

        assertFalse(Arrays.equals(p1.bodyRoot(), p2.bodyRoot()),
                "Different block_number should produce different body roots");
    }

    @Test
    void denebForkDetection() {
        // Deneb has firstVarOffset < 396 (body fixed = 392, so first var offset = 392)
        byte[] ssz = buildMinimalDenebBlock(500L, 3L, new byte[32], new byte[32]);
        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);

        assertEquals(500L, parsed.slot());
        assertEquals(3L, parsed.proposerIndex());
        assertNotNull(parsed.bodyRoot());
        assertNotNull(parsed.blockHeaderRoot());
        assertEquals(32, parsed.bodyRoot().length);
        assertEquals(32, parsed.blockHeaderRoot().length);
    }

    @Test
    void electraAndDenebProduceDifferentBodyRoots() {
        // Same header fields, but Electra has an extra field (execution_requests)
        // so the body root computation differs
        byte[] parentRoot = new byte[32];
        byte[] stateRoot = new byte[32];

        byte[] electraSsz = buildMinimalElectraBlock(
                100L, 1L, parentRoot, stateRoot,
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );
        byte[] denebSsz = buildMinimalDenebBlock(100L, 1L, parentRoot, stateRoot);

        BeaconBlockParser.ParsedBlock electra = BeaconBlockParser.parse(electraSsz);
        BeaconBlockParser.ParsedBlock deneb = BeaconBlockParser.parse(denebSsz);

        assertFalse(Arrays.equals(electra.bodyRoot(), deneb.bodyRoot()),
                "Electra (13 fields) and Deneb (12 fields) should produce different body roots");
    }

    @Test
    void parseWithNonZeroExtraData() {
        byte[] extraData = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};

        byte[] ssz = buildMinimalElectraBlock(
                200L, 5L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                fillBytes(32, (byte) 0xDD), new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                42L, 30000000L, 21000L, 1700000000L,
                extraData, new byte[32], new byte[32], 131072L, 131072L
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);
        assertEquals(200L, parsed.slot());
        assertNotNull(parsed.bodyRoot());
    }

    @Test
    void parseRejectsShortInput() {
        assertThrows(IllegalArgumentException.class, () ->
                BeaconBlockParser.parse(new byte[50]));
    }

    @Test
    void parseRejectsInvalidMessageOffset() {
        byte[] ssz = new byte[200];
        // Set message offset to beyond the array
        writeUint32(ssz, 0, 999);
        assertThrows(IllegalArgumentException.class, () ->
                BeaconBlockParser.parse(ssz));
    }

    @Test
    void parseRejectsInvalidBodyOffset() {
        byte[] ssz = new byte[300];
        writeUint32(ssz, 0, 100); // message starts at 100
        // block at offset 100: set body offset to something invalid
        writeUint32(ssz, 180, 999); // body offset at block+80 = 100+80 = 180
        assertThrows(IllegalArgumentException.class, () ->
                BeaconBlockParser.parse(ssz));
    }

    @Test
    void slotZeroIsValid() {
        byte[] ssz = buildMinimalElectraBlock(
                0L, 0L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);
        assertEquals(0L, parsed.slot());
        assertEquals(0L, parsed.proposerIndex());
    }

    @Test
    void largeSlotValue() {
        long largeSlot = 0x7FFFFFFFFFFFFFFFL; // max positive long
        byte[] ssz = buildMinimalElectraBlock(
                largeSlot, 0L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);
        assertEquals(largeSlot, parsed.slot());
    }

    @Test
    void headerRootChangesWhenSlotChanges() {
        byte[] parentRoot = fillBytes(32, (byte) 0x11);
        byte[] stateRoot = fillBytes(32, (byte) 0x22);

        byte[] ssz1 = buildMinimalElectraBlock(
                100L, 1L, parentRoot, stateRoot,
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );
        byte[] ssz2 = buildMinimalElectraBlock(
                101L, 1L, parentRoot, stateRoot,
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock p1 = BeaconBlockParser.parse(ssz1);
        BeaconBlockParser.ParsedBlock p2 = BeaconBlockParser.parse(ssz2);

        // Same body, different slot → same bodyRoot, different headerRoot
        assertArrayEquals(p1.bodyRoot(), p2.bodyRoot());
        assertFalse(Arrays.equals(p1.blockHeaderRoot(), p2.blockHeaderRoot()),
                "Different slots should produce different header roots");
    }

    @Test
    void allRootsAre32Bytes() {
        byte[] ssz = buildMinimalElectraBlock(
                1L, 1L, fillBytes(32, (byte) 0x01), fillBytes(32, (byte) 0x02),
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);
        assertEquals(32, parsed.parentRoot().length);
        assertEquals(32, parsed.stateRoot().length);
        assertEquals(32, parsed.bodyRoot().length);
        assertEquals(32, parsed.executionStateRoot().length);
        assertEquals(32, parsed.blockHeaderRoot().length);
    }

    @Test
    void nonZeroEth1DepositCountAffectsBodyRoot() {
        byte[] ssz1 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        byte[] ssz2 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 999, new byte[32], new byte[32],
                new byte[64], new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock p1 = BeaconBlockParser.parse(ssz1);
        BeaconBlockParser.ParsedBlock p2 = BeaconBlockParser.parse(ssz2);

        assertFalse(Arrays.equals(p1.bodyRoot(), p2.bodyRoot()),
                "Different eth1_deposit_count should produce different body roots");
    }

    @Test
    void syncAggregateBitsAffectBodyRoot() {
        byte[] bits1 = new byte[64];
        bits1[0] = (byte) 0xFF;
        byte[] bits2 = new byte[64];
        bits2[0] = (byte) 0x00;

        byte[] ssz1 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                bits1, new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        byte[] ssz2 = buildMinimalElectraBlock(
                100L, 1L, new byte[32], new byte[32],
                new byte[96], new byte[32], 0, new byte[32], new byte[32],
                bits2, new byte[96],
                new byte[32], new byte[20], new byte[32], new byte[32],
                new byte[256], new byte[32],
                0, 0, 0, 0, new byte[0], new byte[32], new byte[32], 0, 0
        );

        BeaconBlockParser.ParsedBlock p1 = BeaconBlockParser.parse(ssz1);
        BeaconBlockParser.ParsedBlock p2 = BeaconBlockParser.parse(ssz2);

        assertFalse(Arrays.equals(p1.bodyRoot(), p2.bodyRoot()),
                "Different sync_committee_bits should produce different body roots");
    }

    /**
     * Snapshot test: record the exact body root and header root for a known
     * minimal Electra block. Any refactoring that changes these values indicates
     * a behavioral change.
     */
    @Test
    void snapshotMinimalElectraBlock() {
        byte[] ssz = buildMinimalElectraBlock(
                1000L, 42L,
                fillBytes(32, (byte) 0xAA),
                fillBytes(32, (byte) 0xBB),
                fillBytes(96, (byte) 0x01),      // randao
                fillBytes(32, (byte) 0x02),      // eth1 deposit root
                100L,                             // eth1 deposit count
                fillBytes(32, (byte) 0x03),      // eth1 block hash
                fillBytes(32, (byte) 0x04),      // graffiti
                fillBytes(64, (byte) 0xFF),      // sync bits (all 1s)
                fillBytes(96, (byte) 0x05),      // sync sig
                fillBytes(32, (byte) 0x10),      // exec parent hash
                fillBytes(20, (byte) 0x11),      // exec fee recipient
                fillBytes(32, (byte) 0x12),      // exec state root
                fillBytes(32, (byte) 0x13),      // exec receipts root
                fillBytes(256, (byte) 0x14),     // exec logs bloom
                fillBytes(32, (byte) 0x15),      // exec prev randao
                1000000L, 30000000L, 21000L, 1700000000L,
                new byte[]{0x01, 0x02, 0x03},   // exec extra data
                fillBytes(32, (byte) 0x16),      // exec base fee
                fillBytes(32, (byte) 0x17),      // exec block hash
                131072L, 131072L                  // blob gas
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);

        // Record the current roots as snapshot values.
        // If these change, the refactoring broke something.
        String bodyRootHex = toHex(parsed.bodyRoot());
        String headerRootHex = toHex(parsed.blockHeaderRoot());

        // These values were computed by the current (known-good) implementation.
        // A rewrite must produce exactly these same roots for the same input.
        assertNotNull(bodyRootHex);
        assertNotNull(headerRootHex);
        assertEquals(64, bodyRootHex.length(), "Body root should be 32 bytes hex-encoded");
        assertEquals(64, headerRootHex.length(), "Header root should be 32 bytes hex-encoded");

        assertEquals("ca83daf59b79c363cd19046a2e8da3d588ce1706f0f21927c5b856d927256516",
                bodyRootHex, "Body root snapshot mismatch — rewrite changed behavior");
        assertEquals("822ccda45f33e381520b4ef5813c68b35debbc20d9d056d09d562a4a1e121d5d",
                headerRootHex, "Header root snapshot mismatch — rewrite changed behavior");
    }

    /**
     * Snapshot test for a minimal Deneb block.
     */
    @Test
    void snapshotMinimalDenebBlock() {
        byte[] ssz = buildMinimalDenebBlock(
                500L, 3L, fillBytes(32, (byte) 0xCC), fillBytes(32, (byte) 0xDD)
        );

        BeaconBlockParser.ParsedBlock parsed = BeaconBlockParser.parse(ssz);

        String bodyRootHex = toHex(parsed.bodyRoot());
        String headerRootHex = toHex(parsed.blockHeaderRoot());

        assertEquals("bce73ee2c617851846af2b3ea2287e3b686098e18ae508c7271aaa06ab1d06cd",
                bodyRootHex, "Deneb body root snapshot mismatch — rewrite changed behavior");
        assertEquals("a185853eb798d4635ce8cc267cc47ea37ce8d0fcbbcb978cc078ac839f4ea5af",
                headerRootHex, "Deneb header root snapshot mismatch — rewrite changed behavior");
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
