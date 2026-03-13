package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: ExecutionPayloadHeader (Electra/Deneb variant, 22 fields).
 *
 * Fixed-part field offsets:
 *   0:   parentHash         (32B)
 *  32:   feeRecipient       (20B)
 *  52:   stateRoot          (32B)
 *  84:   receiptsRoot       (32B)
 * 116:   logsBloom          (256B)
 * 372:   prevRandao         (32B)
 * 404:   blockNumber        (8B, uint64)
 * 412:   gasLimit           (8B, uint64)
 * 420:   gasUsed            (8B, uint64)
 * 428:   timestamp          (8B, uint64)
 * 436:   extraData offset   (4B, uint32 LE) — variable length
 * 440:   baseFeePerGas      (32B, uint256 LE)
 * 472:   blockHash          (32B)
 * 504:   transactionsRoot   (32B)
 * 536:   withdrawalsRoot    (32B)
 * 568:   blobGasUsed        (8B, uint64)
 * 576:   excessBlobGas      (8B, uint64)
 * 584:   depositRequestsRoot    (32B) — Electra
 * 616:   withdrawalRequestsRoot (32B) — Electra
 * 648:   consolidationRequestsRoot (32B) — Electra
 * Total fixed: 680 bytes (before variable extraData)
 */
public final class ExecutionPayloadHeader {

    // Field index 0
    private final byte[] parentHash;         // 32 bytes
    // Field index 1
    private final byte[] feeRecipient;       // 20 bytes
    // Field index 2
    private final byte[] stateRoot;          // 32 bytes
    // Field index 3
    private final byte[] receiptsRoot;       // 32 bytes
    // Field index 4
    private final byte[] logsBloom;          // 256 bytes
    // Field index 5
    private final byte[] prevRandao;         // 32 bytes
    // Field index 6
    private final long blockNumber;
    // Field index 7
    private final long gasLimit;
    // Field index 8
    private final long gasUsed;
    // Field index 9
    private final long timestamp;
    // Field index 10 — variable length
    private final byte[] extraData;
    // Field index 11
    private final byte[] baseFeePerGas;      // 32 bytes (uint256 LE)
    // Field index 12
    private final byte[] blockHash;          // 32 bytes
    // Field index 13
    private final byte[] transactionsRoot;   // 32 bytes
    // Field index 14
    private final byte[] withdrawalsRoot;    // 32 bytes
    // Field index 15
    private final long blobGasUsed;
    // Field index 16
    private final long excessBlobGas;
    // Field index 17 — Electra
    private final byte[] depositRequestsRoot;        // 32 bytes
    // Field index 18 — Electra
    private final byte[] withdrawalRequestsRoot;     // 32 bytes
    // Field index 19 — Electra
    private final byte[] consolidationRequestsRoot;  // 32 bytes

    // Minimum fixed part size (with one 4B offset for extraData)
    public static final int ELECTRA_FIXED_SIZE = 680;
    public static final int DENEB_FIXED_SIZE = 584; // no request roots
    public static final int FIXED_SIZE = DENEB_FIXED_SIZE; // minimum required

    public ExecutionPayloadHeader(
            byte[] parentHash,
            byte[] feeRecipient,
            byte[] stateRoot,
            byte[] receiptsRoot,
            byte[] logsBloom,
            byte[] prevRandao,
            long blockNumber,
            long gasLimit,
            long gasUsed,
            long timestamp,
            byte[] extraData,
            byte[] baseFeePerGas,
            byte[] blockHash,
            byte[] transactionsRoot,
            byte[] withdrawalsRoot,
            long blobGasUsed,
            long excessBlobGas,
            byte[] depositRequestsRoot,
            byte[] withdrawalRequestsRoot,
            byte[] consolidationRequestsRoot
    ) {
        this.parentHash = parentHash;
        this.feeRecipient = feeRecipient;
        this.stateRoot = stateRoot;
        this.receiptsRoot = receiptsRoot;
        this.logsBloom = logsBloom;
        this.prevRandao = prevRandao;
        this.blockNumber = blockNumber;
        this.gasLimit = gasLimit;
        this.gasUsed = gasUsed;
        this.timestamp = timestamp;
        this.extraData = extraData;
        this.baseFeePerGas = baseFeePerGas;
        this.blockHash = blockHash;
        this.transactionsRoot = transactionsRoot;
        this.withdrawalsRoot = withdrawalsRoot;
        this.blobGasUsed = blobGasUsed;
        this.excessBlobGas = excessBlobGas;
        this.depositRequestsRoot = depositRequestsRoot;
        this.withdrawalRequestsRoot = withdrawalRequestsRoot;
        this.consolidationRequestsRoot = consolidationRequestsRoot;
    }

    /**
     * Decode from SSZ bytes.
     * The fixed part is 680 bytes (including 4-byte offset for extraData).
     * extraData starts at the offset stored at position 436.
     */
    public static ExecutionPayloadHeader decode(byte[] ssz) {
        if (ssz.length < FIXED_SIZE) {
            throw new IllegalArgumentException(
                    "ExecutionPayloadHeader requires at least " + FIXED_SIZE + " bytes, got " + ssz.length);
        }
        ByteBuffer buf = ByteBuffer.wrap(ssz).order(ByteOrder.LITTLE_ENDIAN);

        byte[] parentHash = new byte[32];
        buf.get(parentHash);                                    // offset 0

        byte[] feeRecipient = new byte[20];
        buf.get(feeRecipient);                                  // offset 32

        byte[] stateRoot = new byte[32];
        buf.get(stateRoot);                                     // offset 52

        byte[] receiptsRoot = new byte[32];
        buf.get(receiptsRoot);                                  // offset 84

        byte[] logsBloom = new byte[256];
        buf.get(logsBloom);                                     // offset 116

        byte[] prevRandao = new byte[32];
        buf.get(prevRandao);                                    // offset 372

        long blockNumber = buf.getLong();                       // offset 404
        long gasLimit = buf.getLong();                          // offset 412
        long gasUsed = buf.getLong();                           // offset 420
        long timestamp = buf.getLong();                         // offset 428

        int extraDataOffset = buf.getInt();                     // offset 436

        byte[] baseFeePerGas = new byte[32];
        buf.get(baseFeePerGas);                                 // offset 440

        byte[] blockHash = new byte[32];
        buf.get(blockHash);                                     // offset 472

        byte[] transactionsRoot = new byte[32];
        buf.get(transactionsRoot);                              // offset 504

        byte[] withdrawalsRoot = new byte[32];
        buf.get(withdrawalsRoot);                               // offset 536

        long blobGasUsed = buf.getLong();                       // offset 568
        long excessBlobGas = buf.getLong();                     // offset 576

        // Detect Deneb vs Electra: extraDataOffset tells us the fixed part size.
        // Deneb: extraDataOffset == 584 (no request roots)
        // Electra: extraDataOffset == 680 (3 request roots after offset 584)
        boolean isElectra = extraDataOffset >= ELECTRA_FIXED_SIZE;

        byte[] depositRequestsRoot = null;
        byte[] withdrawalRequestsRoot = null;
        byte[] consolidationRequestsRoot = null;

        if (isElectra) {
            depositRequestsRoot = new byte[32];
            buf.get(depositRequestsRoot);                       // offset 584

            withdrawalRequestsRoot = new byte[32];
            buf.get(withdrawalRequestsRoot);                    // offset 616

            consolidationRequestsRoot = new byte[32];
            buf.get(consolidationRequestsRoot);                 // offset 648
            // buf.position() == 680 now
        }

        int fixedSize = isElectra ? ELECTRA_FIXED_SIZE : DENEB_FIXED_SIZE;

        // Read variable-length extraData
        byte[] extraData;
        if (extraDataOffset >= fixedSize && extraDataOffset <= ssz.length) {
            int extraDataLength = ssz.length - extraDataOffset;
            extraData = new byte[extraDataLength];
            System.arraycopy(ssz, extraDataOffset, extraData, 0, extraDataLength);
        } else {
            extraData = new byte[0];
        }

        return new ExecutionPayloadHeader(
                parentHash, feeRecipient, stateRoot, receiptsRoot, logsBloom,
                prevRandao, blockNumber, gasLimit, gasUsed, timestamp,
                extraData, baseFeePerGas, blockHash, transactionsRoot, withdrawalsRoot,
                blobGasUsed, excessBlobGas, depositRequestsRoot, withdrawalRequestsRoot,
                consolidationRequestsRoot
        );
    }

    // ---- Getters ----

    public byte[] stateRoot() { return stateRoot; }
    public byte[] parentHash() { return parentHash; }
    public byte[] feeRecipient() { return feeRecipient; }
    public byte[] receiptsRoot() { return receiptsRoot; }
    public byte[] logsBloom() { return logsBloom; }
    public byte[] prevRandao() { return prevRandao; }
    public long blockNumber() { return blockNumber; }
    public long gasLimit() { return gasLimit; }
    public long gasUsed() { return gasUsed; }
    public long timestamp() { return timestamp; }
    public byte[] extraData() { return extraData; }
    public byte[] baseFeePerGas() { return baseFeePerGas; }
    public byte[] blockHash() { return blockHash; }
    public byte[] transactionsRoot() { return transactionsRoot; }
    public byte[] withdrawalsRoot() { return withdrawalsRoot; }
    public long blobGasUsed() { return blobGasUsed; }
    public long excessBlobGas() { return excessBlobGas; }
    public byte[] depositRequestsRoot() { return depositRequestsRoot; }
    public byte[] withdrawalRequestsRoot() { return withdrawalRequestsRoot; }
    public byte[] consolidationRequestsRoot() { return consolidationRequestsRoot; }

    /**
     * hash_tree_root for Electra ExecutionPayloadHeader (20 fields).
     *
     * Fields (in order):
     *  0:  parentHash         (bytes32)
     *  1:  feeRecipient       (bytes20)
     *  2:  stateRoot          (bytes32)
     *  3:  receiptsRoot       (bytes32)
     *  4:  logsBloom          (bytes256 → 8 chunks)
     *  5:  prevRandao         (bytes32)
     *  6:  blockNumber        (uint64)
     *  7:  gasLimit           (uint64)
     *  8:  gasUsed            (uint64)
     *  9:  timestamp          (uint64)
     * 10:  extraData          (ByteList[MAX_EXTRA_DATA_BYTES])
     * 11:  baseFeePerGas      (uint256 = bytes32 LE)
     * 12:  blockHash          (bytes32)
     * 13:  transactionsRoot   (bytes32)
     * 14:  withdrawalsRoot    (bytes32)
     * 15:  blobGasUsed        (uint64)
     * 16:  excessBlobGas      (uint64)
     * 17:  depositRequestsRoot    (bytes32)
     * 18:  withdrawalRequestsRoot (bytes32)
     * 19:  consolidationRequestsRoot (bytes32)
     */
    public byte[] hashTreeRoot() {
        // MAX_EXTRA_DATA_BYTES = 32 in Ethereum consensus spec => chunkLimit = ceil(32/32) = 1
        final int MAX_EXTRA_DATA_CHUNKS = 1;

        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes32(parentHash),                          // 0
                SszUtil.hashTreeRootBytes20(feeRecipient),                        // 1
                SszUtil.hashTreeRootBytes32(stateRoot),                           // 2
                SszUtil.hashTreeRootBytes32(receiptsRoot),                        // 3
                SszUtil.hashTreeRootBytes256(logsBloom),                          // 4
                SszUtil.hashTreeRootBytes32(prevRandao),                          // 5
                SszUtil.hashTreeRootUint64(blockNumber),                          // 6
                SszUtil.hashTreeRootUint64(gasLimit),                             // 7
                SszUtil.hashTreeRootUint64(gasUsed),                              // 8
                SszUtil.hashTreeRootUint64(timestamp),                            // 9
                SszUtil.hashTreeRootByteList(extraData, MAX_EXTRA_DATA_CHUNKS),   // 10
                SszUtil.hashTreeRootUint256(baseFeePerGas),                       // 11
                SszUtil.hashTreeRootBytes32(blockHash),                           // 12
                SszUtil.hashTreeRootBytes32(transactionsRoot),                    // 13
                SszUtil.hashTreeRootBytes32(withdrawalsRoot),                     // 14
                SszUtil.hashTreeRootUint64(blobGasUsed),                          // 15
                SszUtil.hashTreeRootUint64(excessBlobGas),                        // 16
                SszUtil.hashTreeRootBytes32(depositRequestsRoot),                 // 17
                SszUtil.hashTreeRootBytes32(withdrawalRequestsRoot),              // 18
                SszUtil.hashTreeRootBytes32(consolidationRequestsRoot)            // 19
        );
    }

    @Override
    public String toString() {
        return "ExecutionPayloadHeader{blockNumber=" + blockNumber + ", timestamp=" + timestamp + "}";
    }
}
