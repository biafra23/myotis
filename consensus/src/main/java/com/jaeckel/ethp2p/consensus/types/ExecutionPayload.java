package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: ExecutionPayload (17 fields, Deneb/Electra)
 *
 * <p>Fixed layout (528 bytes):
 * parent_hash(32) fee_recipient(20) state_root(32) receipts_root(32) logs_bloom(256)
 * prev_randao(32) block_number(8) gas_limit(8) gas_used(8) timestamp(8)
 * extra_data_offset(4) base_fee_per_gas(32) block_hash(32)
 * transactions_offset(4) withdrawals_offset(4) blob_gas_used(8) excess_blob_gas(8)
 *
 * <p>Variable fields: extra_data, transactions, withdrawals
 */
public final class ExecutionPayload {

    private static final int MAX_EXTRA_DATA_BYTES = 32;
    private static final int MAX_TRANSACTIONS_PER_PAYLOAD = 1_048_576;
    private static final int MAX_BYTES_PER_TRANSACTION = 1_073_741_824;
    private static final int MAX_WITHDRAWALS = 16;

    private final byte[] parentHash;
    private final byte[] feeRecipient;
    private final byte[] stateRoot;
    private final byte[] receiptsRoot;
    private final byte[] logsBloom;
    private final byte[] prevRandao;
    private final long blockNumber;
    private final long gasLimit;
    private final long gasUsed;
    private final long timestamp;
    private final byte[] extraData;
    private final byte[] baseFeePerGas;
    private final byte[] blockHash;
    private final long blobGasUsed;
    private final long excessBlobGas;

    // Raw bytes for transaction/withdrawal list hashing (kept to avoid re-copying)
    private final byte[] rawBytes;
    private final int txOffset;
    private final int wdOffset;
    private final int rawLength;

    private ExecutionPayload(
            byte[] parentHash, byte[] feeRecipient, byte[] stateRoot, byte[] receiptsRoot,
            byte[] logsBloom, byte[] prevRandao, long blockNumber, long gasLimit,
            long gasUsed, long timestamp, byte[] extraData, byte[] baseFeePerGas,
            byte[] blockHash, long blobGasUsed, long excessBlobGas,
            byte[] rawBytes, int txOffset, int wdOffset, int rawLength
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
        this.blobGasUsed = blobGasUsed;
        this.excessBlobGas = excessBlobGas;
        this.rawBytes = rawBytes;
        this.txOffset = txOffset;
        this.wdOffset = wdOffset;
        this.rawLength = rawLength;
    }

    /**
     * Decode from body bytes between [offset, end).
     * The raw byte range is retained for transaction/withdrawal list hashing.
     */
    public static ExecutionPayload decode(byte[] data, int offset, int end) {
        byte[] ep = Arrays.copyOfRange(data, offset, end);
        int p = 0;
        byte[] parentHash = Arrays.copyOfRange(ep, p, p + 32); p += 32;
        byte[] feeRecipient = Arrays.copyOfRange(ep, p, p + 20); p += 20;
        byte[] stateRoot = Arrays.copyOfRange(ep, p, p + 32); p += 32;
        byte[] receiptsRoot = Arrays.copyOfRange(ep, p, p + 32); p += 32;
        byte[] logsBloom = Arrays.copyOfRange(ep, p, p + 256); p += 256;
        byte[] prevRandao = Arrays.copyOfRange(ep, p, p + 32); p += 32;
        long blockNumber = SszUtil.readUint64(ep, p); p += 8;
        long gasLimit = SszUtil.readUint64(ep, p); p += 8;
        long gasUsed = SszUtil.readUint64(ep, p); p += 8;
        long timestamp = SszUtil.readUint64(ep, p); p += 8;
        int extraDataOffset = SszUtil.readUint32(ep, p); p += 4;
        byte[] baseFeePerGas = Arrays.copyOfRange(ep, p, p + 32); p += 32;
        byte[] blockHash = Arrays.copyOfRange(ep, p, p + 32); p += 32;
        int txOffset = SszUtil.readUint32(ep, p); p += 4;
        int wdOffset = SszUtil.readUint32(ep, p); p += 4;
        long blobGasUsed = SszUtil.readUint64(ep, p); p += 8;
        long excessBlobGas = SszUtil.readUint64(ep, p);

        byte[] extraData = Arrays.copyOfRange(ep, extraDataOffset, txOffset);

        return new ExecutionPayload(
                parentHash, feeRecipient, stateRoot, receiptsRoot, logsBloom,
                prevRandao, blockNumber, gasLimit, gasUsed, timestamp,
                extraData, baseFeePerGas, blockHash, blobGasUsed, excessBlobGas,
                ep, txOffset, wdOffset, ep.length
        );
    }

    public byte[] stateRoot() { return stateRoot; }

    public byte[] hashTreeRoot() {
        byte[][] fr = new byte[17][];
        fr[0]  = SszUtil.hashTreeRootBytes32(parentHash);
        fr[1]  = SszUtil.hashTreeRootBytes20(feeRecipient);
        fr[2]  = SszUtil.hashTreeRootBytes32(stateRoot);
        fr[3]  = SszUtil.hashTreeRootBytes32(receiptsRoot);
        fr[4]  = SszUtil.hashTreeRootBytes256(logsBloom);
        fr[5]  = SszUtil.hashTreeRootBytes32(prevRandao);
        fr[6]  = SszUtil.hashTreeRootUint64(blockNumber);
        fr[7]  = SszUtil.hashTreeRootUint64(gasLimit);
        fr[8]  = SszUtil.hashTreeRootUint64(gasUsed);
        fr[9]  = SszUtil.hashTreeRootUint64(timestamp);
        fr[10] = SszUtil.hashTreeRootByteList(extraData, (MAX_EXTRA_DATA_BYTES + 31) / 32);
        fr[11] = SszUtil.hashTreeRootUint256(baseFeePerGas);
        fr[12] = SszUtil.hashTreeRootBytes32(blockHash);
        fr[13] = hashTransactionList(rawBytes, txOffset, wdOffset);
        fr[14] = hashWithdrawalList(rawBytes, wdOffset, rawLength);
        fr[15] = SszUtil.hashTreeRootUint64(blobGasUsed);
        fr[16] = SszUtil.hashTreeRootUint64(excessBlobGas);
        return SszUtil.merkleize(fr);
    }

    private static byte[] hashTransactionList(byte[] ep, int start, int end) {
        int len = end - start;
        if (len == 0) {
            byte[] emptyRoot = SszUtil.merkleizeSparse(new byte[0][], MAX_TRANSACTIONS_PER_PAYLOAD);
            return SszUtil.mixInLength(emptyRoot, 0);
        }

        int firstOffset = SszUtil.readUint32(ep, start);
        int txCount = firstOffset / 4;

        int[] offsets = new int[txCount];
        for (int i = 0; i < txCount; i++) {
            offsets[i] = SszUtil.readUint32(ep, start + i * 4);
        }

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

    private static byte[] hashWithdrawalList(byte[] ep, int start, int end) {
        return SszUtil.hashFixedElementList(ep, start, end,
                Withdrawal.SSZ_SIZE, MAX_WITHDRAWALS, Withdrawal::hashTreeRootAt);
    }
}
