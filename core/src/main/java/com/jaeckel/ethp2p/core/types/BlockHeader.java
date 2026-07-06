package com.jaeckel.ethp2p.core.types;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.units.bigints.UInt256;

import java.math.BigInteger;
import java.util.List;

/**
 * Ethereum Execution Layer block header (post-London, post-Merge).
 *
 * RLP field order (eth/68, EIP-1559, EIP-3675):
 *   parentHash, ommersHash, beneficiary, stateRoot, transactionsRoot,
 *   receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed,
 *   timestamp, extraData, mixHashOrPrevRandao, nonce,
 *   baseFeePerGas (EIP-1559), withdrawalsRoot (EIP-4895),
 *   blobGasUsed (EIP-4844), excessBlobGas (EIP-4844),
 *   parentBeaconBlockRoot (EIP-4788)
 */
public final class BlockHeader {

    public final Bytes32 parentHash;
    public final Bytes32 ommersHash;
    public final Bytes beneficiary;         // 20 bytes
    public final Bytes32 stateRoot;
    public final Bytes32 transactionsRoot;
    public final Bytes32 receiptsRoot;
    public final Bytes logsBloom;           // 256 bytes
    public final BigInteger difficulty;
    public final long number;
    public final long gasLimit;
    public final long gasUsed;
    public final long timestamp;
    public final Bytes extraData;
    public final Bytes32 mixHashOrPrevRandao;
    public final Bytes nonce;               // 8 bytes
    public final BigInteger baseFeePerGas;  // null for pre-London
    public final Bytes32 withdrawalsRoot;   // null for pre-Shanghai
    public final long blobGasUsed;          // -1 for pre-Cancun
    public final long excessBlobGas;        // -1 for pre-Cancun
    public final Bytes32 parentBeaconBlockRoot; // null for pre-Cancun

    private BlockHeader(
            Bytes32 parentHash, Bytes32 ommersHash, Bytes beneficiary,
            Bytes32 stateRoot, Bytes32 transactionsRoot, Bytes32 receiptsRoot,
            Bytes logsBloom, BigInteger difficulty, long number,
            long gasLimit, long gasUsed, long timestamp, Bytes extraData,
            Bytes32 mixHashOrPrevRandao, Bytes nonce,
            BigInteger baseFeePerGas, Bytes32 withdrawalsRoot,
            long blobGasUsed, long excessBlobGas, Bytes32 parentBeaconBlockRoot) {
        this.parentHash = parentHash;
        this.ommersHash = ommersHash;
        this.beneficiary = beneficiary;
        this.stateRoot = stateRoot;
        this.transactionsRoot = transactionsRoot;
        this.receiptsRoot = receiptsRoot;
        this.logsBloom = logsBloom;
        this.difficulty = difficulty;
        this.number = number;
        this.gasLimit = gasLimit;
        this.gasUsed = gasUsed;
        this.timestamp = timestamp;
        this.extraData = extraData;
        this.mixHashOrPrevRandao = mixHashOrPrevRandao;
        this.nonce = nonce;
        this.baseFeePerGas = baseFeePerGas;
        this.withdrawalsRoot = withdrawalsRoot;
        this.blobGasUsed = blobGasUsed;
        this.excessBlobGas = excessBlobGas;
        this.parentBeaconBlockRoot = parentBeaconBlockRoot;
    }

    /**
     * Decode a block header from RLP bytes.
     * Handles post-Cancun headers (all fields present).
     *
     * <p>Strict about the envelope (Rust-twin parity, pinned by the el/core
     * conformance corpus): trailing bytes after the header list are rejected
     * — the header hash is keccak256 of the WHOLE input, so slack bytes
     * would silently change the hash of what was decoded. Numeric fields
     * are rejected when the signed read goes negative (an 8-byte high-bit
     * scalar), which would otherwise collide with the -1 "absent" sentinel
     * of the EIP-4844 pair.
     */
    public static BlockHeader decode(Bytes rlpBytes) {
        return RLP.decode(rlpBytes, outer -> {
            BlockHeader header = outer.readList(BlockHeader::decodeFields);
            if (!outer.isComplete()) {
                throw new IllegalArgumentException("Trailing bytes after header RLP");
            }
            return header;
        });
    }

    private static BlockHeader decodeFields(org.apache.tuweni.rlp.RLPReader reader) {
        Bytes32 parentHash = Bytes32.wrap(reader.readValue());
        Bytes32 ommersHash = Bytes32.wrap(reader.readValue());
        Bytes beneficiary = reader.readValue();
        Bytes32 stateRoot = Bytes32.wrap(reader.readValue());
        Bytes32 txRoot = Bytes32.wrap(reader.readValue());
        Bytes32 rcptRoot = Bytes32.wrap(reader.readValue());
        Bytes logsBloom = reader.readValue();
        BigInteger difficulty = reader.readBigInteger();
        long number = readNonNegativeLong(reader, "number");
        long gasLimit = readNonNegativeLong(reader, "gasLimit");
        long gasUsed = readNonNegativeLong(reader, "gasUsed");
        long timestamp = readNonNegativeLong(reader, "timestamp");
        Bytes extraData = reader.readValue();
        Bytes32 mixHash = Bytes32.wrap(reader.readValue());
        Bytes nonce = reader.readValue();

        // Optional post-London fields
        BigInteger baseFee = null;
        Bytes32 withdrawalsRoot = null;
        long blobGasUsed = -1;
        long excessBlobGas = -1;
        Bytes32 parentBeaconRoot = null;

        if (!reader.isComplete()) baseFee = reader.readBigInteger();
        if (!reader.isComplete()) withdrawalsRoot = Bytes32.wrap(reader.readValue());
        if (!reader.isComplete()) blobGasUsed = readNonNegativeLong(reader, "blobGasUsed");
        if (!reader.isComplete()) excessBlobGas = readNonNegativeLong(reader, "excessBlobGas");
        if (!reader.isComplete()) parentBeaconRoot = Bytes32.wrap(reader.readValue());
        // EIP-7685 (Prague/Electra): requestsHash — skip if present
        if (!reader.isComplete()) reader.readValue();

        return new BlockHeader(parentHash, ommersHash, beneficiary,
                stateRoot, txRoot, rcptRoot, logsBloom, difficulty,
                number, gasLimit, gasUsed, timestamp, extraData,
                mixHash, nonce, baseFee, withdrawalsRoot,
                blobGasUsed, excessBlobGas, parentBeaconRoot);
    }

    /** Tuweni readLong is signed; every header scalar is unsigned on the wire. */
    private static long readNonNegativeLong(org.apache.tuweni.rlp.RLPReader reader, String name) {
        long v = reader.readLong();
        if (v < 0) {
            throw new IllegalArgumentException("Header field " + name + " out of range");
        }
        return v;
    }

    /** keccak256 of the RLP-encoded header. Verifiable against trusted block hash. */
    public static Bytes32 hash(Bytes rlpBytes) {
        return Hash.keccak256(rlpBytes);
    }

    @Override
    public String toString() {
        return "BlockHeader{" +
               "number=" + number +
               ", stateRoot=" + stateRoot.toShortHexString() +
               ", baseFee=" + (baseFeePerGas != null ? baseFeePerGas : "n/a") +
               '}';
    }
}
