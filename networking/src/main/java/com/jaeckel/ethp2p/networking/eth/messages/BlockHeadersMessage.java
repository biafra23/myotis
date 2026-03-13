package com.jaeckel.ethp2p.networking.eth.messages;

import com.jaeckel.ethp2p.core.types.BlockHeader;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPReader;

import java.util.ArrayList;
import java.util.List;

/**
 * eth/BlockHeaders (message code 0x14).
 *
 * eth/68 format:
 *   RLP: [requestId, [header, header, ...]]
 * eth/69 format:
 *   RLP: [header, header, ...]
 *
 * Each header is an RLP list in the standard block header format.
 */
public final class BlockHeadersMessage {

    public static final int CODE = 0x14;

    private BlockHeadersMessage() {}

    public record VerifiedHeader(Bytes32 hash, BlockHeader header, Bytes rawRlp) {}

    /** Decoded response including the request ID (0 for eth/69). */
    public record DecodeResult(long requestId, List<VerifiedHeader> headers) {}

    /**
     * Decode and return parsed headers with their computed hashes.
     * The hash can be verified against a trusted block hash from sync committees.
     */
    public static List<VerifiedHeader> decode(byte[] rlp) {
        return decodeWithRequestId(rlp).headers();
    }

    /**
     * eth/69: Decode headers without requestId wrapper.
     * Wire format: [header, header, ...]
     */
    public static DecodeResult decodeWithoutRequestId(byte[] rlp) {
        List<VerifiedHeader> result = new ArrayList<>();
        RLP.decodeList(Bytes.wrap(rlp), headersReader -> {
            decodeHeaderList(headersReader, result);
            return null;
        });
        return new DecodeResult(0, result);
    }

    /**
     * Decode and return parsed headers together with the eth/68 request ID.
     */
    public static DecodeResult decodeWithRequestId(byte[] rlp) {
        List<VerifiedHeader> result = new ArrayList<>();
        long[] reqId = {0};
        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong(); // eth/68 request ID
            reader.readList(headersReader -> {
                decodeHeaderList(headersReader, result);
                return null;
            });
            return null;
        });
        return new DecodeResult(reqId[0], result);
    }

    /** Decode all headers from a list-level reader into the result list. */
    private static void decodeHeaderList(RLPReader headersReader, List<VerifiedHeader> result) {
        while (!headersReader.isComplete()) {
            Bytes[] rawHolder = {null};
            headersReader.readList(headerReader -> {
                Bytes32 parentHash = Bytes32.wrap(headerReader.readValue());
                Bytes32 ommersHash = Bytes32.wrap(headerReader.readValue());
                Bytes beneficiary = headerReader.readValue();
                Bytes32 stateRoot = Bytes32.wrap(headerReader.readValue());
                Bytes32 txRoot = Bytes32.wrap(headerReader.readValue());
                Bytes32 rcptRoot = Bytes32.wrap(headerReader.readValue());
                Bytes logsBloom = headerReader.readValue();
                java.math.BigInteger difficulty = headerReader.readBigInteger();
                long number = headerReader.readLong();
                long gasLimit = headerReader.readLong();
                long gasUsed = headerReader.readLong();
                long timestamp = headerReader.readLong();
                Bytes extraData = headerReader.readValue();
                Bytes32 mixHash = Bytes32.wrap(headerReader.readValue());
                Bytes nonce = headerReader.readValue();

                // Optional fields
                java.math.BigInteger baseFee = null;
                Bytes32 withdrawalsRoot = null;
                long blobGasUsed = -1;
                long excessBlobGas = -1;
                Bytes32 parentBeaconRoot = null;
                Bytes32 requestsHash = null;  // EIP-7685 (Prague/Electra)
                if (!headerReader.isComplete()) baseFee = headerReader.readBigInteger();
                if (!headerReader.isComplete()) withdrawalsRoot = Bytes32.wrap(headerReader.readValue());
                if (!headerReader.isComplete()) blobGasUsed = headerReader.readLong();
                if (!headerReader.isComplete()) excessBlobGas = headerReader.readLong();
                if (!headerReader.isComplete()) parentBeaconRoot = Bytes32.wrap(headerReader.readValue());
                if (!headerReader.isComplete()) requestsHash = Bytes32.wrap(headerReader.readValue());
                // Capture any future unknown fields as raw values
                java.util.List<Bytes> unknownFields = new java.util.ArrayList<>();
                while (!headerReader.isComplete()) {
                    unknownFields.add(headerReader.readValue());
                }

                // Re-encode to get the canonical RLP for hashing
                final java.math.BigInteger fBaseFee = baseFee;
                final Bytes32 fWR = withdrawalsRoot;
                final long fBGU = blobGasUsed;
                final long fEBG = excessBlobGas;
                final Bytes32 fPBR = parentBeaconRoot;
                final Bytes32 fRH = requestsHash;
                final java.util.List<Bytes> fExtra = unknownFields;
                rawHolder[0] = RLP.encodeList(w -> {
                    w.writeValue(parentHash); w.writeValue(ommersHash);
                    w.writeValue(beneficiary); w.writeValue(stateRoot);
                    w.writeValue(txRoot); w.writeValue(rcptRoot);
                    w.writeValue(logsBloom); w.writeBigInteger(difficulty);
                    w.writeLong(number); w.writeLong(gasLimit);
                    w.writeLong(gasUsed); w.writeLong(timestamp);
                    w.writeValue(extraData); w.writeValue(mixHash);
                    w.writeValue(nonce);
                    if (fBaseFee != null) w.writeBigInteger(fBaseFee);
                    if (fWR != null) w.writeValue(fWR);
                    if (fBGU >= 0) w.writeLong(fBGU);
                    if (fEBG >= 0) w.writeLong(fEBG);
                    if (fPBR != null) w.writeValue(fPBR);
                    if (fRH != null) w.writeValue(fRH);
                    for (Bytes extra : fExtra) w.writeValue(extra);
                });
                return null;
            });
            if (rawHolder[0] != null) {
                Bytes rlpHeader = rawHolder[0];
                Bytes32 hash = Hash.keccak256(rlpHeader);
                BlockHeader header = BlockHeader.decode(rlpHeader);
                result.add(new VerifiedHeader(hash, header, rlpHeader));
            }
        }
    }
}
