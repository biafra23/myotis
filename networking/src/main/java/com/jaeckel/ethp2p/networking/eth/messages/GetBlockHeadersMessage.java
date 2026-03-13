package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * eth/GetBlockHeaders (message code 0x13).
 *
 * eth/68 format:
 *   RLP: [requestId, [startBlockOrHash, maxHeaders, skip, reverse]]
 *
 * Reference: ethereum/devp2p/caps/eth.md §GetBlockHeaders
 */
public final class GetBlockHeadersMessage {

    public static final int CODE = 0x13;

    private GetBlockHeadersMessage() {}

    /** Request headers by block number. */
    public static byte[] encodeByNumber(long requestId, long blockNumber,
                                        int maxHeaders, int skip, boolean reverse) {
        return RLP.encodeList(writer -> {
            writer.writeLong(requestId);
            writer.writeList(bodyWriter -> {
                bodyWriter.writeLong(blockNumber);
                bodyWriter.writeInt(maxHeaders);
                bodyWriter.writeInt(skip);
                bodyWriter.writeInt(reverse ? 1 : 0);
            });
        }).toArrayUnsafe();
    }

    /** Request headers by block hash. */
    public static byte[] encodeByHash(long requestId, Bytes32 blockHash,
                                      int maxHeaders, int skip, boolean reverse) {
        return RLP.encodeList(writer -> {
            writer.writeLong(requestId);
            writer.writeList(bodyWriter -> {
                bodyWriter.writeValue(blockHash);
                bodyWriter.writeInt(maxHeaders);
                bodyWriter.writeInt(skip);
                bodyWriter.writeInt(reverse ? 1 : 0);
            });
        }).toArrayUnsafe();
    }

    /** eth/69: Request headers by block number (no requestId). */
    public static byte[] encodeByNumber69(long blockNumber, int maxHeaders,
                                           int skip, boolean reverse) {
        return RLP.encodeList(writer -> {
            writer.writeLong(blockNumber);
            writer.writeInt(maxHeaders);
            writer.writeInt(skip);
            writer.writeInt(reverse ? 1 : 0);
        }).toArrayUnsafe();
    }

    /** eth/69: Request headers by block hash (no requestId). */
    public static byte[] encodeByHash69(Bytes32 blockHash, int maxHeaders,
                                         int skip, boolean reverse) {
        return RLP.encodeList(writer -> {
            writer.writeValue(blockHash);
            writer.writeInt(maxHeaders);
            writer.writeInt(skip);
            writer.writeInt(reverse ? 1 : 0);
        }).toArrayUnsafe();
    }
}
