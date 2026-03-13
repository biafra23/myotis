package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * eth/GetBlockBodies (message code 0x15).
 *
 * eth/68 format:
 *   RLP: [requestId, [hash1, hash2, ...]]
 */
public final class GetBlockBodiesMessage {

    public static final int CODE = 0x15;

    private GetBlockBodiesMessage() {}

    /** Request block bodies by hash list. */
    public static byte[] encode(long requestId, Bytes32... blockHashes) {
        return RLP.encodeList(writer -> {
            writer.writeLong(requestId);
            writer.writeList(hashWriter -> {
                for (Bytes32 hash : blockHashes) {
                    hashWriter.writeValue(hash);
                }
            });
        }).toArrayUnsafe();
    }

    /** eth/69: Request block bodies by hash list (no requestId). */
    public static byte[] encode69(Bytes32... blockHashes) {
        return RLP.encodeList(writer -> {
            for (Bytes32 hash : blockHashes) {
                writer.writeValue(hash);
            }
        }).toArrayUnsafe();
    }
}
