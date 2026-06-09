package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * eth/GetReceipts (wire code 0x1f = eth message 0x0f + base offset 0x10).
 *
 * eth/66-68 format:
 *   RLP: [requestId, [blockHash1, blockHash2, ...]]
 *
 * The response ({@link ReceiptsMessage}, 0x20) carries the full consensus-encoded
 * receipts per block, which the caller verifies by rebuilding the receipts trie and
 * comparing its root to the (beacon-anchored) header's {@code receiptsRoot}.
 */
public final class GetReceiptsMessage {

    public static final int CODE = 0x1f;

    private GetReceiptsMessage() {}

    /** Request receipts for the given block hashes. */
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
}
