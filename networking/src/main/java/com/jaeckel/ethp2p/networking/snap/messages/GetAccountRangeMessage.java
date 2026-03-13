package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * snap/1 GetAccountRange request (absolute message code 0x21).
 *
 * Wire format: [reqId, stateRoot, startingHash, limitHash, responseBytes]
 *
 * For a single-address lookup set startingHash = keccak256(address) and
 * limitHash = 0xff..ff so the peer returns the first account at or after
 * startingHash.  The 128 KB responseBytes cap limits how much data is returned.
 */
public final class GetAccountRangeMessage {

    private GetAccountRangeMessage() {}

    /**
     * Encode a GetAccountRange request.
     *
     * @param requestId     unique request ID
     * @param stateRoot     32-byte state root of the block to query
     * @param startingHash  32-byte account hash lower bound (inclusive)
     * @param limitHash     32-byte account hash upper bound (inclusive)
     * @param responseBytes max response size hint in bytes
     * @return RLP-encoded payload bytes
     */
    public static byte[] encode(long requestId, Bytes32 stateRoot,
                                Bytes32 startingHash, Bytes32 limitHash,
                                long responseBytes) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeValue(stateRoot);
            w.writeValue(startingHash);
            w.writeValue(limitHash);
            w.writeLong(responseBytes);
        }).toArrayUnsafe();
    }
}
