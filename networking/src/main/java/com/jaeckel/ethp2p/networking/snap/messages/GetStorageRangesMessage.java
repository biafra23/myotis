package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * snap/1 GetStorageRanges request.
 *
 * Wire format: [reqId, stateRoot, [accountHash, ...], startingHash, limitHash, responseBytes]
 *
 * For a single-slot lookup on a single account, set accountHashes = [keccak256(address)],
 * startingHash = keccak256(storageSlotKey) and limitHash = 0xff..ff.
 */
public final class GetStorageRangesMessage {

    private GetStorageRangesMessage() {}

    /**
     * Encode a GetStorageRanges request for a single account.
     *
     * @param requestId     unique request ID
     * @param stateRoot     32-byte state root of the block to query
     * @param accountHash   32-byte keccak256(address) of the contract
     * @param startingHash  32-byte storage key hash lower bound (inclusive)
     * @param limitHash     32-byte storage key hash upper bound (inclusive)
     * @param responseBytes max response size hint in bytes
     * @return RLP-encoded payload bytes
     */
    public static byte[] encode(long requestId, Bytes32 stateRoot,
                                Bytes32 accountHash,
                                Bytes32 startingHash, Bytes32 limitHash,
                                long responseBytes) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeValue(stateRoot);
            // accounts list: [accountHash]
            w.writeList(accounts -> accounts.writeValue(accountHash));
            w.writeValue(startingHash);
            w.writeValue(limitHash);
            w.writeLong(responseBytes);
        }).toArrayUnsafe();
    }
}
