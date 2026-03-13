package com.jaeckel.ethp2p.consensus.proof;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Verifies Ethereum Merkle-Patricia Trie proofs (as used in the eth_getProof / snap/1 response)
 * against a trusted state root.
 *
 * The proof is a list of RLP-encoded trie nodes forming a path from the root down to the
 * account leaf. The path key is keccak256(address), traversed as nibbles.
 *
 * Node types:
 * - Branch node:    17-item RLP list. Items [0..15] are child references, item [16] is value.
 * - Extension node: 2-item RLP list. Item [0] is compact-encoded shared prefix, item [1] is child ref.
 * - Leaf node:      2-item RLP list. Item [0] is compact-encoded remaining key, item [1] is RLP-encoded account.
 *
 * Compact encoding:
 *   - First nibble of first byte indicates type and whether length is odd/even:
 *       0 → extension, even length  (skip first byte's low nibble, it's padding)
 *       1 → extension, odd length   (first byte's low nibble is first nibble of path)
 *       2 → leaf, even length
 *       3 → leaf, odd length
 *
 * Node references:
 *   - If an RLP value in a branch/extension is exactly 32 bytes → it's a hash reference.
 *   - If it's shorter (embedded/inline node) → it IS the node RLP directly.
 *   - An empty reference is the RLP empty string (0x80) or empty bytes.
 */
public class MerklePatriciaVerifier {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MerklePatriciaVerifier.class);

    private MerklePatriciaVerifier() {}

    /**
     * Verify that the account proof is valid against the given state root.
     *
     * @param stateRoot      32-byte trusted state root (from beacon chain)
     * @param address        20-byte Ethereum address
     * @param proofNodes     list of RLP-encoded trie nodes forming the proof path
     * @param expectedNonce  expected nonce (-1 to skip check)
     * @param expectedBalance expected balance as decimal string, or null to skip check
     * @return true if proof is internally consistent AND roots to stateRoot
     */
    public static boolean verify(byte[] stateRoot, byte[] address,
                                  List<byte[]> proofNodes,
                                  long expectedNonce, String expectedBalance) {

        if (proofNodes == null || proofNodes.isEmpty()) return false;
        if (stateRoot == null || stateRoot.length != 32) return false;
        if (address == null || address.length != 20) return false;

        byte[] keyHash = keccak256(address);
        byte[] leafValue = traverseProof(stateRoot, keyHash, proofNodes);
        if (leafValue == null) return false;
        return verifyAccountValue(leafValue, expectedNonce, expectedBalance);
    }

    /**
     * Verify a storage proof against an account's storage root.
     *
     * <p>The storage trie uses the same Merkle-Patricia structure as the account trie,
     * but is rooted at the account's {@code storageRoot} instead of the block's {@code stateRoot}.
     * The key path is {@code keccak256(storageSlotKey)} where {@code storageSlotKey} is
     * the 32-byte storage key (e.g. {@code keccak256(abi.encode(address, uint256(slot)))} for mappings).
     *
     * @param storageRoot    32-byte storage root from the account
     * @param storageSlotKey 32-byte storage slot key (pre-computed, NOT hashed yet)
     * @param proofNodes     list of RLP-encoded trie nodes forming the proof path
     * @return the raw storage value bytes, or null if the proof is invalid or the slot is empty
     */
    public static byte[] verifyStorageProof(byte[] storageRoot, byte[] storageSlotKey,
                                             List<byte[]> proofNodes) {
        if (proofNodes == null || proofNodes.isEmpty()) return null;
        if (storageRoot == null || storageRoot.length != 32) return null;
        if (storageSlotKey == null || storageSlotKey.length != 32) return null;

        byte[] keyHash = keccak256(storageSlotKey);
        return traverseProof(storageRoot, keyHash, proofNodes);
    }

    /**
     * Traverse a Merkle-Patricia trie proof from root to leaf.
     *
     * @param root       32-byte expected root hash
     * @param keyHash    32-byte keccak256 of the key (address or storage slot)
     * @param proofNodes list of RLP-encoded trie nodes
     * @return the raw leaf value bytes, or null if the proof is invalid
     */
    private static byte[] traverseProof(byte[] root, byte[] keyHash, List<byte[]> proofNodes) {
        byte[] nibbles = toNibbles(keyHash);
        byte[] expectedNodeHash = root;
        int nibbleOffset = 0;

        for (int i = 0; i < proofNodes.size(); i++) {
            byte[] nodeRlp = proofNodes.get(i);

            // Verify this node's hash matches what we expect
            byte[] nodeHash = keccak256(nodeRlp);
            if (!Arrays.equals(nodeHash, expectedNodeHash)) {
                log.debug("[proof] Node {} hash mismatch: expected={} got={} nodeLen={}",
                    i, hex(expectedNodeHash), hex(nodeHash), nodeRlp.length);
                return null; // hash mismatch in proof chain
            }

            // Decode the RLP node
            List<byte[]> items = decodeRlpList(nodeRlp);
            if (items == null) return null;

            if (items.size() == 17) {
                // Branch node
                if (nibbleOffset >= nibbles.length) {
                    return null;
                }
                int nibble = nibbles[nibbleOffset] & 0xFF;
                byte[] childRef = items.get(nibble);

                if (childRef == null || childRef.length == 0) {
                    return null;
                }

                nibbleOffset++;

                if (i == proofNodes.size() - 1) {
                    // Last node — if the child ref is a leaf embedded inline, handle it
                    if (childRef.length < 32) {
                        List<byte[]> leafItems = decodeRlpList(childRef);
                        if (leafItems == null || leafItems.size() != 2) return null;
                        return verifyLeafAndExtract(leafItems, nibbles, nibbleOffset);
                    }
                    return null;
                } else {
                    if (childRef.length == 32) {
                        expectedNodeHash = childRef;
                    } else {
                        if (!Arrays.equals(proofNodes.get(i + 1), childRef)) {
                            return null;
                        }
                        expectedNodeHash = keccak256(childRef);
                    }
                }

            } else if (items.size() == 2) {
                byte[] encodedPath = items.get(0);
                byte[] value = items.get(1);

                if (encodedPath == null || encodedPath.length == 0) return null;

                int firstHalfByte = (encodedPath[0] & 0xFF) >> 4;
                boolean isLeaf = (firstHalfByte == 2) || (firstHalfByte == 3);
                boolean isOdd = (firstHalfByte & 1) == 1;

                byte[] nodeNibbles = compactToNibbles(encodedPath, isOdd);

                if (nibbleOffset + nodeNibbles.length > nibbles.length) {
                    return null;
                }
                for (int j = 0; j < nodeNibbles.length; j++) {
                    if (nibbles[nibbleOffset + j] != nodeNibbles[j]) {
                        return null;
                    }
                }
                nibbleOffset += nodeNibbles.length;

                if (isLeaf) {
                    if (nibbleOffset != nibbles.length) {
                        return null;
                    }
                    return value;

                } else {
                    if (i == proofNodes.size() - 1) {
                        return null;
                    }

                    if (value.length == 32) {
                        expectedNodeHash = value;
                    } else {
                        if (!Arrays.equals(proofNodes.get(i + 1), value)) {
                            return null;
                        }
                        expectedNodeHash = keccak256(value);
                    }
                }
            } else {
                return null;
            }
        }

        log.debug("[proof] Proof incomplete: iterated all {} nodes without finding leaf (nibbleOffset={})",
            proofNodes.size(), nibbleOffset);
        return null;
    }

    // -------------------------------------------------------------------------
    // Leaf value verification
    // -------------------------------------------------------------------------

    /**
     * Verify a leaf node path matches remaining nibbles, and extract the value.
     */
    private static byte[] verifyLeafAndExtract(List<byte[]> leafItems, byte[] nibbles, int nibbleOffset) {
        byte[] encodedPath = leafItems.get(0);
        byte[] value = leafItems.get(1);

        if (encodedPath == null || encodedPath.length == 0) return null;

        int firstHalfByte = (encodedPath[0] & 0xFF) >> 4;
        boolean isLeaf = (firstHalfByte == 2) || (firstHalfByte == 3);
        if (!isLeaf) return null;

        boolean isOdd = (firstHalfByte & 1) == 1;
        byte[] nodeNibbles = compactToNibbles(encodedPath, isOdd);

        // Verify path matches remaining nibbles
        if (nibbleOffset + nodeNibbles.length != nibbles.length) return null;
        for (int j = 0; j < nodeNibbles.length; j++) {
            if (nibbles[nibbleOffset + j] != nodeNibbles[j]) return null;
        }

        return value;
    }

    /**
     * Decode account RLP [nonce, balance, storageRoot, codeHash] and optionally
     * verify nonce and/or balance against expected values.
     *
     * Account RLP: [nonce (integer), balance (integer), storageRoot (bytes32), codeHash (bytes32)]
     */
    private static boolean verifyAccountValue(byte[] accountRlp,
                                               long expectedNonce,
                                               String expectedBalance) {
        if (accountRlp == null || accountRlp.length == 0) return false;

        try {
            Bytes rlpBytes = Bytes.wrap(accountRlp);
            long[] nonceHolder = new long[1];
            BigInteger[] balanceHolder = new BigInteger[1];

            RLP.decodeList(rlpBytes, reader -> {
                // nonce: uint
                Bytes nonceBytes = reader.readValue();
                nonceHolder[0] = nonceBytes.isEmpty() ? 0L : nonceBytes.toLong();

                // balance: arbitrary-precision big integer
                Bytes balanceBytes = reader.readValue();
                if (balanceBytes.isEmpty()) {
                    balanceHolder[0] = BigInteger.ZERO;
                } else {
                    balanceHolder[0] = new BigInteger(1, balanceBytes.toArrayUnsafe());
                }

                // storageRoot and codeHash (32 bytes each) — we skip validation here;
                // the state root check already validates consistency
                reader.readValue(); // storageRoot
                reader.readValue(); // codeHash

                return null;
            });

            // Validate expected nonce if requested
            if (expectedNonce >= 0 && nonceHolder[0] != expectedNonce) {
                return false;
            }

            // Validate expected balance if requested
            if (expectedBalance != null) {
                BigInteger expected;
                if (expectedBalance.startsWith("0x") || expectedBalance.startsWith("0X")) {
                    expected = new BigInteger(expectedBalance.substring(2), 16);
                } else {
                    expected = new BigInteger(expectedBalance, 10);
                }
                if (!balanceHolder[0].equals(expected)) {
                    return false;
                }
            }

            return true;

        } catch (Exception e) {
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // RLP decoding helpers
    // -------------------------------------------------------------------------

    /**
     * Decode an RLP-encoded list and return each item's raw bytes.
     *
     * <p>This is a manual low-level RLP parser so we can capture the raw bytes of each
     * item (including nested lists / inline nodes) without relying on Tuweni's RLPReader
     * API for re-encoding.
     *
     * <p>Returns null if the input is not a valid RLP list.
     */
    private static List<byte[]> decodeRlpList(byte[] rlp) {
        if (rlp == null || rlp.length == 0) return null;

        // An RLP list starts with a byte >= 0xC0
        int first = rlp[0] & 0xFF;
        if (first < 0xC0) return null; // not a list

        int listPayloadOffset;
        int listPayloadLength;
        if (first <= 0xF7) {
            // Short list: first byte encodes (0xC0 + length)
            listPayloadLength = first - 0xC0;
            listPayloadOffset = 1;
        } else {
            // Long list: next (first - 0xF7) bytes are the length
            int lenLen = first - 0xF7;
            if (rlp.length < 1 + lenLen) return null;
            listPayloadLength = 0;
            for (int i = 0; i < lenLen; i++) {
                listPayloadLength = (listPayloadLength << 8) | (rlp[1 + i] & 0xFF);
            }
            listPayloadOffset = 1 + lenLen;
        }

        if (listPayloadOffset + listPayloadLength > rlp.length) return null;

        java.util.List<byte[]> items = new java.util.ArrayList<>();
        int pos = listPayloadOffset;
        int end = listPayloadOffset + listPayloadLength;

        while (pos < end) {
            int[] itemRange = rlpItemRange(rlp, pos, end);
            if (itemRange == null) return null;

            int itemStart = itemRange[0];
            int itemEnd   = itemRange[1];
            int itemFirst = rlp[pos] & 0xFF;

            if (itemFirst >= 0xC0) {
                // Nested list — return the full raw RLP encoding (header + payload)
                byte[] nested = new byte[itemEnd - pos];
                System.arraycopy(rlp, pos, nested, 0, nested.length);
                items.add(nested);
            } else {
                // Value — return only the payload bytes (strip RLP header)
                byte[] payload = new byte[itemEnd - itemStart];
                System.arraycopy(rlp, itemStart, payload, 0, payload.length);
                items.add(payload);
            }
            pos = itemEnd;
        }

        return items;
    }

    /**
     * Compute the [payloadStart, itemEnd] range for an RLP item starting at {@code pos}.
     * Returns null on malformed input.
     */
    private static int[] rlpItemRange(byte[] data, int pos, int end) {
        if (pos >= end) return null;
        int first = data[pos] & 0xFF;

        if (first < 0x80) {
            // Single byte value
            return new int[]{pos, pos + 1};
        } else if (first <= 0xB7) {
            // Short string/bytes: next (first - 0x80) bytes are payload
            int payloadLen = first - 0x80;
            if (pos + 1 + payloadLen > end) return null;
            return new int[]{pos + 1, pos + 1 + payloadLen};
        } else if (first <= 0xBF) {
            // Long string: next (first - 0xB7) bytes encode payload length
            int lenLen = first - 0xB7;
            if (pos + 1 + lenLen > end) return null;
            int payloadLen = 0;
            for (int i = 0; i < lenLen; i++) {
                payloadLen = (payloadLen << 8) | (data[pos + 1 + i] & 0xFF);
            }
            int headerLen = 1 + lenLen;
            if (pos + headerLen + payloadLen > end) return null;
            return new int[]{pos + headerLen, pos + headerLen + payloadLen};
        } else if (first <= 0xF7) {
            // Short list: (first - 0xC0) bytes of payload
            int payloadLen = first - 0xC0;
            if (pos + 1 + payloadLen > end) return null;
            return new int[]{pos + 1, pos + 1 + payloadLen};
        } else {
            // Long list: next (first - 0xF7) bytes encode payload length
            int lenLen = first - 0xF7;
            if (pos + 1 + lenLen > end) return null;
            int payloadLen = 0;
            for (int i = 0; i < lenLen; i++) {
                payloadLen = (payloadLen << 8) | (data[pos + 1 + i] & 0xFF);
            }
            int headerLen = 1 + lenLen;
            if (pos + headerLen + payloadLen > end) return null;
            return new int[]{pos + headerLen, pos + headerLen + payloadLen};
        }
    }

    // -------------------------------------------------------------------------
    // Nibble / compact encoding helpers
    // -------------------------------------------------------------------------

    /**
     * Convert a byte array to a nibble array (each byte becomes 2 nibbles, high nibble first).
     */
    static byte[] toNibbles(byte[] bytes) {
        byte[] nibbles = new byte[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            nibbles[2 * i]     = (byte) ((bytes[i] >> 4) & 0x0F);
            nibbles[2 * i + 1] = (byte) (bytes[i] & 0x0F);
        }
        return nibbles;
    }

    /**
     * Decode the nibbles from a compact-encoded path.
     *
     * Compact encoding layout:
     *   - High nibble of first byte encodes type + odd/even flag:
     *       0 → extension, even (skip entire first byte, no nibbles from it)
     *       1 → extension, odd  (low nibble of first byte is first nibble)
     *       2 → leaf, even      (skip entire first byte)
     *       3 → leaf, odd       (low nibble of first byte is first nibble)
     *   - Remaining bytes contribute 2 nibbles each.
     *
     * @param compact compact-encoded byte array
     * @param isOdd   whether the original nibble length was odd
     * @return the decoded nibbles
     */
    static byte[] compactToNibbles(byte[] compact, boolean isOdd) {
        if (compact.length == 0) return new byte[0];

        if (isOdd) {
            // First nibble of the path is the low nibble of compact[0]
            // Remaining nibbles come from compact[1], compact[2], ...
            int totalNibbles = 1 + (compact.length - 1) * 2;
            byte[] nibbles = new byte[totalNibbles];
            nibbles[0] = (byte) (compact[0] & 0x0F);
            for (int i = 1; i < compact.length; i++) {
                nibbles[1 + (i - 1) * 2]     = (byte) ((compact[i] >> 4) & 0x0F);
                nibbles[1 + (i - 1) * 2 + 1] = (byte) (compact[i] & 0x0F);
            }
            return nibbles;
        } else {
            // Even: skip compact[0] entirely, decode nibbles from compact[1..]
            int totalNibbles = (compact.length - 1) * 2;
            byte[] nibbles = new byte[totalNibbles];
            for (int i = 1; i < compact.length; i++) {
                nibbles[(i - 1) * 2]     = (byte) ((compact[i] >> 4) & 0x0F);
                nibbles[(i - 1) * 2 + 1] = (byte) (compact[i] & 0x0F);
            }
            return nibbles;
        }
    }

    // -------------------------------------------------------------------------
    // Crypto
    // -------------------------------------------------------------------------

    /**
     * Compute keccak256 of the input bytes.
     */
    private static byte[] keccak256(byte[] input) {
        return Hash.keccak256(Bytes.wrap(input)).toArrayUnsafe();
    }

    private static String hex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder("0x");
        for (int i = 0; i < Math.min(bytes.length, 8); i++) sb.append(String.format("%02x", bytes[i]));
        if (bytes.length > 8) sb.append("...");
        return sb.toString();
    }
}
