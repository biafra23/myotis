package com.jaeckel.ethp2p.core.trie;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifier for inclusion and exclusion proofs against the Ethereum Modified
 * Merkle Patricia Trie.
 *
 * <p>Given a trusted {@code root} (32-byte keccak-256 of the root node), an
 * unhashed {@code key} (e.g. an account hash or storage slot hash for the
 * Ethereum state / storage tries), and a list of RLP-encoded trie nodes,
 * this class decides whether the proof is consistent with the root and, if
 * so, returns the value associated with the key (or absence, for an
 * exclusion proof).
 *
 * <p>The walk descends from the root:
 * <ul>
 *   <li>The current expected node hash is matched against
 *       {@code keccak256(node-rlp)}. A mismatch is an invalid proof.
 *   <li><strong>Branch (17 entries):</strong> consume one nibble of the
 *       remaining path and descend into that child slot, or read the value
 *       at index 16 if the path is exhausted.
 *   <li><strong>Leaf (2 entries, leaf flag):</strong> the encoded path's
 *       nibbles must equal the remaining path nibbles for a Found result;
 *       any divergence is an exclusion proof.
 *   <li><strong>Extension (2 entries, extension flag):</strong> the encoded
 *       path is a prefix of the remaining path; consume those nibbles and
 *       descend into the second element.
 * </ul>
 *
 * <p>Children referenced by 32-byte hash require another node in the proof;
 * embedded children (RLP lists shorter than 32 bytes encoded) are decoded
 * directly without a hash step.
 *
 * <p>This is the trust anchor for SNAP-served state.
 */
public final class MerklePatriciaProofVerifier {

    /** keccak256(rlp("")) — the conventional root of an empty trie. */
    public static final Bytes32 EMPTY_TRIE_ROOT = Bytes32.fromHexString(
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

    /** Outcome of a verification attempt. */
    public sealed interface Result {
        /** Proof verifies and the key is present with this value. */
        record Found(Bytes value) implements Result {}
        /** Proof verifies and the key is provably absent. */
        record Absent() implements Result {}
        /** Proof did not verify; {@code reason} explains why. */
        record Invalid(String reason) implements Result {}
    }

    private MerklePatriciaProofVerifier() {}

    /**
     * Verify a proof. {@code key} is the un-hashed key — the Ethereum state
     * trie hashes account addresses with keccak256 before insertion, so for
     * the state trie callers pass {@code keccak256(address).toArrayUnsafe()}
     * (32 bytes); the verifier converts those bytes to nibbles internally.
     */
    public static Result verify(Bytes32 root, byte[] key, List<Bytes> proofNodes) {
        if (key.length == 0) {
            return new Result.Invalid("empty key");
        }
        if (proofNodes == null || proofNodes.isEmpty()) {
            // The empty trie has a well-known root. With no proof nodes we can
            // only assert absence if the root says the trie is empty.
            if (EMPTY_TRIE_ROOT.equals(root)) return new Result.Absent();
            return new Result.Invalid("empty proof for non-empty root");
        }

        // Index proof nodes by their keccak256 hash so descent picks the next
        // node by hash match. The wire returns nodes in walk order, but a
        // hash-keyed map tolerates clients that don't (and lets us share
        // intermediate nodes across multiple key proofs in a future batched
        // verification API).
        Map<Bytes32, Bytes> byHash = new HashMap<>(proofNodes.size());
        for (Bytes n : proofNodes) {
            byHash.put(Bytes32.wrap(Hash.keccak256(n).toArrayUnsafe()), n);
        }

        byte[] path = HexPrefix.toNibbles(key);
        return descendByHash(root, path, 0, byHash);
    }

    /** Descend into a node addressed by hash; the proof must contain it. */
    private static Result descendByHash(Bytes32 expectedHash, byte[] path, int idx, Map<Bytes32, Bytes> byHash) {
        Bytes nodeRlp = byHash.get(expectedHash);
        if (nodeRlp == null) {
            return new Result.Invalid("missing node " + expectedHash + " (path idx=" + idx + ")");
        }
        return interpret(nodeRlp, path, idx, byHash);
    }

    /** Descend into a node already in hand (embedded sub-32-byte child). */
    private static Result descendEmbedded(Bytes nodeRlp, byte[] path, int idx, Map<Bytes32, Bytes> byHash) {
        return interpret(nodeRlp, path, idx, byHash);
    }

    /** Interpret an RLP-encoded node at the given path position. */
    private static Result interpret(Bytes nodeRlp, byte[] path, int idx, Map<Bytes32, Bytes> byHash) {
        List<Bytes> items;
        try {
            items = RlpItems.split(nodeRlp);
        } catch (IllegalArgumentException e) {
            return new Result.Invalid("malformed node RLP: " + e.getMessage());
        }
        if (items.size() == 17) return interpretBranch(items, path, idx, byHash);
        if (items.size() == 2) return interpretShort(items, path, idx, byHash);
        return new Result.Invalid("unexpected node arity: " + items.size());
    }

    /** Branch: 17 raw RLP items — 16 child slots + 1 value at slot 16. */
    private static Result interpretBranch(List<Bytes> items, byte[] path, int idx, Map<Bytes32, Bytes> byHash) {
        if (idx == path.length) {
            // Path exhausted; the value at slot 16 is what we want. The 17th
            // item is always a value (RLP-encoded byte string).
            Bytes valueItem = items.get(16);
            Bytes value = stripBytesHeader(valueItem);
            return value.isEmpty() ? new Result.Absent() : new Result.Found(value);
        }
        int nibble = path[idx] & 0x0f;
        Bytes childItem = items.get(nibble);
        // Branch slots are either an empty bytes value (0x80), a 32-byte hash
        // wrapped as RLP bytes (header 0xa0 + 32 bytes), or an embedded list.
        if (RlpItems.isList(childItem)) {
            return descendEmbedded(childItem, path, idx + 1, byHash);
        }
        Bytes child = stripBytesHeader(childItem);
        if (child.isEmpty()) return new Result.Absent();
        if (child.size() != 32) {
            return new Result.Invalid("branch child " + nibble + " is " + child.size()
                    + " bytes; expected 32-byte hash or embedded list");
        }
        return descendByHash(Bytes32.wrap(child), path, idx + 1, byHash);
    }

    /** Leaf or extension: 2 raw RLP items — encoded-path + (value | next-hash | embedded-list). */
    private static Result interpretShort(List<Bytes> items, byte[] path, int idx, Map<Bytes32, Bytes> byHash) {
        Bytes encodedPath = stripBytesHeader(items.get(0));
        HexPrefix.Decoded decoded = HexPrefix.decode(encodedPath.toArrayUnsafe());
        byte[] nodeNibbles = decoded.nibbles();

        // Remaining path must start with the node's nibbles; otherwise the
        // queried key cannot live below this node.
        int remaining = path.length - idx;
        if (nodeNibbles.length > remaining) return new Result.Absent();
        for (int i = 0; i < nodeNibbles.length; i++) {
            if (nodeNibbles[i] != path[idx + i]) return new Result.Absent();
        }
        int newIdx = idx + nodeNibbles.length;

        Bytes second = items.get(1);
        if (decoded.leaf()) {
            if (newIdx != path.length) {
                // Leaf claims the key ends here, but our path has more nibbles
                // than the leaf consumes — a different key would live below.
                return new Result.Absent();
            }
            return new Result.Found(stripBytesHeader(second));
        }
        // Extension: descend into child.
        if (RlpItems.isList(second)) {
            return descendEmbedded(second, path, newIdx, byHash);
        }
        Bytes child = stripBytesHeader(second);
        if (child.size() != 32) {
            return new Result.Invalid("extension child is " + child.size()
                    + " bytes; expected 32-byte hash or embedded list");
        }
        return descendByHash(Bytes32.wrap(child), path, newIdx, byHash);
    }

    /**
     * Strip the RLP header from a raw RLP-bytes item, returning just the
     * payload. Lists pass through unchanged — the caller checks for that
     * separately.
     */
    private static Bytes stripBytesHeader(Bytes item) {
        if (item.isEmpty()) return item;
        int first = item.get(0) & 0xff;
        if (first < 0x80) {
            // Single byte value.
            return item;
        }
        if (first <= 0xb7) {
            int len = first - 0x80;
            return len == 0 ? Bytes.EMPTY : item.slice(1, len);
        }
        if (first <= 0xbf) {
            int lenOfLen = first - 0xb7;
            int payloadLen = 0;
            for (int i = 0; i < lenOfLen; i++) {
                payloadLen = (payloadLen << 8) | (item.get(1 + i) & 0xff);
            }
            return item.slice(1 + lenOfLen, payloadLen);
        }
        // It's a list — return as-is; the caller decided how to handle it.
        return item;
    }
}
