package com.jaeckel.ethp2p.consensus.proof;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Computes the root of an Ethereum "ordered" Merkle-Patricia trie — the construction
 * used for a block's {@code transactionsRoot} and {@code receiptsRoot}, where the trie
 * maps {@code key = RLP(index)} to {@code value = consensus-encoding of the item}.
 *
 * <p>Unlike {@link MerklePatriciaVerifier} (which only walks an existing proof downward,
 * root → leaf), this builds the trie bottom-up to <em>derive</em> the root, so a caller
 * can verify a full transaction or receipt list against a trusted header without trusting
 * the peer that supplied it: rebuild the trie from the received items and compare the
 * computed root to {@code header.transactionsRoot} / {@code header.receiptsRoot}.
 *
 * <p>Trie encoding follows the Yellow Paper: hex-prefix (compact) node keys, 17-item
 * branch nodes, 2-item leaf/extension nodes, child references inlined when their RLP is
 * &lt; 32 bytes and keccak256-hashed otherwise, and the root always hashed.
 */
public final class OrderedTrieRoot {

    /** keccak256(RLP("")) — the root of an empty trie. */
    public static final Bytes32 EMPTY_ROOT =
            Hash.keccak256(RLP.encodeValue(Bytes.EMPTY));

    private OrderedTrieRoot() {}

    /** True iff the ordered trie over {@code items} (index → item) roots to {@code expectedRoot}. */
    public static boolean verify(List<Bytes> items, Bytes32 expectedRoot) {
        return expectedRoot != null && expectedRoot.equals(ofList(items));
    }

    /** Root of the ordered trie mapping {@code RLP(i) -> items.get(i)}. */
    public static Bytes32 ofList(List<Bytes> items) {
        if (items == null || items.isEmpty()) return EMPTY_ROOT;
        List<Bytes> keys = new ArrayList<>(items.size());
        for (int i = 0; i < items.size(); i++) {
            keys.add(RLP.encodeValue(minimalBytes(i)));
        }
        return rootOf(keys, items);
    }

    /** Root of an arbitrary-keyed Merkle-Patricia trie (keys used directly as the path,
     *  not hashed — the tx/receipt-trie convention). Package-private: lets tests drive
     *  the branch/extension/leaf machinery with crafted keys. */
    static Bytes32 rootOf(List<Bytes> keys, List<Bytes> values) {
        if (keys.isEmpty()) return EMPTY_ROOT;
        List<Entry> entries = new ArrayList<>(keys.size());
        for (int i = 0; i < keys.size(); i++) {
            entries.add(new Entry(nibbles(keys.get(i)), values.get(i)));
        }
        // The trie shape is determined by key-nibble order, not insertion order,
        // so sort lexicographically before building.
        entries.sort(Comparator.comparing(e -> e.path, OrderedTrieRoot::compareNibbles));
        return Hash.keccak256(buildNode(entries, 0));
    }

    /** RLP bytes of the trie node covering {@code entries}, which all share nibbles [0, depth). */
    private static Bytes buildNode(List<Entry> entries, int depth) {
        if (entries.size() == 1) {
            Entry e = entries.get(0);
            int[] rest = java.util.Arrays.copyOfRange(e.path, depth, e.path.length);
            return RLP.encodeList(w -> {
                w.writeValue(hexPrefix(rest, true));
                w.writeValue(e.value);
            });
        }
        int common = commonPrefixEnd(entries, depth);
        if (common > depth) {
            int[] shared = java.util.Arrays.copyOfRange(entries.get(0).path, depth, common);
            Bytes child = buildNode(entries, common);
            return RLP.encodeList(w -> {
                w.writeValue(hexPrefix(shared, false));
                writeRef(w, child);
            });
        }
        // Branch node: 16 child slots + a value slot (for a key ending exactly here).
        List<List<Entry>> groups = new ArrayList<>(16);
        for (int i = 0; i < 16; i++) groups.add(new ArrayList<>());
        Bytes branchValue = Bytes.EMPTY;
        for (Entry e : entries) {
            if (e.path.length == depth) branchValue = e.value;
            else groups.get(e.path[depth]).add(e);
        }
        Bytes finalBranchValue = branchValue;
        return RLP.encodeList(w -> {
            for (int n = 0; n < 16; n++) {
                List<Entry> g = groups.get(n);
                if (g.isEmpty()) w.writeValue(Bytes.EMPTY);
                else writeRef(w, buildNode(g, depth + 1));
            }
            w.writeValue(finalBranchValue);
        });
    }

    /** Embed a child reference: inline the node RLP if < 32 bytes, else its keccak256 hash. */
    private static void writeRef(org.apache.tuweni.rlp.RLPWriter w, Bytes childRlp) {
        if (childRlp.size() < 32) {
            w.writeRLP(childRlp); // inline the node's RLP directly
        } else {
            w.writeValue(Hash.keccak256(childRlp)); // 32-byte hash reference
        }
    }

    /** Largest nibble index c (>= depth) such that every entry shares nibbles [depth, c). */
    private static int commonPrefixEnd(List<Entry> entries, int depth) {
        int[] first = entries.get(0).path;
        int[] last = entries.get(entries.size() - 1).path; // sorted, so these bound the set
        int c = depth;
        while (c < first.length && c < last.length && first[c] == last[c]) c++;
        return c;
    }

    /** Hex-prefix (compact) encoding of a nibble path with the leaf/extension flag. */
    private static Bytes hexPrefix(int[] path, boolean leaf) {
        boolean odd = (path.length & 1) == 1;
        int flag = (leaf ? 2 : 0) | (odd ? 1 : 0);
        int[] nibs = new int[(odd ? 1 : 2) + path.length];
        int idx = 0;
        nibs[idx++] = flag;
        if (!odd) nibs[idx++] = 0; // even path: pad first byte's low nibble
        for (int p : path) nibs[idx++] = p;
        byte[] out = new byte[nibs.length / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((nibs[2 * i] << 4) | nibs[2 * i + 1]);
        }
        return Bytes.wrap(out);
    }

    private static int[] nibbles(Bytes key) {
        int[] out = new int[key.size() * 2];
        for (int i = 0; i < key.size(); i++) {
            int b = key.get(i) & 0xFF;
            out[2 * i] = b >>> 4;
            out[2 * i + 1] = b & 0x0F;
        }
        return out;
    }

    /** Minimal big-endian byte representation of a non-negative long (empty for 0). */
    private static Bytes minimalBytes(long v) {
        if (v == 0) return Bytes.EMPTY;
        byte[] tmp = new byte[8];
        int i = 8;
        while (v != 0) { tmp[--i] = (byte) (v & 0xFF); v >>>= 8; }
        return Bytes.wrap(java.util.Arrays.copyOfRange(tmp, i, 8));
    }

    private static int compareNibbles(int[] a, int[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            if (a[i] != b[i]) return Integer.compare(a[i], b[i]);
        }
        return Integer.compare(a.length, b.length);
    }

    private record Entry(int[] path, Bytes value) {}
}
