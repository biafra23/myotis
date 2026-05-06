package com.jaeckel.ethp2p.core.trie;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Verifies the proof verifier against hand-constructed tries.
 *
 * <p>Each test builds a small trie programmatically (RLP-encoding the nodes,
 * computing keccak256 hashes), then hands the verifier the trusted root and
 * the proof bytes. This avoids relying on an external trie implementation
 * for fixtures while still exercising every code path.
 */
class MerklePatriciaProofVerifierTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ---- Single-leaf trie --------------------------------------------------

    @Test
    void singleLeafTrieFindsValue() {
        // Trie with one entry: key=0x1234, value=32-byte 0xaa.
        byte[] key = hex("1234");
        Bytes value = Bytes.wrap(repeat((byte) 0xaa, 32));

        // Leaf node: [hexPrefix(key_nibbles, leaf=true), value]
        byte[] encodedPath = HexPrefix.encode(HexPrefix.toNibbles(key), true);
        Bytes leafRlp = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(encodedPath));
            w.writeValue(value);
        });
        Bytes32 root = keccak(leafRlp);

        var result = MerklePatriciaProofVerifier.verify(root, key, List.of(leafRlp));
        var found = assertInstanceOf(MerklePatriciaProofVerifier.Result.Found.class, result);
        assertEquals(value, found.value());
    }

    @Test
    void singleLeafTrieDifferentKeyIsAbsent() {
        // Same trie as above but query a different key sharing the prefix.
        byte[] storedKey = hex("1234");
        byte[] queriedKey = hex("1235");
        Bytes value = Bytes.wrap(repeat((byte) 0xaa, 32));

        byte[] encodedPath = HexPrefix.encode(HexPrefix.toNibbles(storedKey), true);
        Bytes leafRlp = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(encodedPath));
            w.writeValue(value);
        });
        Bytes32 root = keccak(leafRlp);

        var result = MerklePatriciaProofVerifier.verify(root, queriedKey, List.of(leafRlp));
        assertInstanceOf(MerklePatriciaProofVerifier.Result.Absent.class, result);
    }

    // ---- Empty trie --------------------------------------------------------

    @Test
    void emptyTrieAnyKeyIsAbsent() {
        var result = MerklePatriciaProofVerifier.verify(
                MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT,
                hex("deadbeef"),
                List.of());
        assertInstanceOf(MerklePatriciaProofVerifier.Result.Absent.class, result);
    }

    @Test
    void emptyProofForNonEmptyRootIsInvalid() {
        Bytes32 fakeRoot = Bytes32.fromHexString(
                "0x1111111111111111111111111111111111111111111111111111111111111111");
        var result = MerklePatriciaProofVerifier.verify(fakeRoot, hex("aa"), List.of());
        assertInstanceOf(MerklePatriciaProofVerifier.Result.Invalid.class, result);
    }

    // ---- Extension + branch + two leaves -----------------------------------

    @Test
    void twoLeafTrieFindsBothKeys() {
        var trie = buildTwoLeafTrie();

        var r1 = MerklePatriciaProofVerifier.verify(
                trie.root, trie.key1, List.of(trie.extension, trie.branch, trie.leaf1));
        assertEquals(trie.value1,
                assertInstanceOf(MerklePatriciaProofVerifier.Result.Found.class, r1).value());

        var r2 = MerklePatriciaProofVerifier.verify(
                trie.root, trie.key2, List.of(trie.extension, trie.branch, trie.leaf2));
        assertEquals(trie.value2,
                assertInstanceOf(MerklePatriciaProofVerifier.Result.Found.class, r2).value());
    }

    @Test
    void twoLeafTrieKeyOutsideBranchIsAbsent() {
        var trie = buildTwoLeafTrie();
        // Key shares the [1,2,3] prefix but lands on an empty branch slot.
        byte[] absentKey = hex("1239");
        var result = MerklePatriciaProofVerifier.verify(
                trie.root, absentKey, List.of(trie.extension, trie.branch));
        assertInstanceOf(MerklePatriciaProofVerifier.Result.Absent.class, result);
    }

    @Test
    void twoLeafTrieKeyOutsideExtensionIsAbsent() {
        var trie = buildTwoLeafTrie();
        // Key doesn't even match the root extension's prefix [1,2,3].
        byte[] absentKey = hex("abcd");
        var result = MerklePatriciaProofVerifier.verify(
                trie.root, absentKey, List.of(trie.extension));
        assertInstanceOf(MerklePatriciaProofVerifier.Result.Absent.class, result);
    }

    // ---- Proof tampering ---------------------------------------------------

    @Test
    void tamperedNodeFailsVerification() {
        var trie = buildTwoLeafTrie();
        // Replace one byte of leaf1's value, breaking its hash.
        byte[] tampered = trie.leaf1.toArray();
        tampered[tampered.length - 1] ^= 0x01;
        Bytes tamperedLeaf = Bytes.wrap(tampered);

        var result = MerklePatriciaProofVerifier.verify(
                trie.root, trie.key1, List.of(trie.extension, trie.branch, tamperedLeaf));
        // The leaf's hash no longer matches what the branch points at, so the
        // descent into branch[4] looks for a node whose hash doesn't exist in
        // the proof — surfaces as Invalid("missing node ...").
        assertInstanceOf(MerklePatriciaProofVerifier.Result.Invalid.class, result);
    }

    @Test
    void missingProofNodeFailsVerification() {
        var trie = buildTwoLeafTrie();
        // Drop the branch from the proof, leaving extension → ??? for descent.
        var result = MerklePatriciaProofVerifier.verify(
                trie.root, trie.key1, List.of(trie.extension, trie.leaf1));
        assertInstanceOf(MerklePatriciaProofVerifier.Result.Invalid.class, result);
    }

    // ---- Embedded sub-32-byte child ---------------------------------------

    @Test
    void embeddedLeafInBranchVerifies() {
        // Build a trie where the leaf nodes are small enough to be embedded
        // (RLP < 32 bytes). Use 1-byte values.
        byte[] key1 = hex("12");
        byte[] key2 = hex("13");
        Bytes value1 = Bytes.fromHexString("0x42");
        Bytes value2 = Bytes.fromHexString("0xab");

        // Both keys have nibbles [1, X]. Root branch consumes nibble 1 — wait,
        // actually the root *itself* is a branch in this layout, not preceded
        // by an extension, since the keys diverge at the very first nibble
        // position. With keys [1,2] and [1,3] they share prefix [1] and
        // diverge at nibble 2/3, so we still need an extension([1])->branch.
        byte[] leaf1Path = HexPrefix.encode(new byte[0], true);   // empty path leaf
        byte[] leaf2Path = HexPrefix.encode(new byte[0], true);
        Bytes leaf1Rlp = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(leaf1Path));
            w.writeValue(value1);
        });
        Bytes leaf2Rlp = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(leaf2Path));
            w.writeValue(value2);
        });
        // These leaves are small (a few bytes); they will be embedded in the
        // branch as RLP lists rather than referenced by hash.

        Bytes branchRlp = RLP.encodeList(w -> {
            for (int i = 0; i < 2; i++) w.writeValue(Bytes.EMPTY);
            // slot[2] = leaf1, slot[3] = leaf2 (embedded).
            w.writeRLP(leaf1Rlp);
            w.writeRLP(leaf2Rlp);
            for (int i = 4; i < 16; i++) w.writeValue(Bytes.EMPTY);
            w.writeValue(Bytes.EMPTY); // slot[16]
        });
        // The branch itself is small enough (~30 bytes with 1-byte values) it
        // would also be embedded if it had a parent — but here it's the root.
        Bytes32 branchHash = keccak(branchRlp);
        byte[] extPath = HexPrefix.encode(new byte[]{1}, false);
        Bytes extRlp = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(extPath));
            w.writeValue(branchHash);
        });
        Bytes32 root = keccak(extRlp);

        var r1 = MerklePatriciaProofVerifier.verify(root, key1, List.of(extRlp, branchRlp));
        // Note: leaf1Rlp and leaf2Rlp are NOT in the proof — they're embedded.
        assertEquals(value1,
                assertInstanceOf(MerklePatriciaProofVerifier.Result.Found.class, r1).value());

        var r2 = MerklePatriciaProofVerifier.verify(root, key2, List.of(extRlp, branchRlp));
        assertEquals(value2,
                assertInstanceOf(MerklePatriciaProofVerifier.Result.Found.class, r2).value());
    }

    // ---- helpers -----------------------------------------------------------

    private record TwoLeafTrie(
            byte[] key1, byte[] key2,
            Bytes value1, Bytes value2,
            Bytes leaf1, Bytes leaf2,
            Bytes branch, Bytes extension,
            Bytes32 root) {}

    /**
     * Build a trie with two leaves sharing prefix [1,2,3]:
     *   key1 = 0x1234 → 32-byte 0xaa value (leaf1, hashed)
     *   key2 = 0x1235 → 32-byte 0xbb value (leaf2, hashed)
     * Structure: extension([1,2,3]) → branch with slot[4]=leaf1Hash, slot[5]=leaf2Hash.
     */
    private static TwoLeafTrie buildTwoLeafTrie() {
        byte[] key1 = hex("1234");
        byte[] key2 = hex("1235");
        Bytes value1 = Bytes.wrap(repeat((byte) 0xaa, 32));
        Bytes value2 = Bytes.wrap(repeat((byte) 0xbb, 32));

        // Leaf nodes: empty path (branch consumes the last nibble), value-bearing.
        byte[] emptyLeafPath = HexPrefix.encode(new byte[0], true); // [0x20]
        Bytes leaf1 = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(emptyLeafPath));
            w.writeValue(value1);
        });
        Bytes leaf2 = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(emptyLeafPath));
            w.writeValue(value2);
        });
        Bytes32 hash1 = keccak(leaf1);
        Bytes32 hash2 = keccak(leaf2);

        // Branch: 17 entries. slot[4]=hash1, slot[5]=hash2, all others empty.
        Bytes branch = RLP.encodeList(w -> {
            for (int i = 0; i < 4; i++) w.writeValue(Bytes.EMPTY);
            w.writeValue(hash1);
            w.writeValue(hash2);
            for (int i = 6; i < 16; i++) w.writeValue(Bytes.EMPTY);
            w.writeValue(Bytes.EMPTY); // slot[16]
        });
        Bytes32 branchHash = keccak(branch);

        // Extension: path = [1,2,3] (odd nibbles), child = branchHash.
        byte[] extPath = HexPrefix.encode(new byte[]{1, 2, 3}, false); // [0x11, 0x23]
        Bytes extension = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(extPath));
            w.writeValue(branchHash);
        });
        Bytes32 root = keccak(extension);

        return new TwoLeafTrie(key1, key2, value1, value2, leaf1, leaf2, branch, extension, root);
    }

    private static Bytes32 keccak(Bytes rlp) {
        return Bytes32.wrap(Hash.keccak256(rlp).toArrayUnsafe());
    }

    private static byte[] hex(String s) {
        return java.util.HexFormat.of().parseHex(s);
    }

    private static byte[] repeat(byte b, int n) {
        byte[] out = new byte[n];
        java.util.Arrays.fill(out, b);
        return out;
    }
}
