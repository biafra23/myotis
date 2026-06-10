package com.jaeckel.ethp2p.consensus.proof;

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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrderedTrieRootTest {

    // Static block: runs before the static field initializers below, which call
    // keccak256 (needs the BC provider). @BeforeAll would be too late for those.
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** The empty-trie root is keccak256(RLP("")) = keccak256(0x80). Derived here from
     *  the proven-correct primitives (keccak256 is validated against the "abc" vector in
     *  {@link #keccakIsRealEthereumKeccak256()}) rather than a hand-copied constant. */
    private static final Bytes32 KNOWN_EMPTY_ROOT =
            Hash.keccak256(Bytes.fromHexString("0x80"));

    @Test
    void keccakIsRealEthereumKeccak256() {
        // keccak256("abc") — the canonical NIST-Keccak (not SHA3) test vector.
        assertEquals(
                Bytes32.fromHexString("0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
                Hash.keccak256(Bytes.wrap("abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII))));
    }

    @Test
    void emptyListRootIsTheCanonicalEmptyTrieRoot() {
        assertEquals(KNOWN_EMPTY_ROOT, OrderedTrieRoot.ofList(List.of()));
        assertEquals(KNOWN_EMPTY_ROOT, OrderedTrieRoot.EMPTY_ROOT);
    }

    /** Single item → single leaf at key RLP(0)=0x80 (nibbles [8,0], even). Root is the
     *  hash of leaf [HP(even-leaf [8,0])=0x2080, value], built independently here. */
    @Test
    void singleItemMatchesIndependentlyBuiltLeaf() {
        Bytes v = Bytes.fromHexString("0x01020304");
        Bytes leafRlp = RLP.encodeList(w -> {
            w.writeValue(Bytes.fromHexString("0x2080")); // HP(leaf, [8,0])
            w.writeValue(v);
        });
        assertEquals(Hash.keccak256(leafRlp), OrderedTrieRoot.ofList(List.of(v)));
    }

    /** Two items diverging at nibble 0 → a branch node with inlined small leaves at
     *  slots 0 (RLP(1)=0x01 → [0,1]) and 8 (RLP(0)=0x80 → [8,0]). Built independently. */
    @Test
    void twoSmallItemsMatchIndependentlyBuiltBranchWithInlineLeaves() {
        Bytes v0 = Bytes.fromHexString("0xaa"); // index 0, path [8,0]
        Bytes v1 = Bytes.fromHexString("0xbb"); // index 1, path [0,1]
        Bytes leaf0 = RLP.encodeList(w -> { w.writeValue(Bytes.fromHexString("0x30")); w.writeValue(v0); }); // odd leaf [0]
        Bytes leaf1 = RLP.encodeList(w -> { w.writeValue(Bytes.fromHexString("0x31")); w.writeValue(v1); }); // odd leaf [1]
        assertTrue(leaf0.size() < 32 && leaf1.size() < 32, "leaves should inline");
        Bytes branch = RLP.encodeList(w -> {
            for (int n = 0; n < 16; n++) {
                if (n == 0) w.writeRLP(leaf1);
                else if (n == 8) w.writeRLP(leaf0);
                else w.writeValue(Bytes.EMPTY);
            }
            w.writeValue(Bytes.EMPTY); // branch value
        });
        assertEquals(Hash.keccak256(branch), OrderedTrieRoot.ofList(List.of(v0, v1)));
    }

    /** Same shape but a large value at index 0 forces a hashed (not inlined) child ref. */
    @Test
    void largeLeafForcesHashedChildReference() {
        Bytes v0 = Bytes.repeat((byte) 0x11, 40); // >32 once wrapped in a leaf → hashed ref
        Bytes v1 = Bytes.fromHexString("0xbb");
        Bytes leaf0 = RLP.encodeList(w -> { w.writeValue(Bytes.fromHexString("0x30")); w.writeValue(v0); });
        Bytes leaf1 = RLP.encodeList(w -> { w.writeValue(Bytes.fromHexString("0x31")); w.writeValue(v1); });
        assertTrue(leaf0.size() >= 32, "leaf0 should be hashed");
        Bytes branch = RLP.encodeList(w -> {
            for (int n = 0; n < 16; n++) {
                if (n == 0) w.writeRLP(leaf1);
                else if (n == 8) w.writeValue(Hash.keccak256(leaf0));
                else w.writeValue(Bytes.EMPTY);
            }
            w.writeValue(Bytes.EMPTY);
        });
        assertEquals(Hash.keccak256(branch), OrderedTrieRoot.ofList(List.of(v0, v1)));
    }

    /** Two keys sharing a 2-nibble prefix [1,2] force an EXTENSION node above a branch.
     *  Built independently: ext[HP(ext,[1,2])=0x0012, branch{slot3=leaf[4], slot5=leaf[6]}]. */
    @Test
    void sharedPrefixKeysProduceExtensionNode() {
        Bytes kA = Bytes.fromHexString("0x1234"); // nibbles [1,2,3,4]
        Bytes kB = Bytes.fromHexString("0x1256"); // nibbles [1,2,5,6]
        Bytes vA = Bytes.fromHexString("0xaa");
        Bytes vB = Bytes.fromHexString("0xbb");
        Bytes leafA = RLP.encodeList(w -> { w.writeValue(Bytes.fromHexString("0x34")); w.writeValue(vA); }); // odd leaf [4]
        Bytes leafB = RLP.encodeList(w -> { w.writeValue(Bytes.fromHexString("0x36")); w.writeValue(vB); }); // odd leaf [6]
        Bytes branch = RLP.encodeList(w -> {
            for (int n = 0; n < 16; n++) {
                if (n == 3) w.writeRLP(leafA);
                else if (n == 5) w.writeRLP(leafB);
                else w.writeValue(Bytes.EMPTY);
            }
            w.writeValue(Bytes.EMPTY);
        });
        assertTrue(branch.size() < 32, "branch should inline into the extension");
        Bytes ext = RLP.encodeList(w -> {
            w.writeValue(Bytes.fromHexString("0x0012")); // HP(extension, [1,2])
            w.writeRLP(branch);
        });
        assertEquals(Hash.keccak256(ext),
                OrderedTrieRoot.rootOf(List.of(kA, kB), List.of(vA, vB)));
    }

    @Test
    void verifyHelperMatchesAndRejects() {
        Bytes v = Bytes.fromHexString("0x01020304");
        Bytes32 root = OrderedTrieRoot.ofList(List.of(v));
        assertTrue(OrderedTrieRoot.verify(List.of(v), root));
        assertFalse(OrderedTrieRoot.verify(List.of(v), KNOWN_EMPTY_ROOT));
    }
}
