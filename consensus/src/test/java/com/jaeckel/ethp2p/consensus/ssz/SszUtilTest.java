package com.jaeckel.ethp2p.consensus.ssz;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SszUtil SHA-256 merkleization.
 * Reference values from https://github.com/ethereum/consensus-spec-tests
 */
class SszUtilTest {

    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    private static final byte[] SHA256_EMPTY =
            hexBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    @Test
    void zeroHashDepth0IsAllZeros() {
        assertArrayEquals(new byte[32], SszUtil.ZERO_HASHES[0]);
    }

    @Test
    void zeroHashDepth1IsSha256OfTwoZeroChunks() {
        byte[] expected = SszUtil.sha256(new byte[32], new byte[32]);
        assertArrayEquals(expected, SszUtil.ZERO_HASHES[1]);
    }

    @Test
    void merkleizeSingleChunk() {
        byte[] chunk = new byte[32];
        chunk[0] = 0x01;
        byte[][] chunks = {chunk};
        byte[] root = SszUtil.merkleize(chunks);
        // Single chunk — root is the chunk itself (padded to power-of-2 = 1)
        assertArrayEquals(chunk, root);
    }

    @Test
    void merkleizeTwoChunks() {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        a[0] = 0x01;
        b[0] = 0x02;
        byte[][] chunks = {a, b};
        byte[] root = SszUtil.merkleize(chunks);
        byte[] expected = SszUtil.sha256(a, b);
        assertArrayEquals(expected, root);
    }

    @Test
    void merkleizeFourChunks() {
        byte[][] chunks = new byte[4][32];
        for (int i = 0; i < 4; i++) chunks[i][0] = (byte) (i + 1);
        byte[] root = SszUtil.merkleize(chunks);

        byte[] h01 = SszUtil.sha256(chunks[0], chunks[1]);
        byte[] h23 = SszUtil.sha256(chunks[2], chunks[3]);
        byte[] expected = SszUtil.sha256(h01, h23);
        assertArrayEquals(expected, root);
    }

    @Test
    void merkleizeWithLimitPadsWithZeroHashes() {
        // 1 chunk with limit=4 should pad with zero hashes to depth 2
        byte[] chunk = new byte[32];
        chunk[0] = (byte) 0xAB;
        byte[][] chunks = {chunk};
        byte[] root = SszUtil.merkleize(chunks, 4);

        byte[] h01 = SszUtil.sha256(chunk, new byte[32]);             // pad[0] = ZERO_HASH[0]
        byte[] h23 = SszUtil.sha256(new byte[32], new byte[32]);      // both ZERO_HASH[0]
        byte[] expected = SszUtil.sha256(h01, h23);
        assertArrayEquals(expected, root);
    }

    @Test
    void hashTreeRootUint64Zero() {
        byte[] root = SszUtil.hashTreeRootUint64(0L);
        assertArrayEquals(new byte[32], root);
    }

    @Test
    void hashTreeRootUint64One() {
        byte[] root = SszUtil.hashTreeRootUint64(1L);
        byte[] expected = new byte[32];
        expected[0] = 0x01;
        assertArrayEquals(expected, root);
    }

    @Test
    void hashTreeRootUint64BigEndianNotUsed() {
        // 256 in LE is [0x00, 0x01, 0, 0, ...] not [0, 0, 0x01, 0x00, ...]
        byte[] root = SszUtil.hashTreeRootUint64(256L);
        assertEquals(0x00, root[0] & 0xFF);
        assertEquals(0x01, root[1] & 0xFF);
        assertEquals(0x00, root[2] & 0xFF);
    }

    @Test
    void mixInLength() {
        byte[] root = new byte[32];
        root[0] = 0x42;
        byte[] mixed = SszUtil.mixInLength(root, 5L);
        // Should be SHA256(root || LE64(5) zero-padded to 32 bytes)
        byte[] lengthChunk = new byte[32];
        lengthChunk[0] = 0x05;
        byte[] expected = SszUtil.sha256(root, lengthChunk);
        assertArrayEquals(expected, mixed);
    }

    @Test
    void hashTreeRootContainerTwoFields() {
        byte[] f0 = SszUtil.hashTreeRootUint64(42L);
        byte[] f1 = new byte[32];
        f1[15] = (byte) 0xFF;
        byte[] root = SszUtil.hashTreeRootContainer(f0, f1);
        byte[] expected = SszUtil.sha256(f0, f1);
        assertArrayEquals(expected, root);
    }

    @Test
    void verifyMerkleBranchSingleDepth() {
        // leaf at index 0, depth 1, branch = [sibling]
        byte[] leaf = new byte[32];
        leaf[0] = 0x01;
        byte[] sibling = new byte[32];
        sibling[0] = 0x02;
        byte[] root = SszUtil.sha256(leaf, sibling); // leaf is left child

        assertTrue(SszUtil.verifyMerkleBranch(leaf, new byte[][]{sibling}, 1, 0, root));
        assertFalse(SszUtil.verifyMerkleBranch(leaf, new byte[][]{sibling}, 1, 1, root));
    }

    @Test
    void verifyMerkleBranchDepth2() {
        // 4 leaves, verify leaf at index 2 (binary 10)
        byte[][] leaves = new byte[4][32];
        for (int i = 0; i < 4; i++) leaves[i][0] = (byte) (i + 1);

        byte[] h01 = SszUtil.sha256(leaves[0], leaves[1]);
        byte[] h23 = SszUtil.sha256(leaves[2], leaves[3]);
        byte[] root = SszUtil.sha256(h01, h23);

        // leaf=leaves[2], index=2 (binary 10): first branch node is leaves[3] (right sibling),
        // second branch node is h01 (left sibling of h23)
        byte[][] branch = {leaves[3], h01};
        assertTrue(SszUtil.verifyMerkleBranch(leaves[2], branch, 2, 2, root));
    }

    // Utility
    static byte[] hexBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
