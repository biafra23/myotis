package com.jaeckel.ethp2p.consensus.ssz;

import com.jaeckel.ethp2p.consensus.TestUtil;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive tests for SszUtil.verifyMerkleBranch with larger trees and tampering.
 */
class SszUtilMerkleBranchTest {

    @Test
    void validBranchDepth3() {
        // 8-leaf tree, verify each leaf position
        byte[][] leaves = new byte[8][32];
        for (int i = 0; i < 8; i++) {
            leaves[i][0] = (byte) (i + 1);
            leaves[i][31] = (byte) (0xFF - i);
        }

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];

        for (int leafIdx = 0; leafIdx < 8; leafIdx++) {
            byte[][] branch = TestUtil.extractBranch(tree, 3, leafIdx);
            assertTrue(SszUtil.verifyMerkleBranch(leaves[leafIdx], branch, 3, leafIdx, root),
                    "Valid branch should verify for leaf " + leafIdx);
        }
    }

    @Test
    void validBranchDepth6MatchesFinalityDepth() {
        // 64-leaf tree at depth 6 (matches FINALIZED_ROOT_DEPTH)
        byte[][] leaves = new byte[64][32];
        for (int i = 0; i < 64; i++) {
            leaves[i][0] = (byte) i;
            leaves[i][1] = (byte) (i >>> 8);
        }

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];

        // Verify a few representative positions
        for (int leafIdx : new int[]{0, 1, 31, 41, 63}) {
            byte[][] branch = TestUtil.extractBranch(tree, 6, leafIdx);
            assertTrue(SszUtil.verifyMerkleBranch(leaves[leafIdx], branch, 6, leafIdx, root),
                    "Valid branch should verify at depth 6 for leaf " + leafIdx);
        }
    }

    @Test
    void validBranchDepth5MatchesSyncCommitteeDepth() {
        // 32-leaf tree at depth 5 (matches CURRENT_SYNC_COMMITTEE_DEPTH)
        byte[][] leaves = new byte[32][32];
        for (int i = 0; i < 32; i++) {
            leaves[i][0] = (byte) (i + 100);
        }

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];

        for (int leafIdx : new int[]{0, 15, 22, 31}) {
            byte[][] branch = TestUtil.extractBranch(tree, 5, leafIdx);
            assertTrue(SszUtil.verifyMerkleBranch(leaves[leafIdx], branch, 5, leafIdx, root),
                    "Valid branch should verify at depth 5 for leaf " + leafIdx);
        }
    }

    @Test
    void rejectsWrongLeaf() {
        byte[][] leaves = new byte[8][32];
        for (int i = 0; i < 8; i++) leaves[i][0] = (byte) (i + 1);

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];
        byte[][] branch = TestUtil.extractBranch(tree, 3, 3);

        // Tamper the leaf
        byte[] tamperedLeaf = Arrays.copyOf(leaves[3], 32);
        tamperedLeaf[0] ^= 0x01;
        assertFalse(SszUtil.verifyMerkleBranch(tamperedLeaf, branch, 3, 3, root));
    }

    @Test
    void rejectsWrongRoot() {
        byte[][] leaves = new byte[8][32];
        for (int i = 0; i < 8; i++) leaves[i][0] = (byte) (i + 1);

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];
        byte[][] branch = TestUtil.extractBranch(tree, 3, 2);

        byte[] wrongRoot = Arrays.copyOf(root, 32);
        wrongRoot[0] ^= 0x01;
        assertFalse(SszUtil.verifyMerkleBranch(leaves[2], branch, 3, 2, wrongRoot));
    }

    @Test
    void rejectsWrongBranchNode() {
        byte[][] leaves = new byte[8][32];
        for (int i = 0; i < 8; i++) leaves[i][0] = (byte) (i + 1);

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];
        byte[][] branch = TestUtil.extractBranch(tree, 3, 5);

        // Flip a byte in the middle branch node
        branch[1] = Arrays.copyOf(branch[1], 32);
        branch[1][0] ^= 0x01;
        assertFalse(SszUtil.verifyMerkleBranch(leaves[5], branch, 3, 5, root));
    }

    @Test
    void rejectsWrongIndex() {
        byte[][] leaves = new byte[8][32];
        for (int i = 0; i < 8; i++) leaves[i][0] = (byte) (i + 1);

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];
        byte[][] branch = TestUtil.extractBranch(tree, 3, 4);

        // Use wrong index (5 instead of 4)
        assertFalse(SszUtil.verifyMerkleBranch(leaves[4], branch, 3, 5, root));
    }

    @Test
    void rejectsSwappedBranchNodes() {
        byte[][] leaves = new byte[8][32];
        for (int i = 0; i < 8; i++) leaves[i][0] = (byte) (i + 1);

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];
        byte[][] branch = TestUtil.extractBranch(tree, 3, 0);

        // Swap branch[0] and branch[1]
        byte[] tmp = branch[0];
        branch[0] = branch[1];
        branch[1] = tmp;
        assertFalse(SszUtil.verifyMerkleBranch(leaves[0], branch, 3, 0, root));
    }

    @Test
    void rejectsBranchLengthMismatch() {
        byte[][] leaves = new byte[8][32];
        for (int i = 0; i < 8; i++) leaves[i][0] = (byte) (i + 1);

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[] root = tree[1];
        byte[][] branch = TestUtil.extractBranch(tree, 3, 0);

        // Truncate branch to length 2 (should be 3)
        byte[][] shortBranch = Arrays.copyOf(branch, 2);
        assertFalse(SszUtil.verifyMerkleBranch(leaves[0], shortBranch, 3, 0, root));

        // Extend branch to length 4
        byte[][] longBranch = Arrays.copyOf(branch, 4);
        longBranch[3] = new byte[32];
        assertFalse(SszUtil.verifyMerkleBranch(leaves[0], longBranch, 3, 0, root));
    }
}
