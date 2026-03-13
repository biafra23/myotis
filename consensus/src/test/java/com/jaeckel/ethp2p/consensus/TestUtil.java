package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import supranational.blst.P1;
import supranational.blst.P2;
import supranational.blst.SecretKey;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Shared test utilities for BLS signing, Merkle tree construction, and dummy object creation.
 */
public final class TestUtil {

    private static final String DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    private TestUtil() {}

    /**
     * Generate a deterministic BLS secret key from a seed.
     * Uses SHA-256 of the seed to produce a 32-byte scalar, then loads via from_bendian.
     */
    public static SecretKey generateSecretKey(int seed) {
        byte[] seedBytes = new byte[32];
        seedBytes[0] = (byte) (seed);
        seedBytes[1] = (byte) (seed >>> 8);
        seedBytes[2] = (byte) (seed >>> 16);
        seedBytes[3] = (byte) (seed >>> 24);
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(seedBytes);
            // Ensure the scalar is valid (< group order) by clearing the top bit
            hash[0] &= 0x7F;
            // Ensure non-zero
            if (isAllZero(hash)) hash[31] = 0x01;
            SecretKey sk = new SecretKey();
            sk.from_bendian(hash);
            return sk;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Get the compressed public key (48 bytes) for a secret key.
     */
    public static byte[] getPublicKey(SecretKey sk) {
        return new P1(sk).compress();
    }

    /**
     * Sign a message with a secret key using the Ethereum 2.0 DST.
     * Returns 96-byte compressed G2 signature.
     */
    public static byte[] blsSign(SecretKey sk, byte[] message) {
        return new P2().hash_to(message, DST).sign_with(sk).compress();
    }

    /**
     * Aggregate multiple compressed G2 signatures into one.
     */
    public static byte[] aggregateSignatures(List<byte[]> compressedSigs) {
        P2 agg = new P2(new supranational.blst.P2_Affine(compressedSigs.get(0)));
        for (int i = 1; i < compressedSigs.size(); i++) {
            agg.aggregate(new supranational.blst.P2_Affine(compressedSigs.get(i)));
        }
        return agg.compress();
    }

    /**
     * Build a complete binary Merkle tree from leaves and return all node hashes.
     * The returned array has length 2*size where size = nextPow2(leaves.length).
     * Index 1 = root, index 2..3 = depth-1 nodes, etc.
     * Leaves at indices [size .. size+leaves.length-1], remaining padded with ZERO_HASHES[0].
     */
    public static byte[][] buildMerkleTree(byte[][] leaves) {
        int size = nextPowerOfTwo(leaves.length);
        byte[][] tree = new byte[2 * size][];
        // Fill leaves
        for (int i = 0; i < size; i++) {
            tree[size + i] = (i < leaves.length) ? leaves[i] : SszUtil.ZERO_HASHES[0];
        }
        // Build upward
        for (int i = size - 1; i >= 1; i--) {
            tree[i] = SszUtil.sha256(tree[2 * i], tree[2 * i + 1]);
        }
        return tree;
    }

    /**
     * Extract a Merkle branch for a given leaf index from a tree built by buildMerkleTree.
     * Returns the sibling hashes from leaf to root (length = depth).
     */
    public static byte[][] extractBranch(byte[][] tree, int depth, int leafIndex) {
        int size = tree.length / 2;
        byte[][] branch = new byte[depth][];
        int idx = size + leafIndex;
        for (int i = 0; i < depth; i++) {
            // Sibling is the other child of the same parent
            branch[i] = (idx % 2 == 0) ? tree[idx + 1] : tree[idx - 1];
            idx /= 2;
        }
        return branch;
    }

    /**
     * Create a dummy LightClientHeader wrapping a BeaconBlockHeader
     * with zero execution payload and zero execution branch.
     */
    public static LightClientHeader dummyLightClientHeader(BeaconBlockHeader beacon) {
        return new LightClientHeader(beacon, dummyExecutionPayloadHeader(), zeroExecutionBranch());
    }

    /**
     * Create an all-zero ExecutionPayloadHeader (Electra variant with request roots).
     */
    public static ExecutionPayloadHeader dummyExecutionPayloadHeader() {
        return new ExecutionPayloadHeader(
                new byte[32],  // parentHash
                new byte[20],  // feeRecipient
                new byte[32],  // stateRoot
                new byte[32],  // receiptsRoot
                new byte[256], // logsBloom
                new byte[32],  // prevRandao
                0L, 0L, 0L, 0L, // blockNumber, gasLimit, gasUsed, timestamp
                new byte[0],   // extraData
                new byte[32],  // baseFeePerGas
                new byte[32],  // blockHash
                new byte[32],  // transactionsRoot
                new byte[32],  // withdrawalsRoot
                0L, 0L,        // blobGasUsed, excessBlobGas
                new byte[32],  // depositRequestsRoot
                new byte[32],  // withdrawalRequestsRoot
                new byte[32]   // consolidationRequestsRoot
        );
    }

    private static byte[][] zeroExecutionBranch() {
        byte[][] branch = new byte[4][32];
        return branch;
    }

    private static int nextPowerOfTwo(int n) {
        if (n <= 1) return 1;
        int p = 1;
        while (p < n) p <<= 1;
        return p;
    }

    private static boolean isAllZero(byte[] b) {
        for (byte v : b) if (v != 0) return false;
        return true;
    }
}
