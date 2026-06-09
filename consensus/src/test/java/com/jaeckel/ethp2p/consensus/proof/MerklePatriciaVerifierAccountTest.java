package com.jaeckel.ethp2p.consensus.proof;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that {@link MerklePatriciaVerifier#verifyAndExtractAccount} returns the
 * {@code storageRoot}/{@code codeHash} taken from the <em>proof-verified leaf</em>
 * (the value whose hash chains to the trusted state root), so callers no longer
 * have to trust a snap peer's separately-decoded slim account body for those two
 * fields. Tries are hand-built (RLP + keccak), same approach as the core trie test.
 */
class MerklePatriciaVerifierAccountTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final byte[] ADDRESS = repeat((byte) 0x01, 20);
    private static final long NONCE = 5;
    private static final BigInteger BALANCE = new BigInteger("1000000000000000000"); // 1 ETH
    private static final byte[] STORAGE_ROOT = repeat((byte) 0x11, 32);
    private static final byte[] CODE_HASH = repeat((byte) 0x22, 32);

    /** A single-leaf account trie at keccak256(ADDRESS): returns (root, proof). */
    private record Trie(byte[] root, List<byte[]> proof) {}

    private static Trie buildAccountTrie(long nonce, BigInteger balance,
                                         byte[] storageRoot, byte[] codeHash) {
        byte[] keyHash = Hash.keccak256(Bytes.wrap(ADDRESS)).toArrayUnsafe();
        // Canonical account leaf value: RLP[nonce, balance, storageRoot, codeHash].
        Bytes account = RLP.encodeList(w -> {
            w.writeLong(nonce);
            w.writeBigInteger(balance);
            w.writeValue(Bytes.wrap(storageRoot));
            w.writeValue(Bytes.wrap(codeHash));
        });
        // Leaf node: [hexPrefix(64 nibbles, leaf=true) = 0x20||keyHash, account].
        byte[] leafPath = new byte[33];
        leafPath[0] = 0x20;
        System.arraycopy(keyHash, 0, leafPath, 1, 32);
        Bytes leaf = RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(leafPath));
            w.writeValue(account);
        });
        byte[] root = Hash.keccak256(leaf).toArrayUnsafe();
        return new Trie(root, List.of(leaf.toArrayUnsafe()));
    }

    @Test
    void returnsStorageRootAndCodeHashFromProvenLeaf() {
        Trie t = buildAccountTrie(NONCE, BALANCE, STORAGE_ROOT, CODE_HASH);
        var v = MerklePatriciaVerifier.verifyAndExtractAccount(
                t.root, ADDRESS, t.proof, NONCE, BALANCE.toString());
        assertNotNull(v);
        assertArrayEquals(STORAGE_ROOT, v.storageRoot());
        assertArrayEquals(CODE_HASH, v.codeHash());
    }

    @Test
    void extractsCanonicalEmptyValuesForEoaLeaf() {
        // An EOA's leaf carries the canonical empty-trie root + empty-code hash.
        byte[] emptyTrieRoot = Hash.keccak256(Bytes.of((byte) 0x80)).toArrayUnsafe();
        byte[] emptyCodeHash = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();
        Trie t = buildAccountTrie(0, BigInteger.ZERO, emptyTrieRoot, emptyCodeHash);
        var v = MerklePatriciaVerifier.verifyAndExtractAccount(
                t.root, ADDRESS, t.proof, 0, "0");
        assertNotNull(v);
        assertArrayEquals(emptyTrieRoot, v.storageRoot());
        assertArrayEquals(emptyCodeHash, v.codeHash());
    }

    @Test
    void nonceMismatchRejected() {
        Trie t = buildAccountTrie(NONCE, BALANCE, STORAGE_ROOT, CODE_HASH);
        assertNull(MerklePatriciaVerifier.verifyAndExtractAccount(
                t.root, ADDRESS, t.proof, NONCE + 1, BALANCE.toString()));
    }

    @Test
    void balanceMismatchRejected() {
        Trie t = buildAccountTrie(NONCE, BALANCE, STORAGE_ROOT, CODE_HASH);
        assertNull(MerklePatriciaVerifier.verifyAndExtractAccount(
                t.root, ADDRESS, t.proof, NONCE, BALANCE.add(BigInteger.ONE).toString()));
    }

    @Test
    void wrongRootRejected() {
        Trie t = buildAccountTrie(NONCE, BALANCE, STORAGE_ROOT, CODE_HASH);
        byte[] wrongRoot = t.root.clone();
        wrongRoot[0] ^= 0x01;
        assertNull(MerklePatriciaVerifier.verifyAndExtractAccount(
                wrongRoot, ADDRESS, t.proof, NONCE, BALANCE.toString()));
    }

    @Test
    void verifyDelegatesToExtract() {
        Trie t = buildAccountTrie(NONCE, BALANCE, STORAGE_ROOT, CODE_HASH);
        assertTrue(MerklePatriciaVerifier.verify(t.root, ADDRESS, t.proof, NONCE, BALANCE.toString()));
        assertFalse(MerklePatriciaVerifier.verify(t.root, ADDRESS, t.proof, NONCE + 1, BALANCE.toString()));
    }

    private static byte[] repeat(byte b, int n) {
        byte[] out = new byte[n];
        java.util.Arrays.fill(out, b);
        return out;
    }
}
