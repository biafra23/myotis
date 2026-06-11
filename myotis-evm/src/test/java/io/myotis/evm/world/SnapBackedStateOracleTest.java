package io.myotis.evm.world;

import com.jaeckel.ethp2p.core.trie.HexPrefix;
import io.myotis.evm.Address;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests for {@link SnapBackedStateOracle} using hand-built proofs.
 *
 * <p>Each test constructs a small trie with known leaves, stores the trie
 * nodes in a {@link FixturePeer}, then asks the oracle to fetch — exercising
 * the verifier + decoder pipeline end-to-end. The retry loop is exercised by
 * a peer that returns wrong data on the first attempt.
 */
class SnapBackedStateOracleTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ---- Account fetches ---------------------------------------------------

    @Test
    void fetchAccountReturnsDecodedFields() throws Exception {
        // One-account trie: address=0xab..., nonce=42, balance=1e18, codeHash=keccak256("").
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        long nonce = 42L;
        BigInteger balance = new BigInteger("1000000000000000000");
        Bytes32 codeHash = Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe());
        Bytes32 storageRoot = TrieFixture.EMPTY_TRIE_ROOT;

        Bytes accountValue = encodeAccount(nonce, balance, storageRoot, codeHash);
        var trie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);

        FixturePeer peer = new FixturePeer();
        peer.addTrieNodes(trie.root, trie.proof);

        var oracle = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory());
        AccountState got = oracle.fetchAccount(trie.root.toArrayUnsafe(), addr).get();
        assertEquals(addr, got.address());
        assertEquals(nonce, got.nonce());
        assertEquals(balance, got.balance());
        assertArrayEquals(codeHash.toArrayUnsafe(), got.codeHash());
    }

    @Test
    void fetchAccountAbsentReturnsEmptyDefault() throws Exception {
        // Trie holds key 0x11..; we ask for a key that lands on an empty branch slot.
        Address present = Address.fromHex("0x1111111111111111111111111111111111111111");
        Address absent = Address.fromHex("0x9999999999999999999999999999999999999999");

        Bytes accountValue = encodeAccount(0L, BigInteger.ZERO,
                TrieFixture.EMPTY_TRIE_ROOT,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var trie = TrieFixture.singleLeaf(keccak(present.toByteArray()), accountValue);

        FixturePeer peer = new FixturePeer();
        peer.addTrieNodes(trie.root, trie.proof);

        var oracle = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory());
        AccountState got = oracle.fetchAccount(trie.root.toArrayUnsafe(), absent).get();
        assertEquals(0L, got.nonce());
        assertEquals(BigInteger.ZERO, got.balance());
        assertArrayEquals(
                Hash.keccak256(Bytes.EMPTY).toArrayUnsafe(),
                got.codeHash());
    }

    @Test
    void fetchAccountWithInvalidProofRetriesThenFails() {
        // Peer always returns garbage proof nodes that don't hash to the requested root.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes32 root = Bytes32.fromHexString(
                "0x1111111111111111111111111111111111111111111111111111111111111111");
        Bytes garbage = RLP.encodeList(w -> {
            w.writeValue(Bytes.fromHexString("0x20"));
            w.writeValue(Bytes.fromHexString("0xdead"));
        });
        FixturePeer peer = new FixturePeer();
        peer.addTrieNodes(root, List.of(garbage)); // hash won't match the (fake) root

        AtomicInteger attempts = new AtomicInteger();
        Supplier<SnapPeer> supplier = () -> {
            attempts.incrementAndGet();
            return peer;
        };

        var oracle = new SnapBackedStateOracle(supplier, BytecodeCache.inMemory(), 3);
        try {
            oracle.fetchAccount(root.toArrayUnsafe(), addr).get();
            fail("expected fetchAccount to fail");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.InvalidProof.class, eee.error());
        }
        // Supplier was consulted once per attempt.
        assertEquals(3, attempts.get());
        // Each InvalidProof tells the peer it can't serve this root, so a routing
        // supplier can rotate away from it (the fix for empty-proof churn).
        assertEquals(3, peer.rootUnavailableCalls.get());
    }

    @Test
    void successDoesNotReportRootUnavailable() throws Exception {
        // A peer that serves a valid account proof must NOT be flagged root-unavailable.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes accountValue = encodeAccount(42L, new BigInteger("1000000000000000000"),
                TrieFixture.EMPTY_TRIE_ROOT,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var trie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);

        FixturePeer peer = new FixturePeer();
        peer.addTrieNodes(trie.root, trie.proof);

        var oracle = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory());
        oracle.fetchAccount(trie.root.toArrayUnsafe(), addr).get();
        assertEquals(0, peer.rootUnavailableCalls.get());
    }

    // ---- Storage fetch -----------------------------------------------------

    @Test
    void fetchStorageReturnsValue() throws Exception {
        // Storage trie holds a single slot.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger value = new BigInteger("1234567890123456789");

        Bytes32 slotKey = paddedSlot(slot);
        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(slotKey).toArrayUnsafe());
        Bytes valueRlp = RLP.encode(w -> w.writeBigInteger(value));
        var storageTrie = TrieFixture.singleLeaf(slotHash, valueRlp);

        // Account trie points at storageTrie.root for our address.
        Bytes accountValue = encodeAccount(0L, BigInteger.ZERO,
                storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var accountTrie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);

        FixturePeer peer = new FixturePeer();
        // Real snap peers serve both walks indexed by stateRoot + path-set
        // shape; the fixture mimics that with two registers.
        peer.addAccountProof(accountTrie.root, accountTrie.proof);
        peer.addStorageProof(accountTrie.root, storageTrie.proof);

        var oracle = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory());
        BigInteger got = oracle.fetchStorage(accountTrie.root.toArrayUnsafe(), addr, slot).get();
        assertEquals(value, got);
    }

    @Test
    void fetchStorageOnEmptyTrieReturnsZero() throws Exception {
        // Account exists with EMPTY storage root → any slot is zero, no second request needed.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes accountValue = encodeAccount(1L, BigInteger.TEN,
                TrieFixture.EMPTY_TRIE_ROOT,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var trie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);

        FixturePeer peer = new FixturePeer();
        peer.addTrieNodes(trie.root, trie.proof);

        var oracle = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory());
        BigInteger got = oracle.fetchStorage(
                trie.root.toArrayUnsafe(), addr, BigInteger.valueOf(42)).get();
        assertEquals(BigInteger.ZERO, got);
    }

    // ---- Bytecode fetch ----------------------------------------------------

    @Test
    void fetchBytecodeChecksHashAndCaches() throws Exception {
        byte[] code = {0x60, 0x00, 0x60, 0x00, (byte) 0xfd}; // PUSH1 0; PUSH1 0; REVERT
        byte[] codeHash = Hash.keccak256(Bytes.wrap(code)).toArrayUnsafe();

        FixturePeer peer = new FixturePeer();
        peer.addByteCode(Bytes32.wrap(codeHash), Bytes.wrap(code));

        var cache = BytecodeCache.inMemory();
        var oracle = new SnapBackedStateOracle(() -> peer, cache);
        byte[] got = oracle.fetchBytecode(codeHash).get();
        assertArrayEquals(code, got);

        // Cache hit on second call: peer wasn't queried again. Detect by clearing
        // the peer's bytecode map and confirming we still get the right bytes.
        peer.clearByteCodes();
        byte[] gotAgain = oracle.fetchBytecode(codeHash).get();
        assertArrayEquals(code, gotAgain);
    }

    @Test
    void fetchBytecodeRejectsHashMismatch() {
        // Peer returns a different bytecode than requested; oracle must not accept it.
        byte[] requestedHash = Hash.keccak256(Bytes.wrap(new byte[]{1, 2, 3})).toArrayUnsafe();
        byte[] returnedCode = {9, 9, 9}; // hash doesn't match requestedHash

        FixturePeer peer = new FixturePeer();
        peer.addByteCode(Bytes32.wrap(requestedHash), Bytes.wrap(returnedCode));

        var oracle = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory(), 2);
        try {
            oracle.fetchBytecode(requestedHash).get();
            fail("expected hash-mismatch failure");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.InvalidProof.class, eee.error());
        }
    }

    @Test
    void fetchBytecodeReturnsEmptyForEmptyCodeHash() throws Exception {
        byte[] emptyHash = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();
        // No peer interaction needed — handler short-circuits.
        var oracle = new SnapBackedStateOracle(() -> { throw new AssertionError("peer should not be called"); },
                BytecodeCache.inMemory());
        byte[] got = oracle.fetchBytecode(emptyHash).get();
        assertEquals(0, got.length);
    }

    // ---- Helpers -----------------------------------------------------------

    private static Bytes32 keccak(byte[] data) {
        return Bytes32.wrap(Hash.keccak256(Bytes.wrap(data)).toArrayUnsafe());
    }

    private static Bytes encodeAccount(long nonce, BigInteger balance, Bytes32 storageRoot, Bytes32 codeHash) {
        return RLP.encodeList(w -> {
            w.writeLong(nonce);
            w.writeBigInteger(balance);
            w.writeValue(storageRoot);
            w.writeValue(codeHash);
        });
    }

    private static Bytes32 paddedSlot(BigInteger slot) {
        byte[] padded = new byte[32];
        byte[] raw = slot.toByteArray();
        System.arraycopy(raw, 0, padded, 32 - raw.length, raw.length);
        return Bytes32.wrap(padded);
    }

    /** Trie fixture: a single-leaf trie storing one (key, value) pair. */
    private static final class TrieFixture {
        static final Bytes32 EMPTY_TRIE_ROOT = Bytes32.fromHexString(
                "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

        final Bytes32 root;
        final List<Bytes> proof;

        TrieFixture(Bytes32 root, List<Bytes> proof) {
            this.root = root;
            this.proof = proof;
        }

        static TrieFixture singleLeaf(Bytes32 key, Bytes value) {
            byte[] keyNibbles = HexPrefix.toNibbles(key.toArrayUnsafe());
            byte[] encodedPath = HexPrefix.encode(keyNibbles, true);
            Bytes leaf = RLP.encodeList(w -> {
                w.writeValue(Bytes.wrap(encodedPath));
                w.writeValue(value);
            });
            Bytes32 root = Bytes32.wrap(Hash.keccak256(leaf).toArrayUnsafe());
            return new TrieFixture(root, List.of(leaf));
        }
    }

    /** In-memory {@link SnapPeer} that returns pre-arranged proof bytes. */
    private static final class FixturePeer implements SnapPeer {
        private final Map<Bytes32, List<Bytes>> accountProofsByRoot = new HashMap<>();
        private final Map<Bytes32, List<Bytes>> storageProofsByRoot = new HashMap<>();
        private final Map<Bytes32, Bytes> codeByHash = new HashMap<>();

        void addAccountProof(Bytes32 stateRoot, List<Bytes> nodes) {
            accountProofsByRoot.put(stateRoot, new ArrayList<>(nodes));
        }

        void addStorageProof(Bytes32 stateRoot, List<Bytes> nodes) {
            storageProofsByRoot.put(stateRoot, new ArrayList<>(nodes));
        }

        /**
         * Convenience that registers the same proof for both lookup shapes —
         * fine when a test only does one kind of fetch.
         */
        void addTrieNodes(Bytes32 stateRoot, List<Bytes> nodes) {
            addAccountProof(stateRoot, nodes);
            addStorageProof(stateRoot, nodes);
        }

        void addByteCode(Bytes32 codeHash, Bytes code) {
            codeByHash.put(codeHash, code);
        }

        void clearByteCodes() {
            codeByHash.clear();
        }

        @Override
        public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 stateRoot, List<PathSet> paths) {
            // Real peers walk both the account trie and (when requested) the
            // account's storage trie, returning all the proof nodes either
            // walk traversed. We approximate by dispatching on the path set
            // shape: account-only requests get the account proof, requests
            // that include a storage path get the storage proof. The verifier
            // catches any mismatch via hash-of-node checks.
            boolean isStorageRequest = !paths.isEmpty() && !paths.get(0).storagePaths().isEmpty();
            Map<Bytes32, List<Bytes>> map = isStorageRequest ? storageProofsByRoot : accountProofsByRoot;
            List<Bytes> nodes = map.get(stateRoot);
            return CompletableFuture.completedFuture(nodes != null ? nodes : List.of());
        }

        @Override
        public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> hashes) {
            List<Bytes> result = new ArrayList<>(hashes.size());
            for (Bytes32 h : hashes) {
                Bytes code = codeByHash.get(h);
                if (code != null) result.add(code);
            }
            return CompletableFuture.completedFuture(result);
        }

        final AtomicInteger rootUnavailableCalls = new AtomicInteger();

        @Override
        public void reportRootUnavailable() {
            rootUnavailableCalls.incrementAndGet();
        }
    }
}
