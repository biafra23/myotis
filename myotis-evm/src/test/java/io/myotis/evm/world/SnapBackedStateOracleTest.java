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
import java.util.Set;
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
        // Fail-fast: the refusal is deterministic, so the operation ends after ONE
        // real attempt instead of burning the rest of the retry budget re-asking
        // the same peer (the 30s zombie-call fix). The supplier is consulted once
        // for the real attempt plus a short I/O-free skim (bounded per attempt
        // slot) that discovers there is nothing untried.
        assertEquals(1 + SnapBackedStateOracle.FAIL_FAST_CONSULTS_PER_ATTEMPT, attempts.get());
        // The one real attempt reports the peer so a routing supplier rotates
        // away from it for the rest of this head context.
        assertEquals(1, peer.rootUnavailableCalls.get());
    }

    @Test
    void maxAttemptsStillCapsRotationAcrossDistinctPeers() {
        // Three DISTINCT refusing peers with maxAttempts=2: the budget branch (not
        // fail-fast) must end the operation — two real attempts, the third peer
        // never asked, and the LAST real attempt's error surfaces.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes32 root = Bytes32.fromHexString(
                "0x7777777777777777777777777777777777777777777777777777777777777777");
        Bytes garbage = RLP.encodeList(w -> {
            w.writeValue(Bytes.fromHexString("0x20"));
            w.writeValue(Bytes.fromHexString("0xdead"));
        });
        List<FixturePeer> peers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            FixturePeer fp = new FixturePeer();
            fp.addTrieNodes(root, List.of(garbage));
            peers.add(fp);
        }
        AtomicInteger consults = new AtomicInteger();
        Supplier<SnapPeer> supplier = () -> peers.get(consults.getAndIncrement() % peers.size());

        var oracle = new SnapBackedStateOracle(supplier, BytecodeCache.inMemory(), 2);
        try {
            oracle.fetchAccount(root.toArrayUnsafe(), addr).get();
            fail("expected fetchAccount to fail");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.InvalidProof.class, eee.error(),
                    "the exhaustion branch surfaces the last real attempt's error");
        }
        // Budget branch, not fail-fast: exactly maxAttempts consults (each found an
        // untried peer on the first try), and the third peer was never asked.
        assertEquals(2, consults.get());
        assertEquals(1, peers.get(0).rootUnavailableCalls.get());
        assertEquals(1, peers.get(1).rootUnavailableCalls.get());
        assertEquals(0, peers.get(2).rootUnavailableCalls.get(),
                "the peer beyond the budget must never be asked");
    }

    @Test
    void failFastSeesThroughFreshAdapterWrappers() {
        // Production suppliers (VerifiedRpcBackend) wrap the long-lived connection
        // in a NEW adapter object on every supplier call. The dedup must key on
        // SnapPeer.identity() — the underlying connection — or it never fires in
        // production (each wrapper would look like a fresh peer).
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes32 root = Bytes32.fromHexString(
                "0x6666666666666666666666666666666666666666666666666666666666666666");
        Bytes garbage = RLP.encodeList(w -> {
            w.writeValue(Bytes.fromHexString("0x20"));
            w.writeValue(Bytes.fromHexString("0xdead"));
        });
        FixturePeer underlying = new FixturePeer();
        underlying.addTrieNodes(root, List.of(garbage));

        record Wrapper(FixturePeer delegate) implements SnapPeer {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                return delegate.getTrieNodes(sr, p);
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return delegate.getByteCodes(h);
            }
            @Override public void reportRootUnavailable() { delegate.reportRootUnavailable(); }
            @Override public Object identity() { return delegate; }
        }
        AtomicInteger consults = new AtomicInteger();
        Supplier<SnapPeer> freshWrapperPerCall = () -> {
            consults.incrementAndGet();
            return new Wrapper(underlying); // new object identity every call
        };

        var oracle = new SnapBackedStateOracle(freshWrapperPerCall, BytecodeCache.inMemory(), 3);
        try {
            oracle.fetchAccount(root.toArrayUnsafe(), addr).get();
            fail("expected fetchAccount to fail");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.InvalidProof.class, eee.error());
        }
        // One real attempt + the bounded skim — NOT maxAttempts real attempts.
        // Without identity()-keyed dedup this would be 3 real attempts and the
        // report counter would read 3.
        assertEquals(1 + SnapBackedStateOracle.FAIL_FAST_CONSULTS_PER_ATTEMPT, consults.get());
        assertEquals(1, underlying.rootUnavailableCalls.get());
    }

    @Test
    void failFastEndsAfterBothDistinctPeersRefuse() {
        // Two refusing peers, supplier alternating between them, budget of 5: the
        // operation must try each exactly once, then fail fast when the supplier
        // has nothing it hasn't already tried — never re-asking either peer.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes32 root = Bytes32.fromHexString(
                "0x5555555555555555555555555555555555555555555555555555555555555555");
        Bytes garbage = RLP.encodeList(w -> {
            w.writeValue(Bytes.fromHexString("0x20"));
            w.writeValue(Bytes.fromHexString("0xdead"));
        });
        FixturePeer a = new FixturePeer();
        FixturePeer b = new FixturePeer();
        a.addTrieNodes(root, List.of(garbage));
        b.addTrieNodes(root, List.of(garbage));
        AtomicInteger consults = new AtomicInteger();
        Supplier<SnapPeer> alternating = () -> consults.getAndIncrement() % 2 == 0 ? a : b;

        var oracle = new SnapBackedStateOracle(alternating, BytecodeCache.inMemory(), 5);
        try {
            oracle.fetchAccount(root.toArrayUnsafe(), addr).get();
            fail("expected fetchAccount to fail");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.InvalidProof.class, eee.error(),
                    "the surfaced failure is the last real attempt's, not a synthetic one");
        }
        // a tried, b tried, then the bounded skim finds only repeats → fail fast
        // with most of the 5-attempt budget unused (2 real attempts, not 5).
        assertEquals(2 + SnapBackedStateOracle.FAIL_FAST_CONSULTS_PER_ATTEMPT, consults.get(),
                "one consult per real attempt plus the bounded fail-fast skim");
        assertEquals(1, a.rootUnavailableCalls.get());
        assertEquals(1, b.rootUnavailableCalls.get());
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

    @Test
    void hangingPeerIsReportedRootUnavailable() {
        // A peer that accepts the request then times out (or the connection drops) is as
        // useless for this head as an empty-proof one — it must be flagged so the routing
        // supplier rotates away from it, not re-dialed every retry (the confirm-screen hang).
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes32 root = Bytes32.fromHexString(
                "0x2222222222222222222222222222222222222222222222222222222222222222");
        AtomicInteger reported = new AtomicInteger();
        SnapPeer hanging = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                return CompletableFuture.failedFuture(new java.util.concurrent.TimeoutException("hung"));
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.failedFuture(new java.util.concurrent.TimeoutException("hung"));
            }
            @Override public void reportRootUnavailable() { reported.incrementAndGet(); }
        };

        var oracle = new SnapBackedStateOracle(() -> hanging, BytecodeCache.inMemory(), 3);
        try {
            oracle.fetchAccount(root.toArrayUnsafe(), addr).get();
            fail("expected fetchAccount to fail");
        } catch (ExecutionException e) {
            assertInstanceOf(java.util.concurrent.TimeoutException.class, e.getCause(),
                    "the surfaced failure must be the timeout, not an unrelated error");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail("interrupted");
        }
        // One report, not maxAttempts: after the first timeout the fail-fast path
        // refuses to re-ask the only peer (each extra ask would cost a full request
        // timeout for a peer already flagged useless for this head).
        assertEquals(1, reported.get(), "the timeout must report the peer root-unavailable");
    }

    @Test
    void channelClosedIsReportedRootUnavailable() {
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes32 root = Bytes32.fromHexString(
                "0x3333333333333333333333333333333333333333333333333333333333333333");
        AtomicInteger reported = new AtomicInteger();
        SnapPeer dropped = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                return CompletableFuture.failedFuture(new java.io.IOException("Channel closed"));
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.failedFuture(new java.io.IOException("Channel closed"));
            }
            @Override public void reportRootUnavailable() { reported.incrementAndGet(); }
        };

        var oracle = new SnapBackedStateOracle(() -> dropped, BytecodeCache.inMemory(), 2);
        try {
            oracle.fetchAccount(root.toArrayUnsafe(), addr).get();
            fail("expected fetchAccount to fail");
        } catch (ExecutionException e) {
            assertInstanceOf(java.io.IOException.class, e.getCause(),
                    "the surfaced failure must be the channel-closed IOException");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail("interrupted");
        }
        assertEquals(1, reported.get(), "one report — fail-fast skips the identical re-ask");
    }

    @Test
    void deeplyWrappedTimeoutIsStillReportedRootUnavailable() {
        // The real fetch path fans out through nested allOf(...).join() stages, each of
        // which re-wraps the failure in another CompletionException. The root-cause
        // unwrap must peel ALL of them, not just one — otherwise the TimeoutException
        // stays buried, cantServe is false, and the hanging peer is never denied.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        Bytes32 root = Bytes32.fromHexString(
                "0x4444444444444444444444444444444444444444444444444444444444444444");
        AtomicInteger reported = new AtomicInteger();
        SnapPeer hangingDeep = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                java.util.concurrent.CompletionException nested =
                        new java.util.concurrent.CompletionException(
                                new java.util.concurrent.CompletionException(
                                        new java.util.concurrent.TimeoutException("hung")));
                return CompletableFuture.failedFuture(nested);
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.failedFuture(new java.util.concurrent.TimeoutException("hung"));
            }
            @Override public void reportRootUnavailable() { reported.incrementAndGet(); }
        };

        var oracle = new SnapBackedStateOracle(() -> hangingDeep, BytecodeCache.inMemory(), 2);
        try {
            oracle.fetchAccount(root.toArrayUnsafe(), addr).get();
            fail("expected fetchAccount to fail");
        } catch (ExecutionException e) {
            // unwrap() must have peeled every CompletionException layer, so the
            // surfaced cause is the bare TimeoutException — not a wrapper.
            assertInstanceOf(java.util.concurrent.TimeoutException.class, e.getCause(),
                    "the multiply-wrapped timeout must be unwrapped to its root cause");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail("interrupted");
        }
        assertEquals(1, reported.get(),
                "a multiply-wrapped timeout must still be unwrapped and denied");
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

    @Test
    void fetchBatchVerifiesAndWarmsCacheInOneRequest() throws Exception {
        // A real peer answers a PathSet(account,[slot]) GetTrieNodes with BOTH the
        // account-walk and storage-walk nodes COMBINED. fetchBatch must verify each
        // (account against stateRoot, slot against storageRoot) from that one combined
        // response and warm the proof cache — so a later fetchAccount/fetchStorage
        // needs ZERO further round-trips. This is the coalescing that turns a
        // 1000-token sweep's ~1000 sequential proofs into a handful.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger value = new BigInteger("1234567890123456789");
        long nonce = 5L;
        BigInteger balance = new BigInteger("999000000000000000");

        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        Bytes valueRlp = RLP.encode(w -> w.writeBigInteger(value));
        var storageTrie = TrieFixture.singleLeaf(slotHash, valueRlp);
        Bytes accountValue = encodeAccount(nonce, balance, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var accountTrie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);

        List<Bytes> combined = new ArrayList<>();
        combined.addAll(accountTrie.proof);
        combined.addAll(storageTrie.proof);
        AtomicInteger calls = new AtomicInteger();
        SnapPeer peer = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                calls.incrementAndGet();
                return CompletableFuture.completedFuture(combined);
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.completedFuture(List.of());
            }
            @Override public void reportRootUnavailable() { }
        };
        // fetchBatch warms the SHARED proof cache — give the oracle a real one (the
        // 2-arg ctor uses a noop cache, into which a warm would vanish).
        var oracle = new SnapBackedStateOracle(
                () -> peer, BytecodeCache.inMemory(), 8, StateProofCache.inMemory(1024));
        byte[] root = accountTrie.root.toArrayUnsafe();

        Map<Address, Set<BigInteger>> req = new HashMap<>();
        req.put(addr, Set.of(slot));
        oracle.fetchBatch(root, req).get();
        assertEquals(1, calls.get(), "the batch must issue exactly one GetTrieNodes");

        int before = calls.get();
        assertEquals(value, oracle.fetchStorage(root, addr, slot).get(),
                "the verified slot value must be warmed into the cache");
        assertEquals(balance, oracle.fetchAccount(root, addr).get().balance(),
                "the verified account must be warmed into the cache");
        assertEquals(before, calls.get(),
                "reads after a batch warm must hit the cache, not the peer");
    }

    @Test
    void fetchBatchOnForgedProofLeavesCacheCold() throws Exception {
        // A peer that returns garbage nodes: the batch's verify must REJECT it (the
        // chunk fails + is left uncached), never poisoning the cache with unverified
        // state. The follow-up fetchStorage then re-fetches per-item (and here fails
        // too) — but crucially the batch never weakened the trust path.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        Bytes32 root = Bytes32.fromHexString(
                "0x5555555555555555555555555555555555555555555555555555555555555555");
        SnapPeer forging = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                return CompletableFuture.completedFuture(List.of(Bytes.fromHexString("0xdeadbeef")));
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.completedFuture(List.of());
            }
            @Override public void reportRootUnavailable() { }
        };
        var oracle = new SnapBackedStateOracle(() -> forging, BytecodeCache.inMemory(), 2);

        Map<Address, Set<BigInteger>> req = new HashMap<>();
        req.put(addr, Set.of(slot));
        // Best-effort: the batch completes (doesn't throw) but caches nothing forged.
        oracle.fetchBatch(root.toArrayUnsafe(), req).get();

        // The cache stayed cold — a real fetch still has to verify from scratch (and
        // here fails, because the peer forges). The point: no unverified value was cached.
        try {
            oracle.fetchStorage(root.toArrayUnsafe(), addr, slot).get();
            fail("a forged proof must not yield a value");
        } catch (ExecutionException expected) {
            // verifier rejected the garbage — correct.
        }
    }

    @Test
    void chunkFullyCacheFilledMidFlightGrantsNoServeCredit() throws Exception {
        // The serve credit (SnapPeer.reportServed — it resets the pool's eviction
        // streak and re-confirms the peer cache) must fire only when something of
        // THIS peer's bytes verified. The hole this pins shut: a batch chunk built
        // while the cache was cold can find every item cache-filled by a CONCURRENT
        // batch by the time its response arrives — verifyAndCacheChunk then checks
        // nothing, and a slow peer answering garbage would have been credited for a
        // "serve" nobody verified, farming streak resets off the race.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        Bytes valueRlp = RLP.encode(w -> w.writeBigInteger(new BigInteger("42")));
        var storageTrie = TrieFixture.singleLeaf(slotHash, valueRlp);
        Bytes accountValue = encodeAccount(1L, BigInteger.TEN, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var accountTrie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);
        List<Bytes> combined = new ArrayList<>();
        combined.addAll(accountTrie.proof);
        combined.addAll(storageTrie.proof);
        byte[] root = accountTrie.root.toArrayUnsafe();
        var shared = StateProofCache.inMemory(1024);
        Map<Address, Set<BigInteger>> req = new HashMap<>();
        req.put(addr, Set.of(slot));

        // The junk peer's batch is BUILT against the cold cache (items included),
        // but its response hangs in flight...
        AtomicInteger junkCredits = new AtomicInteger();
        CompletableFuture<List<Bytes>> junkResponse = new CompletableFuture<>();
        SnapPeer junk = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                return junkResponse;
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.completedFuture(List.of());
            }
            @Override public void reportServed() { junkCredits.incrementAndGet(); }
        };
        CompletableFuture<Void> inFlight = new SnapBackedStateOracle(
                () -> junk, BytecodeCache.inMemory(), 2, shared).fetchBatch(root, req);

        // ...while a concurrent honest batch verifies and fills the SHARED cache
        // (and earns the credit — the positive half of the pin)...
        AtomicInteger honestCredits = new AtomicInteger();
        SnapPeer honest = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                return CompletableFuture.completedFuture(combined);
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.completedFuture(List.of());
            }
            @Override public void reportServed() { honestCredits.incrementAndGet(); }
        };
        new SnapBackedStateOracle(() -> honest, BytecodeCache.inMemory(), 2, shared)
                .fetchBatch(root, req).get();
        assertEquals(1, honestCredits.get(), "a verified batch chunk must credit its peer");

        // ...and only then does the junk peer answer, with garbage. Every item is
        // now a cache hit, so the chunk completes without touching those bytes —
        // and must therefore credit nothing.
        junkResponse.complete(List.of(Bytes.fromHexString("0xdeadbeef")));
        inFlight.get();
        assertEquals(0, junkCredits.get(),
                "a chunk that verified nothing of this peer's bytes must not credit it");
    }

    @Test
    void fetchBatchRetryServesAlreadyVerifiedItemsFromCache() throws Exception {
        // Retry robustness across peer rotation. Attempt 1 proves the account but NOT
        // the slot, so the slot verify fails and the whole chunk retries on the next
        // peer. Attempt 2 proves the slot but NOT the account. Because verifyAndCacheChunk
        // queries the cache LIVE, the account verified+cached on attempt 1 is served from
        // cache on the retry, so the chunk completes even though no single response
        // carried both proofs. A static "cached when the batch was built?" snapshot would
        // force re-verifying the account from the retry response (which lacks it) and fail.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger value = new BigInteger("1234567890123456789");
        long nonce = 5L;
        BigInteger balance = new BigInteger("999000000000000000");

        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        Bytes valueRlp = RLP.encode(w -> w.writeBigInteger(value));
        var storageTrie = TrieFixture.singleLeaf(slotHash, valueRlp);
        Bytes accountValue = encodeAccount(nonce, balance, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var accountTrie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);

        // Two DISTINCT peers (fail-fast never re-asks a peer that failed within one
        // operation, so the rotation must be real): the first serves only the account
        // proof, the second only the storage proof.
        AtomicInteger attempt = new AtomicInteger();
        record HalfPeer(java.util.function.Supplier<List<Bytes>> proof, AtomicInteger counter)
                implements SnapPeer {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 sr, List<PathSet> p) {
                counter.incrementAndGet();
                return CompletableFuture.completedFuture(proof.get());
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.completedFuture(List.of());
            }
        }
        SnapPeer accountOnly = new HalfPeer(() -> accountTrie.proof, attempt);
        SnapPeer storageOnly = new HalfPeer(() -> storageTrie.proof, attempt);
        AtomicInteger consults = new AtomicInteger();
        Supplier<SnapPeer> rotation = () ->
                consults.getAndIncrement() == 0 ? accountOnly : storageOnly;
        var oracle = new SnapBackedStateOracle(
                rotation, BytecodeCache.inMemory(), 8, StateProofCache.inMemory(1024));
        byte[] root = accountTrie.root.toArrayUnsafe();

        Map<Address, Set<BigInteger>> req = new HashMap<>();
        req.put(addr, Set.of(slot));
        oracle.fetchBatch(root, req).get();
        assertTrue(attempt.get() >= 2, "the slot miss must have forced at least one retry");

        int after = attempt.get();
        assertEquals(value, oracle.fetchStorage(root, addr, slot).get(),
                "slot warmed by the retry that succeeded via the cached account");
        assertEquals(balance, oracle.fetchAccount(root, addr).get().balance(),
                "account warmed on the first attempt, retained across the retry");
        assertEquals(after, attempt.get(), "reads after the batch warm must hit the cache, not the peer");
    }

    @Test
    void sharedStateCacheServesStorageAcrossOraclesWithoutRefetch() throws Exception {
        // The fix for the confirm-screen retry-storm: a node-level StateProofCache
        // shared across head-context oracle instances. A verified storage value must
        // survive an oracle rebuild so a wallet's repeated retries reuse it instead of
        // re-proving every slot. Prove it: oracle 1 populates the shared cache; oracle 2
        // (a "later head-context", given a peer that serves NOTHING) must still answer
        // from cache with zero round-trips.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger value = new BigInteger("1234567890123456789");

        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        Bytes valueRlp = RLP.encode(w -> w.writeBigInteger(value));
        var storageTrie = TrieFixture.singleLeaf(slotHash, valueRlp);
        Bytes accountValue = encodeAccount(0L, BigInteger.ZERO, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var accountTrie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);

        FixturePeer peer = new FixturePeer();
        peer.addAccountProof(accountTrie.root, accountTrie.proof);
        peer.addStorageProof(accountTrie.root, storageTrie.proof);

        StateProofCache shared = StateProofCache.inMemory(1024);
        var oracle1 = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        assertEquals(value, oracle1.fetchStorage(accountTrie.root.toArrayUnsafe(), addr, slot).get());

        SnapPeer deadPeer = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 r, List<PathSet> p) {
                return CompletableFuture.failedFuture(new java.io.IOException("no peer available"));
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.failedFuture(new java.io.IOException("no peer available"));
            }
        };
        var oracle2 = new SnapBackedStateOracle(() -> deadPeer, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        assertEquals(value, oracle2.fetchStorage(accountTrie.root.toArrayUnsafe(), addr, slot).get(),
                "second oracle must serve the slot from the shared cache, no peer round-trip");
    }

    @Test
    void storageCacheReusedAcrossBlocksWhenStorageRootUnchanged() throws Exception {
        // The cross-BLOCK reuse the storageRoot keying buys: a slot verified at world
        // root A must be served from cache at world root B — zero storage round-trips —
        // when the account's storageRoot is unchanged (the per-block account proof is
        // the freshness check). This is what turns a wallet's per-poll 67KB Multicall3
        // sweep from re-proving hundreds of slots every block into one account proof
        // per contract per block.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger value = new BigInteger("1234567890123456789");

        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        Bytes valueRlp = RLP.encode(w -> w.writeBigInteger(value));
        var storageTrie = TrieFixture.singleLeaf(slotHash, valueRlp);

        // Two world roots ("block N" / "block N+1"): the account's nonce differs, its
        // storageRoot is the SAME trie.
        Bytes accountAtA = encodeAccount(1L, BigInteger.TEN, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        Bytes accountAtB = encodeAccount(2L, BigInteger.TEN, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var worldA = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountAtA);
        var worldB = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountAtB);

        FixturePeer peer = new FixturePeer();
        peer.addAccountProof(worldA.root, worldA.proof);
        peer.addStorageProof(worldA.root, storageTrie.proof);
        // Root B's peer serves ONLY the account proof — a storage request at B
        // would come back empty and fail the verify, so a pass proves the slot
        // was replayed from cache, not re-fetched.
        peer.addAccountProof(worldB.root, worldB.proof);

        StateProofCache shared = StateProofCache.inMemory(1024);
        var oracleA = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        assertEquals(value, oracleA.fetchStorage(worldA.root.toArrayUnsafe(), addr, slot).get());

        var oracleB = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        assertEquals(value, oracleB.fetchStorage(worldB.root.toArrayUnsafe(), addr, slot).get(),
                "unchanged storageRoot at the new world root must replay the cached slot");
    }

    @Test
    void storageCacheNotReusedWhenStorageRootChanges() throws Exception {
        // Safety control for the reuse above: when the contract's storage DID change
        // between blocks (different storageRoot in the new account leaf), the cached
        // value from the old root must NOT be served — the slot re-proves against the
        // new storage trie and returns the new value.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger oldValue = new BigInteger("1234567890123456789");
        BigInteger newValue = new BigInteger("987654321");

        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        var oldStorage = TrieFixture.singleLeaf(slotHash, RLP.encode(w -> w.writeBigInteger(oldValue)));
        var newStorage = TrieFixture.singleLeaf(slotHash, RLP.encode(w -> w.writeBigInteger(newValue)));

        Bytes accountAtA = encodeAccount(1L, BigInteger.TEN, oldStorage.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        Bytes accountAtB = encodeAccount(1L, BigInteger.TEN, newStorage.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var worldA = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountAtA);
        var worldB = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountAtB);

        FixturePeer peer = new FixturePeer();
        peer.addAccountProof(worldA.root, worldA.proof);
        peer.addStorageProof(worldA.root, oldStorage.proof);
        peer.addAccountProof(worldB.root, worldB.proof);
        peer.addStorageProof(worldB.root, newStorage.proof);

        StateProofCache shared = StateProofCache.inMemory(1024);
        var oracleA = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        assertEquals(oldValue, oracleA.fetchStorage(worldA.root.toArrayUnsafe(), addr, slot).get());

        var oracleB = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        assertEquals(newValue, oracleB.fetchStorage(worldB.root.toArrayUnsafe(), addr, slot).get(),
                "a changed storageRoot must re-prove the slot, never replay the stale value");
    }

    @Test
    void fetchBatchPrefiltersSlotsCachedUnderKnownStorageRoot() throws Exception {
        // fetchBatch at a NEW world root, where the account record is already cached
        // at that root (as the head-build priming does) and the slots were verified at
        // the PREVIOUS root under the same storageRoot: nothing is left to fetch, so
        // the batch must issue ZERO GetTrieNodes requests.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger value = new BigInteger("1234567890123456789");

        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        var storageTrie = TrieFixture.singleLeaf(slotHash, RLP.encode(w -> w.writeBigInteger(value)));
        Bytes accountAtA = encodeAccount(1L, BigInteger.TEN, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        Bytes accountAtB = encodeAccount(2L, BigInteger.TEN, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var worldA = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountAtA);
        var worldB = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountAtB);

        FixturePeer warmPeer = new FixturePeer();
        warmPeer.addAccountProof(worldA.root, worldA.proof);
        warmPeer.addStorageProof(worldA.root, storageTrie.proof);

        StateProofCache shared = StateProofCache.inMemory(1024);
        var oracle = new SnapBackedStateOracle(() -> warmPeer, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        // Warm: slot at root A (banks it under storageRoot). fetchStorage banks the
        // slot before its future completes, so this is race-free.
        assertEquals(value, oracle.fetchStorage(worldA.root.toArrayUnsafe(), addr, slot).get());
        // Bank the account at root B directly (what the head-build priming does).
        // Going through fetchAccount here would be racy: its promotion to the shared
        // cache runs async after the future completes.
        shared.putAccount(worldB.root.toArrayUnsafe(), addr.toByteArray(),
                new StateProofCache.AccountEntry(
                        new AccountState(addr, 2L, BigInteger.TEN,
                                Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()),
                        storageTrie.root.toArrayUnsafe()));

        AtomicInteger calls = new AtomicInteger();
        SnapPeer countingDead = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 r, List<PathSet> p) {
                calls.incrementAndGet();
                return CompletableFuture.failedFuture(new java.io.IOException("should not be called"));
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.failedFuture(new java.io.IOException("should not be called"));
            }
        };
        var oracleB = new SnapBackedStateOracle(() -> countingDead, BytecodeCache.inMemory(),
                SnapBackedStateOracle.DEFAULT_MAX_ATTEMPTS, shared);
        Map<Address, Set<BigInteger>> req = new HashMap<>();
        req.put(addr, Set.of(slot));
        oracleB.fetchBatch(worldB.root.toArrayUnsafe(), req).get();
        assertEquals(0, calls.get(),
                "a fully carried-over account (cached record + slots under its storageRoot) "
                        + "must add no batch work");
        assertEquals(value, oracleB.fetchStorage(worldB.root.toArrayUnsafe(), addr, slot).get());
    }

    @Test
    void noopStateCacheStillRefetchesAcrossOracles() throws Exception {
        // Control for the test above: with the default noop cache, a fresh oracle has
        // no memory, so a dead peer DOES fail — confirming the pass above is the cache
        // working, not the fixture being lenient.
        Address addr = Address.fromHex("0xabcdef0102030405060708090a0b0c0d0e0f1011");
        BigInteger slot = BigInteger.valueOf(7);
        BigInteger value = new BigInteger("1234567890123456789");
        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(paddedSlot(slot)).toArrayUnsafe());
        Bytes valueRlp = RLP.encode(w -> w.writeBigInteger(value));
        var storageTrie = TrieFixture.singleLeaf(slotHash, valueRlp);
        Bytes accountValue = encodeAccount(0L, BigInteger.ZERO, storageTrie.root,
                Bytes32.wrap(Hash.keccak256(Bytes.EMPTY).toArrayUnsafe()));
        var accountTrie = TrieFixture.singleLeaf(keccak(addr.toByteArray()), accountValue);
        FixturePeer peer = new FixturePeer();
        peer.addAccountProof(accountTrie.root, accountTrie.proof);
        peer.addStorageProof(accountTrie.root, storageTrie.proof);

        var oracle1 = new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory()); // noop cache
        assertEquals(value, oracle1.fetchStorage(accountTrie.root.toArrayUnsafe(), addr, slot).get());

        SnapPeer deadPeer = new SnapPeer() {
            @Override public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 r, List<PathSet> p) {
                return CompletableFuture.failedFuture(new java.io.IOException("no peer available"));
            }
            @Override public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> h) {
                return CompletableFuture.failedFuture(new java.io.IOException("no peer available"));
            }
        };
        var oracle2 = new SnapBackedStateOracle(() -> deadPeer, BytecodeCache.inMemory());
        try {
            oracle2.fetchStorage(accountTrie.root.toArrayUnsafe(), addr, slot).get();
            fail("without a shared cache, a dead peer must fail");
        } catch (ExecutionException expected) {
            // expected — no cache, no peer, no value
        }
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
