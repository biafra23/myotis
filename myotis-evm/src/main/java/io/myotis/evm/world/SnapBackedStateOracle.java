package io.myotis.evm.world;

import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier;
import io.myotis.evm.Address;
import io.myotis.evm.CryptoProviders;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;

/**
 * {@link SnapStateOracle} backed by a real {@link SnapPeer} connection.
 *
 * <p>For each call:
 * <ol>
 *   <li>Issue the SNAP request via the peer.
 *   <li>Verify the proof against {@code stateRoot} using the MPT verifier in
 *       {@code :core} (or, for bytecode, hash the response and match against
 *       {@code codeHash}).
 *   <li>On verification failure, request a different peer from the supplier
 *       and try again, up to {@link #maxAttempts}.
 *   <li>After the retry budget is exhausted, fail with
 *       {@link EvmExecutionError.InvalidProof} (or
 *       {@link EvmExecutionError.StateUnavailable} if the peer never
 *       answered).
 * </ol>
 *
 * <p>Bytecode is cached via the supplied {@link BytecodeCache}; the cache is
 * checked before issuing any request. State is not cached here — the
 * per-call cache lives in {@link SyncStateView}.
 *
 * <p>The peer abstraction lets tests substitute a fixture peer and lets the
 * wallet integration provide an {@code EthHandler}-backed implementation
 * without {@code :myotis-evm} taking a dependency on {@code :networking}.
 */
public final class SnapBackedStateOracle implements SnapStateOracle {

    private static final Logger log = LoggerFactory.getLogger(SnapBackedStateOracle.class);

    /** Default number of peers to try before giving up on a single fetch. */
    public static final int DEFAULT_MAX_ATTEMPTS = 3;

    private static final byte[] EMPTY_CODE_HASH;
    static {
        CryptoProviders.ensureRegistered();
        EMPTY_CODE_HASH = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();
    }

    private final Supplier<SnapPeer> peerSupplier;
    private final BytecodeCache bytecodeCache;
    private final int maxAttempts;
    /** Cross-call, node-level cache of verified account/storage state keyed by
     *  stateRoot — survives head-context rebuilds so a wallet's repeated retries of
     *  the same heavy call reuse fetched slots instead of re-proving them. */
    private final StateProofCache stateCache;

    /**
     * Per-oracle (i.e. per-resolution) memoization of account-record fetches,
     * keyed by {@code stateRoot:address}. A single ENS resolution issues many
     * SLOADs against the same few contracts (registry, resolver, …) and
     * {@link #fetchStorage} re-derives the account record on every slot — so
     * without this, reading N storage slots of a contract would trigger N
     * redundant account proofs, i.e. N extra snap round-trips. On Android each
     * round-trip is ~2-6 s, so those dominate latency. The account record at a
     * fixed stateRoot is immutable and already proof-verified, so memoizing the
     * in-flight fetch is safe (view calls never mutate state) and collapses the
     * N fetches into one shared request. Failed fetches are evicted so a later
     * read can still retry across peers.
     */
    private final java.util.concurrent.ConcurrentHashMap<String, CompletableFuture<AccountWithStorageRoot>>
            accountCache = new java.util.concurrent.ConcurrentHashMap<>();

    public SnapBackedStateOracle(Supplier<SnapPeer> peerSupplier, BytecodeCache bytecodeCache) {
        this(peerSupplier, bytecodeCache, DEFAULT_MAX_ATTEMPTS, StateProofCache.noop());
    }

    public SnapBackedStateOracle(
            Supplier<SnapPeer> peerSupplier,
            BytecodeCache bytecodeCache,
            int maxAttempts) {
        this(peerSupplier, bytecodeCache, maxAttempts, StateProofCache.noop());
    }

    public SnapBackedStateOracle(
            Supplier<SnapPeer> peerSupplier,
            BytecodeCache bytecodeCache,
            int maxAttempts,
            StateProofCache stateCache) {
        this.peerSupplier = peerSupplier;
        this.bytecodeCache = bytecodeCache;
        this.maxAttempts = maxAttempts;
        this.stateCache = stateCache == null ? StateProofCache.noop() : stateCache;
    }

    @Override
    public CompletableFuture<AccountState> fetchAccount(byte[] stateRoot, Address address) {
        return fetchAccountWithRoot(stateRoot, address)
                .thenApply(AccountWithStorageRoot::account);
    }

    @Override
    public CompletableFuture<BigInteger> fetchStorage(byte[] stateRoot, Address address, BigInteger slot) {
        byte[] addr = address.toByteArray();
        // Cross-call cache hit: the verified value at this (stateRoot, addr, slot)
        // is returned with zero round-trips. This is what lets a wallet's repeated
        // retries of a 1000-slot balance sweep converge instead of re-proving every
        // slot each time.
        Optional<BigInteger> cached = stateCache.getStorage(stateRoot, addr, slot);
        if (cached.isPresent()) return CompletableFuture.completedFuture(cached.get());

        Bytes32 root = Bytes32.wrap(stateRoot.clone());
        Bytes addressBytes = Bytes.wrap(addr);
        Bytes32 accountHash = Bytes32.wrap(Hash.keccak256(addressBytes).toArrayUnsafe());
        Bytes32 slotKey = paddedSlotKey(slot);
        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(slotKey).toArrayUnsafe());

        // Storage proofs anchor at the account's storageRoot, not the world
        // stateRoot — so we need the account record first. The per-call
        // SyncStateView cache means this account fetch happens only once
        // even when the EVM does many SLOADs against the same contract.
        return fetchAccountWithRoot(stateRoot, address).thenCompose(awr -> {
            Bytes32 storageRoot = awr.storageRoot();
            if (MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT.equals(storageRoot)) {
                // Account has no storage at all; every slot is zero.
                stateCache.putStorage(stateRoot, addr, slot, BigInteger.ZERO);
                return CompletableFuture.completedFuture(BigInteger.ZERO);
            }
            return tryWithRetries(peer -> peer
                    .getTrieNodes(root, List.of(SnapPeer.PathSet.storageSlot(accountHash, slotHash)))
                    .thenApply(nodes -> verifyAndDecodeStorage(storageRoot, slotHash, address, nodes)))
                    .thenApply(value -> {
                        stateCache.putStorage(stateRoot, addr, slot, value);
                        return value;
                    });
        });
    }

    /** Max path-sets (accounts) per GetTrieNodes request. Bounds the response size a
     *  peer must assemble (each path-set is ~one account proof + its slot proofs ≈
     *  several KB), keeping any one request servable while still collapsing a
     *  1000-account sweep from ~1000 round-trips to ~16. */
    private static final int BATCH_PATHSET_CHUNK = 64;

    /** Per-account batch work: the address + its hash + the UNCACHED slots wanted
     *  ({@code slots}) paired index-for-index with their keccak hashes ({@code
     *  slotHashes}, used both for the GetTrieNodes path and the slot-proof verify). */
    private record BatchItem(Address address, byte[] addr, Bytes32 accountHash,
                             List<BigInteger> slots, List<Bytes32> slotHashes) {}

    @Override
    public CompletableFuture<Void> fetchBatch(
            byte[] stateRoot, Map<Address, ? extends Set<BigInteger>> request) {
        if (request == null || request.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }
        Bytes32 root = Bytes32.wrap(stateRoot.clone());
        // Build per-account work, skipping anything already in the proof cache so a
        // partially-warm sweep only fetches the misses.
        List<BatchItem> items = new ArrayList<>();
        for (Map.Entry<Address, ? extends Set<BigInteger>> entry : request.entrySet()) {
            Address address = entry.getKey();
            byte[] addr = address.toByteArray();
            Bytes32 accountHash = Bytes32.wrap(Hash.keccak256(Bytes.wrap(addr)).toArrayUnsafe());
            boolean accountCached = stateCache.getAccount(stateRoot, addr).isPresent();
            List<BigInteger> slots = new ArrayList<>();
            List<Bytes32> slotHashes = new ArrayList<>();
            for (BigInteger slot : entry.getValue()) {
                if (stateCache.getStorage(stateRoot, addr, slot).isPresent()) continue;
                slots.add(slot);
                slotHashes.add(Bytes32.wrap(Hash.keccak256(paddedSlotKey(slot)).toArrayUnsafe()));
            }
            if (accountCached && slots.isEmpty()) continue;  // fully cached → nothing to do
            items.add(new BatchItem(address, addr, accountHash, slots, slotHashes));
        }
        if (items.isEmpty()) return CompletableFuture.completedFuture(null);

        List<CompletableFuture<Void>> chunkFutures = new ArrayList<>();
        for (int i = 0; i < items.size(); i += BATCH_PATHSET_CHUNK) {
            final List<BatchItem> chunk = items.subList(i, Math.min(i + BATCH_PATHSET_CHUNK, items.size()));
            List<SnapPeer.PathSet> paths = new ArrayList<>(chunk.size());
            for (BatchItem it : chunk) {
                List<Bytes> storagePaths = new ArrayList<>(it.slotHashes().size());
                storagePaths.addAll(it.slotHashes());   // Bytes32 -> Bytes per element
                paths.add(new SnapPeer.PathSet(it.accountHash(), storagePaths));
            }
            // tryWithRetries rotates peers exactly like the per-item path: a peer that
            // returns an incomplete/forged proof for ANY item in the chunk fails its
            // verify and the whole chunk retries on the next peer. Best-effort overall —
            // a chunk that can't be verified after retries is left uncached (the caller's
            // per-item path re-fetches it), so the batch never weakens correctness.
            CompletableFuture<Void> cf = tryWithRetries(peer -> peer.getTrieNodes(root, paths)
                    .thenApply(nodes -> { verifyAndCacheChunk(stateRoot, root, chunk, nodes); return (Void) null; }))
                    .exceptionally(t -> {
                        log.debug("[snap-oracle] batch chunk ({} accounts) failed: {}",
                                chunk.size(), t.getMessage());
                        return null;
                    });
            chunkFutures.add(cf);
        }
        return CompletableFuture.allOf(chunkFutures.toArray(CompletableFuture[]::new));
    }

    /** Verify + cache every account/slot in {@code chunk} from the ONE combined node
     *  list the peer returned. Each proof is checked with the same verifier the
     *  per-item path uses (the verifier builds a hash→node map, so a combined node set
     *  verifies each key independently); a bad proof throws InvalidProof, failing the
     *  whole chunk so tryWithRetries rotates to another peer. */
    private void verifyAndCacheChunk(byte[] stateRoot, Bytes32 root,
                                     List<BatchItem> chunk, List<Bytes> nodes) {
        for (BatchItem it : chunk) {
            // Query the cache live (not a static per-build snapshot): on a chunk retry
            // against a different peer, items the previous attempt already verified are
            // served from cache, so the new peer's response need not re-prove them. A
            // static "was it cached when the batch was built?" flag would instead force
            // re-verification and fail the retry whenever the new peer omits those proofs.
            AccountWithStorageRoot awr;
            Optional<StateProofCache.AccountEntry> cached = stateCache.getAccount(stateRoot, it.addr());
            if (cached.isPresent()) {
                awr = new AccountWithStorageRoot(cached.get().account(),
                        Bytes32.wrap(cached.get().storageRoot()));
            } else {
                awr = verifyAndDecodeAccount(root, it.accountHash(), it.address(), nodes);
                stateCache.putAccount(stateRoot, it.addr(),
                        new StateProofCache.AccountEntry(awr.account(), awr.storageRoot().toArrayUnsafe()));
            }
            Bytes32 storageRoot = awr.storageRoot();
            boolean emptyStorage = MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT.equals(storageRoot);
            for (int s = 0; s < it.slots().size(); s++) {
                BigInteger slot = it.slots().get(s);
                if (stateCache.getStorage(stateRoot, it.addr(), slot).isPresent()) continue;
                BigInteger value = emptyStorage ? BigInteger.ZERO
                        : verifyAndDecodeStorage(storageRoot, it.slotHashes().get(s), it.address(), nodes);
                stateCache.putStorage(stateRoot, it.addr(), slot, value);
            }
        }
    }

    @Override
    public CompletableFuture<byte[]> fetchBytecode(byte[] codeHash) {
        var cached = bytecodeCache.get(codeHash);
        if (cached.isPresent()) return CompletableFuture.completedFuture(cached.get());
        if (Arrays.equals(codeHash, EMPTY_CODE_HASH)) {
            return CompletableFuture.completedFuture(new byte[0]);
        }

        Bytes32 hash = Bytes32.wrap(codeHash.clone());
        return tryWithRetries(peer -> peer
                .getByteCodes(List.of(hash))
                .thenApply(codes -> {
                    if (codes.isEmpty()) {
                        throw new EvmExecutionException(
                                new EvmExecutionError.BytecodeUnavailable(codeHash));
                    }
                    Bytes returned = codes.get(0);
                    byte[] code = returned.toArrayUnsafe();
                    byte[] actualHash = Hash.keccak256(returned).toArrayUnsafe();
                    if (!Arrays.equals(actualHash, codeHash)) {
                        throw new EvmExecutionException(
                                new EvmExecutionError.InvalidProof(
                                        new byte[32], Address.ZERO,
                                        "bytecode hash mismatch: expected 0x"
                                                + HexFormat.of().formatHex(codeHash)
                                                + " got 0x" + HexFormat.of().formatHex(actualHash)));
                    }
                    bytecodeCache.put(codeHash, code);
                    return code;
                }));
    }

    /**
     * Internal helper: fetch the account record AND its storage root, since
     * {@link AccountState} doesn't expose the latter publicly. The MPT proof
     * verification happens inside the retry loop so a peer that returns a
     * mismatched proof is rotated out of consideration immediately.
     */
    private CompletableFuture<AccountWithStorageRoot> fetchAccountWithRoot(byte[] stateRoot, Address address) {
        byte[] addr = address.toByteArray();
        // Cross-call L2: a verified account record at this stateRoot, reused across
        // head-context rebuilds and calls (the per-oracle accountCache below is only
        // an in-flight dedup for one resolution).
        Optional<StateProofCache.AccountEntry> cachedAccount = stateCache.getAccount(stateRoot, addr);
        if (cachedAccount.isPresent()) {
            StateProofCache.AccountEntry e = cachedAccount.get();
            return CompletableFuture.completedFuture(
                    new AccountWithStorageRoot(e.account(), Bytes32.wrap(e.storageRoot())));
        }

        Bytes32 root = Bytes32.wrap(stateRoot.clone());
        Bytes addressBytes = Bytes.wrap(addr);
        Bytes32 accountHash = Bytes32.wrap(Hash.keccak256(addressBytes).toArrayUnsafe());

        String key = root.toHexString() + ':' + addressBytes.toHexString();
        return accountCache.computeIfAbsent(key, k -> {
            CompletableFuture<AccountWithStorageRoot> f = tryWithRetries(peer -> peer
                    .getTrieNodes(root, List.of(SnapPeer.PathSet.account(accountHash)))
                    .thenApply(nodes -> verifyAndDecodeAccount(root, accountHash, address, nodes)));
            // Evict failed fetches so a later read can retry across peers; on success
            // promote the verified record to the cross-call cache. Use *Async so
            // neither runs synchronously inside computeIfAbsent (a reentrant map
            // mutation); the value-conditional remove keeps a racing re-fetch intact.
            f.whenCompleteAsync((v, e) -> {
                if (e != null) {
                    accountCache.remove(k, f);
                } else if (v != null) {
                    stateCache.putAccount(stateRoot, addr,
                            new StateProofCache.AccountEntry(v.account(), v.storageRoot().toArrayUnsafe()));
                }
            }, java.util.concurrent.ForkJoinPool.commonPool());
            return f;
        });
    }

    /**
     * Run {@code op} against successive peers until it succeeds or we hit
     * {@link #maxAttempts}. {@link EvmExecutionError.InvalidProof} and
     * generic IO failures both trigger retries with the next peer; the last
     * failure surfaces if every attempt fails.
     */
    private <T> CompletableFuture<T> tryWithRetries(java.util.function.Function<SnapPeer, CompletableFuture<T>> op) {
        CompletableFuture<T> result = new CompletableFuture<>();
        attempt(op, 0, null, result);
        return result;
    }

    private <T> void attempt(
            java.util.function.Function<SnapPeer, CompletableFuture<T>> op,
            int attemptIdx,
            Throwable lastError,
            CompletableFuture<T> sink) {
        if (attemptIdx >= maxAttempts) {
            sink.completeExceptionally(lastError != null ? lastError
                    : new EvmExecutionException(new EvmExecutionError.InvalidProof(
                            new byte[32], Address.ZERO,
                            "exhausted " + maxAttempts + " peer attempts")));
            return;
        }
        SnapPeer peer = peerSupplier.get();
        if (peer == null) {
            sink.completeExceptionally(lastError != null ? lastError
                    : new EvmExecutionException(new EvmExecutionError.StateUnavailable(
                            new byte[32], Address.ZERO, null)));
            return;
        }
        CompletableFuture<T> future;
        try {
            future = op.apply(peer);
        } catch (Throwable t) {
            log.warn("[snap-oracle] attempt {} threw synchronously: {}", attemptIdx, t.getMessage());
            attempt(op, attemptIdx + 1, t, sink);
            return;
        }
        future.whenComplete((value, error) -> {
            if (error == null) {
                sink.complete(value);
                return;
            }
            Throwable cause = unwrap(error);
            // This peer can't serve stateRoot for this head, via any of:
            //   - empty proof for a non-empty root / no state at all (InvalidProof /
            //     StateUnavailable) — it doesn't retain the trie;
            //   - it accepted the request then HUNG (TimeoutException) or the connection
            //     dropped (IOException) — equally useless for this short-lived context.
            // Tell it so, so a routing peerSupplier rotates AWAY from it for this head.
            // The head context is shared across an eth_call burst (confirm screen fires
            // many), so denying a hanger once makes the whole burst converge on responsive
            // peers instead of re-dialing the same hangers and eating the 30s budget on
            // each call — the cause of the "stuck confirmation" hangs on a flaky peer set.
            boolean cantServe =
                    (cause instanceof EvmExecutionException ee
                        && (ee.error() instanceof EvmExecutionError.InvalidProof
                            || ee.error() instanceof EvmExecutionError.StateUnavailable))
                    || cause instanceof java.util.concurrent.TimeoutException
                    || cause instanceof java.io.IOException;
            if (cantServe) {
                try { peer.reportRootUnavailable(); } catch (RuntimeException ignore) {}
            }
            log.warn("[snap-oracle] attempt {} failed: {}", attemptIdx, error.getMessage());
            attempt(op, attemptIdx + 1, cause, sink);
        });
    }

    /**
     * Peel the real cause out of the executor's wrapper exceptions. A single
     * snap fetch fans out through nested {@code CompletableFuture.allOf(...).join()}
     * stages, each of which re-wraps a failure in its own
     * {@link CompletionException} (and {@code ExecutionException} from any
     * {@code get()}). Unwrapping only one layer would leave the
     * {@code TimeoutException}/{@code IOException}/{@code InvalidProof} root cause
     * buried, so the {@code cantServe} routing check would miss it and never
     * deny the hanging peer. Recurse to the innermost non-wrapper cause, with a
     * self-cause guard so a malformed cycle can't spin forever.
     */
    private static Throwable unwrap(Throwable t) {
        Throwable cur = t;
        while ((cur instanceof CompletionException
                || cur instanceof java.util.concurrent.ExecutionException)
                && cur.getCause() != null
                && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        return cur;
    }

    private AccountWithStorageRoot verifyAndDecodeAccount(
            Bytes32 stateRoot, Bytes32 accountHash, Address address, List<Bytes> proofNodes) {
        var result = MerklePatriciaProofVerifier.verify(
                stateRoot, accountHash.toArrayUnsafe(), proofNodes);
        if (result instanceof MerklePatriciaProofVerifier.Result.Invalid invalid) {
            throw new EvmExecutionException(new EvmExecutionError.InvalidProof(
                    stateRoot.toArrayUnsafe(), address, invalid.reason()));
        }
        if (result instanceof MerklePatriciaProofVerifier.Result.Absent) {
            return new AccountWithStorageRoot(
                    new AccountState(address, 0L, BigInteger.ZERO, EMPTY_CODE_HASH),
                    MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT);
        }
        Bytes value = ((MerklePatriciaProofVerifier.Result.Found) result).value();
        // Account leaf value is RLP-encoded [nonce, balance, storageRoot, codeHash].
        return RLP.decodeList(value, reader -> {
            long nonce = reader.readLong();
            BigInteger balance = reader.readBigInteger();
            Bytes32 storageRoot = Bytes32.wrap(reader.readValue());
            Bytes32 codeHash = Bytes32.wrap(reader.readValue());
            return new AccountWithStorageRoot(
                    new AccountState(address, nonce, balance, codeHash.toArrayUnsafe()),
                    storageRoot);
        });
    }

    private BigInteger verifyAndDecodeStorage(
            Bytes32 storageRoot, Bytes32 slotHash, Address address, List<Bytes> proofNodes) {
        var result = MerklePatriciaProofVerifier.verify(
                storageRoot, slotHash.toArrayUnsafe(), proofNodes);
        if (result instanceof MerklePatriciaProofVerifier.Result.Invalid invalid) {
            throw new EvmExecutionException(new EvmExecutionError.InvalidProof(
                    storageRoot.toArrayUnsafe(), address, invalid.reason()));
        }
        if (result instanceof MerklePatriciaProofVerifier.Result.Absent) {
            return BigInteger.ZERO;
        }
        Bytes value = ((MerklePatriciaProofVerifier.Result.Found) result).value();
        // Storage leaves carry RLP-encoded uint256 (the trimmed-leading-zeros
        // big-endian encoding). The verifier already strips the outer RLP
        // header; the inner item is itself RLP-wrapped, so strip again.
        if (value.isEmpty()) return BigInteger.ZERO;
        Bytes raw = stripIntegerHeader(value);
        return raw.isEmpty() ? BigInteger.ZERO : new BigInteger(1, raw.toArrayUnsafe());
    }

    /**
     * Storage trie values are stored as {@code rlp(trimmed_uint256)} — the
     * leaf-value bytes carry an RLP integer encoding. Strip the header.
     */
    private static Bytes stripIntegerHeader(Bytes raw) {
        if (raw.isEmpty()) return raw;
        int first = raw.get(0) & 0xff;
        if (first < 0x80) return raw;
        if (first <= 0xb7) {
            int len = first - 0x80;
            return len == 0 ? Bytes.EMPTY : raw.slice(1, len);
        }
        // Long string — should never happen for a uint256, but handle gracefully.
        int lenLen = first - 0xb7;
        return raw.slice(1 + lenLen);
    }

    /** Storage trie keys are keccak256 of the 32-byte zero-padded slot index. */
    private static Bytes32 paddedSlotKey(BigInteger slot) {
        byte[] padded = new byte[32];
        byte[] raw = slot.toByteArray();
        if (raw.length > 32) {
            // BigInteger may emit a sign byte; strip a leading zero if present.
            if (raw.length == 33 && raw[0] == 0) {
                System.arraycopy(raw, 1, padded, 0, 32);
            } else {
                throw new IllegalArgumentException("slot exceeds 256 bits");
            }
        } else {
            System.arraycopy(raw, 0, padded, 32 - raw.length, raw.length);
        }
        return Bytes32.wrap(padded);
    }

    /** Internal helper: AccountState's public API doesn't carry storageRoot. */
    private record AccountWithStorageRoot(AccountState account, Bytes32 storageRoot) {}
}
