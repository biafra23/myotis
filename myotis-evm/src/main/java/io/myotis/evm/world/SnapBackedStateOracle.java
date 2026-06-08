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
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
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
        this(peerSupplier, bytecodeCache, DEFAULT_MAX_ATTEMPTS);
    }

    public SnapBackedStateOracle(
            Supplier<SnapPeer> peerSupplier,
            BytecodeCache bytecodeCache,
            int maxAttempts) {
        this.peerSupplier = peerSupplier;
        this.bytecodeCache = bytecodeCache;
        this.maxAttempts = maxAttempts;
    }

    @Override
    public CompletableFuture<AccountState> fetchAccount(byte[] stateRoot, Address address) {
        return fetchAccountWithRoot(stateRoot, address)
                .thenApply(AccountWithStorageRoot::account);
    }

    @Override
    public CompletableFuture<BigInteger> fetchStorage(byte[] stateRoot, Address address, BigInteger slot) {
        Bytes32 root = Bytes32.wrap(stateRoot.clone());
        Bytes addressBytes = Bytes.wrap(address.toByteArray());
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
                return CompletableFuture.completedFuture(BigInteger.ZERO);
            }
            return tryWithRetries(peer -> peer
                    .getTrieNodes(root, List.of(SnapPeer.PathSet.storageSlot(accountHash, slotHash)))
                    .thenApply(nodes -> verifyAndDecodeStorage(storageRoot, slotHash, address, nodes)));
        });
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
        Bytes32 root = Bytes32.wrap(stateRoot.clone());
        Bytes addressBytes = Bytes.wrap(address.toByteArray());
        Bytes32 accountHash = Bytes32.wrap(Hash.keccak256(addressBytes).toArrayUnsafe());

        String key = root.toHexString() + ':' + addressBytes.toHexString();
        return accountCache.computeIfAbsent(key, k -> {
            CompletableFuture<AccountWithStorageRoot> f = tryWithRetries(peer -> peer
                    .getTrieNodes(root, List.of(SnapPeer.PathSet.account(accountHash)))
                    .thenApply(nodes -> verifyAndDecodeAccount(root, accountHash, address, nodes)));
            // Evict failed fetches so a later read can retry across peers. Use
            // *Async so the removal never runs synchronously inside
            // computeIfAbsent (which would be a reentrant map mutation); the
            // value-conditional remove keeps a racing re-fetch intact.
            f.whenCompleteAsync((v, e) -> {
                if (e != null) accountCache.remove(k, f);
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
            log.warn("[snap-oracle] attempt {} failed: {}", attemptIdx, error.getMessage());
            attempt(op, attemptIdx + 1, unwrap(error), sink);
        });
    }

    private static Throwable unwrap(Throwable t) {
        return t instanceof CompletionException && t.getCause() != null ? t.getCause() : t;
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
