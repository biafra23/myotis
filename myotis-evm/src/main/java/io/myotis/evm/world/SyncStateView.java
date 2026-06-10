package io.myotis.evm.world;

import io.myotis.evm.Address;
import io.myotis.evm.CryptoProviders;
import io.myotis.evm.EvmExecutionException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.units.bigints.UInt256;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletionException;

/**
 * Synchronous facade over an asynchronous {@link SnapStateOracle}.
 *
 * <p>Besu's EVM is synchronous: the {@code runToHalt} loop calls
 * {@code WorldUpdater#get} and {@code Account#getStorageValue} expecting
 * values returned directly. Our oracle is async by nature (a SNAP fetch is a
 * network round trip). The bridge has three modes:
 * <ul>
 *   <li><strong>Cache-only:</strong> read from the in-view cache. Misses
 *       fall through to one of the two paths below.
 *   <li><strong>Block-on-miss</strong> (default): on a cache miss, call the
 *       oracle and {@code join()} the future. Slow but correct. This is
 *       what {@link io.myotis.evm.DefaultEvmExecutor} uses.
 *   <li><strong>Sentinel-on-miss</strong> (Phase 2 prefetch loop, iter 0):
 *       on a cache miss, return a sentinel value (zero / empty) without
 *       blocking. The miss is recorded in the {@link AccessTracker} and the
 *       sentinel is <em>not</em> cached — so a subsequent run with the flag
 *       cleared will hit the oracle. The convergence loop runs the EVM with
 *       this flag set, collects the access list, parallel-fetches the misses,
 *       and re-runs with the flag cleared to get a real result.
 * </ul>
 *
 * <p>The view caches {@code (address) → AccountState} and
 * {@code (address, slot) → UInt256} so that repeated reads — both within a
 * single EVM run and across iterations of the Phase 2 prefetch loop — hit
 * memory rather than the oracle. Bytecode caching is delegated to the
 * supplied {@link BytecodeCache}.
 */
public final class SyncStateView {

    private static final byte[] EMPTY_CODE_HASH;
    static {
        CryptoProviders.ensureRegistered();
        EMPTY_CODE_HASH = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();
    }

    private final SnapStateOracle oracle;
    private final byte[] stateRoot;
    private final BytecodeCache bytecodeCache;

    /**
     * Tracker that receives every account/storage/bytecode access. Mutable
     * so the Phase 2 prefetch loop can swap a fresh tracker in per
     * iteration (the per-iteration access set drives the parallel batch
     * fetch wave between iterations). May be null if no recording is
     * needed.
     */
    private volatile AccessTracker accessTracker;

    private final Map<Address, AccountState> accountCache = new ConcurrentHashMap<>();
    private final Map<SlotKey, UInt256> storageCache = new ConcurrentHashMap<>();

    /**
     * When true, cache misses return zero-shaped sentinel values without
     * calling the oracle. The miss is recorded in {@code accessTracker};
     * the sentinel is not cached. See class Javadoc.
     */
    private volatile boolean sentinelOnMiss = false;

    /** Count of sentinel values handed out (cache misses while {@link #sentinelOnMiss}
     *  is on). Lets the convergence loop tell a sentinel run that was ALL cache hits
     *  (its result is real — every read returned verified data) from one that may
     *  have computed on placeholders. */
    private final java.util.concurrent.atomic.AtomicLong sentinelMisses =
            new java.util.concurrent.atomic.AtomicLong();

    /** Total sentinel values handed out so far; diff across a run to detect misses. */
    public long sentinelMissCount() {
        return sentinelMisses.get();
    }

    public SyncStateView(
            SnapStateOracle oracle,
            byte[] stateRoot,
            BytecodeCache bytecodeCache,
            AccessTracker accessTracker) {
        this.oracle = oracle;
        this.stateRoot = stateRoot.clone();
        this.bytecodeCache = bytecodeCache;
        this.accessTracker = accessTracker;
    }

    /** Toggle sentinel-on-miss mode for the next run. See class Javadoc. */
    public void setSentinelOnMiss(boolean v) {
        this.sentinelOnMiss = v;
    }

    public boolean isSentinelOnMiss() {
        return sentinelOnMiss;
    }

    /**
     * Swap the access tracker. Used by the Phase 2 prefetch loop to install
     * a fresh per-iteration tracker without rebuilding the whole view (and
     * losing the cache).
     */
    public void setAccessTracker(AccessTracker accessTracker) {
        this.accessTracker = accessTracker;
    }

    public AccountState account(Address address) {
        if (accessTracker != null) accessTracker.recordAccount(address);
        AccountState cached = accountCache.get(address);
        if (cached != null) return cached;
        if (sentinelOnMiss) {
            // Empty default; intentionally NOT cached so a subsequent run
            // with the flag cleared will fetch the real value.
            sentinelMisses.incrementAndGet();
            return new AccountState(address, 0L, BigInteger.ZERO, EMPTY_CODE_HASH);
        }
        try {
            AccountState fetched = oracle.fetchAccount(stateRoot, address).join();
            accountCache.put(address, fetched);
            return fetched;
        } catch (CompletionException ce) {
            unwrap(ce);
            throw ce;
        }
    }

    public UInt256 storage(Address address, UInt256 slot) {
        if (accessTracker != null) accessTracker.recordStorage(address, slot.toUnsignedBigInteger());
        SlotKey key = new SlotKey(address, slot);
        UInt256 cached = storageCache.get(key);
        if (cached != null) return cached;
        if (sentinelOnMiss) {
            // Zero is a valid storage value, so this is indistinguishable
            // from a real zero — but the access is recorded in the tracker
            // either way, and the convergence loop will re-run with the
            // flag cleared to confirm.
            sentinelMisses.incrementAndGet();
            return UInt256.ZERO;
        }
        try {
            BigInteger v = oracle.fetchStorage(stateRoot, address, slot.toUnsignedBigInteger()).join();
            UInt256 value = UInt256.valueOf(v);
            storageCache.put(key, value);
            return value;
        } catch (CompletionException ce) {
            unwrap(ce);
            throw ce;
        }
    }

    public byte[] bytecode(byte[] codeHash) {
        if (accessTracker != null) accessTracker.recordBytecode(codeHash);
        var cached = bytecodeCache.get(codeHash);
        if (cached.isPresent()) return cached.get();
        if (sentinelOnMiss) {
            // Empty bytecode means "no code" to the EVM — a CALL to such an
            // account returns immediately with no execution, so the iter-0
            // sentinel run will short-circuit any nested calls. That's
            // expected: the access list is still recorded, and iter 1
            // re-enters with real bytecode populated. The PrefetchingEvmExecutor
            // pre-populates the *target* contract's bytecode synchronously so
            // iter 0's run reaches actual bytecode at the top level.
            sentinelMisses.incrementAndGet();
            return new byte[0];
        }
        try {
            byte[] code = oracle.fetchBytecode(codeHash).join();
            bytecodeCache.put(codeHash, code);
            return code;
        } catch (CompletionException ce) {
            unwrap(ce);
            throw ce;
        }
    }

    /** Phase 2 helpers — let the prefetch loop pre-populate values from a parallel batch fetch. */

    public boolean hasAccount(Address address) {
        return accountCache.containsKey(address);
    }

    public boolean hasStorage(Address address, UInt256 slot) {
        return storageCache.containsKey(new SlotKey(address, slot));
    }

    public void putAccount(Address address, AccountState value) {
        accountCache.put(address, value);
    }

    public void putStorage(Address address, UInt256 slot, UInt256 value) {
        storageCache.put(new SlotKey(address, slot), value);
    }

    private static void unwrap(CompletionException ce) {
        if (ce.getCause() instanceof EvmExecutionException eee) throw eee;
        if (ce.getCause() instanceof RuntimeException re) throw re;
    }

    private record SlotKey(Address address, UInt256 slot) {
        SlotKey {
            Objects.requireNonNull(address);
            Objects.requireNonNull(slot);
        }
    }
}
