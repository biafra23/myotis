package io.myotis.evm.world;

import io.myotis.evm.Address;
import io.myotis.evm.EvmExecutionException;
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
 * network round trip). The bridge is one of two strategies:
 * <ul>
 *   <li>Phase 0: the fixture oracle returns already-completed futures, so
 *       {@code join()} is effectively free.
 *   <li>Phase 1: a single synchronous round trip per miss is acceptable but
 *       slow. {@code join()} blocks the calling thread for the duration of the
 *       fetch.
 *   <li>Phase 2: the prefetch loop populates the in-view cache before the EVM
 *       reaches each miss, making the {@code join()} a no-op in the common
 *       case.
 * </ul>
 *
 * <p>The view caches {@code (address) → AccountState} and
 * {@code (address, slot) → UInt256} so that repeated reads — both within a
 * single EVM run and across iterations of the Phase 2 prefetch loop — hit
 * memory rather than the oracle. Bytecode caching is delegated to the
 * supplied {@link BytecodeCache}.
 */
public final class SyncStateView {

    private final SnapStateOracle oracle;
    private final byte[] stateRoot;
    private final BytecodeCache bytecodeCache;
    private final AccessTracker accessTracker;

    private final Map<Address, AccountState> accountCache = new ConcurrentHashMap<>();
    private final Map<SlotKey, UInt256> storageCache = new ConcurrentHashMap<>();

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

    public AccountState account(Address address) {
        if (accessTracker != null) accessTracker.recordAccount(address);
        AccountState cached = accountCache.get(address);
        if (cached != null) return cached;
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
        return bytecodeCache.get(codeHash).orElseGet(() -> {
            try {
                byte[] code = oracle.fetchBytecode(codeHash).join();
                bytecodeCache.put(codeHash, code);
                return code;
            } catch (CompletionException ce) {
                unwrap(ce);
                throw ce;
            }
        });
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
