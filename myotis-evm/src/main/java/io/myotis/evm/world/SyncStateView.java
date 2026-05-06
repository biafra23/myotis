package io.myotis.evm.world;

import io.myotis.evm.Address;
import io.myotis.evm.EvmExecutionException;
import org.apache.tuweni.units.bigints.UInt256;

import java.math.BigInteger;
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
 *       fetch. The executor must run the EVM on a worker thread so this does
 *       not block the caller's coroutine context.
 *   <li>Phase 2: the prefetch loop populates a per-call cache before the EVM
 *       reaches each miss, making the {@code join()} a no-op in the common
 *       case. Misses fall through and either trigger another iteration of the
 *       loop or return a sentinel (TBD per the open question in the plan).
 * </ul>
 */
public final class SyncStateView {

    private final SnapStateOracle oracle;
    private final byte[] stateRoot;
    private final BytecodeCache bytecodeCache;
    private final AccessTracker accessTracker;

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
        try {
            return oracle.fetchAccount(stateRoot, address).join();
        } catch (CompletionException ce) {
            unwrap(ce);
            throw ce;
        }
    }

    public UInt256 storage(Address address, UInt256 slot) {
        if (accessTracker != null) accessTracker.recordStorage(address, slot.toUnsignedBigInteger());
        try {
            BigInteger v = oracle.fetchStorage(stateRoot, address, slot.toUnsignedBigInteger()).join();
            return UInt256.valueOf(v);
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

    private static void unwrap(CompletionException ce) {
        if (ce.getCause() instanceof EvmExecutionException eee) throw eee;
        if (ce.getCause() instanceof RuntimeException re) throw re;
    }
}
