package io.myotis.evm.world;

import io.myotis.evm.Address;
import org.apache.tuweni.bytes.Bytes;

import java.math.BigInteger;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Records (address, slot) and codeHash <em>accesses</em> observed during a
 * single EVM run.
 *
 * <p>Phase 0/1: records every read; the executor uses the snapshot only as
 * an audit trail. Phase 2 will distinguish hits vs misses (likely by adding
 * a separate {@code recordMiss(...)} entry point so the prefetch loop can
 * iterate on the miss set without re-walking everything). The current API
 * intentionally reports every access so that switching the policy in Phase 2
 * is purely additive.
 *
 * <p>Thread-safe in the limited sense that all updates are recorded via
 * {@code synchronized} and snapshots return immutable copies.
 */
public final class AccessTracker {

    private final Set<Address> accounts = new HashSet<>();
    private final Set<SlotKey> storage = new HashSet<>();
    private final Set<Bytes> codeHashes = new HashSet<>();

    public synchronized void recordAccount(Address address) {
        accounts.add(address);
    }

    public synchronized void recordStorage(Address address, BigInteger slot) {
        storage.add(new SlotKey(address, slot));
    }

    public synchronized void recordBytecode(byte[] codeHash) {
        codeHashes.add(Bytes.wrap(codeHash.clone()));
    }

    public synchronized Snapshot snapshot() {
        return new Snapshot(
                Collections.unmodifiableSet(new HashSet<>(accounts)),
                Collections.unmodifiableSet(new HashSet<>(storage)),
                Collections.unmodifiableSet(new HashSet<>(codeHashes)));
    }

    public synchronized void clear() {
        accounts.clear();
        storage.clear();
        codeHashes.clear();
    }

    public record SlotKey(Address address, BigInteger slot) {}

    public record Snapshot(Set<Address> accounts, Set<SlotKey> storage, Set<Bytes> codeHashes) {}
}
