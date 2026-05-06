package io.myotis.evm.world;

import io.myotis.evm.Address;
import org.apache.tuweni.bytes.Bytes;

import java.math.BigInteger;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Tracks (address, slot) and codeHash misses observed during a single EVM run.
 *
 * <p>Phase 2 deliverable. The first execution pass uses sentinel values for
 * every miss and produces a (likely incorrect) result, but a complete access
 * list. The prefetch loop then batches the misses, populates the cache, and
 * re-runs.
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
