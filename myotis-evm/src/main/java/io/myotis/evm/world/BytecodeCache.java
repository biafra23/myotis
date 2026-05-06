package io.myotis.evm.world;

import org.apache.tuweni.bytes.Bytes;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Cache of {@code codeHash -> bytecode}. Bytecode is immutable forever, so
 * cross-session caching is safe.
 *
 * <p>The default implementation is an in-process map. The Phase 1+ wallet
 * integration will plug in a persistent variant backed by the existing
 * Myotis local DB; that backing is intentionally not part of this module's
 * compile-time surface.
 */
public interface BytecodeCache {

    /** Returns the bytecode for {@code codeHash}, if cached. */
    Optional<byte[]> get(byte[] codeHash);

    /** Inserts {@code bytecode} keyed by its keccak256 hash. */
    void put(byte[] codeHash, byte[] bytecode);

    /** In-process implementation; suitable for tests and as a per-session L1. */
    static BytecodeCache inMemory() {
        return new InMemory();
    }

    final class InMemory implements BytecodeCache {
        private final ConcurrentMap<Bytes, byte[]> map = new ConcurrentHashMap<>();

        @Override
        public Optional<byte[]> get(byte[] codeHash) {
            byte[] v = map.get(Bytes.wrap(codeHash));
            return v == null ? Optional.empty() : Optional.of(v.clone());
        }

        @Override
        public void put(byte[] codeHash, byte[] bytecode) {
            map.putIfAbsent(Bytes.wrap(codeHash.clone()), bytecode.clone());
        }
    }
}
