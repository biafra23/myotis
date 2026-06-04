package org.hyperledger.besu.evm.internal;

import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.evm.Code;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Android-compatible drop-in replacement for Besu's
 * {@code org.hyperledger.besu.evm.internal.CodeCache}.
 *
 * <h2>Why this file exists</h2>
 * Besu's real {@code CodeCache} (in {@code org.hyperledger.besu:evm:24.12.2})
 * backs its bytecode/jump-dest cache with <b>Caffeine</b>. Caffeine's
 * {@code StripedBuffer} static initializer reflects into the JDK-internal field
 * {@code java.lang.Thread.threadLocalRandomProbe} via {@code Unsafe} — a field
 * that <b>does not exist on Android's ART runtime</b>. So the first time the EVM
 * is built, {@code EVM.&lt;init&gt;} → {@code new CodeCache(...)} →
 * {@code Caffeine.build()} → {@code StripedBuffer.&lt;clinit&gt;} throws:
 * <pre>{@code NoSuchFieldException: No field threadLocalRandomProbe in class java.lang.Thread}</pre>
 * This is a fundamental Caffeine-on-Android incompatibility (present in 2.8.x
 * and 2.9.x alike — not fixable by a version pin) and it is the only place
 * Besu's {@code :evm} module touches Caffeine on the EVM execution path
 * (alongside its weigher {@code CodeScale}, which is unused once this class no
 * longer asks for it).
 *
 * <h2>What this changes</h2>
 * Same public API as the upstream class, backed by a plain access-ordered
 * {@link LinkedHashMap} LRU instead of Caffeine — so the EVM never loads any
 * Caffeine class. The cache is a pure performance optimisation (it memoises
 * parsed {@link Code} by code {@link Hash}); correctness does not depend on the
 * eviction policy, so a simple entry-count bound is sufficient for the wallet's
 * view-call / ENS workload. {@code getWeightLimit()} still reports the
 * configured byte budget for API parity.
 *
 * <h2>How it takes effect</h2>
 * Same mechanism as our {@code BesuProvider} patch: the {@code stripBesuProvider}
 * artifact transform in {@code android-app/build.gradle.kts} deletes the
 * upstream {@code CodeCache.class} from the evm jar before dexing, so this class
 * is the only definition. Remove this file (and its strip entry) if Besu is
 * upgraded to a release whose code cache is Android-safe, or if a fork replaces
 * Caffeine upstream.
 */
public class CodeCache {

    /**
     * Entry cap for the LRU. Besu's default jump-dest cache budget is ~32 MB of
     * weight; bytecode entries are typically a few KB, so a few thousand entries
     * is a comparable working set. We bound by count (not bytes) to avoid
     * needing Besu's weigher. Generous enough that the wallet's handful of
     * contracts per query never evict mid-call.
     */
    private static final int MAX_ENTRIES = 4_096;

    private final long weightLimit;
    private final Map<Hash, Code> cache;

    public CodeCache(final EvmConfiguration config) {
        this(config.getJumpDestCacheWeightBytes());
    }

    private CodeCache(final long weightLimit) {
        this.weightLimit = weightLimit;
        this.cache = Collections.synchronizedMap(
                new LinkedHashMap<Hash, Code>(64, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(final Map.Entry<Hash, Code> eldest) {
                        return size() > MAX_ENTRIES;
                    }
                });
    }

    public void invalidate(final Hash key) {
        cache.remove(key);
    }

    public void cleanUp() {
        // No background maintenance to flush (unlike Caffeine); no-op.
    }

    public Code getIfPresent(final Hash key) {
        return cache.get(key);
    }

    public void put(final Hash key, final Code value) {
        cache.put(key, value);
    }

    public long size() {
        return cache.size();
    }

    public long getWeightLimit() {
        return weightLimit;
    }
}
