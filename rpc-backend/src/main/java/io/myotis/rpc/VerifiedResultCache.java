package io.myotis.rpc;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A bounded, TTL'd cache of verified RPC results keyed by a string that PINS the anchored
 * state — e.g. {@code stateRoot:to:keccak(calldata)} for eth_call, or
 * {@code stateRoot:from:to:keccak(data):value} for estimateGas.
 *
 * <p>Why this is safe to cache at all: the keyed result is a pure function of the anchored
 * {@code stateRoot}. Once a tuple has been executed-and-verified against that root the
 * answer is bit-identical on every replay, so reuse is a scheduling optimization, never a
 * trust relaxation — the caller only inserts values it has already proof-verified against
 * the root named in the key. A SNAP-proven value does not "expire"; it stays a valid
 * statement about that block forever. The {@code ttlMs} here therefore bounds STALENESS and
 * memory, not correctness: it mirrors how long the underlying head context itself stays
 * servable, so a retried confirm screen that still resolves to the same pinned head finds
 * its answer warm while a "latest" read that has since rolled to a new root simply computes
 * a new key and misses (then recomputes against fresh state).
 *
 * <p>Eviction is twofold: an LRU bound ({@code maxEntries}) caps memory under a confirm
 * screen's hundreds of distinct calls, and a per-entry TTL drops stale answers — expired
 * entries are also pruned lazily on read so no sweeper thread is needed.
 *
 * <p>Time is supplied by the caller (monotonic {@link RpcClock} millis), keeping this a
 * pure, deterministically-testable unit (same convention as {@link SentTxTracker} /
 * {@link PendingNonceTracker}).
 *
 * <p>Thread-safe via a synchronized map. {@link #get} does a get-then-maybe-remove that is
 * not atomic as a pair, but the only race is two threads both observing the same entry
 * expired and both removing it — harmless and idempotent.
 *
 * @param <V> the cached value type (e.g. {@code byte[]} for eth_call return data, {@code Long}
 *            for a gas estimate)
 */
final class VerifiedResultCache<V> {

    /** A cached value with the monotonic ms it was produced (for TTL). */
    private record Entry<V>(V value, long atMs) {}

    private final Map<String, Entry<V>> map;
    private final long ttlMs;

    VerifiedResultCache(int maxEntries, long ttlMs) {
        this.ttlMs = ttlMs;
        this.map = Collections.synchronizedMap(
                new LinkedHashMap<>(64, 0.75f, true) {
                    @Override protected boolean removeEldestEntry(Map.Entry<String, Entry<V>> e) {
                        return size() > maxEntries;
                    }
                });
    }

    /** The cached value for {@code key} if present and within TTL, else {@code null}. Drops an
     *  expired entry on read so the map self-cleans without a sweeper. */
    V get(String key, long nowMs) {
        Entry<V> e = map.get(key);
        if (e == null) return null;
        if (nowMs - e.atMs() >= ttlMs) {
            map.remove(key, e);
            return null;
        }
        return e.value();
    }

    /** Record a verified result for replay. A {@code null} value is ignored — errors/reverts
     *  must not be cached, so a transient failure is never pinned. */
    void put(String key, V value, long nowMs) {
        if (value == null) return;
        map.put(key, new Entry<>(value, nowMs));
    }

    int size() {
        return map.size();
    }

    void clear() {
        map.clear();
    }
}
