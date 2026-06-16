package io.myotis.rpc;

import org.apache.tuweni.bytes.Bytes32;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A "mini-mempool" of only this node's OWN broadcast transactions, used to watch them
 * propagate back across devp2p gossip.
 *
 * <p>A light wallet keeps no mempool and ignores the gossip firehose. But after it
 * broadcasts a signed tx it can watch for that exact hash returning over Transactions
 * (0x12) / NewPooledTransactionHashes (0x18) — positive confirmation the tx reached the
 * network (and, by its continued absence, a hint it may have been dropped). This holds
 * the watch set and stamps the first sighting of each.
 *
 * <p>Keyed by {@link Bytes32} (not hex) because {@link #markSeen} is called on the Netty
 * event loop for every gossip hash while watching — value-typed keys avoid per-hash hex
 * allocation. {@link #watchingAny} is the O(1) guard the handler checks before decoding
 * any gossip at all, so the firehose stays free whenever nothing of ours is in flight.
 *
 * <p>Time is supplied by the caller (monotonic {@link RpcClock} millis), keeping this a
 * pure, deterministically-testable unit.
 */
final class SentTxTracker {

    /** When we broadcast it, and when we first saw it on gossip ({@code -1} until seen). */
    private record Watch(long broadcastAtMs, long seenAtMs) {}

    private final Map<Bytes32, Watch> watched = new ConcurrentHashMap<>();
    private final long ttlMs;

    SentTxTracker(long ttlMs) {
        this.ttlMs = ttlMs;
    }

    /** Start watching a tx we just broadcast. */
    void watch(Bytes32 hash, long nowMs) {
        watched.put(hash, new Watch(nowMs, -1L));
    }

    /** O(1) hot-path guard: do we currently care about any gossip hash at all? */
    boolean watchingAny() {
        return !watched.isEmpty();
    }

    /**
     * Record that {@code hash} was seen on gossip.
     *
     * @return ms since broadcast if this is the FIRST sighting of one of our own txs;
     *         {@code -1} if the hash isn't ours or was already counted.
     */
    long markSeen(Bytes32 hash, long nowMs) {
        Watch[] firstSeen = {null};
        watched.computeIfPresent(hash, (h, w) -> {
            if (w.seenAtMs() >= 0) return w;            // already counted — leave as is
            firstSeen[0] = w;
            return new Watch(w.broadcastAtMs(), nowMs);
        });
        return firstSeen[0] == null ? -1L : nowMs - firstSeen[0].broadcastAtMs();
    }

    /** Stop watching a tx once it's confirmed mined (verified inclusion). */
    void confirmMined(Bytes32 hash) {
        watched.remove(hash);
    }

    /** True iff this is one of ours and we've seen it on gossip. */
    boolean wasSeen(Bytes32 hash) {
        Watch w = watched.get(hash);
        return w != null && w.seenAtMs() >= 0;
    }

    /** Hashes of watched txs we have NOT yet seen echo back on gossip — i.e. our initial
     *  broadcast may have reached too few / non-relaying peers, so they're candidates for
     *  resilient re-broadcast. Once a tx is seen propagating, the network has it and it drops
     *  off this list. */
    java.util.List<Bytes32> unseen() {
        java.util.List<Bytes32> out = new java.util.ArrayList<>();
        watched.forEach((h, w) -> { if (w.seenAtMs() < 0) out.add(h); });
        return out;
    }

    /** Drop entries older than the TTL (a send that never mined and stopped mattering).
     *  @return how many were evicted. */
    int evictExpired(long nowMs) {
        int[] removed = {0};
        watched.entrySet().removeIf(e -> {
            boolean expired = nowMs - e.getValue().broadcastAtMs() > ttlMs;
            if (expired) removed[0]++;
            return expired;
        });
        return removed[0];
    }

    int size() {
        return watched.size();
    }
}
