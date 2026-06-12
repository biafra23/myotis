package io.myotis.rpc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks the highest nonce this node has broadcast for a sender but not yet seen
 * mined, so eth_getTransactionCount("pending") can report next = nonce + 1 instead
 * of reusing a still-pending nonce.
 *
 * <p>A light node has no mempool. Without this, two back-to-back sends from one
 * account collide on a single nonce: the second reads the not-yet-incremented mined
 * count while the first is still pending and reuses its nonce (MetaMask's "second
 * send hangs on the confirm screen" symptom). The txs are ones we relayed ourselves
 * and hold the signed bytes for, so reporting their nonce as pending is our own honest
 * knowledge of the mempool we fed — not a trust assumption.
 *
 * <p>An entry expires when the chain's mined count passes it ({@link #overlay} sees the
 * tx mined) or after {@code ttlMs} (tx dropped/replaced — never wedge the account at a
 * nonce the chain will never reach). The overlay only ever RAISES the nonce; it never
 * returns a value below the supplied verified mined count.
 *
 * <p>Time is supplied by the caller (a monotonic {@link RpcClock} millis) so the tracker
 * stays a pure, deterministically-testable unit with no clock dependency of its own.
 */
final class PendingNonceTracker {

    private record Entry(long nonce, long atMs) {}

    private final Map<String, Entry> bySender = new ConcurrentHashMap<>();
    private final long ttlMs;

    PendingNonceTracker(long ttlMs) {
        this.ttlMs = ttlMs;
    }

    /** Record that {@code senderHex} broadcast a tx with {@code nonce} at {@code nowMs}.
     *  Keeps only the highest nonce seen for the sender. {@code senderHex} should be the
     *  lowercase 0x address. */
    void record(String senderHex, long nonce, long nowMs) {
        bySender.merge(senderHex, new Entry(nonce, nowMs),
                (cur, next) -> next.nonce() >= cur.nonce() ? next : cur);
    }

    /** Overlay our pending nonce onto a freshly-read mined count for {@code senderHex}.
     *  Returns {@code max(minedCount, pendingNonce + 1)} while our send hasn't landed,
     *  else the plain {@code minedCount}. Expires the entry when mined catches up or the
     *  TTL elapses. */
    long overlay(String senderHex, long minedCount, long nowMs) {
        Entry e = bySender.get(senderHex);
        if (e == null) return minedCount;
        // mined count becomes nonce + 1 once our tx lands; until then it's <= nonce.
        boolean mined = minedCount > e.nonce();
        boolean expired = nowMs - e.atMs() > ttlMs;
        if (mined || expired) {
            bySender.remove(senderHex, e);
            return minedCount;
        }
        return Math.max(minedCount, e.nonce() + 1);
    }

    /** True iff we hold an unexpired-by-mining pending nonce for the sender (for logging). */
    boolean has(String senderHex) {
        return bySender.containsKey(senderHex);
    }

    /** The tracked pending nonce for the sender, or -1 if none (for logging). */
    long pendingNonce(String senderHex) {
        Entry e = bySender.get(senderHex);
        return e == null ? -1L : e.nonce();
    }
}
