package io.myotis.rpc;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tracks the wallet's recurring {@code eth_call} shapes so the head warmer can
 * re-execute them against each freshly-built head (the "replay warm").
 *
 * <p><b>Why.</b> A wallet syncs by firing the <em>identical</em> heavy call —
 * observed live: Kohaku's 67KB Multicall3 {@code aggregate3} sweep, MetaMask's
 * ~32KB BalanceChecker — every poll cycle, pinned to the latest block it just
 * fetched from us. Executed on demand, each poll pays the full EVM + snap-fetch
 * cost inside the wallet's timeout and usually dies at the deadline. But the
 * node knows the shape in advance and knows the block the wallet will pin next
 * (it hands out the head via {@code eth_blockNumber}) — so it can run the call
 * once per new head in the background and serve the wallet's poll from the
 * result cache in microseconds.
 *
 * <p>A shape is (from, to, value, calldata) — everything of the call except the
 * block tag. A shape becomes warm-worthy after {@code minHits} sightings within
 * {@code hotTtlMs} (a one-off call is never warmed). Warming is trust-neutral:
 * the replay runs the exact same verified execution path a wallet-triggered
 * call would, just earlier.
 *
 * <p>Per-shape warm bookkeeping lives here too: at most one warm per shape in
 * flight ({@link #beginWarmables} marks, {@link #endWarm} clears, a stuck warm
 * expires after {@code warmTimeoutMs}), and a shape whose last warm FAILED is
 * backed off for {@code failureBackoffMs} so a persistently-failing call can't
 * turn the warmer into a background retry storm.
 *
 * <p>Bounded LRU ({@code maxTracked} shapes; each holds a copy of its calldata,
 * so with the {@code maxCalldataBytes} per-shape cap the whole tracker is a few
 * MB at worst). All methods are synchronized — call rates are a handful per
 * second at most.
 */
final class HotCallTracker {

    static {
        // shapeKey keccaks the calldata via Tuweni, which needs the BC provider.
        io.myotis.evm.CryptoProviders.ensureRegistered();
    }

    /** One recorded call shape. Arrays are defensive copies; {@code from} and
     *  {@code value} may be null (same meaning as in the RPC layer); {@code data}
     *  is never null (empty for a no-calldata call). */
    record HotCall(byte[] from, byte[] to, BigInteger value, byte[] data) {
        HotCall(byte[] from, byte[] to, BigInteger value, byte[] data) {
            this.from = from == null ? null : from.clone();
            this.to = to.clone();
            this.value = value;
            this.data = data == null ? new byte[0] : data.clone();
        }
        @Override public byte[] from() { return from == null ? null : from.clone(); }
        @Override public byte[] to() { return to.clone(); }
        @Override public byte[] data() { return data.clone(); }
    }

    private static final class Entry {
        final HotCall call;
        int hits;
        long lastSeenMs;
        boolean warmInFlight;
        long warmStartedMs;
        long lastWarmFailedMs = Long.MIN_VALUE;

        Entry(HotCall call) {
            this.call = call;
        }
    }

    private final int maxTracked;
    private final int minHits;
    private final long hotTtlMs;
    private final int maxCalldataBytes;
    private final long warmTimeoutMs;
    private final long failureBackoffMs;

    /** Access-ordered LRU of shapes, keyed by the shape's identity string. */
    private final Map<String, Entry> shapes;

    HotCallTracker(int maxTracked, int minHits, long hotTtlMs,
                   int maxCalldataBytes, long warmTimeoutMs, long failureBackoffMs) {
        this.maxTracked = maxTracked;
        this.minHits = minHits;
        this.hotTtlMs = hotTtlMs;
        this.maxCalldataBytes = maxCalldataBytes;
        this.warmTimeoutMs = warmTimeoutMs;
        this.failureBackoffMs = failureBackoffMs;
        this.shapes = new LinkedHashMap<>(16, 0.75f, true) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
                return size() > HotCallTracker.this.maxTracked;
            }
        };
    }

    /** Shape identity: everything of the call except the block tag — mirrors the
     *  root-less tail of the backend's flight key so one hashing scheme keys both. */
    static String shapeKey(byte[] from, byte[] to, BigInteger value, byte[] data) {
        return (from == null ? "0x0" : Bytes.wrap(from).toHexString())
                + ":" + Bytes.wrap(to).toHexString()
                + ":" + (value == null ? "0" : value.toString())
                + ":" + (data == null || data.length == 0
                        ? "0x" : Hash.keccak256(Bytes.wrap(data)).toHexString());
    }

    /** Record one sighting of a call shape. Oversized calldata is not tracked
     *  (nothing real is that big; the cap bounds tracker memory). */
    synchronized void record(byte[] from, byte[] to, BigInteger value, byte[] data, long nowMs) {
        if (to == null || to.length != 20) return;
        // A malformed from would make Address.of throw during EVERY replay of this
        // shape — reject it here so a bad shape can never enter the tracker.
        if (from != null && from.length != 20) return;
        if (data != null && data.length > maxCalldataBytes) return;
        String key = shapeKey(from, to, value, data);
        Entry e = shapes.get(key);
        if (e == null || nowMs - e.lastSeenMs > hotTtlMs) {
            // New shape, or one gone cold: (re)start counting — stale hits must not
            // qualify a shape that only just resumed.
            Entry fresh = new Entry(new HotCall(from, to, value, data));
            if (e != null) {   // keep warm bookkeeping across the reset
                fresh.warmInFlight = e.warmInFlight;
                fresh.warmStartedMs = e.warmStartedMs;
                fresh.lastWarmFailedMs = e.lastWarmFailedMs;
            }
            e = fresh;
            shapes.put(key, e);
        }
        e.hits++;
        e.lastSeenMs = nowMs;
    }

    /**
     * The shapes worth warming right now, most-recently-seen first, at most
     * {@code max}: seen at least {@code minHits} times, last seen within
     * {@code hotTtlMs}, no warm currently in flight (an in-flight warm older than
     * {@code warmTimeoutMs} counts as dead), and not inside the failure backoff.
     * Each returned shape is MARKED warm-in-flight — the caller must pair every
     * one with an {@link #endWarm} call when its warm completes or fails to submit.
     */
    synchronized List<HotCall> beginWarmables(long nowMs, int max) {
        List<Entry> candidates = new ArrayList<>();
        for (Entry e : shapes.values()) {
            if (e.hits < minHits) continue;
            if (nowMs - e.lastSeenMs > hotTtlMs) continue;
            if (e.warmInFlight && nowMs - e.warmStartedMs <= warmTimeoutMs) continue;
            // Sentinel-guarded: nowMs - MIN_VALUE overflows negative, which would
            // read as "inside the backoff" forever.
            if (e.lastWarmFailedMs != Long.MIN_VALUE
                    && nowMs - e.lastWarmFailedMs < failureBackoffMs) continue;
            candidates.add(e);
        }
        candidates.sort((a, b) -> Long.compare(b.lastSeenMs, a.lastSeenMs));
        List<HotCall> out = new ArrayList<>();
        for (Entry e : candidates) {
            if (out.size() >= max) break;
            e.warmInFlight = true;
            e.warmStartedMs = nowMs;
            out.add(e.call);
        }
        return out;
    }

    /** Close out a warm begun by {@link #beginWarmables}. A failed warm starts the
     *  per-shape backoff so the next head builds don't immediately re-run a call
     *  that just demonstrated it can't complete. */
    synchronized void endWarm(HotCall call, boolean success, long nowMs) {
        Entry e = shapes.get(shapeKey(call.from, call.to, call.value, call.data));
        if (e == null) return;   // aged out of the LRU while warming
        e.warmInFlight = false;
        if (!success) e.lastWarmFailedMs = nowMs;
    }

    /** Drop every tracked shape (purge-cache): the recorded calldata profile is
     *  cleared and warming only resumes once the wallet re-qualifies its shapes. */
    synchronized void clear() {
        shapes.clear();
    }

    /** Number of tracked shapes (test hook). */
    synchronized int size() {
        return shapes.size();
    }
}
