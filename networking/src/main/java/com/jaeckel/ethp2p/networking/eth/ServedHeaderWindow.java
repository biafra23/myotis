package com.jaeckel.ethp2p.networking.eth;

import org.apache.tuweni.bytes.Bytes32;

import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * Shared, bounded store of recent block headers this node can serve to peers, and the
 * single source of truth for the eth/69 (EIP-7642) advertised block range.
 *
 * <p>We are a light client, not an archive node. The eth/69 Status range is a promise:
 * a peer that asks for a block inside {@code [earliestBlock, latestBlock]} and gets an
 * empty response scores us down and eventually drops us. So this store enforces a strict
 * invariant — <b>{@link #advertise} never names a block we do not hold</b>. Both
 * {@code earliest} AND {@code latest} of the returned range are held headers (or genesis);
 * callers must send the range as-is and must NOT substitute the chain head for
 * {@code latest} (the chain head is the network's head, learned from peers, which a light
 * client does not hold).
 *
 * <p>One instance per network, shared across every peer connection (owned by the RLPx
 * connector), so a header fetched on one connection is servable on all of them and a
 * freshly connected peer can be told an accurate range immediately. Thread-safe via a
 * single monitor; the window is tiny (tens of entries) so contention is irrelevant.
 *
 * <p>Genesis is held separately and is always servable (peers probe it for fork checks),
 * but it is deliberately NOT folded into the contiguous head window — advertising
 * {@code [0, head]} is exactly the over-claim this class exists to prevent. When the head
 * window is empty we advertise {@code [0, 0]} (genesis, which we do hold) rather than
 * claiming the head.
 */
public final class ServedHeaderWindow {

    /** Advertised eth/69 range: every block in {@code [earliest, latest]} is held and servable. */
    public record Range(long earliest, long latest, Bytes32 latestHash) {}

    private volatile int maxWindow;

    // Recent headers by block number (ascending). Bounded to the most recent maxWindow
    // block numbers seen. hashByNumber/parentByNumber/byHash are kept in lockstep.
    // The parent hash lets the backfill anchor a downward batch to the held run
    // without re-decoding stored RLP. Guarded by `this`.
    private final NavigableMap<Long, byte[]> byNumber = new TreeMap<>();
    private final NavigableMap<Long, Bytes32> hashByNumber = new TreeMap<>();
    private final NavigableMap<Long, Bytes32> parentByNumber = new TreeMap<>();
    private final Map<String, byte[]> byHash = new HashMap<>();

    // Genesis (block 0) — always servable for fork probes, held outside the head window.
    private final Bytes32 genesisHash;    // nullable
    private final byte[] genesisRlp;      // nullable (only where we embed genesis bytes)
    private final String genesisHashHex;  // nullable

    public ServedHeaderWindow(int maxWindow, Bytes32 genesisHash, byte[] genesisRlp) {
        this.maxWindow = Math.max(1, maxWindow);
        this.genesisHash = genesisHash;
        this.genesisRlp = genesisRlp;
        this.genesisHashHex = genesisHash != null ? genesisHash.toHexString() : null;
    }

    /** Live-adjust the window cap (Settings). Shrinking evicts the now-out-of-range tail. */
    public synchronized void setMaxWindow(int n) {
        this.maxWindow = Math.max(1, n);
        evict();
    }

    public int maxWindow() {
        return maxWindow;
    }

    /**
     * Record a header we hold (received and verified). Genesis is ignored here — it is
     * seeded once via the constructor and never evicted.
     */
    public synchronized void put(long number, Bytes32 hash, Bytes32 parentHash, byte[] rlp) {
        if (number <= 0 || hash == null || rlp == null) return;
        byNumber.put(number, rlp);
        // If this number previously mapped to a different hash (reorg), drop the stale hash.
        Bytes32 prev = hashByNumber.put(number, hash);
        if (prev != null && !prev.equals(hash)) byHash.remove(prev.toHexString());
        parentByNumber.put(number, parentHash);
        byHash.put(hash.toHexString(), rlp);
        evict();
    }

    /** The stored parent hash of a held header (the backfill's downward anchor),
     *  or null when the block isn't held. */
    public synchronized Bytes32 parentHashOf(long number) {
        return parentByNumber.get(number);
    }

    /** The stored hash of a held header, or null when the block isn't held. */
    public synchronized Bytes32 hashOf(long number) {
        return hashByNumber.get(number);
    }

    /** Evict every held header BELOW {@code number} (reorg splice repair: a
     *  verified batch whose parent disagrees with the held entry below it proves
     *  the entries below are a stale fork). */
    public synchronized void evictBelow(long number) {
        while (!byNumber.isEmpty() && byNumber.firstKey() < number) {
            long n = byNumber.firstKey();
            byNumber.remove(n);
            parentByNumber.remove(n);
            Bytes32 h = hashByNumber.remove(n);
            if (h != null) byHash.remove(h.toHexString());
        }
    }

    /** Serve a header by block number, or null if we don't hold it. */
    public synchronized byte[] getByNumber(long number) {
        if (number == 0 && genesisRlp != null) return genesisRlp;
        return byNumber.get(number);
    }

    /** Serve a header by hash (lowercase 0x hex), or null if we don't hold it. */
    public synchronized byte[] getByHash(String hashHex) {
        if (hashHex == null) return null;
        if (genesisHashHex != null && genesisHashHex.equals(hashHex)) return genesisRlp;
        return byHash.get(hashHex);
    }

    /**
     * Compute the eth/69 range to advertise, given the current chain head number/hash.
     * The result claims only blocks we actually hold:
     * <ul>
     *   <li>{@code latest} = the highest held header at or below {@code headNumber}, with
     *       its real hash; {@code earliest} walks down from it while the run stays
     *       contiguous, bounded to {@link #maxWindow}.</li>
     *   <li>If the head window holds nothing yet, advertise {@code [0, 0]} with the genesis
     *       hash (genesis we do hold) — never the head, which we do not.</li>
     *   <li>Only if we hold neither recent headers nor genesis (non-mainnet, pre-fetch) do
     *       we fall back to the tip {@code [head, head]} as a self-correcting bootstrap
     *       claim; this is the single case that momentarily names an unheld block.</li>
     * </ul>
     */
    public synchronized Range advertise(long headNumber, Bytes32 headHash) {
        Long top = headNumber > 0 ? byNumber.floorKey(headNumber) : null;
        if (top == null) {
            if (genesisHash != null) return new Range(0, 0, genesisHash);
            return new Range(Math.max(0, headNumber), Math.max(0, headNumber), headHash);
        }
        long floor = Math.max(1, top - maxWindow + 1);
        long earliest = top;
        while (earliest - 1 >= floor && byNumber.containsKey(earliest - 1)) {
            earliest--;
        }
        return new Range(earliest, top, hashByNumber.get(top));
    }

    /** Evict everything below the most-recent-maxWindow band. Caller holds the monitor. */
    private void evict() {
        if (byNumber.isEmpty()) return;
        long top = byNumber.lastKey();
        long floor = top - maxWindow + 1;
        while (!byNumber.isEmpty() && byNumber.firstKey() < floor) {
            long n = byNumber.firstKey();
            byNumber.remove(n);
            Bytes32 h = hashByNumber.remove(n);
            parentByNumber.remove(n);
            if (h != null) byHash.remove(h.toHexString());
        }
    }
}
