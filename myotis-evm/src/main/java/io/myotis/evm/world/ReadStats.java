package io.myotis.evm.world;

import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Read-fetch statistics — a SHADOW CACHE that caches nothing and instead
 * measures how much of the verified state-read traffic a cache <em>could</em>
 * have served, and under which keying. The Java twin of the Rust engine's
 * {@code myotis_net::el::readstats}; both emit the identical JSON shape
 * (schema 1, pinned by a test on each side) so a host reads one schema
 * whichever engine answers.
 *
 * <p>Every verified fetch that actually crossed the network (an account
 * proof, a storage-slot proof, a bytecode blob) is reported here AFTER it
 * verified, with the anchors it verified against. The observer remembers the
 * last verified fact per key (bounded, most-recently-observed wins) and
 * classifies each repeat:
 * <ul>
 *   <li><b>sameStateRoot</b> — the world state root is unchanged since the
 *       previous fetch of this key (same block): a per-root cache would have
 *       served it with zero round-trips.</li>
 *   <li><b>sameStorageRoot</b> (storage only) — the contract's storage trie
 *       root is unchanged, so the slot value is provably the same: a cache
 *       keyed by {@code (storageRoot, slot)} would have served it at the cost
 *       of the account proof alone. This is the sound cross-block scheme (the
 *       account proof is the freshness check) that {@link StateProofCache}
 *       already implements; a non-zero count here means a fetch bypassed it.</li>
 *   <li><b>unchanged</b> / <b>sameValue</b> — the value is identical although
 *       the root moved. No sound cache can exploit this without a proof; it is
 *       the CEILING, reported so "serve a minute-old value" can be judged
 *       against how often such a value would have been right.</li>
 *   <li><b>byAge</b> — repeats bucketed by how long ago the key was last
 *       fetched, each with how many were value-unchanged.</li>
 * </ul>
 * Costs are wall-clock milliseconds of the snap round-trip(s) that produced
 * the observation — never the beacon-anchoring ladder that may follow an
 * operator query — so {@code sameStorageRootFetchMs} is literally the time a
 * storage-root-keyed cache would have saved.
 *
 * <p>Thread-safe (one lock; contention is trivial next to a network fetch).
 * Android-safe: no post-API-29 JDK APIs.
 */
public final class ReadStats {

    private static final int TRACKED_ACCOUNTS = 4096;
    private static final int TRACKED_SLOTS = 16_384;
    private static final int TRACKED_CODES = 4096;
    /** Age-bucket upper bounds in seconds; the last bucket is open-ended. */
    private static final long[] AGE_BOUNDS_SECS = {12, 60, 300};
    private static final String[] AGE_LABELS = {"le12s", "le60s", "le5m", "gt5m"};

    /** keccak256 of the empty byte string — the code hash of every codeless
     *  account (a well-known constant; spelled out so this class needs no
     *  crypto provider). */
    static final Bytes32 EMPTY_CODE_HASH = Bytes32.fromHexString(
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    /**
     * The proof-verified account fields a repeat is compared against. A
     * verified EXCLUSION proof is {@link #absent()} — the empty account —
     * which post-EIP-161 no existing account can equal, so no separate
     * "present" flag is needed. Record equality is the "unchanged" test
     * ({@link Bytes32} compares by content).
     */
    public record AccountFact(long nonce, BigInteger balance, Bytes32 storageRoot, Bytes32 codeHash) {
        public AccountFact {
            if (balance == null) balance = BigInteger.ZERO;
            if (storageRoot == null) storageRoot = MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT;
            if (codeHash == null) codeHash = EMPTY_CODE_HASH;
        }

        public static AccountFact absent() {
            return new AccountFact(0L, BigInteger.ZERO,
                    MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT, EMPTY_CODE_HASH);
        }
    }

    /** One verified account proof out of a batch response (see {@link #observeChunk}). */
    public record AccountObs(byte[] address, AccountFact fact) {}

    /** One verified slot proof out of a batch response (see {@link #observeChunk}). */
    public record SlotObs(byte[] address, byte[] storageKey, byte[] storageRoot, BigInteger value) {}

    private record SlotKey(Bytes address, Bytes32 storageKey) {}
    private record AccountSeen(Bytes32 stateRoot, AccountFact fact, long atNanos) {}
    private record SlotSeen(Bytes32 stateRoot, Bytes32 storageRoot, BigInteger value, long atNanos) {}

    private static final class ByAge {
        final long[] reads = new long[AGE_LABELS.length];
        final long[] unchanged = new long[AGE_LABELS.length];

        void record(long ageNanos, boolean same) {
            long secs = ageNanos / 1_000_000_000L;
            int idx = AGE_BOUNDS_SECS.length;
            for (int i = 0; i < AGE_BOUNDS_SECS.length; i++) {
                if (secs <= AGE_BOUNDS_SECS[i]) { idx = i; break; }
            }
            reads[idx]++;
            if (same) unchanged[idx]++;
        }

        void writeJson(StringBuilder sb) {
            sb.append('{');
            for (int i = 0; i < AGE_LABELS.length; i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(AGE_LABELS[i]).append("\":{");
                num(sb, "reads", reads[i]).append(',');
                num(sb, "unchanged", unchanged[i]).append('}');
            }
            sb.append('}');
        }
    }

    private final Object lock = new Object();
    private final long startedNanos;
    // account
    private long accountFetches, accountRepeats, accountSameStateRoot, accountUnchanged,
            accountFetchMs, accountSameStateRootMs;
    private final ByAge accountByAge = new ByAge();
    // storage
    private long storageFetches, storageRepeats, storageSameStateRoot, storageSameStorageRoot,
            storageSameValue, storageFetchMs, storageSameStorageRootMs;
    private final ByAge storageByAge = new ByAge();
    // code
    private long codeFetches, codeRepeats, codeFetchMs, codeRepeatMs;

    // Plain access-ordered LRUs, guarded by `lock` (no synchronizedMap wrapper:
    // every access already holds the lock).
    private final Map<Bytes, AccountSeen> accounts = StateProofCache.boundedLru(TRACKED_ACCOUNTS);
    private final Map<SlotKey, SlotSeen> slots = StateProofCache.boundedLru(TRACKED_SLOTS);
    private final Map<Bytes32, Boolean> codes = StateProofCache.boundedLru(TRACKED_CODES);

    public ReadStats() {
        this(System.nanoTime());
    }

    ReadStats(long nowNanos) {
        this.startedNanos = nowNanos;
    }

    /** A verified account proof for {@code address} at world root {@code stateRoot}
     *  that took {@code elapsedNanos} of wall-clock to fetch. */
    public void observeAccount(byte[] address, byte[] stateRoot, AccountFact fact, long elapsedNanos) {
        long now = System.nanoTime();
        synchronized (lock) {
            account(Bytes.wrap(address.clone()), Bytes32.wrap(stateRoot.clone()), fact, elapsedNanos, now);
        }
    }

    /** A verified storage-slot proof for {@code (address, storageKey)} anchored at
     *  the account's {@code storageRoot} under world root {@code stateRoot}. */
    public void observeStorage(byte[] address, byte[] storageKey, byte[] stateRoot,
                               byte[] storageRoot, BigInteger value, long elapsedNanos) {
        long now = System.nanoTime();
        synchronized (lock) {
            storage(new SlotKey(Bytes.wrap(address.clone()), Bytes32.wrap(storageKey.clone())),
                    Bytes32.wrap(stateRoot.clone()), Bytes32.wrap(storageRoot.clone()), value,
                    elapsedNanos, now);
        }
    }

    /**
     * Every fact one batch response verified at world root {@code stateRoot}.
     * One wire round-trip served all of them, so its {@code chunkElapsedNanos}
     * is shared out equally per fact rather than charged in full to each
     * (which would count the trip N times). One lock acquisition per chunk.
     */
    public void observeChunk(byte[] stateRoot, List<AccountObs> accountsSeen, List<SlotObs> slotsSeen,
                             long chunkElapsedNanos) {
        int facts = accountsSeen.size() + slotsSeen.size();
        if (facts == 0) return;
        long share = chunkElapsedNanos / facts;
        long now = System.nanoTime();
        Bytes32 root = Bytes32.wrap(stateRoot.clone());
        synchronized (lock) {
            for (AccountObs a : accountsSeen) {
                account(Bytes.wrap(a.address().clone()), root, a.fact(), share, now);
            }
            for (SlotObs s : slotsSeen) {
                storage(new SlotKey(Bytes.wrap(s.address().clone()), Bytes32.wrap(s.storageKey().clone())),
                        root, Bytes32.wrap(s.storageRoot().clone()), s.value(), share, now);
            }
        }
    }

    /** A bytecode blob fetched for {@code codeHash} (content-addressed: every
     *  repeat is avoidable by construction). */
    public void observeCode(byte[] codeHash, long elapsedNanos) {
        long ms = elapsedNanos / 1_000_000L;
        Bytes32 key = Bytes32.wrap(codeHash.clone());
        synchronized (lock) {
            codeFetches++;
            codeFetchMs += ms;
            if (codes.get(key) != null) {
                codeRepeats++;
                codeRepeatMs += ms;
            }
            codes.put(key, Boolean.TRUE);
        }
    }

    // ---- under `lock` ----

    private void account(Bytes address, Bytes32 stateRoot, AccountFact fact, long elapsedNanos, long now) {
        long ms = elapsedNanos / 1_000_000L;
        accountFetches++;
        accountFetchMs += ms;
        AccountSeen prev = accounts.get(address);
        if (prev != null) {
            accountRepeats++;
            boolean same = prev.fact().equals(fact);
            if (prev.stateRoot().equals(stateRoot)) {
                accountSameStateRoot++;
                accountSameStateRootMs += ms;
            } else if (same) {
                accountUnchanged++;
            }
            accountByAge.record(Math.max(0L, now - prev.atNanos()), same);
        }
        accounts.put(address, new AccountSeen(stateRoot, fact, now));
    }

    private void storage(SlotKey key, Bytes32 stateRoot, Bytes32 storageRoot, BigInteger value,
                         long elapsedNanos, long now) {
        long ms = elapsedNanos / 1_000_000L;
        BigInteger v = value == null ? BigInteger.ZERO : value;
        storageFetches++;
        storageFetchMs += ms;
        SlotSeen prev = slots.get(key);
        if (prev != null) {
            storageRepeats++;
            boolean same = prev.value().equals(v);
            if (prev.stateRoot().equals(stateRoot)) storageSameStateRoot++;
            if (prev.storageRoot().equals(storageRoot)) {
                // Includes the same-world-root case: the storage root cannot
                // move while the world root stands still.
                storageSameStorageRoot++;
                storageSameStorageRootMs += ms;
            } else if (same) {
                storageSameValue++;
            }
            storageByAge.record(Math.max(0L, now - prev.atNanos()), same);
        }
        slots.put(key, new SlotSeen(stateRoot, storageRoot, v, now));
    }

    // ---- test seams: the same classification with an injected clock ----

    void observeAccount(byte[] address, byte[] stateRoot, AccountFact fact, long elapsedNanos, long now) {
        synchronized (lock) {
            account(Bytes.wrap(address), Bytes32.wrap(stateRoot), fact, elapsedNanos, now);
        }
    }

    void observeStorage(byte[] address, byte[] storageKey, byte[] stateRoot, byte[] storageRoot,
                        BigInteger value, long elapsedNanos, long now) {
        synchronized (lock) {
            storage(new SlotKey(Bytes.wrap(address), Bytes32.wrap(storageKey)), Bytes32.wrap(stateRoot),
                    Bytes32.wrap(storageRoot), value, elapsedNanos, now);
        }
    }

    /** The counters as JSON: fixed key order, no whitespace (schema 1). */
    public String toJson() {
        return toJson(System.nanoTime());
    }

    String toJson(long now) {
        StringBuilder sb = new StringBuilder(768);
        synchronized (lock) {
            sb.append('{');
            num(sb, "schema", 1).append(',');
            num(sb, "windowSeconds", Math.max(0L, now - startedNanos) / 1_000_000_000L);
            sb.append(",\"account\":{");
            num(sb, "fetches", accountFetches).append(',');
            num(sb, "repeats", accountRepeats).append(',');
            num(sb, "sameStateRoot", accountSameStateRoot).append(',');
            num(sb, "unchanged", accountUnchanged).append(',');
            num(sb, "fetchMs", accountFetchMs).append(',');
            num(sb, "sameStateRootFetchMs", accountSameStateRootMs);
            sb.append(",\"byAge\":");
            accountByAge.writeJson(sb);
            sb.append("},\"storage\":{");
            num(sb, "fetches", storageFetches).append(',');
            num(sb, "repeats", storageRepeats).append(',');
            num(sb, "sameStateRoot", storageSameStateRoot).append(',');
            num(sb, "sameStorageRoot", storageSameStorageRoot).append(',');
            num(sb, "sameValue", storageSameValue).append(',');
            num(sb, "fetchMs", storageFetchMs).append(',');
            num(sb, "sameStorageRootFetchMs", storageSameStorageRootMs);
            sb.append(",\"byAge\":");
            storageByAge.writeJson(sb);
            sb.append("},\"code\":{");
            num(sb, "fetches", codeFetches).append(',');
            num(sb, "repeats", codeRepeats).append(',');
            num(sb, "fetchMs", codeFetchMs).append(',');
            num(sb, "repeatFetchMs", codeRepeatMs);
            sb.append("},\"tracked\":{");
            num(sb, "accounts", accounts.size()).append(',');
            num(sb, "slots", slots.size()).append(',');
            num(sb, "codes", codes.size());
            sb.append("}}");
        }
        return sb.toString();
    }

    private static StringBuilder num(StringBuilder sb, String key, long value) {
        return sb.append('"').append(key).append("\":").append(value);
    }
}
