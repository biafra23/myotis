package io.myotis.evm.world;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Pins the schema-1 JSON shape and the repeat classification — the same
 *  sequences the Rust twin's tests run (rust/myotis-net/src/el/readstats.rs),
 *  so both engines agree byte for byte on the empty object. */
class ReadStatsTest {

    private static final long SEC = 1_000_000_000L;
    private static final long MS = 1_000_000L;

    private static byte[] fill(int len, int v) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) v);
        return b;
    }

    private static ReadStats.AccountFact fact(long nonce, int storageRoot) {
        return new ReadStats.AccountFact(nonce, BigInteger.valueOf(258),
                Bytes32.wrap(fill(32, storageRoot)), Bytes32.wrap(fill(32, 7)));
    }

    private static long field(String json, String... path) {
        JsonObject o = Json.parse(json).asObject();
        for (int i = 0; i < path.length - 1; i++) o = o.get(path[i]).asObject();
        return o.get(path[path.length - 1]).asLong();
    }

    @Test
    void emptyShapeMatchesTheRustEngine() {
        ReadStats s = new ReadStats(0L);
        assertEquals(
                "{\"schema\":1,\"windowSeconds\":0,"
                        + "\"account\":{\"fetches\":0,\"repeats\":0,\"sameStateRoot\":0,\"unchanged\":0,"
                        + "\"fetchMs\":0,\"sameStateRootFetchMs\":0,\"byAge\":{\"le12s\":{\"reads\":0,\"unchanged\":0},"
                        + "\"le60s\":{\"reads\":0,\"unchanged\":0},\"le5m\":{\"reads\":0,\"unchanged\":0},"
                        + "\"gt5m\":{\"reads\":0,\"unchanged\":0}}},"
                        + "\"storage\":{\"fetches\":0,\"repeats\":0,\"sameStateRoot\":0,\"sameStorageRoot\":0,"
                        + "\"sameValue\":0,\"fetchMs\":0,\"sameStorageRootFetchMs\":0,\"byAge\":{"
                        + "\"le12s\":{\"reads\":0,\"unchanged\":0},\"le60s\":{\"reads\":0,\"unchanged\":0},"
                        + "\"le5m\":{\"reads\":0,\"unchanged\":0},\"gt5m\":{\"reads\":0,\"unchanged\":0}}},"
                        + "\"code\":{\"fetches\":0,\"repeats\":0,\"fetchMs\":0,\"repeatFetchMs\":0},"
                        + "\"tracked\":{\"accounts\":0,\"slots\":0,\"codes\":0}}",
                s.toJson(0L));
    }

    @Test
    void storageRepeatsClassifyByRootAndAge() {
        ReadStats s = new ReadStats(0L);
        byte[] addr = fill(20, 0xAA);
        byte[] key = fill(32, 1);
        long ms = 100 * MS;
        BigInteger five = BigInteger.valueOf(5);
        // First fetch: nothing to compare against.
        s.observeStorage(addr, key, fill(32, 1), fill(32, 9), five, ms, 0L);
        // Same block (same world root) 5 s later: a per-root cache would hit.
        s.observeStorage(addr, key, fill(32, 1), fill(32, 9), five, ms, 5 * SEC);
        // New block, storage root unchanged, 30 s later: storageRoot cache hits.
        s.observeStorage(addr, key, fill(32, 2), fill(32, 9), five, ms, 35 * SEC);
        // New block, storage root moved, value unchanged, 4 min later: ceiling only.
        s.observeStorage(addr, key, fill(32, 3), fill(32, 8), five, ms, 275 * SEC);
        // Storage root moved and the value changed, > 5 min later.
        s.observeStorage(addr, key, fill(32, 4), fill(32, 7), BigInteger.valueOf(6), ms, 700 * SEC);
        String j = s.toJson(700 * SEC);
        assertEquals(700, field(j, "windowSeconds"));
        assertEquals(5, field(j, "storage", "fetches"));
        assertEquals(4, field(j, "storage", "repeats"));
        assertEquals(1, field(j, "storage", "sameStateRoot"));
        assertEquals(2, field(j, "storage", "sameStorageRoot"));
        assertEquals(1, field(j, "storage", "sameValue"));
        assertEquals(500, field(j, "storage", "fetchMs"));
        assertEquals(200, field(j, "storage", "sameStorageRootFetchMs"));
        assertEquals(1, field(j, "storage", "byAge", "le12s", "reads"));
        assertEquals(1, field(j, "storage", "byAge", "le12s", "unchanged"));
        assertEquals(1, field(j, "storage", "byAge", "le60s", "reads"));
        assertEquals(1, field(j, "storage", "byAge", "le5m", "reads"));
        assertEquals(1, field(j, "storage", "byAge", "le5m", "unchanged"));
        assertEquals(1, field(j, "storage", "byAge", "gt5m", "reads"));
        assertEquals(0, field(j, "storage", "byAge", "gt5m", "unchanged"));
        assertEquals(1, field(j, "tracked", "slots"));
    }

    @Test
    void accountRepeatsCountSameRootAndUnchangedSeparately() {
        ReadStats s = new ReadStats(0L);
        byte[] addr = fill(20, 0xBB);
        long ms = 40 * MS;
        s.observeAccount(addr, fill(32, 1), fact(1, 9), ms, 0L);
        // Duplicate within the block.
        s.observeAccount(addr, fill(32, 1), fact(1, 9), ms, 1 * SEC);
        // Next block, account untouched: the ceiling case, not sameStateRoot.
        s.observeAccount(addr, fill(32, 2), fact(1, 9), ms, 20 * SEC);
        // Next block, nonce bumped.
        s.observeAccount(addr, fill(32, 3), fact(2, 9), ms, 40 * SEC);
        String j = s.toJson(0L);
        assertEquals(4, field(j, "account", "fetches"));
        assertEquals(3, field(j, "account", "repeats"));
        assertEquals(1, field(j, "account", "sameStateRoot"));
        assertEquals(1, field(j, "account", "unchanged"));
        assertEquals(40, field(j, "account", "sameStateRootFetchMs"));
        assertEquals(1, field(j, "account", "byAge", "le12s", "reads"));
        assertEquals(2, field(j, "account", "byAge", "le60s", "reads"));
        assertEquals(1, field(j, "account", "byAge", "le60s", "unchanged"));
        assertEquals(1, field(j, "tracked", "accounts"));
    }

    @Test
    void absentAccountIsTheEmptyAccountOnEveryPath() {
        // An exclusion proof and a present-but-empty leaf are the same fact for
        // every caching question, so the two producers must agree.
        ReadStats.AccountFact fromLeaf = new ReadStats.AccountFact(0L, BigInteger.ZERO,
                MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT, ReadStats.EMPTY_CODE_HASH);
        assertEquals(ReadStats.AccountFact.absent(), fromLeaf);
        assertEquals(ReadStats.AccountFact.absent(), new ReadStats.AccountFact(0L, null, null, null));
    }

    @Test
    void chunkSharesOneRoundTripAcrossItsFacts() {
        ReadStats s = new ReadStats(0L);
        byte[] a1 = fill(20, 1);
        byte[] a2 = fill(20, 2);
        byte[] root = fill(32, 5);
        // 4 facts from one 400 ms response → 100 ms each; the repeat of a1's
        // slot then costs 100 ms under sameStorageRoot.
        s.observeChunk(root,
                List.of(new ReadStats.AccountObs(a1, fact(1, 9)), new ReadStats.AccountObs(a2, fact(2, 9))),
                List.of(new ReadStats.SlotObs(a1, fill(32, 1), fill(32, 9), BigInteger.ONE),
                        new ReadStats.SlotObs(a2, fill(32, 1), fill(32, 9), BigInteger.TWO)),
                400 * MS);
        s.observeChunk(fill(32, 6),
                List.of(),
                List.of(new ReadStats.SlotObs(a1, fill(32, 1), fill(32, 9), BigInteger.ONE)),
                50 * MS);
        String j = s.toJson(0L);
        assertEquals(2, field(j, "account", "fetches"));
        assertEquals(200, field(j, "account", "fetchMs"));
        assertEquals(3, field(j, "storage", "fetches"));
        assertEquals(1, field(j, "storage", "repeats"));
        assertEquals(1, field(j, "storage", "sameStorageRoot"));
        assertEquals(250, field(j, "storage", "fetchMs"));
        assertEquals(50, field(j, "storage", "sameStorageRootFetchMs"));
        // An empty chunk changes nothing.
        s.observeChunk(root, List.of(), List.of(), 999 * MS);
        assertEquals(250, field(s.toJson(0L), "storage", "fetchMs"));
    }

    @Test
    void subMillisecondSharesAreNotTruncatedPerFact() {
        ReadStats s = new ReadStats(0L);
        // A 200-fact chunk answered in 100 ms: 0.5 ms per fact, 100 ms in total — not 0.
        java.util.List<ReadStats.SlotObs> slots = new java.util.ArrayList<>();
        for (int i = 0; i < 200; i++) {
            byte[] key = new byte[32];
            key[31] = (byte) i;
            slots.add(new ReadStats.SlotObs(fill(20, 1), key, fill(32, 9), BigInteger.ONE));
        }
        s.observeChunk(fill(32, 5), List.of(), slots, 100 * MS);
        assertEquals(100, field(s.toJson(0L), "storage", "fetchMs"));
    }

    @Test
    void codeRepeatsAreAllAvoidable() {
        ReadStats s = new ReadStats(0L);
        s.observeCode(fill(32, 1), 30 * MS);
        s.observeCode(fill(32, 2), 30 * MS);
        s.observeCode(fill(32, 1), 50 * MS);
        String j = s.toJson(0L);
        assertEquals(3, field(j, "code", "fetches"));
        assertEquals(1, field(j, "code", "repeats"));
        assertEquals(110, field(j, "code", "fetchMs"));
        assertEquals(50, field(j, "code", "repeatFetchMs"));
        assertEquals(2, field(j, "tracked", "codes"));
    }

    @Test
    void trackingIsBounded() {
        ReadStats s = new ReadStats(0L);
        for (int i = 0; i < 4096 + 10; i++) {
            byte[] h = new byte[32];
            h[0] = (byte) (i >>> 8);
            h[1] = (byte) i;
            s.observeCode(h, 0L);
        }
        String j = s.toJson(0L);
        assertEquals(4096, field(j, "tracked", "codes"));
        assertEquals(0, field(j, "code", "repeats"));
    }
}
