package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Java half of the LCSS-v1 cross-engine golden contract: the snapshot file
 * ({@code sync-state[-net].snapshot}) is read AND written by both the Java and
 * the Rust engine, so the byte layout is a shared on-disk contract. This test
 * pins the committed golden fixture ({@code rust/testdata/snapshot/lcss-v1-golden.bin});
 * the Rust twin ({@code myotis-consensus/src/snapshot.rs} conformance test) pins
 * the SAME bytes. Both sides build the identical patterned snapshot, so a codec
 * change on either side that shifts a single byte fails one of the two suites.
 *
 * <p>Generates the fixture when absent (mirrors LcVectorConformanceTest's
 * generate-when-missing convention); asserts byte-identity when present.
 */
class SnapshotGoldenConformanceTest {

    private static final Path GOLDEN =
            Path.of("..", "rust", "testdata", "snapshot", "lcss-v1-golden.bin");

    // ---- the patterned snapshot — MUST match snapshot.rs tests exactly ----

    private static byte[] patterned(int seed, int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) (seed + i);
        return b;
    }

    private static byte[] root(int seed) {
        return patterned(seed, 32);
    }

    private static LightClientHeader header(int seed, boolean electra) {
        BeaconBlockHeader beacon = new BeaconBlockHeader(
                14_600_000L + seed, 42L + seed, root(seed), root(seed + 1), root(seed + 2));
        ExecutionPayloadHeader exec = new ExecutionPayloadHeader(
                root(seed + 3), patterned(seed, 20), root(seed + 4), root(seed + 5),
                patterned(seed, 256), root(seed + 6),
                23_000_000L + seed, 30_000_000L, 12_345_678L, 1_751_000_000L + seed,
                patterned(seed, 11), root(seed + 7), root(seed + 8), root(seed + 9),
                root(seed + 10), 131_072L, 0L,
                electra ? root(seed + 11) : null,
                electra ? root(seed + 12) : null,
                electra ? root(seed + 13) : null);
        byte[][] branch = new byte[4][];
        for (int i = 0; i < 4; i++) branch[i] = root(seed + 20 + i);
        return new LightClientHeader(beacon, exec, branch);
    }

    private static SyncCommittee committee(int seed) {
        byte[] flat = patterned(seed, SyncCommittee.PUBKEY_COUNT * SyncCommittee.PUBKEY_SIZE);
        byte[][] pks = new byte[SyncCommittee.PUBKEY_COUNT][];
        for (int i = 0; i < SyncCommittee.PUBKEY_COUNT; i++) {
            byte[] pk = new byte[SyncCommittee.PUBKEY_SIZE];
            System.arraycopy(flat, i * SyncCommittee.PUBKEY_SIZE, pk, 0, SyncCommittee.PUBKEY_SIZE);
            pks[i] = pk;
        }
        return new SyncCommittee(pks, patterned(seed + 1, SyncCommittee.PUBKEY_SIZE));
    }

    private static LightClientStore.Snapshot snapshot() {
        return new LightClientStore.Snapshot(
                header(1, true), header(50, false), committee(3), committee(7),
                14_600_001L, 14_600_033L, 1795L);
    }

    @Test
    void goldenFixtureIsByteStable() throws Exception {
        byte[] gvr = root(99);
        byte[] bytes = LightClientStoreSnapshot.serialize(snapshot(), gvr);
        assertNotNull(bytes);

        if (!Files.exists(GOLDEN)) {
            Files.createDirectories(GOLDEN.getParent());
            Files.write(GOLDEN, bytes);
            System.out.println("[snapshot-golden] wrote " + GOLDEN + " (" + bytes.length + " bytes)");
        }
        byte[] committed = Files.readAllBytes(GOLDEN);
        assertArrayEquals(committed, bytes,
                "LCSS-v1 byte layout drifted from the committed golden fixture — "
                + "this format is a cross-engine on-disk contract (Rust reads/writes "
                + "the same file); change BOTH codecs and regenerate deliberately");

        // And the committed bytes round-trip through the reader.
        LightClientStore.Snapshot back = LightClientStoreSnapshot.deserialize(committed, gvr);
        assertNotNull(back);
        assertEquals(1795L, back.currentSyncCommitteePeriod());
        assertEquals(14_600_001L, back.finalizedSlot());
        assertArrayEquals(bytes, LightClientStoreSnapshot.serialize(back, gvr));
    }
}
