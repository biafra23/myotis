package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import com.jaeckel.ethp2p.core.consensus.LcFork;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for the persisted sync-committee snapshot. This is a trust
 * anchor on resume, so the codec must reproduce every field byte-for-byte.
 */
class LightClientStoreSnapshotTest {

    private static byte[] fill(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) (seed + i);
        return b;
    }

    private static ExecutionPayloadHeader execHeader(int seed, boolean electra, byte[] extra) {
        return new ExecutionPayloadHeader(
                fill(32, seed), fill(20, seed + 1), fill(32, seed + 2), fill(32, seed + 3),
                fill(256, seed + 4), fill(32, seed + 5), 100 + seed, 200 + seed, 300 + seed, 400 + seed,
                extra, fill(32, seed + 6), fill(32, seed + 7), fill(32, seed + 8), fill(32, seed + 9),
                500 + seed, 600 + seed,
                electra ? fill(32, seed + 10) : null,
                electra ? fill(32, seed + 11) : null,
                electra ? fill(32, seed + 12) : null);
    }

    private static LightClientHeader header(int seed, boolean electra, byte[] extra) {
        BeaconBlockHeader beacon = new BeaconBlockHeader(
                1000 + seed, 2000 + seed, fill(32, seed + 20), fill(32, seed + 21), fill(32, seed + 22));
        byte[][] branch = new byte[4][];
        for (int i = 0; i < 4; i++) branch[i] = fill(32, seed + 30 + i);
        return new LightClientHeader(beacon, execHeader(seed, electra, extra), branch);
    }

    private static SyncCommittee committee(int seed) {
        byte[][] pks = new byte[SyncCommittee.PUBKEY_COUNT][];
        for (int i = 0; i < pks.length; i++) pks[i] = fill(SyncCommittee.PUBKEY_SIZE, seed + i);
        return new SyncCommittee(pks, fill(SyncCommittee.PUBKEY_SIZE, seed + 9999));
    }

    private static void assertHeaderEquals(LightClientHeader a, LightClientHeader b) {
        assertEquals(a.beacon().slot(), b.beacon().slot());
        assertArrayEquals(a.beacon().encode(), b.beacon().encode());
        for (int i = 0; i < 4; i++) assertArrayEquals(a.executionBranch()[i], b.executionBranch()[i]);
        assertArrayEquals(a.execution().stateRoot(), b.execution().stateRoot());
        assertArrayEquals(a.execution().extraData(), b.execution().extraData());
        assertArrayEquals(a.execution().blockHash(), b.execution().blockHash());
        assertEquals(a.execution().blockNumber(), b.execution().blockNumber());
        assertEquals(a.execution().excessBlobGas(), b.execution().excessBlobGas());
        assertArrayEquals(a.execution().depositRequestsRoot(), b.execution().depositRequestsRoot());
    }

    private static void assertCommitteeEquals(SyncCommittee a, SyncCommittee b) {
        for (int i = 0; i < SyncCommittee.PUBKEY_COUNT; i++) assertArrayEquals(a.pubkeys()[i], b.pubkeys()[i]);
        assertArrayEquals(a.aggregatePubkey(), b.aggregatePubkey());
    }

    @Test
    void roundTripsElectraWithNextCommittee() {
        byte[] gvr = fill(32, 7);
        LightClientStore.Snapshot orig = new LightClientStore.Snapshot(
                header(1, true, fill(13, 1)), header(2, true, new byte[0]),
                committee(3), committee(4), 14_295_040L, 14_295_072L, 1746L);

        byte[] bytes = LightClientStoreSnapshot.serialize(orig, gvr);
        assertNotNull(bytes);
        LightClientStore.Snapshot back = LightClientStoreSnapshot.deserialize(bytes, gvr);
        assertNotNull(back);

        assertEquals(orig.finalizedSlot(), back.finalizedSlot());
        assertEquals(orig.optimisticSlot(), back.optimisticSlot());
        assertEquals(orig.currentSyncCommitteePeriod(), back.currentSyncCommitteePeriod());
        assertHeaderEquals(orig.finalizedHeader(), back.finalizedHeader());
        assertHeaderEquals(orig.optimisticHeader(), back.optimisticHeader());
        assertCommitteeEquals(orig.currentSyncCommittee(), back.currentSyncCommittee());
        assertNotNull(back.nextSyncCommittee());
        assertCommitteeEquals(orig.nextSyncCommittee(), back.nextSyncCommittee());
    }

    @Test
    void roundTripsDenebWithoutNextCommittee() {
        byte[] gvr = fill(32, 9);
        LightClientStore.Snapshot orig = new LightClientStore.Snapshot(
                header(5, false, new byte[0]), header(6, false, fill(32, 6)),
                committee(7), null, 100L, 132L, 12L);
        byte[] bytes = LightClientStoreSnapshot.serialize(orig, gvr);
        LightClientStore.Snapshot back = LightClientStoreSnapshot.deserialize(bytes, gvr);
        assertNotNull(back);
        assertNull(back.nextSyncCommittee());
        assertHeaderEquals(orig.finalizedHeader(), back.finalizedHeader());
        assertCommitteeEquals(orig.currentSyncCommittee(), back.currentSyncCommittee());
    }

    @Test
    void rejectsWrongChain() {
        byte[] bytes = LightClientStoreSnapshot.serialize(new LightClientStore.Snapshot(
                header(1, true, new byte[0]), header(1, true, new byte[0]),
                committee(1), null, 1, 1, 1), fill(32, 1));
        assertNull(LightClientStoreSnapshot.deserialize(bytes, fill(32, 99)), "different gvr must be rejected");
    }

    @Test
    void rejectsGarbageAndTruncation() {
        assertNull(LightClientStoreSnapshot.deserialize(null, fill(32, 1)));
        assertNull(LightClientStoreSnapshot.deserialize(new byte[]{1, 2, 3}, fill(32, 1)));
        byte[] bytes = LightClientStoreSnapshot.serialize(new LightClientStore.Snapshot(
                header(1, true, new byte[0]), header(1, true, new byte[0]),
                committee(1), null, 1, 1, 1), fill(32, 1));
        assertNull(LightClientStoreSnapshot.deserialize(Arrays.copyOf(bytes, bytes.length - 100), fill(32, 1)),
                "truncated snapshot must be rejected, not partially loaded");
    }

    // ---- LCSS v2 (Gloas). Rust twin: snapshot.rs v2_* tests ----

    /** A Gloas-shaped header: block hash + 11 branch nodes. */
    private static LightClientHeader gloasHeader(int seed) {
        BeaconBlockHeader beacon = new BeaconBlockHeader(
                11_296_768L + seed, 7L + seed, fill(32, seed), fill(32, seed + 1), fill(32, seed + 2));
        byte[][] branch = new byte[11][];
        for (int i = 0; i < 11; i++) branch[i] = fill(32, seed + 30 + i);
        return LightClientHeader.gloas(beacon, fill(32, seed + 3), branch);
    }

    /** Finalized header still payload-shaped (the first epochs after the fork),
     *  optimistic header Gloas-shaped — the mixed state v2 exists for. */
    private static LightClientStore.Snapshot gloasSnapshot() {
        return new LightClientStore.Snapshot(header(1, true, fill(11, 1)), gloasHeader(60),
                committee(3), committee(7), 11_296_700L, 11_296_829L, 1379L);
    }

    private static LightClientStore.Snapshot payloadSnapshot() {
        return new LightClientStore.Snapshot(header(1, true, fill(11, 1)), header(50, false, new byte[0]),
                committee(3), committee(7), 14_600_001L, 14_600_033L, 1795L);
    }

    /**
     * Payload-shaped state keeps writing v1 byte-for-byte (an older build can still
     * resume it); a Gloas-shaped header switches the file to v2, which round-trips
     * both shapes.
     */
    @Test
    void v2OnlyWhenAHeaderNeedsIt() {
        byte[] gvr = fill(32, 99);
        assertEquals(1, LightClientStoreSnapshot.serialize(payloadSnapshot(), gvr)[4]);
        LightClientStore.Snapshot s = gloasSnapshot();
        byte[] bytes = LightClientStoreSnapshot.serialize(s, gvr);
        assertEquals(2, bytes[4]);
        assertSnapshotEquals(s, LightClientStoreSnapshot.deserialize(bytes, gvr));
        LightClientStore.Snapshot both = new LightClientStore.Snapshot(gloasHeader(2), s.optimisticHeader(),
                s.currentSyncCommittee(), s.nextSyncCommittee(), s.finalizedSlot(), s.optimisticSlot(),
                s.currentSyncCommitteePeriod());
        assertSnapshotEquals(both, LightClientStoreSnapshot.deserialize(
                LightClientStoreSnapshot.serialize(both, gvr), gvr));
    }

    /** An unknown shape tag is a corrupt (or future) file: refuse, don't guess. */
    @Test
    void v2RejectsAnUnknownShapeTag() {
        byte[] gvr = fill(32, 99);
        byte[] bytes = LightClientStoreSnapshot.serialize(gloasSnapshot(), gvr);
        // magic 4 + version 1 + gvr 32 + 3 x u64 + finalized beacon 112.
        int tagAt = 4 + 1 + 32 + 24 + 112;
        assertEquals(0, bytes[tagAt]);
        bytes[tagAt] = 2;
        assertNull(LightClientStoreSnapshot.deserialize(bytes, gvr));
    }

    @Test
    void v2RejectsTruncationAndAnUnknownVersion() {
        byte[] gvr = fill(32, 99);
        byte[] v2 = LightClientStoreSnapshot.serialize(gloasSnapshot(), gvr);
        for (int cut : new int[]{5, 173, 174, 700, v2.length - 1}) {
            assertNull(LightClientStoreSnapshot.deserialize(Arrays.copyOf(v2, cut), gvr), "v2 cut at " + cut);
        }
        byte[] wrongVersion = LightClientStoreSnapshot.serialize(payloadSnapshot(), gvr);
        wrongVersion[4] = 3;
        assertNull(LightClientStoreSnapshot.deserialize(wrongVersion, gvr));
    }

    /** A Gloas-shaped store snapshots and restores like any other. */
    @Test
    void restoresAGloasSnapshotIntoStore() {
        byte[] gvr = fill(32, 99);
        LightClientStore store = new LightClientStore();
        store.restore(LightClientStoreSnapshot.deserialize(
                LightClientStoreSnapshot.serialize(gloasSnapshot(), gvr), gvr));
        assertEquals(LcFork.GLOAS, store.getOptimisticHeader().shape());
        assertSnapshotEquals(gloasSnapshot(), store.snapshot());
    }

    /**
     * Field-for-field equality of two snapshots, in either header shape (the consensus
     * types define no {@code equals} of their own). Shared with the golden test.
     */
    static void assertSnapshotEquals(LightClientStore.Snapshot want, LightClientStore.Snapshot got) {
        assertNotNull(got, "snapshot did not decode");
        assertEquals(want.currentSyncCommitteePeriod(), got.currentSyncCommitteePeriod());
        assertEquals(want.finalizedSlot(), got.finalizedSlot());
        assertEquals(want.optimisticSlot(), got.optimisticSlot());
        assertLcHeaderEquals(want.finalizedHeader(), got.finalizedHeader());
        assertLcHeaderEquals(want.optimisticHeader(), got.optimisticHeader());
        assertEquals(want.currentSyncCommittee(), got.currentSyncCommittee());
        assertEquals(want.nextSyncCommittee(), got.nextSyncCommittee());
    }

    private static void assertLcHeaderEquals(LightClientHeader want, LightClientHeader got) {
        assertEquals(want.beacon(), got.beacon());
        assertEquals(want.shape(), got.shape());
        assertArrayEquals(want.executionBlockHash(), got.executionBlockHash());
        assertEquals(want.executionBranch().length, got.executionBranch().length);
        for (int i = 0; i < want.executionBranch().length; i++) {
            assertArrayEquals(want.executionBranch()[i], got.executionBranch()[i], "branch node " + i);
        }
        if (want.shape() == LcFork.GLOAS) {
            assertNull(got.execution());
            return;
        }
        ExecutionPayloadHeader a = want.execution();
        ExecutionPayloadHeader b = got.execution();
        assertArrayEquals(a.parentHash(), b.parentHash());
        assertArrayEquals(a.feeRecipient(), b.feeRecipient());
        assertArrayEquals(a.stateRoot(), b.stateRoot());
        assertArrayEquals(a.receiptsRoot(), b.receiptsRoot());
        assertArrayEquals(a.logsBloom(), b.logsBloom());
        assertArrayEquals(a.prevRandao(), b.prevRandao());
        assertEquals(a.blockNumber(), b.blockNumber());
        assertEquals(a.gasLimit(), b.gasLimit());
        assertEquals(a.gasUsed(), b.gasUsed());
        assertEquals(a.timestamp(), b.timestamp());
        assertArrayEquals(a.extraData(), b.extraData());
        assertArrayEquals(a.baseFeePerGas(), b.baseFeePerGas());
        assertArrayEquals(a.blockHash(), b.blockHash());
        assertArrayEquals(a.transactionsRoot(), b.transactionsRoot());
        assertArrayEquals(a.withdrawalsRoot(), b.withdrawalsRoot());
        assertEquals(a.blobGasUsed(), b.blobGasUsed());
        assertEquals(a.excessBlobGas(), b.excessBlobGas());
        assertArrayEquals(a.depositRequestsRoot(), b.depositRequestsRoot());
        assertArrayEquals(a.withdrawalRequestsRoot(), b.withdrawalRequestsRoot());
        assertArrayEquals(a.consolidationRequestsRoot(), b.consolidationRequestsRoot());
    }

    @Test
    void restoresIntoStore() {
        LightClientStore.Snapshot s = new LightClientStore.Snapshot(
                header(1, true, new byte[0]), header(2, true, new byte[0]),
                committee(3), committee(4), 14_295_040L, 14_295_072L, 1746L);
        LightClientStore store = new LightClientStore();
        store.restore(s);
        assertTrue(store.isInitialized());
        assertEquals(1746L, store.getCurrentSyncCommitteePeriod());
        assertEquals(14_295_040L, store.getFinalizedSlot());
        assertNotNull(store.getNextSyncCommittee());
        LightClientStore.Snapshot back = store.snapshot();
        assertNotNull(back);
        assertEquals(s.currentSyncCommitteePeriod(), back.currentSyncCommitteePeriod());
    }
}
