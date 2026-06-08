package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
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
