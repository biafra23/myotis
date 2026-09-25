package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The execution anchor after Gloas: a light-client header proves only the execution block
 * hash, which waits as PENDING until the EL resolver offers a header whose keccak IS that
 * hash. Twins of the Rust {@code ExecAnchor} tests ({@code rust/myotis-net/src/el/anchor.rs})
 * and of {@code sync.rs}' {@code a_gloas_finality_is_synced_only_once_its_header_resolves} /
 * {@code a_resolver_left_behind_is_not_synced}. Headers are genuine: a real header
 * encoding, hashed over its raw RLP.
 */
class BeaconSyncStateGloasAnchorTest {

    private static final int SLOTS_PER_EPOCH = 32;

    @BeforeAll
    static void registerBouncyCastle() {
        // Tuweni's keccak256 (BlockHeader.hash) is a JCA digest; hosts register BC at boot.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** A genuine execution header: its raw RLP and the keccak of exactly those bytes. */
    private record Header(byte[] raw, byte[] hash) {}

    /** A Prague-shaped header with this number and state root. */
    private static Header header(long number, byte[] stateRoot) {
        Bytes raw = RLP.encodeList(w -> {
            w.writeValue(Bytes32.repeat((byte) 0x01));          // parentHash
            w.writeValue(Bytes32.repeat((byte) 0x02));          // ommersHash
            w.writeValue(Bytes.repeat((byte) 0x03, 20));        // beneficiary
            w.writeValue(Bytes32.wrap(stateRoot));              // stateRoot
            w.writeValue(Bytes32.repeat((byte) 0x05));          // transactionsRoot
            w.writeValue(Bytes32.repeat((byte) 0x06));          // receiptsRoot
            w.writeValue(Bytes.wrap(new byte[256]));            // logsBloom
            w.writeBigInteger(BigInteger.ZERO);                 // difficulty
            w.writeLong(number);                                // number
            w.writeLong(36_000_000L);                           // gasLimit
            w.writeLong(21_000L);                               // gasUsed
            w.writeLong(1_791_294_816L + number);               // timestamp
            w.writeValue(Bytes.wrap(new byte[]{0x6d, 0x79}));   // extraData
            w.writeValue(Bytes32.repeat((byte) 0x07));          // mixHash / prevRandao
            w.writeValue(Bytes.wrap(new byte[8]));              // nonce
            w.writeBigInteger(BigInteger.valueOf(7));           // baseFeePerGas
            w.writeValue(Bytes32.repeat((byte) 0x08));          // withdrawalsRoot
            w.writeLong(0);                                     // blobGasUsed
            w.writeLong(0);                                     // excessBlobGas
            w.writeValue(Bytes32.repeat((byte) 0x09));          // parentBeaconBlockRoot
            w.writeValue(Bytes32.repeat((byte) 0x0a));          // requestsHash
        });
        return new Header(raw.toArray(), BlockHeader.hash(raw).toArray());
    }

    private static byte[] root(int b) {
        byte[] r = new byte[32];
        Arrays.fill(r, (byte) b);
        return r;
    }

    private static void assertPending(BeaconSyncState s, byte[]... want) {
        List<byte[]> got = s.pendingHashes();
        assertEquals(want.length, got.size(), "pending count");
        for (int i = 0; i < want.length; i++) assertArrayEquals(want[i], got.get(i), "pending " + i);
    }

    @Test
    void aGloasFinalityWaitsForItsHeaderThenAdoptsIt() {
        BeaconSyncState s = new BeaconSyncState();
        Header h = header(21_000_000L, root(1));
        s.noteFinalizedHash(100, h.hash());
        assertPending(s, h.hash());
        assertFalse(s.isSynced(), "a hash alone is not an anchor");
        assertNull(s.getFinalizedExecution().stateRoot());

        assertTrue(s.resolveHeader(h.raw()));
        BeaconSyncState.FinalizedExecution fin = s.getFinalizedExecution();
        assertEquals(100L, s.getFinalizedSlot());
        assertEquals(21_000_000L, fin.blockNumber());
        assertArrayEquals(root(1), fin.stateRoot());
        assertArrayEquals(h.hash(), fin.blockHash());
        assertTrue(s.pendingHashes().isEmpty());
        BeaconSyncState.SlottedStateRoot r = s.findStateRoot(root(1));
        assertNotNull(r);
        assertTrue(r.blsVerified() && r.slot() == 100, "the root joins the window as verified");
        assertFalse(s.resolveHeader(h.raw()), "nothing pending any more");
        // The whole resolved header is served, every field bound to the proven hash.
        assertEquals(21_000_000L, s.getFinalizedExecutionHeader().number);
        assertEquals(1_791_294_816L + 21_000_000L, s.getFinalizedExecutionHeader().timestamp);
    }

    @Test
    void aHeaderIsAdoptedOnlyUnderItsOwnHash() {
        BeaconSyncState s = new BeaconSyncState();
        Header wanted = header(21_000_000L, root(1));
        s.noteFinalizedHash(100, wanted.hash());
        // A different block entirely. (The Rust twin also refuses the pending hash CLAIMED
        // over another header's bytes; resolveHeader takes no claim — it hashes the offered
        // bytes itself — so such a forgery is just this case again.)
        assertFalse(s.resolveHeader(header(21_000_000L, root(2)).raw()));
        // Not a header at all, and nothing.
        assertFalse(s.resolveHeader(new byte[]{1, 2, 3}));
        assertFalse(s.resolveHeader(new byte[0]));
        assertFalse(s.resolveHeader(null));
        assertNull(s.getFinalizedExecution().stateRoot());
        assertPending(s, wanted.hash());
    }

    @Test
    void aNewerFinalitySupersedesAndAnOlderOneIsIgnored() {
        BeaconSyncState s = new BeaconSyncState();
        Header a = header(1, root(1));
        Header b = header(2, root(2));
        s.noteFinalizedHash(10, a.hash());
        s.noteFinalizedHash(20, b.hash());
        assertPending(s, b.hash());
        s.noteFinalizedHash(15, a.hash());
        assertPending(s, b.hash()); // an older finality never replaces a newer one
        assertFalse(s.resolveHeader(a.raw()), "superseded");
        assertTrue(s.resolveHeader(b.raw()));
        assertEquals(20L, s.getFinalizedSlot());
        s.noteFinalizedHash(10, a.hash());
        assertTrue(s.pendingHashes().isEmpty(), "nothing older than the resolved finality");
    }

    /** Re-noting the resolved block at a slot below a NEWER pending finality must not
     *  clear it (the store only moves forward, so this is defensive). Rust twin:
     *  {@code re_noting_the_resolved_block_keeps_a_newer_pending_one}. */
    @Test
    void reNotingTheResolvedBlockKeepsANewerPendingOne() {
        BeaconSyncState s = new BeaconSyncState();
        Header a = header(1, root(1));
        Header b = header(2, root(2));
        s.noteFinalizedHash(10, a.hash());
        assertTrue(s.resolveHeader(a.raw()));
        s.noteFinalizedHash(20, b.hash());
        s.noteFinalizedHash(15, a.hash());
        assertPending(s, b.hash());
        // ...while a re-note at or past the pending slot does supersede it.
        s.noteFinalizedHash(20, a.hash());
        assertTrue(s.pendingHashes().isEmpty());

        s.noteOptimisticHash(10, a.hash());
        assertTrue(s.resolveHeader(a.raw()));
        s.noteOptimisticHash(20, b.hash());
        s.noteOptimisticHash(15, a.hash());
        assertPending(s, b.hash());
    }

    @Test
    void theSameBlockUnderANewerSlotNeedsNoFetch() {
        // Payloads empty or withheld for a while: consecutive finalized beacon blocks name
        // the same parent payload.
        BeaconSyncState s = new BeaconSyncState();
        AtomicInteger wakes = new AtomicInteger();
        s.setPendingListener(wakes::incrementAndGet);
        Header h = header(7, root(7));
        s.noteFinalizedHash(100, h.hash());
        assertTrue(s.resolveHeader(h.raw()));
        int before = wakes.get();
        s.noteFinalizedHash(132, h.hash());
        assertTrue(s.pendingHashes().isEmpty());
        assertEquals(before, wakes.get(), "no fetch for a block already resolved");
        assertEquals(132L, s.getFinalizedSlot());
        assertEquals(7L, s.getFinalizedExecution().blockNumber());
        boolean atNewSlot = s.exportKnownStateRoots().stream()
                .anyMatch(e -> e.slot() == 132 && e.blsVerified() && Arrays.equals(e.stateRoot(), root(7)));
        assertTrue(atNewSlot, "the root is recorded under the newer slot as well");
    }

    @Test
    void oneHeaderResolvesBothHeadsWhenTheyNameTheSameBlock() {
        BeaconSyncState s = new BeaconSyncState();
        Header h = header(9, root(9));
        s.noteFinalizedHash(64, h.hash());
        s.noteOptimisticHash(65, h.hash());
        assertPending(s, h.hash()); // fetched once
        assertTrue(s.resolveHeader(h.raw()));
        assertEquals(9L, s.getOptimisticBlockNumber());
        assertArrayEquals(h.hash(), s.getOptimisticBlockHash());
        assertArrayEquals(root(9), s.getOptimisticStateRoot());
        assertEquals(65L, s.getOptimisticSlot());
        assertEquals(9L, s.getFinalizedExecution().blockNumber());
        assertEquals(64L, s.getFinalizedSlot());
    }

    @Test
    void aNewPendingHashWakesTheResolver() {
        BeaconSyncState s = new BeaconSyncState();
        AtomicInteger wakes = new AtomicInteger();
        s.setPendingListener(wakes::incrementAndGet);
        byte[] five = header(5, root(5)).hash();
        s.noteOptimisticHash(5, five);
        assertEquals(1, wakes.get());
        s.noteOptimisticHash(6, five);
        assertEquals(1, wakes.get(), "the same pending block at a newer slot is not news");
        s.noteOptimisticHash(7, header(6, root(6)).hash());
        assertEquals(2, wakes.get());
        s.noteOptimisticHash(3, header(3, root(3)).hash());
        assertEquals(2, wakes.get(), "an older head is ignored");
        // A failing resolver hook never breaks the light client's thread.
        s.setPendingListener(() -> { throw new IllegalStateException("resolver down"); });
        s.noteFinalizedHash(8, header(8, root(8)).hash());
        assertEquals(2, s.pendingHashes().size());
    }

    @Test
    void aZeroOrMalformedHashIsNeverPending() {
        BeaconSyncState s = new BeaconSyncState();
        s.noteFinalizedHash(10, null);
        s.noteFinalizedHash(10, new byte[31]);
        s.noteOptimisticHash(10, new byte[33]);
        assertTrue(s.pendingHashes().isEmpty());
    }

    /**
     * Gloas: the store's headers carry only block hashes, so the state is not SYNCED until
     * the finality's header is resolved — however current the light client itself is.
     * (The Rust twin reads CATCHING_UP before resolution; this engine's gate has always
     * said SYNCING while no execution root is held, and still does.)
     */
    @Test
    void aGloasFinalityIsSyncedOnlyOnceItsHeaderResolves() {
        long wall = 10_000_000L;
        BeaconSyncState s = new BeaconSyncState();
        s.setCurrentSyncCommitteePeriod(BeaconChainSpec.computeSyncCommitteePeriod(wall));
        // A window populated by earlier finality polls.
        for (int i = 0; i < BeaconSyncState.FILL_THRESHOLD; i++) {
            s.recordStateRoot(wall - 1_000 - i, root(0x40 + i), true);
        }
        Header resolved = header(21_004_000L, root(3));
        s.noteFinalizedHash(wall - 64, resolved.hash());
        s.noteOptimisticHash(wall - 1, root(9));
        assertEquals(BeaconSyncState.State.SYNCING, s.syncStateAt(wall, SLOTS_PER_EPOCH));
        assertPending(s, resolved.hash(), root(9));
        assertFalse(s.isSynced(), "a proven hash alone anchors nothing");

        assertTrue(s.resolveHeader(resolved.raw()));
        assertEquals(BeaconSyncState.State.SYNCED, s.syncStateAt(wall, SLOTS_PER_EPOCH));
        assertEquals(wall - 64, s.getFinalizedSlot());
        assertEquals(21_004_000L, s.getFinalizedExecution().blockNumber());
        assertArrayEquals(root(3), s.getFinalizedExecution().stateRoot());
        assertPending(s, root(9)); // the optimistic head still waits
    }

    /**
     * A resolver that stays behind — no EL peer serves the header — drops the state out of
     * SYNCED within the finality gate's own slack, instead of reading as verification-ready
     * on a finality it cannot use.
     */
    @Test
    void aResolverLeftBehindIsNotSynced() {
        long wall = 10_000_000L;
        long resolvedSlot = wall - 6L * SLOTS_PER_EPOCH;
        BeaconSyncState s = new BeaconSyncState();
        s.setCurrentSyncCommitteePeriod(BeaconChainSpec.computeSyncCommitteePeriod(wall));
        for (int i = 0; i < BeaconSyncState.FILL_THRESHOLD; i++) {
            s.recordStateRoot(resolvedSlot - i, root(0x40 + i), true);
        }
        // Resolved long ago (a payload-shaped finality six epochs back)...
        s.update(resolvedSlot, root(2), resolvedSlot + 1, 21_000_000L, root(1));
        assertEquals(BeaconSyncState.State.SYNCED, s.syncStateAt(resolvedSlot, SLOTS_PER_EPOCH));
        // ...then the light client finalizes Gloas blocks the EL never resolves.
        s.noteFinalizedHash(wall - 64, root(7));
        assertEquals(BeaconSyncState.State.CATCHING_UP, s.syncStateAt(wall, SLOTS_PER_EPOCH));
        // The previous finality still anchors reads — final, only older.
        assertEquals(21_000_000L, s.getFinalizedExecution().blockNumber());
        assertEquals(resolvedSlot, s.getFinalizedSlot());
    }

    /** The payload path is untouched: a payload-shaped update carries no resolved EL header. */
    @Test
    void aPayloadUpdateClearsTheResolvedHeader() {
        BeaconSyncState s = new BeaconSyncState();
        Header h = header(5, root(5));
        s.noteFinalizedHash(10, h.hash());
        assertTrue(s.resolveHeader(h.raw()));
        assertNotNull(s.getFinalizedExecutionHeader());
        s.update(20, root(6), 21, 6, root(0x66));
        assertNull(s.getFinalizedExecutionHeader());
        assertEquals(6L, s.getFinalizedExecution().blockNumber());
    }
}
