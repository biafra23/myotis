package io.myotis.engines;

import io.myotis.api.BeaconState;
import io.myotis.api.BeaconStatus;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.StatusSnapshot;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The Java half of the status-JSON golden contract: parse the not-started status
 * shape (the exact object {@code host::status_object(false, None)} emits in Rust —
 * pinned there by {@code not_started_status_shape_is_stable}) into a
 * {@link StatusSnapshot} / {@link BeaconStatus} and assert the CL-only mapping.
 *
 * <p>The parse/mapping part needs no native library; the live-JNI part (create →
 * status through the real {@code libmyotis_engine}) self-skips when the library
 * isn't on {@code java.library.path}, mirroring {@link RustCatalogParityTest}.
 */
class RustStatusJsonTest {

    /** The committed not-started golden shape — byte-for-byte the Rust fallback const. */
    private static final String NOT_STARTED_JSON =
            "{\"running\":false,\"paused\":false,\"network\":\"mainnet\",\"beaconState\":\"STARTING\","
            + "\"bootstrapped\":false,\"finalizedSlot\":0,\"optimisticSlot\":0,"
            + "\"currentPeriod\":0,\"targetPeriod\":0,\"peerCount\":0,\"servedPeersLastMinute\":0,"
            + "\"discv5TableSize\":0,\"syncStartPeriod\":-1,"
            + "\"finalizedRootHex\":\"0000000000000000000000000000000000000000000000000000000000000000\","
            + "\"elReaderAvailable\":false,"
            + "\"snapPeers\":0,\"readyPeers\":0,\"discoveredPeers\":0,\"attemptedDials\":0,"
            + "\"backedOffPeers\":0,\"blacklistedPeers\":0,\"optimisticBlockNumber\":0,"
            + "\"finalizedBlockNumber\":0,\"executionBlockNumber\":0,"
            + "\"peerHeaderRequests\":0,\"peerHeaderRequestsServed\":0,"
            + "\"peerBodyRequests\":0,\"peerBodyRequestsServed\":0}";

    /** A synthetic catching-up shape (real running numbers, incl. EL counts). */
    private static final String CATCHING_UP_JSON =
            "{\"running\":true,\"network\":\"mainnet\",\"beaconState\":\"CATCHING_UP\","
            + "\"bootstrapped\":true,\"finalizedSlot\":14560000,\"optimisticSlot\":14560032,"
            + "\"currentPeriod\":1777,\"targetPeriod\":1795,\"peerCount\":5,\"servedPeersLastMinute\":2,"
            + "\"discv5TableSize\":7,\"syncStartPeriod\":1777,\"lcHunting\":true,\"elHunting\":true,"
            + "\"finalizedRootHex\":\"58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e\","
            + "\"elReaderAvailable\":true,"
            + "\"snapPeers\":6,\"readyPeers\":6,\"discoveredPeers\":240,\"attemptedDials\":14,"
            + "\"backedOffPeers\":30,\"blacklistedPeers\":66,"
            + "\"optimisticBlockNumber\":21000010,\"finalizedBlockNumber\":20999000,"
            + "\"executionBlockNumber\":20999000,"
            + "\"peerHeaderRequests\":6,\"peerHeaderRequestsServed\":2,"
            + "\"peerBodyRequests\":1,\"peerBodyRequestsServed\":0}";

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** The idle-slept shape: running=false + paused=true, the beacon fields frozen
     *  at pause time (still SYNCED), and all EL counts zero (networking torn down). */
    private static final String PAUSED_JSON =
            "{\"running\":false,\"paused\":true,\"network\":\"mainnet\",\"beaconState\":\"SYNCED\","
            + "\"bootstrapped\":true,\"finalizedSlot\":14560000,\"optimisticSlot\":14560032,"
            + "\"currentPeriod\":1777,\"targetPeriod\":1795,\"peerCount\":0,\"servedPeersLastMinute\":0,"
            + "\"discv5TableSize\":0,\"syncStartPeriod\":1777,"
            + "\"finalizedRootHex\":\"58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e\","
            + "\"elReaderAvailable\":false,"
            + "\"snapPeers\":0,\"readyPeers\":0,\"discoveredPeers\":0,\"attemptedDials\":0,"
            + "\"backedOffPeers\":0,\"blacklistedPeers\":0,"
            + "\"optimisticBlockNumber\":0,\"finalizedBlockNumber\":0,\"executionBlockNumber\":0}";

    @Test
    void pausedStatusMapsToPausedLifecycleWithFrozenBeaconFields() {
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", PAUSED_JSON);
        // The API contract: paused ⇒ running=false, lifecycle=PAUSED.
        assertFalse(s.running());
        assertEquals(io.myotis.api.LifecycleState.PAUSED, s.lifecycle());
        // Warm beacon fields keep showing while asleep (frozen at pause time).
        assertEquals(BeaconState.SYNCED, s.beaconState());
        assertEquals(14560000L, s.finalizedSlot());
        assertEquals(1777L, s.syncCurrentPeriod());
        assertEquals(1795L, s.syncTargetPeriod());
        // Networking is down: no snap peers / anchored head → no verified head to age.
        assertEquals(0, s.snapPeers());
        assertEquals(Long.MAX_VALUE, s.verifiedHeadAgeMs());
        // No pause has been driven THROUGH this Java handle (the metrics are
        // Java-side accounting over pause()/resume() calls, not status parsing).
        assertEquals(0, s.pauseCount());
        assertEquals(0L, s.totalPausedMs());
    }

    @Test
    void oldShapeWithoutPausedKeyReadsAsStopped() {
        // An older .so has no "paused" key: not-running parses as STOPPED, never PAUSED.
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet",
                "{\"running\":false,\"network\":\"mainnet\",\"beaconState\":\"STARTING\"}");
        assertEquals(io.myotis.api.LifecycleState.STOPPED, s.lifecycle());
    }

    @Test
    void notStartedStatusMapsToStartingSnapshot() {
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", NOT_STARTED_JSON);
        assertFalse(s.running());
        assertEquals(io.myotis.api.LifecycleState.STOPPED, s.lifecycle());
        assertEquals("mainnet", s.network());
        assertEquals(BeaconState.STARTING, s.beaconState());
        assertEquals(0, s.connectedPeers());
        assertEquals(0L, s.finalizedSlot());
        assertEquals(0L, s.syncCurrentPeriod());
        assertEquals(0L, s.syncTargetPeriod());
        assertEquals(-1L, s.syncStartPeriod());
        // EL block/peer fields are 0 for a not-started handle (no anchor head yet).
        assertEquals(0L, s.executionBlockNumber());
        assertEquals(0L, s.optimisticBlockNumber());
        assertEquals(0, s.snapPeers());
        assertEquals(Long.MAX_VALUE, s.verifiedHeadAgeMs());
        // Older natives omit the hunt keys → default to false, never throw.
        assertFalse(s.lcHunting());
        assertFalse(s.elHunting());
        // No listener configured on the test seam → row-hidden sentinel values.
        assertEquals(0, s.rpcPort());
        assertFalse(s.rpcServing());
    }

    @Test
    void configuredButUnservedRpcPortSurfacesAsNotServing() {
        // A handle configured with a port whose server never started (bind
        // failure shape): the RUNNING status must carry the port with
        // rpcServing=false — the state the UI renders as the red
        // "port N unavailable" row. A stopped handle must hide the row (port 0).
        RustChainHandle h = new RustChainHandle(0L, "mainnet", 1L, 8545, false);
        StatusSnapshot running = h.statusFromJsonOnThisHandle(CATCHING_UP_JSON);
        assertEquals(8545, running.rpcPort());
        assertFalse(running.rpcServing());
        StatusSnapshot stopped = h.statusFromJsonOnThisHandle(NOT_STARTED_JSON);
        assertEquals(0, stopped.rpcPort(), "stopped handle must hide the RPC row");
        // PAUSED keeps the row: the listener survives idle sleep — a request on
        // this very port is what wakes the stack, so hiding it would remove the
        // one address the user needs while sleeping.
        StatusSnapshot paused = h.statusFromJsonOnThisHandle(PAUSED_JSON);
        assertEquals(8545, paused.rpcPort(), "paused handle must keep showing the RPC port");
    }

    @Test
    void catchingUpStatusMapsBeaconFields() {
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", CATCHING_UP_JSON);
        assertTrue(s.running());
        assertEquals(BeaconState.CATCHING_UP, s.beaconState());
        assertEquals(5, s.connectedPeers());
        assertEquals(14560000L, s.finalizedSlot());
        assertEquals(1777L, s.syncCurrentPeriod());
        assertEquals(1795L, s.syncTargetPeriod());
        assertEquals(1795L, s.wallClockPeriod());
        assertEquals(7, s.discv5TableSize());
        // Inbound-serve counters flow from the engine's status JSON (not zeros).
        assertEquals(6L, s.peerHeaderRequests());
        assertEquals(2L, s.peerHeaderRequestsServed());
        assertEquals(1L, s.peerBodyRequests());
        assertEquals(0L, s.peerBodyRequestsServed());
        assertEquals(1777L, s.syncStartPeriod());
        assertEquals(14560000L / 8192L, s.finalizedPeriod());
        assertTrue(s.lcHunting());
        assertTrue(s.elHunting());
        // EL pool/discovery counts now flow through (not hardcoded 0). The pool
        // holds only snap-capable READY peers, so readyPeers == snapPeers.
        assertEquals(6, s.snapPeers());
        assertEquals(6, s.readyPeers());
        assertEquals(240, s.discoveredPeers());
        assertEquals(14, s.attemptedDials());
        assertEquals(30, s.backedOffPeers());
        assertEquals(66, s.blacklistedPeers());
        // Execution block numbers now flow from the beacon anchor (not hardcoded 0):
        // optimistic head drives eth_blockNumber; executionBlockNumber == finalized.
        assertEquals(21000010L, s.optimisticBlockNumber());
        assertEquals(20999000L, s.finalizedBlockNumber());
        assertEquals(20999000L, s.executionBlockNumber());
        // Not SYNCED → no verified head yet (readiness dot stays amber).
        assertEquals(Long.MAX_VALUE, s.verifiedHeadAgeMs());
    }

    @Test
    void syncedWithHeadAndPeersReportsFreshVerifiedHead() {
        // SYNCED + an anchored optimistic head + snap peers → verified reads serve,
        // so verifiedHeadAgeMs is 0 (fresh → ready/green), not the MAX sentinel.
        String syncedJson = CATCHING_UP_JSON.replace("CATCHING_UP", "SYNCED");
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", syncedJson);
        assertEquals(BeaconState.SYNCED, s.beaconState());
        assertEquals(0L, s.verifiedHeadAgeMs());
    }

    @Test
    void syncedButNoSnapPeersHasNoVerifiedHead() {
        // SYNCED but zero snap peers → a verified read can't be served → MAX sentinel.
        String noPeers = CATCHING_UP_JSON.replace("CATCHING_UP", "SYNCED")
                .replace("\"snapPeers\":6", "\"snapPeers\":0");
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", noPeers);
        assertEquals(Long.MAX_VALUE, s.verifiedHeadAgeMs());
    }

    @Test
    void verifiedHeadAgeGrowsBetweenBlocksAndResetsOnAdvance() throws InterruptedException {
        // One persistent handle polled repeatedly — the real on-device behavior.
        RustChainHandle h = new RustChainHandle(0L, "mainnet", 1L, 0, true);
        String synced = CATCHING_UP_JSON.replace("CATCHING_UP", "SYNCED"); // optimisticBlockNumber 21000010
        long age1 = h.statusFromJsonOnThisHandle(synced).verifiedHeadAgeMs();
        assertEquals(0L, age1);                       // just observed the head
        // Poll (bounded) until the age at the SAME head grows past age1 — proves it
        // isn't a constant without pinning to a wall-clock threshold a slow/oversleeping
        // scheduler could trip. sleep() only ever floors elapsed time, so this converges.
        long age2 = age1;
        long deadline = System.nanoTime() + 2_000_000_000L; // 2 s ceiling
        while (age2 <= age1 && System.nanoTime() < deadline) {
            Thread.sleep(5);
            age2 = h.statusFromJsonOnThisHandle(synced).verifiedHeadAgeMs();
        }
        assertTrue(age2 > age1, "age must GROW at the same head, was " + age2); // not a constant
        // A new block resets the age back toward 0.
        String advanced = synced.replace("21000010", "21000011");
        long age3 = h.statusFromJsonOnThisHandle(advanced).verifiedHeadAgeMs();
        assertTrue(age3 < age2, "a new head must reset the age, was " + age3);
    }

    @Test
    void beaconStatusMapping() {
        BeaconStatus bs = RustChainHandle.beaconStatusFromJson("mainnet", CATCHING_UP_JSON);
        assertEquals(BeaconState.CATCHING_UP, bs.state());
        assertTrue(bs.bootstrapped());
        assertEquals(1777L, bs.currentPeriod());
        assertEquals(1795L, bs.targetPeriod());
        assertEquals(2, bs.servedPeersLastMinute());
        assertEquals(7, bs.discv5TableSize());
        assertEquals(14560000L, bs.finalizedSlot());
        assertEquals(14560032L, bs.optimisticSlot());
        assertEquals(5, bs.connectedPeers());
        assertEquals(5L, bs.lightClientPeers());
        // EL fields empty on the CL-only engine.
        assertNull(bs.executionStateRootHex());
        assertNull(bs.executionBlockHashHex());
        assertEquals(0L, bs.executionBlockNumber());
    }

    /** The weak-subjectivity park: STALE_ANCHOR maps through BOTH surfaces with the
     *  refused anchor as currentPeriod and the enforced bound alongside. */
    private static final String STALE_ANCHOR_JSON =
            "{\"running\":true,\"network\":\"mainnet\",\"beaconState\":\"STALE_ANCHOR\","
            + "\"bootstrapped\":false,\"finalizedSlot\":0,\"optimisticSlot\":0,"
            + "\"currentPeriod\":1825,\"targetPeriod\":1845,\"peerCount\":0,"
            + "\"discv5TableSize\":3,\"syncStartPeriod\":-1,\"wsBoundPeriods\":13}";

    @Test
    void staleAnchorMapsThroughBothSurfaces() {
        BeaconStatus bs = RustChainHandle.beaconStatusFromJson("mainnet", STALE_ANCHOR_JSON);
        assertEquals(BeaconState.STALE_ANCHOR, bs.state());
        assertFalse(bs.bootstrapped());
        assertEquals(1825L, bs.currentPeriod());
        assertEquals(1845L, bs.targetPeriod());
        assertEquals(13L, bs.wsBoundPeriods());

        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", STALE_ANCHOR_JSON);
        assertEquals(BeaconState.STALE_ANCHOR, s.beaconState());
        assertEquals(13L, s.wsBoundPeriods());
        // Not serveable while parked: no verified head.
        assertEquals(Long.MAX_VALUE, s.verifiedHeadAgeMs());
    }

    @Test
    void unknownBeaconStateFromNewerNativeReadsAsStarting() {
        // A NEWER .so than this wrapper may emit a state this enum doesn't know:
        // the whole parse must not throw — it degrades to STARTING (fail closed).
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet",
                "{\"running\":true,\"network\":\"mainnet\",\"beaconState\":\"SOME_FUTURE_STATE\","
                + "\"currentPeriod\":5,\"targetPeriod\":6}");
        assertEquals(BeaconState.STARTING, s.beaconState());
        assertEquals(5L, s.syncCurrentPeriod());
    }

    /** The pre-targetPeriod shape an older native library emits (no "targetPeriod"
     *  key). Kept as a fixture so the missing-key default path stays covered. */
    private static final String OLD_SHAPE_CATCHING_UP_JSON =
            "{\"running\":true,\"network\":\"mainnet\",\"beaconState\":\"CATCHING_UP\","
            + "\"bootstrapped\":true,\"finalizedSlot\":14560000,\"optimisticSlot\":14560032,"
            + "\"currentPeriod\":1777,\"peerCount\":5,"
            + "\"finalizedRootHex\":\"58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e\"}";

    @Test
    void oldShapeWithoutTargetPeriodFallsBackToCurrentPeriod() {
        // An older .so parses without throwing, and the missing target falls back
        // to the pre-targetPeriod behavior (mirror currentPeriod), preserving the
        // target >= current invariant.
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", OLD_SHAPE_CATCHING_UP_JSON);
        assertEquals(1777L, s.syncCurrentPeriod());
        assertEquals(1777L, s.syncTargetPeriod());
        assertEquals(1777L, s.wallClockPeriod());
        BeaconStatus bs = RustChainHandle.beaconStatusFromJson("mainnet", OLD_SHAPE_CATCHING_UP_JSON);
        assertEquals(1777L, bs.targetPeriod());
    }

    @Test
    void unknownHandleJsonMapsToNotRunning() {
        // "{}" is what the native returns for an unknown handle.
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", "{}");
        assertFalse(s.running());
        assertEquals(BeaconState.STARTING, s.beaconState());
    }

    @Test
    void liveCreateReportsNotStartedThenIsRunnable() {
        assumeTrue(RustMyotisEngine.isAvailable(),
                "libmyotis_engine not on java.library.path — skipping live JNI status test");
        RustMyotisEngine rust = new RustMyotisEngine();
        EngineConfig cfg = new EngineConfig(
                "mainnet", 0, 0, 0, null, false, 0, true, "/tmp/myotis-r1-test");
        var handle = rust.create(cfg, null);
        try {
            // A created-but-not-started handle reports not-running / STARTING.
            assertFalse(handle.isRunning());
            StatusSnapshot s = handle.status();
            assertFalse(s.running());
            assertEquals(BeaconState.STARTING, s.beaconState());
            assertEquals("mainnet", s.network());

            // Idle sleep on a created-but-not-started handle: not RUNNING → pause
            // refuses, not PAUSED → resume refuses, and no accounting accrues.
            assertFalse(handle.pause());
            assertFalse(handle.resume());
            assertEquals(io.myotis.api.LifecycleState.STOPPED, handle.lifecycle());
            assertEquals(0, handle.status().pauseCount());

            // Re-creating an already-hosted network must throw, not silently orphan
            // the live handle's native entry (the double-create leak guard).
            EngineException dup = assertThrows(EngineException.class,
                    () -> rust.create(cfg, null));
            assertTrue(dup.getMessage().contains("already hosted"),
                    "unexpected message: " + dup.getMessage());
            // The original handle is untouched by the rejected re-create.
            assertEquals(handle, rust.get("mainnet"));
        } finally {
            rust.stop("mainnet");
        }
    }
}
