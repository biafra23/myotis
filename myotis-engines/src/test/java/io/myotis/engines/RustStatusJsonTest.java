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
            "{\"running\":false,\"network\":\"mainnet\",\"beaconState\":\"STARTING\","
            + "\"bootstrapped\":false,\"finalizedSlot\":0,\"optimisticSlot\":0,"
            + "\"currentPeriod\":0,\"targetPeriod\":0,\"peerCount\":0,\"servedPeersLastMinute\":0,"
            + "\"discv5TableSize\":0,"
            + "\"finalizedRootHex\":\"0000000000000000000000000000000000000000000000000000000000000000\"}";

    /** A synthetic catching-up shape (real running numbers). */
    private static final String CATCHING_UP_JSON =
            "{\"running\":true,\"network\":\"mainnet\",\"beaconState\":\"CATCHING_UP\","
            + "\"bootstrapped\":true,\"finalizedSlot\":14560000,\"optimisticSlot\":14560032,"
            + "\"currentPeriod\":1777,\"targetPeriod\":1795,\"peerCount\":5,\"servedPeersLastMinute\":2,"
            + "\"discv5TableSize\":7,"
            + "\"finalizedRootHex\":\"58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e\"}";

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void notStartedStatusMapsToStartingSnapshot() {
        StatusSnapshot s = RustChainHandle.statusFromJson("mainnet", NOT_STARTED_JSON);
        assertFalse(s.running());
        assertEquals("mainnet", s.network());
        assertEquals(BeaconState.STARTING, s.beaconState());
        assertEquals(0, s.connectedPeers());
        assertEquals(0L, s.finalizedSlot());
        assertEquals(0L, s.syncCurrentPeriod());
        assertEquals(0L, s.syncTargetPeriod());
        // EL-only fields are zeroed on the CL-only R1 engine.
        assertEquals(0L, s.executionBlockNumber());
        assertEquals(0, s.snapPeers());
        assertEquals(Long.MAX_VALUE, s.verifiedHeadAgeMs());
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
        assertEquals(14560000L / 8192L, s.finalizedPeriod());
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
