package com.jaeckel.ethp2p.consensus;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trip for the known-state-roots window export/import that backs the snapshot
 * sidecar — a warm restart restores the window so SYNCED needs one fresh finality poll
 * instead of {@link BeaconSyncState#FILL_THRESHOLD}.
 */
class BeaconSyncStateRootsTest {

    private static byte[] root(int seed) {
        byte[] r = new byte[32];
        for (int i = 0; i < 32; i++) r[i] = (byte) (seed + i);
        return r;
    }

    @Test
    void exportImportRoundTripPreservesWindow() {
        BeaconSyncState a = new BeaconSyncState();
        for (int i = 0; i < BeaconSyncState.FILL_THRESHOLD; i++) {
            a.recordStateRoot(1000 + i, root(i), false);
        }
        List<BeaconSyncState.SlottedStateRoot> exported = a.exportKnownStateRoots();
        assertEquals(BeaconSyncState.FILL_THRESHOLD, exported.size());

        BeaconSyncState b = new BeaconSyncState();
        assertEquals(0, b.getKnownStateRootCount());
        b.importKnownStateRoots(exported);
        assertEquals(BeaconSyncState.FILL_THRESHOLD, b.getKnownStateRootCount());

        // Imported roots are individually matchable (findStateRoot) and carry the slot.
        BeaconSyncState.SlottedStateRoot hit = b.findStateRoot(root(0));
        assertNotNull(hit);
        assertEquals(1000, hit.slot());
    }

    @Test
    void importIsIdempotentAndNullSafe() {
        BeaconSyncState a = new BeaconSyncState();
        a.recordStateRoot(42, root(7), true);
        List<BeaconSyncState.SlottedStateRoot> exported = a.exportKnownStateRoots();

        BeaconSyncState b = new BeaconSyncState();
        b.importKnownStateRoots(null);          // tolerated
        b.importKnownStateRoots(exported);
        b.importKnownStateRoots(exported);      // dedup, no double count
        assertEquals(1, b.getKnownStateRootCount());
        // blsVerified flag survives the round trip.
        assertTrue(b.findStateRoot(root(7)).blsVerified());
    }
}
