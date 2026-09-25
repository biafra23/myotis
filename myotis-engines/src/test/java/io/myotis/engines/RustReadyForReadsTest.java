package io.myotis.engines;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Rust handle's readiness predicate — what the wake gate holds a warming stack
 * for — over status JSON, without JNI. "Ready" means "attempt the read now": the
 * handle can serve, or it sits in a state no amount of holding fixes (#312).
 */
class RustReadyForReadsTest {

    /** The ABI >= 31 shape with every pooled peer also serving. */
    private static String status(boolean running, String beaconState, long head, int snapPeers,
                                 boolean elReader) {
        return status(running, beaconState, head, snapPeers, snapPeers, elReader);
    }

    private static String status(boolean running, String beaconState, long head, int snapPeers,
                                 int snapServing, boolean elReader) {
        return "{\"running\":" + running + ",\"paused\":false,\"network\":\"sepolia\","
                + "\"beaconState\":\"" + beaconState + "\",\"elReaderAvailable\":" + elReader
                + ",\"optimisticBlockNumber\":" + head + ",\"snapPeers\":" + snapPeers
                + ",\"snapServingPeers\":" + snapServing + "}";
    }

    private static boolean ready(String json) {
        return RustChainHandle.readyForReadsFromJson(json);
    }

    @Test
    void syncedWithAnAnchoredHeadAndSnapPeersIsReady() {
        assertTrue(ready(status(true, "SYNCED", 9_000_000, 4, true)));
    }

    @Test
    void catchingUpNoSnapPeerOrNoHeadIsNotReady() {
        assertFalse(ready(status(true, "CATCHING_UP", 9_000_000, 4, true)));
        assertFalse(ready(status(true, "SYNCED", 9_000_000, 0, true)));
        assertFalse(ready(status(true, "SYNCED", 0, 4, true)));
    }

    @Test
    void syncedWithPooledButNonServingPeersIsNotReady() {
        // The #465 shape: SYNCED, a full pool of peers still syncing themselves,
        // none able to answer at the anchored head — holding is right, a read
        // now fails with "peer returned 0 headers".
        assertFalse(ready(status(true, "SYNCED", 9_000_000, 6, 0, true)));
        assertTrue(ready(status(true, "SYNCED", 9_000_000, 6, 1, true)));
    }

    @Test
    void aStatusWithoutTheServingKeyIsNotReady() {
        // Fail CLOSED: a status with no snapServingPeers key (a hand-written
        // fixture — a loaded native always emits it, the ABI gate is exact)
        // reads as nobody serving, never as the pooled count.
        String noKey = status(true, "SYNCED", 9_000_000, 4, true)
                .replace(",\"snapServingPeers\":4", "");
        assertFalse(ready(noKey));
    }

    @Test
    void aStaleAnchorParkIsAttemptedAtOnce() {
        // Only a human moves it (raise the bound / accept the risk): holding can't help,
        // and the router answers the park with its curated message straight away.
        assertTrue(ready(status(true, "STALE_ANCHOR", 0, 0, true)));
    }

    @Test
    void runningWithoutAnElReaderIsAttemptedAtOnce() {
        // The CL-only degraded mode: only a pause→resume rebuilds the reader.
        assertTrue(ready(status(true, "SYNCING", 0, 0, false)));
    }

    @Test
    void aHandleThatIsNotRunningIsNeverReady() {
        assertFalse(ready(status(false, "SYNCED", 9_000_000, 4, true)));
        assertFalse(ready("{}"));
        assertFalse(ready("{\"running\":false,\"paused\":true,\"beaconState\":\"STALE_ANCHOR\","
                + "\"elReaderAvailable\":false}"));
    }
}
