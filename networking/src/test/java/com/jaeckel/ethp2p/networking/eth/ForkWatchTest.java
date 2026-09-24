package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.networking.NetworkConfig;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static com.jaeckel.ethp2p.networking.eth.ForkIdsTest.SEPOLIA_GLAMSTERDAM;
import static com.jaeckel.ethp2p.networking.eth.ForkIdsTest.SEPOLIA_GLAMSTERDAM_FORK_ID;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Scenario tests on Sepolia's real parameters: our pinned (Fulu/BPO2) fork id, and the
 * Glamsterdam activation this detector exists for.
 */
class ForkWatchTest {

    private static final NetworkConfig SEPOLIA = NetworkConfig.SEPOLIA;
    private static final byte[] LOCAL = SEPOLIA.forkIdHash();                    // 0x268956b6
    private static final byte[] SUCCESSOR = bytes(SEPOLIA_GLAMSTERDAM_FORK_ID);  // 0x6c1d9423
    private static final long EPOCH = 32 * 12;
    private static final long DAY = 24 * 3600;
    /** A September-2026 wall clock, ~2 weeks before the activation. */
    private static final long BEFORE = SEPOLIA_GLAMSTERDAM - 14 * DAY;

    private final AtomicLong clock = new AtomicLong(BEFORE);

    private ForkWatch watch(long localNext) {
        return new ForkWatch("sepolia", LOCAL, localNext, SEPOLIA.clGenesisTime(), EPOCH, clock::get);
    }

    private static byte[] bytes(int hash) {
        return new byte[]{(byte) (hash >>> 24), (byte) (hash >>> 16), (byte) (hash >>> 8), (byte) hash};
    }

    private static void announce(ForkWatch w, int peers, byte[] hash, long next) {
        for (int i = 0; i < peers; i++) w.observe("peer" + i, hash, next);
    }

    @Test
    void enabledOnSepoliaOnly() {
        assertTrue(ForkWatch.enabledFor(NetworkConfig.SEPOLIA));
        assertFalse(ForkWatch.enabledFor(NetworkConfig.MAINNET));
        assertFalse(ForkWatch.enabledFor(NetworkConfig.GNOSIS));
    }

    @Test
    void quietNetworkRaisesNothing() {
        ForkWatch w = watch(0);
        assertNull(w.advisory());
        announce(w, 8, LOCAL, 0);   // everyone on our fork, nothing scheduled
        assertNull(w.advisory());
    }

    @Test
    void scheduledNeedsThreeDistinctPeers() {
        ForkWatch w = watch(0);
        announce(w, 2, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory(), "two peers are below the threshold");
        for (int i = 0; i < 5; i++) w.observe("peer0", LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory(), "re-observing a peer must not count it twice");

        w.observe("peer2", LOCAL, SEPOLIA_GLAMSTERDAM);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(ForkWatch.Phase.SCHEDULED, a.phase());
        assertEquals(SEPOLIA_GLAMSTERDAM, a.activationTime());
        assertEquals("0x6c1d9423", a.forkHashHex());
        assertEquals(3, a.peers());
    }

    @Test
    void activeIsProvenFromSuccessorHashesWithoutAnyAnnouncement() {
        // The wallet was offline for the whole announcement window: it only ever meets
        // upgraded peers after the fork. The epoch-grid search must still place them.
        clock.set(SEPOLIA_GLAMSTERDAM + 3 * DAY);
        ForkWatch w = watch(0);
        announce(w, 3, SUCCESSOR, 0);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(SEPOLIA_GLAMSTERDAM, a.activationTime());
        assertEquals(SEPOLIA_GLAMSTERDAM_FORK_ID, a.forkHash());
    }

    @Test
    void announcementTurnsActiveAtItsTimeThenAgesOutWithoutProof() {
        clock.set(SEPOLIA_GLAMSTERDAM - 3600);   // seen an hour before: within the TTL throughout
        ForkWatch w = watch(0);
        announce(w, 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertEquals(ForkWatch.Phase.SCHEDULED, w.evaluate(SEPOLIA_GLAMSTERDAM - 1).phase());
        assertEquals(ForkWatch.Phase.ACTIVE, w.evaluate(SEPOLIA_GLAMSTERDAM + 3600).phase(),
                "inside the grace window the announced fork counts as active");
        assertNull(w.evaluate(SEPOLIA_GLAMSTERDAM + ForkWatch.ACTIVATION_GRACE_SECONDS + 1),
                "no successor proof after the grace window: a moved date, not a fork");
    }

    @Test
    void proofOutranksAnnouncements() {
        long later = SEPOLIA_GLAMSTERDAM + 30 * DAY;
        clock.set(SEPOLIA_GLAMSTERDAM + DAY);
        ForkWatch w = watch(0);
        for (int i = 0; i < 4; i++) w.observe("announcer" + i, LOCAL, later);
        for (int i = 0; i < 3; i++) w.observe("upgraded" + i, SUCCESSOR, 0);
        ForkWatch.Advisory a = w.advisory();
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(SEPOLIA_GLAMSTERDAM, a.activationTime());
    }

    @Test
    void rescheduledDateFollowsThePeersLatestAnnouncements() {
        // What actually happened on Sepolia: 2026-09-21 was projected, 2026-10-06 decided.
        long projected = SEPOLIA_GLAMSTERDAM - 15 * DAY;
        clock.set(projected - 7 * DAY);
        ForkWatch w = watch(0);
        announce(w, 3, LOCAL, projected);
        assertEquals(projected, w.advisory().activationTime());
        announce(w, 3, LOCAL, SEPOLIA_GLAMSTERDAM);   // same peers, upgraded again
        assertEquals(SEPOLIA_GLAMSTERDAM, w.advisory().activationTime());
    }

    @Test
    void aForkThisBuildKnowsIsNotNews() {
        ForkWatch w = watch(SEPOLIA_GLAMSTERDAM);   // a build that carries the activation
        announce(w, 5, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory());
        clock.set(SEPOLIA_GLAMSTERDAM + DAY);
        for (int i = 0; i < 5; i++) w.observe("upgraded" + i, SUCCESSOR, 0);
        assertNull(w.advisory());
    }

    @Test
    void implausibleAnnouncementsAreIgnored() {
        ForkWatch w = watch(0);
        announce(w, 4, LOCAL, 1_150_000);                                          // a block number
        assertNull(w.advisory());
        announce(w, 4, LOCAL, BEFORE + ForkWatch.MAX_HORIZON_SECONDS + DAY);       // beyond the horizon
        assertNull(w.advisory());
        announce(w, 4, LOCAL, BEFORE - 30 * DAY);                                  // long past, no proof
        assertNull(w.advisory());
        announce(w, 4, LOCAL, -1L);                                                // uint64 garbage
        assertNull(w.advisory());
    }

    @Test
    void foreignHashesThatAreNotOurSuccessorAreIgnored() {
        ForkWatch w = watch(0);
        // Stale peers on the fork BEFORE ours (and one on some unrelated id).
        announce(w, 4, bytes(0x1dd8e8d9), 1_760_000_000L);
        w.observe("odd", bytes(0xdeadbeef), 0);
        assertNull(w.advisory());
    }

    @Test
    void observationsExpire() {
        ForkWatch w = watch(0);
        announce(w, 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNotNull(w.advisory());
        assertNull(w.evaluate(BEFORE + ForkWatch.OBSERVATION_TTL_SECONDS + 1));
    }

    @Test
    void malformedInputIsIgnored() {
        ForkWatch w = watch(0);
        w.observe(null, LOCAL, SEPOLIA_GLAMSTERDAM);
        w.observe("a", null, SEPOLIA_GLAMSTERDAM);
        w.observe("b", new byte[3], SEPOLIA_GLAMSTERDAM);
        w.observe("c", new byte[5], SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory());
    }
}
