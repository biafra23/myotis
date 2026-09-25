package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.networking.NetworkConfig;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static com.jaeckel.ethp2p.networking.eth.ForkIdsTest.SEPOLIA_GLAMSTERDAM;
import static com.jaeckel.ethp2p.networking.eth.ForkIdsTest.SEPOLIA_GLAMSTERDAM_FORK_ID;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Scenario tests on Sepolia's real parameters: our pinned (Fulu/BPO2) fork id, and the
 * Glamsterdam activation this detector exists for. Mirrored by the Rust twin's tests.
 */
class ForkWatchTest {

    private static final NetworkConfig SEPOLIA = NetworkConfig.SEPOLIA;
    private static final byte[] LOCAL = SEPOLIA.forkIdHash();                    // 0x268956b6
    private static final byte[] SUCCESSOR = bytes(SEPOLIA_GLAMSTERDAM_FORK_ID);  // 0x6c1d9423
    private static final long EPOCH = 32 * 12;
    private static final long DAY = 24 * 3600;
    /** A September-2026 wall clock, ~2 weeks before the activation. */
    private static final long BEFORE = SEPOLIA_GLAMSTERDAM - 14 * DAY;
    /** A made-up hash that places on the epoch grid (see ForkIdsTest). */
    private static final byte[] FORGED = bytes(0x47e12c82);
    private static final long FORGED_AT = 1_790_207_712L;

    private final AtomicLong clock = new AtomicLong(BEFORE);

    private ForkWatch watch(long localNext) {
        return new ForkWatch("sepolia", LOCAL, localNext, SEPOLIA.clGenesisTime(), EPOCH, clock::get);
    }

    private static byte[] bytes(int hash) {
        return new byte[]{(byte) (hash >>> 24), (byte) (hash >>> 16), (byte) (hash >>> 8), (byte) hash};
    }

    /** {@code n} sources named {@code prefix0..} each presenting {@code (hash, next)}. */
    private static List<String> announce(ForkWatch w, String prefix, int n, byte[] hash, long next) {
        List<String> sources = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            sources.add(prefix + i);
            w.observe(prefix + i, hash, next);
        }
        return sources;
    }

    @Test
    void enabledOnSepoliaOnly() {
        assertTrue(ForkWatch.enabledFor(NetworkConfig.SEPOLIA));
        assertFalse(ForkWatch.enabledFor(NetworkConfig.MAINNET));
        assertFalse(ForkWatch.enabledFor(NetworkConfig.GNOSIS));
    }

    @Test
    void constantsMatchTheSharedTwinPins() throws Exception {
        // The Rust twin asserts the same file, so the engines can't drift apart silently.
        Path f = Path.of("..", "rust", "testdata", "el", "fork_watch", "params.txt");
        assumeTrue(Files.isRegularFile(f), "shared twin pins not found at " + f.toAbsolutePath());
        Map<String, String> p = new HashMap<>();
        for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
            String l = line.strip();
            if (l.isEmpty() || l.startsWith("#")) continue;
            int eq = l.indexOf('=');
            p.put(l.substring(0, eq), l.substring(eq + 1));
        }
        assertEquals(ForkWatch.MIN_PEERS, Integer.parseInt(p.get("min_peers")));
        assertEquals(ForkWatch.OBSERVATION_TTL_SECONDS, Long.parseLong(p.get("observation_ttl_seconds")));
        assertEquals(ForkWatch.ACTIVATION_GRACE_SECONDS, Long.parseLong(p.get("activation_grace_seconds")));
        assertEquals(ForkWatch.MAX_HORIZON_SECONDS, Long.parseLong(p.get("max_horizon_seconds")));
        assertEquals(ForkWatch.LOOKBACK_SECONDS, Long.parseLong(p.get("lookback_seconds")));
        assertEquals(ForkWatch.MAX_TRACKED, Integer.parseInt(p.get("max_tracked")));
        Set<String> enabled = Set.of(p.get("enabled_networks").split(","));
        for (NetworkConfig net : List.of(NetworkConfig.MAINNET, NetworkConfig.SEPOLIA, NetworkConfig.GNOSIS)) {
            assertEquals(enabled.contains(net.name()), ForkWatch.enabledFor(net), net.name());
        }
    }

    @Test
    void quietNetworkRaisesNothing() {
        ForkWatch w = watch(0);
        assertNull(w.advisory());
        announce(w, "on-our-fork", 8, LOCAL, 0);   // everyone on our fork, nothing scheduled
        assertNull(w.advisory());
    }

    @Test
    void scheduledNeedsThreeDistinctSources() {
        ForkWatch w = watch(0);
        announce(w, "s", 2, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory(), "two sources are below the threshold");
        for (int i = 0; i < 5; i++) w.observe("s0", LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory(), "re-observing a source must not count it twice");

        w.observe("s2", LOCAL, SEPOLIA_GLAMSTERDAM);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(ForkWatch.Phase.SCHEDULED, a.phase());
        assertEquals(SEPOLIA_GLAMSTERDAM, a.activationTime());
        assertEquals("0x6c1d9423", a.forkHashHex());
        assertEquals(3, a.peers());
    }

    @Test
    void oneNetworkIsOneVote() throws Exception {
        String a = ForkWatch.sourceOf(InetAddress.getByName("203.0.113.5"));
        assertEquals("203.0.113.0/24", a);
        assertEquals(a, ForkWatch.sourceOf(InetAddress.getByName("203.0.113.250")));
        assertNotEquals(a, ForkWatch.sourceOf(InetAddress.getByName("203.0.114.5")));
        assertEquals("2001:db8:abcd::/48", ForkWatch.sourceOf(InetAddress.getByName("2001:db8:abcd:12::1")));
        assertEquals("2001:db8:abcd::/48", ForkWatch.sourceOf(InetAddress.getByName("2001:db8:abcd:ffff::9")));
        byte[] mapped = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 198, 51, 100, 9};
        assertEquals("198.51.100.0/24", ForkWatch.sourceOf(InetAddress.getByAddress(mapped)));

        // Many node ids behind one /24 are one voice.
        ForkWatch w = watch(0);
        for (int host = 1; host <= 5; host++) {
            w.observe(ForkWatch.sourceOf(InetAddress.getByName("198.51.100." + host)), LOCAL, SEPOLIA_GLAMSTERDAM);
        }
        assertNull(w.advisory());
    }

    @Test
    void activeIsPlacedFromSuccessorHashesWithoutAnyAnnouncement() {
        // The wallet was offline for the whole announcement window: it only ever meets
        // upgraded peers after the fork. Their hash must still place on the epoch grid.
        clock.set(SEPOLIA_GLAMSTERDAM + 3 * DAY);
        ForkWatch w = watch(0);
        announce(w, "upgraded", 3, SUCCESSOR, 0);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(SEPOLIA_GLAMSTERDAM, a.activationTime());
        assertEquals(SEPOLIA_GLAMSTERDAM_FORK_ID, a.forkHash());
    }

    @Test
    void aMinorityCannotOutvoteThePeersItContradicts() {
        // Three sources minting a grid-aligned "successor" against five on our fork with
        // nothing scheduled: no advisory. It takes MORE sources than the dissent.
        clock.set(FORGED_AT + DAY);
        ForkWatch w = watch(0);
        announce(w, "honest", 5, LOCAL, 0);
        announce(w, "forger", 3, FORGED, 0);
        assertNull(w.advisory());
        announce(w, "forger", 5, FORGED, 0);
        assertNull(w.advisory(), "a tie is not a majority");
        w.observe("forger5", FORGED, 0);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(FORGED_AT, a.activationTime());
        assertEquals(6, a.peers());
    }

    @Test
    void announcementTurnsActiveAtItsTimeThenAgesOutIfItsSourcesLeft() {
        clock.set(SEPOLIA_GLAMSTERDAM - 3600);   // seen an hour before: within the TTL throughout
        ForkWatch w = watch(0);
        announce(w, "s", 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertEquals(ForkWatch.Phase.SCHEDULED, w.evaluate(SEPOLIA_GLAMSTERDAM - 1).phase());
        assertEquals(ForkWatch.Phase.ACTIVE, w.evaluate(SEPOLIA_GLAMSTERDAM + 3600).phase(),
                "inside the grace window the announced fork counts as active");
        assertNull(w.evaluate(SEPOLIA_GLAMSTERDAM + ForkWatch.ACTIVATION_GRACE_SECONDS + 1),
                "sources gone since before T, no successor after the grace: a moved date, not a fork");
    }

    @Test
    void connectedAnnouncersKeepAnActiveForkAlive() {
        // A stable pool: the announcers stay connected across the fork, and nobody new
        // handshakes (the Rust pool stops dialing at its target).
        clock.set(SEPOLIA_GLAMSTERDAM - 3600);
        ForkWatch w = watch(0);
        List<String> sources = announce(w, "s", 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        long touched = SEPOLIA_GLAMSTERDAM + 60;
        clock.set(touched);
        w.touch(sources);
        ForkWatch.Advisory a = w.evaluate(SEPOLIA_GLAMSTERDAM + ForkWatch.ACTIVATION_GRACE_SECONDS + 1);
        assertNotNull(a, "seen connected past T: they passed the fork configured for it");
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertNull(w.evaluate(touched + ForkWatch.OBSERVATION_TTL_SECONDS + 1), "expires once they're gone");
    }

    @Test
    void aPassedDateAnnouncedAfterTheFactIsNotEvidence() {
        clock.set(SEPOLIA_GLAMSTERDAM + 2 * DAY);
        ForkWatch w = watch(0);
        List<String> sources = announce(w, "behind", 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        w.touch(sources);
        assertNull(w.advisory(), "still announcing T two days after it: far behind, not on the fork");
    }

    @Test
    void touchKeepsAStablePoolFreshAndIgnoresStrangers() {
        ForkWatch touched = watch(0);
        ForkWatch untouched = watch(0);
        List<String> sources = announce(touched, "s", 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        announce(untouched, "s", 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        clock.set(BEFORE + 20 * 3600);
        touched.touch(sources);
        touched.touch(List.of("never-observed"));
        long later = BEFORE + 30 * 3600;
        assertEquals(ForkWatch.Phase.SCHEDULED, touched.evaluate(later).phase());
        assertNull(untouched.evaluate(later), "the TTL runs from the last sighting");
        assertEquals(3, touched.tracked(), "touch must not create entries");
    }

    @Test
    void placedAndAnnouncedEvidenceAddUp() {
        clock.set(SEPOLIA_GLAMSTERDAM - 3600);
        ForkWatch w = watch(0);
        List<String> announcers = announce(w, "announcer", 2, LOCAL, SEPOLIA_GLAMSTERDAM);
        clock.set(SEPOLIA_GLAMSTERDAM + 3600);
        w.touch(announcers);
        w.observe("upgraded0", SUCCESSOR, 0);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(3, a.peers());
    }

    @Test
    void theBestBackedActivationWinsAndPlacementsBreakTies() {
        long later = SEPOLIA_GLAMSTERDAM + 30 * DAY;
        clock.set(SEPOLIA_GLAMSTERDAM + DAY);
        ForkWatch w = watch(0);
        announce(w, "announcer", 4, LOCAL, later);
        announce(w, "upgraded", 3, SUCCESSOR, 0);
        ForkWatch.Advisory a = w.advisory();
        assertEquals(ForkWatch.Phase.SCHEDULED, a.phase(), "a placement is not proof: 4 beat 3");
        assertEquals(later, a.activationTime());
        w.observe("upgraded3", SUCCESSOR, 0);
        a = w.advisory();
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase(), "on a tie, placed evidence wins");
        assertEquals(SEPOLIA_GLAMSTERDAM, a.activationTime());
    }

    @Test
    void rescheduledDateFollowsTheSourcesLatestAnnouncements() {
        // What actually happened on Sepolia: 2026-09-21 was projected, 2026-10-06 decided.
        long projected = SEPOLIA_GLAMSTERDAM - 15 * DAY;
        clock.set(projected - 7 * DAY);
        ForkWatch w = watch(0);
        announce(w, "s", 3, LOCAL, projected);
        assertEquals(projected, w.advisory().activationTime());
        announce(w, "s", 3, LOCAL, SEPOLIA_GLAMSTERDAM);   // same sources, upgraded again
        assertEquals(SEPOLIA_GLAMSTERDAM, w.advisory().activationTime());
    }

    @Test
    void aForkThisBuildKnowsIsNotNews() {
        ForkWatch w = watch(SEPOLIA_GLAMSTERDAM);   // a build that carries the activation
        announce(w, "announcer", 5, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory());
        clock.set(SEPOLIA_GLAMSTERDAM + DAY);
        announce(w, "upgraded", 5, SUCCESSOR, 0);
        assertNull(w.advisory());
    }

    @Test
    void theBaselineFollowsOurOwnKnownFork() {
        // A build that carries Glamsterdam: past it, peers on its successor are on OUR
        // chain, and a further fork they announce is what the watch reports.
        long nextFork = SEPOLIA_GLAMSTERDAM + 60 * DAY;
        clock.set(SEPOLIA_GLAMSTERDAM + DAY);
        ForkWatch w = watch(SEPOLIA_GLAMSTERDAM);
        announce(w, "upgraded", 3, SUCCESSOR, 0);
        assertNull(w.advisory(), "our own fork's successor is not news");
        announce(w, "upgraded", 3, SUCCESSOR, nextFork);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(ForkWatch.Phase.SCHEDULED, a.phase());
        assertEquals(nextFork, a.activationTime());
        assertEquals(ForkIds.successor(SEPOLIA_GLAMSTERDAM_FORK_ID, nextFork), a.forkHash());
    }

    @Test
    void aRescheduledForkStaysNewsPastTheDateThisBuildKnows() {
        // Glamsterdam moves AFTER this build shipped (it moved once already, 09-21 → 10-06).
        // Past OUR date we present its successor, which peers on the new date reject — but
        // they show their Status first, still on the pin: that is the whole signal then.
        long moved = SEPOLIA_GLAMSTERDAM + 7 * DAY;
        int movedForkId = ForkIds.successor(ForkIds.toInt(LOCAL), moved);
        clock.set(SEPOLIA_GLAMSTERDAM - 3600);
        ForkWatch w = watch(SEPOLIA_GLAMSTERDAM);
        announce(w, "upgraded", 3, LOCAL, moved);
        ForkWatch.Advisory scheduled = new ForkWatch.Advisory(ForkWatch.Phase.SCHEDULED, moved, movedForkId, 3);
        assertEquals(scheduled, w.advisory());
        assertEquals(scheduled, w.evaluate(SEPOLIA_GLAMSTERDAM + 3600),
                "past our date the pin still measures them: their fork id, not a successor of ours");
        clock.set(moved + DAY);
        announce(w, "upgraded", 3, bytes(movedForkId), 0);
        assertEquals(new ForkWatch.Advisory(ForkWatch.Phase.ACTIVE, moved, movedForkId, 3), w.advisory(),
                "once their date passed, their hash places from the pin");
    }

    @Test
    void thePoolFromBeforeOurDateStillDissentsPastIt() {
        // A stable pool that handshook before our date and stays connected across it. Its
        // Status is still on the pin — four on our date, one on none — and right after T it
        // is most of what we know: if its verdict lapsed at OUR date, a few fresh sources
        // minting a "successor of ours" would face no dissent at all.
        clock.set(SEPOLIA_GLAMSTERDAM - 3600);
        ForkWatch w = watch(SEPOLIA_GLAMSTERDAM);
        List<String> pool = new ArrayList<>(announce(w, "on-our-date", 4, LOCAL, SEPOLIA_GLAMSTERDAM));
        pool.addAll(announce(w, "not-upgraded", 1, LOCAL, 0));
        clock.set(SEPOLIA_GLAMSTERDAM + 3600);
        w.touch(pool);
        long forgedAt = SEPOLIA_GLAMSTERDAM + EPOCH;   // grid-aligned, one epoch past ours
        byte[] forged = bytes(ForkIds.successor(SEPOLIA_GLAMSTERDAM_FORK_ID, forgedAt));
        announce(w, "forger", 3, forged, 0);
        assertNull(w.advisory());
        announce(w, "forger", 5, forged, 0);
        assertNull(w.advisory(), "a tie is not a majority");
        w.observe("forger5", forged, 0);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(forgedAt, a.activationTime());
        assertEquals(ForkIds.toInt(forged), a.forkHash());
        assertEquals(6, a.peers());
    }

    @Test
    void theSameDateFromEitherBaselineIsTwoForks() {
        // Past our date, "a fork after ours at t" (announced on its successor) and "our fork
        // moved to t" (announced on the pin) are different forks with different ids: they
        // must not pool their sources into one vote.
        long later = SEPOLIA_GLAMSTERDAM + 30 * DAY;
        clock.set(SEPOLIA_GLAMSTERDAM + DAY);
        ForkWatch w = watch(SEPOLIA_GLAMSTERDAM);
        announce(w, "after-ours", 3, SUCCESSOR, later);
        announce(w, "moved", 3, LOCAL, later);
        assertEquals(ForkIds.successor(SEPOLIA_GLAMSTERDAM_FORK_ID, later), w.advisory().forkHash(),
                "on a full tie, the current baseline's reading wins");
        announce(w, "current", 3, SUCCESSOR, 0);
        assertNull(w.advisory(), "three and three are not six");
        w.observe("moved3", LOCAL, later);
        assertEquals(new ForkWatch.Advisory(ForkWatch.Phase.SCHEDULED, later,
                ForkIds.successor(ForkIds.toInt(LOCAL), later), 4), w.advisory());
    }

    @Test
    void implausibleAnnouncementsAreIgnored() {
        ForkWatch w = watch(0);
        announce(w, "s", 4, LOCAL, 1_150_000);                                       // a block number
        assertNull(w.advisory());
        announce(w, "s", 4, LOCAL, BEFORE + ForkWatch.MAX_HORIZON_SECONDS + DAY);    // beyond the horizon
        assertNull(w.advisory());
        announce(w, "s", 4, LOCAL, BEFORE - 30 * DAY);                               // long past, no proof
        assertNull(w.advisory());
        announce(w, "s", 4, LOCAL, -1L);                                             // uint64 garbage
        assertNull(w.advisory());
    }

    @Test
    void foreignHashesThatAreNotOurSuccessorAreIgnored() {
        ForkWatch w = watch(0);
        // Stale peers still on Sepolia's BPO1 (the fork BEFORE ours, announcing BPO2's
        // activation), and one on some unrelated id: neither places on the grid.
        announce(w, "stale", 4, bytes(0x56078a1e), 1_761_607_008L);
        w.observe("odd", bytes(0xdeadbeef), 0);
        assertNull(w.advisory());
    }

    @Test
    void observationsExpire() {
        ForkWatch w = watch(0);
        announce(w, "s", 3, LOCAL, SEPOLIA_GLAMSTERDAM);
        assertNotNull(w.advisory());
        assertNull(w.evaluate(BEFORE + ForkWatch.OBSERVATION_TTL_SECONDS + 1));
    }

    @Test
    void trackedSourcesAreBounded() {
        ForkWatch w = watch(0);
        for (int i = 0; i < ForkWatch.MAX_TRACKED + 10; i++) {
            clock.set(BEFORE + i);
            w.observe("s" + i, LOCAL, 0);
        }
        assertEquals(ForkWatch.MAX_TRACKED, w.tracked());
    }

    @Test
    void malformedInputIsIgnored() {
        ForkWatch w = watch(0);
        w.observe(null, LOCAL, SEPOLIA_GLAMSTERDAM);
        w.observe("a", null, SEPOLIA_GLAMSTERDAM);
        w.observe("b", new byte[3], SEPOLIA_GLAMSTERDAM);
        w.observe("c", new byte[5], SEPOLIA_GLAMSTERDAM);
        assertNull(w.advisory());
        assertEquals(0, w.tracked());
    }
}
