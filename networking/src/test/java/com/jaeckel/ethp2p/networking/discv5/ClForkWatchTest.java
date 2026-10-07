package com.jaeckel.ethp2p.networking.discv5;

import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.eth.ForkWatch;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Scenario tests on Sepolia's real parameters, as a build shipped BEFORE Glamsterdam
 * would see them: a schedule ending at Fulu, peers announcing and then crossing Gloas.
 * Mirrored by the Rust twin's tests ({@code cl_fork_watch::tests}); the vectors are pinned
 * in {@code rust/testdata/lc/fork_watch/params.txt}.
 */
class ClForkWatchTest {

    private static final NetworkConfig SEPOLIA = NetworkConfig.SEPOLIA;
    private static final byte[] FULU_VERSION = {(byte) 0x90, 0, 0, 0x75};
    private static final byte[] GLOAS_VERSION = {(byte) 0x90, 0, 0, 0x76};
    /** Sepolia's Fulu digest with BPO2 folded in (the live wire value). */
    private static final byte[] FULU_DIGEST = {0x74, (byte) 0xD0, 0x14, 0x59};
    /** Sepolia's Gloas digest (same blob params). */
    private static final byte[] GLOAS_DIGEST = {0x66, (byte) 0x9E, 0x6C, 0x11};
    private static final long GLOAS_EPOCH = 353_024L;
    /** Sepolia's Glamsterdam activation, unix seconds (epoch 353024). */
    private static final long T = 1_791_294_816L;
    private static final long DAY = 24 * 3600;
    private static final long BEFORE = T - 14 * DAY;
    private static final long AFTER = T + DAY;

    private final AtomicLong clock = new AtomicLong(BEFORE);

    /** Sepolia on the schedule a build shipped before Glamsterdam carried: no Gloas. */
    private ClForkWatch preGloasSepolia() {
        List<ForkSchedule.Fork> forks = new ArrayList<>();
        for (ForkSchedule.Fork f : SEPOLIA.forkSchedule().forks()) {
            if (f.version() != 0x90000076) forks.add(f);
        }
        assertEquals(SEPOLIA.forkSchedule().forks().size() - 1, forks.size(), "the real schedule carries Gloas");
        return watch(new ForkSchedule(SEPOLIA.forkSchedule().slotsPerEpoch(), forks));
    }

    /** Sepolia on the schedule this build ships (Gloas included). */
    private ClForkWatch currentSepolia() {
        return watch(SEPOLIA.forkSchedule());
    }

    private ClForkWatch watch(ForkSchedule schedule) {
        return new ClForkWatch("sepolia", schedule, SEPOLIA.genesisValidatorsRoot(),
                SEPOLIA.activeBlobParamsEpoch(), SEPOLIA.activeBlobParamsMaxBlobs(),
                SEPOLIA.clGenesisTime(), SEPOLIA.secondsPerSlot(), clock::get);
    }

    private static void announce(ClForkWatch w, String prefix, int n) {
        for (int i = 0; i < n; i++) w.observeEnr(prefix + i, FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH);
    }

    private static void quiet(ClForkWatch w, String prefix, int n) {
        for (int i = 0; i < n; i++) w.observeEnr(prefix + i, FULU_DIGEST, FULU_VERSION, ClForkWatch.FAR_FUTURE_EPOCH);
    }

    private static void upgraded(ClForkWatch w, String prefix, int n) {
        for (int i = 0; i < n; i++) w.observeEnr(prefix + i, GLOAS_DIGEST, GLOAS_VERSION, ClForkWatch.FAR_FUTURE_EPOCH);
    }

    @Test
    void digestsReproduceThePinnedWireValues() {
        ClForkWatch w = preGloasSepolia();
        assertArrayEquals(FULU_DIGEST, w.digestOf(FULU_VERSION));
        assertArrayEquals(GLOAS_DIGEST, w.digestOf(GLOAS_VERSION));
        assertArrayEquals(SEPOLIA.forkDigestAtEpoch(GLOAS_EPOCH), GLOAS_DIGEST, "NetworkConfig agrees");
    }

    @Test
    void constantsMatchTheSharedTwinPins() throws Exception {
        Path f = Path.of("..", "rust", "testdata", "lc", "fork_watch", "params.txt");
        assumeTrue(Files.isRegularFile(f), "shared twin pins not found at " + f.toAbsolutePath());
        Map<String, String> p = new HashMap<>();
        for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
            String l = line.strip();
            if (l.isEmpty() || l.startsWith("#")) continue;
            int eq = l.indexOf('=');
            p.put(l.substring(0, eq), l.substring(eq + 1));
        }
        assertEquals(ClForkWatch.MIN_PEERS, Integer.parseInt(p.get("min_peers")));
        assertEquals(ClForkWatch.OBSERVATION_TTL_SECONDS, Long.parseLong(p.get("observation_ttl_seconds")));
        assertEquals(ClForkWatch.ACTIVATION_GRACE_SECONDS, Long.parseLong(p.get("activation_grace_seconds")));
        assertEquals(ClForkWatch.MAX_HORIZON_SECONDS, Long.parseLong(p.get("max_horizon_seconds")));
        assertEquals(ClForkWatch.MAX_TRACKED, Integer.parseInt(p.get("max_tracked")));
        assertEquals("mainnet,sepolia,gnosis", p.get("enabled_networks"));
        // Every network has one: forNetwork never returns null.
        for (NetworkConfig net : List.of(NetworkConfig.MAINNET, NetworkConfig.SEPOLIA, NetworkConfig.GNOSIS)) {
            assertNotNull(ClForkWatch.forNetwork(net), net.name());
        }
        assertEquals("0x74d01459", p.get("sepolia_fulu_digest"));
        assertEquals("0x669e6c11", p.get("sepolia_gloas_digest"));
        assertEquals(T, Long.parseLong(p.get("sepolia_gloas_activation")));
    }

    @Test
    void quietNetworkRaisesNothing() {
        ClForkWatch w = preGloasSepolia();
        assertNull(w.advisory());
        quiet(w, "q", 8);
        assertNull(w.advisory());
    }

    @Test
    void aForkThisBuildKnowsIsNotNews() {
        ClForkWatch w = currentSepolia();
        announce(w, "a", 6);
        assertNull(w.advisory(), "Gloas is on the schedule: nothing unknown ahead");
        clock.set(AFTER);
        upgraded(w, "u", 6);
        assertNull(w.advisory(), "peers on Gloas are on OUR chain after the fork");
        // The configured blob-parameter epoch is a known transition too.
        clock.set(BEFORE);
        w = preGloasSepolia();
        for (int i = 0; i < 4; i++) w.observeEnr("b" + i, FULU_DIGEST, FULU_VERSION, 275_712L);
        assertNull(w.advisory());
    }

    @Test
    void scheduledNeedsThreeDistinctSources() {
        ClForkWatch w = preGloasSepolia();
        announce(w, "s", 2);
        assertNull(w.advisory(), "two sources are below the threshold");
        for (int i = 0; i < 5; i++) w.observeEnr("s0", FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH);
        assertNull(w.advisory(), "re-observing a source must not count it twice");
        w.observeEnr("s2", FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH);
        ForkWatch.Advisory a = w.advisory();
        assertNotNull(a);
        assertEquals(ForkWatch.Phase.SCHEDULED, a.phase());
        assertEquals(T, a.activationTime());
        assertEquals("0x669e6c11", a.forkHashHex());
        assertEquals(3, a.peers());
    }

    @Test
    void aMinorityCannotOutvoteThePeersItContradicts() {
        ClForkWatch w = preGloasSepolia();
        announce(w, "s", 3);
        quiet(w, "q", 3);
        assertNull(w.advisory(), "3 for, 3 against: not a majority");
        w.observeEnr("s3", FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH);
        assertEquals(4, w.advisory().peers());
    }

    @Test
    void statusDigestsAloneNeitherSupportNorDissent() {
        ClForkWatch w = preGloasSepolia();
        announce(w, "s", 3);
        for (int i = 0; i < 20; i++) w.observeStatus("st" + i, FULU_DIGEST);
        assertEquals(3, w.advisory().peers(), "our own digest says nothing about ahead");
        for (int i = 0; i < 20; i++) w.observeStatus("x" + i, new byte[]{(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef});
        assertEquals(3, w.advisory().peers(), "an unplaceable digest is ignored");
    }

    @Test
    void announcedBecomesActiveOnTheWallClock() {
        ClForkWatch w = preGloasSepolia();
        clock.set(T - 3600);
        announce(w, "s", 3);
        assertEquals(ForkWatch.Phase.SCHEDULED, w.evaluate(T - 1).phase());
        ForkWatch.Advisory a = w.evaluate(T);
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(T, a.activationTime());
        // The grace bridges the rollover; after it a stale announcement ages out.
        assertNotNull(w.evaluate(T + ClForkWatch.ACTIVATION_GRACE_SECONDS - 1));
        assertNull(w.evaluate(T + ClForkWatch.ACTIVATION_GRACE_SECONDS));
    }

    @Test
    void upgradedPeersPlaceTheForkWithoutAnAnnouncement() {
        // A wallet started after the fork: every ENR it sees carries the new digest with
        // the new version and no further fork scheduled.
        ClForkWatch w = preGloasSepolia();
        clock.set(AFTER);
        upgraded(w, "u", 2);
        assertNull(w.advisory());
        upgraded(w, "u", 3);
        ForkWatch.Advisory a = w.advisory();
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase(), "placed by three sources");
        assertEquals(0, a.activationTime(), "a digest does not encode its epoch");
        assertEquals("0x669e6c11", a.forkHashHex());
        assertEquals(3, a.peers());
    }

    @Test
    void placementRequiresASelfConsistentNewerVersion() {
        ClForkWatch w = preGloasSepolia();
        clock.set(AFTER);
        // Digest and version disagree: another chain, or a lie — unplaceable.
        for (int i = 0; i < 4; i++) w.observeEnr("lie" + i, GLOAS_DIGEST, new byte[]{(byte) 0x90, 0, 0, 0x77}, ClForkWatch.FAR_FUTURE_EPOCH);
        assertNull(w.advisory());
        // Self-consistent but OLDER than our fork (a peer left behind): not news.
        byte[] electra = {(byte) 0x90, 0, 0, 0x74};
        byte[] electraDigest = w.digestOf(electra);
        for (int i = 0; i < 4; i++) w.observeEnr("old" + i, electraDigest, electra, ClForkWatch.FAR_FUTURE_EPOCH);
        assertNull(w.advisory());
    }

    @Test
    void aStatusOnAnAnnouncedForkPlacesThePeer() {
        ClForkWatch w = preGloasSepolia();
        long now = T + 3600;
        clock.set(now);
        announce(w, "s", 2);
        assertNull(w.advisory(), "two announcements are below the threshold");
        // A third source answers a Status on the digest the announced version yields: it
        // has crossed the fork.
        w.observeStatus("st0", GLOAS_DIGEST);
        ForkWatch.Advisory a = w.advisory();
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(T, a.activationTime(), "the announcement names the epoch the Status cannot");
        assertEquals(3, a.peers());
        // Past the grace the announcements stop counting; the Status alone is then
        // unplaceable (no version left in play).
        assertNull(w.evaluate(T + ClForkWatch.ACTIVATION_GRACE_SECONDS));
    }

    @Test
    void anAnnouncementPinsTheEpochForPlacedPeers() {
        ClForkWatch w = preGloasSepolia();
        announce(w, "s", 3);
        clock.set(AFTER);
        upgraded(w, "u", 3);
        ForkWatch.Advisory a = w.advisory();
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(0, a.activationTime(), "the announcements aged out a day after T");
        assertEquals(3, a.peers());

        w = preGloasSepolia();
        clock.set(T + 1800);
        announce(w, "s", 3);
        clock.set(T + 3600);
        upgraded(w, "u", 3);
        a = w.advisory();
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(T, a.activationTime());
        assertEquals(6, a.peers());
    }

    @Test
    void oneVotePerSourceAcrossBothFeeds() {
        ClForkWatch w = preGloasSepolia();
        clock.set(T + 60);
        announce(w, "s", 3);
        // The same three sources also answer a Status on the new digest: still 3.
        for (int i = 0; i < 3; i++) w.observeStatus("s" + i, GLOAS_DIGEST);
        assertEquals(3, w.advisory().peers());
    }

    @Test
    void evidenceAgesOut() {
        ClForkWatch w = preGloasSepolia();
        announce(w, "s", 3);
        assertNotNull(w.evaluate(BEFORE + ClForkWatch.OBSERVATION_TTL_SECONDS - 1));
        assertNull(w.evaluate(BEFORE + ClForkWatch.OBSERVATION_TTL_SECONDS + 1));
    }

    @Test
    void garbageEpochsAreIgnored() {
        ClForkWatch w = preGloasSepolia();
        for (int i = 0; i < 4; i++) w.observeEnr("g" + i, FULU_DIGEST, GLOAS_VERSION, -2L);   // uint64 max - 1
        assertNull(w.advisory(), "an epoch past the horizon (or overflowing) is garbage");
        for (int i = 0; i < 4; i++) w.observeEnr("h" + i, FULU_DIGEST, GLOAS_VERSION, 1L);
        assertNull(w.advisory(), "a long-passed epoch announced now is not evidence");
        for (int i = 0; i < 4; i++) w.observeEnr("f" + i, FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH + 100_000_000L);
        assertNull(w.advisory(), "beyond the 400-day horizon");
    }

    @Test
    void aForkWithAFurtherTransitionScheduledStillPlaces() {
        // Clients on Gloas with a blob-parameter fork scheduled after it publish
        // (gloas_digest, gloas_version, bpo_epoch) — the normal post-fork shape on a chain
        // that ships BPOs — and must place like the FAR_FUTURE form.
        ClForkWatch w = preGloasSepolia();
        clock.set(AFTER);
        for (int i = 0; i < 3; i++) w.observeEnr("u" + i, GLOAS_DIGEST, GLOAS_VERSION, 400_000L);
        ForkWatch.Advisory a = w.advisory();
        assertEquals(ForkWatch.Phase.ACTIVE, a.phase());
        assertEquals(0, a.activationTime());
        assertEquals("0x669e6c11", a.forkHashHex());
        assertEquals(3, a.peers());
    }

    @Test
    void aBlobParameterForkAnnouncesUnderOurVersionWithNoForkId() {
        // A BPO-only fork: announced under OUR version at an epoch we do not know. It is an
        // upgrade (the digest rotates), but to a digest this build cannot compute, so the
        // fork id is 0.
        ClForkWatch w = preGloasSepolia();
        for (int i = 0; i < 3; i++) w.observeEnr("b" + i, FULU_DIGEST, FULU_VERSION, 400_000L);
        ForkWatch.Advisory a = w.advisory();
        assertEquals(ForkWatch.Phase.SCHEDULED, a.phase());
        assertEquals(SEPOLIA.clGenesisTime() + 400_000L * 32 * 12, a.activationTime());
        assertEquals(0, a.forkHash(), "the post-BPO digest is not computable");
        assertEquals(3, a.peers());
        // Our version is in play, but peers on OUR digest are never placed on it.
        for (int i = 0; i < 4; i++) w.observeEnr("g" + i, FULU_DIGEST, FULU_VERSION, 1L);
        for (int i = 0; i < 4; i++) w.observeStatus("s" + i, FULU_DIGEST);
        assertEquals(3, w.advisory().peers());
    }

    @Test
    void aTieBetweenPlacedVersionsResolvesToTheLowestAndStaysPut() {
        ClForkWatch w = preGloasSepolia();
        clock.set(AFTER);
        byte[] higher = {(byte) 0x90, 0, 0, 0x77};
        byte[] higherDigest = w.digestOf(higher);
        for (int i = 0; i < 3; i++) w.observeEnr("h" + i, higherDigest, higher, ClForkWatch.FAR_FUTURE_EPOCH);
        upgraded(w, "u", 3);
        for (int i = 0; i < 5; i++) {
            ForkWatch.Advisory a = w.advisory();
            assertEquals("0x669e6c11", a.forkHashHex(), "the lower version, every time");
            assertEquals(3, a.peers());
        }
    }

    @Test
    void trackedSourcesAreBounded() {
        ClForkWatch w = preGloasSepolia();
        for (int i = 0; i < ClForkWatch.MAX_TRACKED + 50; i++) {
            w.observeEnr("e" + i, FULU_DIGEST, FULU_VERSION, ClForkWatch.FAR_FUTURE_EPOCH);
        }
        for (int i = 0; i < ClForkWatch.MAX_TRACKED + 50; i++) w.observeStatus("s" + i, FULU_DIGEST);
        assertEquals(2 * ClForkWatch.MAX_TRACKED, w.tracked());
    }

    @Test
    void mergePrefersActiveThenAKnownTimeThenMorePeersThenEl() {
        int el = 0x6c1d9423, cl = 0x669e6c11;
        assertNull(ClForkWatch.merge(null, null));
        assertEquals(el, ClForkWatch.merge(adv(ForkWatch.Phase.SCHEDULED, T, el, 3), null).forkHash());
        assertEquals(cl, ClForkWatch.merge(null, adv(ForkWatch.Phase.SCHEDULED, T, cl, 3)).forkHash());
        assertEquals(cl, ClForkWatch.merge(adv(ForkWatch.Phase.SCHEDULED, T, el, 9),
                adv(ForkWatch.Phase.ACTIVE, 0, cl, 3)).forkHash(), "ACTIVE outranks SCHEDULED regardless of peers");
        assertEquals(el, ClForkWatch.merge(adv(ForkWatch.Phase.ACTIVE, T, el, 3),
                adv(ForkWatch.Phase.ACTIVE, 0, cl, 9)).forkHash(), "a known activation time outranks an unknown one");
        assertEquals(cl, ClForkWatch.merge(adv(ForkWatch.Phase.ACTIVE, T, el, 3),
                adv(ForkWatch.Phase.ACTIVE, T, cl, 9)).forkHash(), "then more sources");
        assertEquals(el, ClForkWatch.merge(adv(ForkWatch.Phase.ACTIVE, T, el, 3),
                adv(ForkWatch.Phase.ACTIVE, T, cl, 3)).forkHash(), "a full tie goes to the EL");
    }

    private static ForkWatch.Advisory adv(ForkWatch.Phase phase, long t, int hash, int peers) {
        return new ForkWatch.Advisory(phase, t, hash, peers);
    }

    @Test
    void sourceOfMultiaddrReadsIp4AndIp6() throws Exception {
        assertEquals(ForkWatch.sourceOf(InetAddress.getByName("1.2.3.4")),
                ClForkWatch.sourceOfMultiaddr("/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAm"));
        assertEquals(ForkWatch.sourceOf(InetAddress.getByName("2001:db8::1")),
                ClForkWatch.sourceOfMultiaddr("/ip6/2001:db8::1/tcp/9000"));
        assertNull(ClForkWatch.sourceOfMultiaddr("/dns4/example.org/tcp/9000"));
        assertNull(ClForkWatch.sourceOfMultiaddr(null));
    }
}
