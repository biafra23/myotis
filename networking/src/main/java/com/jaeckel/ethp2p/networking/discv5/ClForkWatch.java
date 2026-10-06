package com.jaeckel.ethp2p.networking.discv5;

import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.eth.ForkIds;
import com.jaeckel.ethp2p.networking.eth.ForkWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Consensus-layer stale-software detection — the CL twin of {@link ForkWatch} (same vote
 * rules, same constants, same Sepolia vectors in the tests; Rust twin:
 * {@code myotis_net::cl_fork_watch}).
 *
 * <p>Notices, from what consensus peers advertise, that the beacon chain has scheduled —
 * or already activated — a fork this build's {@link ForkSchedule} does not carry. The EL
 * watch needs eth peers past the handshake; this one needs only a discv5 table and a
 * Status exchange, so it also fires on a network where the wallet holds no EL peer yet,
 * and on a CL-only fork.
 *
 * <p>Evidence:
 * <ul>
 *   <li><b>Announced</b> — a discv5 ENR whose {@code eth2} field (SSZ {@code ENRForkID}:
 *       {@code fork_digest || next_fork_version || next_fork_epoch}) carries one of OUR
 *       digests with a {@code next_fork_epoch} this schedule does not know. Upgraded
 *       clients publish it from the day their release carries the fork.</li>
 *   <li><b>Placed</b> — an ENR on a digest we do not know whose {@code next_fork_version}
 *       REPRODUCES that digest under this chain's genesis root and blob params (a client
 *       with no further fork scheduled publishes its CURRENT version there, per the spec),
 *       and whose version is NEWER than ours: the peer is on a fork past this build. Also
 *       a Status {@code fork_digest} — or an ENR digest — that reproduces from a version
 *       some source announced: the peer has crossed the announced fork. Placing separates
 *       "a later fork of this chain" from another chain's digest; it is not proof — a lying
 *       peer can mint a self-consistent record for any version.</li>
 * </ul>
 *
 * <p>The vote mirrors the EL watch exactly: one vote per SOURCE network
 * ({@link ForkWatch#sourceOf}: IPv4 /24, IPv6 /48) — node ids are free; an advisory needs
 * {@link #MIN_PEERS} sources behind one fork AND more of them than sources on our chain
 * announcing nothing unknown (a known transition — a scheduled fork or the configured
 * blob-parameter epoch — is nothing unknown). ADVISORY ONLY: nothing in verification reads
 * it. Evidence ages out {@link #OBSERVATION_TTL_SECONDS} after it was presented; a passed
 * announcement keeps counting {@link #ACTIVATION_GRACE_SECONDS} past its activation
 * (bridges the rollover to the new digest, ages out a moved date).
 *
 * <p>A Status carrying one of our digests says nothing about what lies ahead, so it is
 * neither support nor dissent — otherwise every exchange before the fork would outvote the
 * announcements. The activation time of a fork known only from placement is unknown
 * (reported as 0): the digest is a truncated hash and does not encode the epoch. A
 * blob-parameter-only fork is announced under OUR version (only the digest rotates, to a
 * value this build cannot compute), so its fork id is reported as 0; once it passes, only
 * the EL watch can still place peers (their new digest reproduces from nothing we know).
 *
 * <p>ENR evidence is the discv5 LIVE table's (ping-checked entries, re-heard on every
 * poll tick — {@code DiscV5Service.setOnEnrHeard}), never records merely relayed in a
 * NODES response: those are self-declared, and node keys are free, so they would make
 * the source floor free too. Known limit of this engine: {@code core.enr.Enr} reads the
 * {@code ip} key only, so an IPv6-only record casts no vote here (the Rust twin reads
 * {@code ip6} as well) — an undercount, never a wrong vote.
 *
 * <p>One instance per network stack, shared across pause/resume rebuilds (like
 * {@link ForkWatch}). Thread-safe: observed from the discv5 and libp2p threads, read by
 * status surfaces.
 */
public final class ClForkWatch {

    private static final Logger log = LoggerFactory.getLogger(ClForkWatch.class);

    public static final int MIN_PEERS = ForkWatch.MIN_PEERS;
    static final long OBSERVATION_TTL_SECONDS = ForkWatch.OBSERVATION_TTL_SECONDS;
    static final long ACTIVATION_GRACE_SECONDS = ForkWatch.ACTIVATION_GRACE_SECONDS;
    static final long MAX_HORIZON_SECONDS = ForkWatch.MAX_HORIZON_SECONDS;
    static final int MAX_TRACKED = ForkWatch.MAX_TRACKED;
    /** {@code FAR_FUTURE_EPOCH} (uint64 max) as the signed long {@code Enr.eth2()} yields. */
    public static final long FAR_FUTURE_EPOCH = -1L;

    private record EnrObservation(byte[] digest, byte[] nextVersion, long nextEpoch, long observedAt) {}

    private record StatusObservation(byte[] digest, long observedAt) {}

    /** What one source's evidence says, after classification. */
    private record Vote(Kind kind, int version, long epoch) {
        enum Kind { DISSENT, ANNOUNCED, PLACED }
    }

    private final String label;
    private final ForkSchedule schedule;
    private final byte[] genesisValidatorsRoot;
    private final long blobParamsEpoch;
    private final long blobParamsMaxBlobs;
    private final long genesisTime;
    private final long secondsPerSlot;
    private final LongSupplier clock;
    /** Every digest the schedule can produce — "ours" — computed once. */
    private final List<byte[]> knownDigests;

    /** Latest observation per source, access-ordered so the LRU bound drops the stalest. */
    private final LinkedHashMap<String, EnrObservation> enrBySource = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, EnrObservation> eldest) {
            return size() > MAX_TRACKED;
        }
    };
    private final LinkedHashMap<String, StatusObservation> statusBySource = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, StatusObservation> eldest) {
            return size() > MAX_TRACKED;
        }
    };
    private ForkWatch.Advisory lastLogged;

    /**
     * A watch over {@code schedule}: the forks this build knows, judged on the chain's
     * genesis root, blob params and slot timing. {@code blobParamsEpoch} is also a KNOWN
     * transition (a peer announcing it announces nothing unknown).
     *
     * @param clock wall clock, unix SECONDS
     */
    public ClForkWatch(String label, ForkSchedule schedule, byte[] genesisValidatorsRoot,
                       long blobParamsEpoch, long blobParamsMaxBlobs,
                       long genesisTime, int secondsPerSlot, LongSupplier clock) {
        this.label = label;
        this.schedule = schedule;
        this.genesisValidatorsRoot = genesisValidatorsRoot.clone();
        this.blobParamsEpoch = blobParamsEpoch;
        this.blobParamsMaxBlobs = blobParamsMaxBlobs;
        this.genesisTime = genesisTime;
        this.secondsPerSlot = secondsPerSlot;
        this.clock = clock;
        List<byte[]> known = new ArrayList<>(schedule.forks().size());
        for (ForkSchedule.Fork f : schedule.forks()) known.add(digestOf(f.versionBytes()));
        this.knownDigests = List.copyOf(known);
    }

    /** A watch over {@code net}'s schedule, on the system wall clock. Every network. */
    public static ClForkWatch forNetwork(NetworkConfig net) {
        return new ClForkWatch(net.name(), net.forkSchedule(), net.genesisValidatorsRoot(),
                net.activeBlobParamsEpoch(), net.activeBlobParamsMaxBlobs(),
                net.clGenesisTime(), net.secondsPerSlot(), () -> System.currentTimeMillis() / 1000);
    }

    /**
     * The vote key for a peer named by a libp2p multiaddr ({@code /ip4/…} or {@code /ip6/…}),
     * or null when the address names no IP literal (a {@code /dns4/} peer is not resolved
     * here — a lookup on the network thread is not worth a vote).
     */
    public static String sourceOfMultiaddr(String multiaddr) {
        if (multiaddr == null) return null;
        String[] parts = multiaddr.split("/");
        for (int i = 0; i + 1 < parts.length; i++) {
            if (parts[i].equals("ip4") || parts[i].equals("ip6")) {
                try {
                    // A literal never triggers a DNS lookup.
                    return ForkWatch.sourceOf(InetAddress.getByName(parts[i + 1]));
                } catch (Exception malformed) {
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * The one advisory a host reports when both detectors have one: ACTIVE over SCHEDULED;
     * then a known activation time over an unknown one; then more sources; then the EL's.
     * Rust twin: {@code cl_fork_watch::merge_advisories}.
     */
    public static ForkWatch.Advisory merge(ForkWatch.Advisory el, ForkWatch.Advisory cl) {
        if (el == null) return cl;
        if (cl == null) return el;
        return rank(cl) > rank(el) ? cl : el;
    }

    /** Totally ordered: phase, then a known time, then sources (each strictly outranks the next). */
    private static long rank(ForkWatch.Advisory a) {
        return (a.phase() == ForkWatch.Phase.ACTIVE ? 1L << 62 : 0)
                + (a.activationTime() != 0 ? 1L << 61 : 0)
                + a.peers();
    }

    /** The digest a fork {@code version} yields on this chain (blob params folded in). */
    public byte[] digestOf(byte[] version) {
        return NetworkConfig.forkDigest(version, genesisValidatorsRoot, blobParamsEpoch, blobParamsMaxBlobs);
    }

    /**
     * Record a discv5 ENR's {@code eth2} field from {@code source} ({@link ForkWatch#sourceOf}).
     * Cheap; logs when it changes the advisory. Malformed input is ignored.
     */
    public void observeEnr(String source, byte[] forkDigest, byte[] nextForkVersion, long nextForkEpoch) {
        if (source == null || forkDigest == null || forkDigest.length != 4
                || nextForkVersion == null || nextForkVersion.length != 4) return;
        update(now -> enrBySource.put(source,
                new EnrObservation(forkDigest.clone(), nextForkVersion.clone(), nextForkEpoch, now)));
    }

    /** Record the {@code fork_digest} a peer from {@code source} presented in its Status. */
    public void observeStatus(String source, byte[] forkDigest) {
        if (source == null || forkDigest == null || forkDigest.length != 4) return;
        update(now -> statusBySource.put(source, new StatusObservation(forkDigest.clone(), now)));
    }

    /** Tracked sources (ENR + Status) — for tests of the {@link #MAX_TRACKED} bound. */
    synchronized int tracked() {
        return enrBySource.size() + statusBySource.size();
    }

    /** The current advisory on the wall clock, or null. */
    public ForkWatch.Advisory advisory() {
        return evaluate(clock.getAsLong());
    }

    private void update(java.util.function.LongConsumer mutation) {
        ForkWatch.Advisory current;
        synchronized (this) {
            long now = clock.getAsLong();
            mutation.accept(now);
            current = evaluate(now);
            if (sameFork(lastLogged, current)) return;
            lastLogged = current;
        }
        if (current == null) {
            log.info("[{}][cl-fork-watch] upgrade advisory cleared", label);
        } else if (current.phase() == ForkWatch.Phase.SCHEDULED) {
            log.warn("[{}][cl-fork-watch] consensus peers on {} networks announce a network upgrade at {} "
                    + "(fork digest {}) that this build does not support — update before then", label,
                    current.peers(), Instant.ofEpochSecond(current.activationTime()), current.forkHashHex());
        } else {
            log.warn("[{}][cl-fork-watch] consensus peers on {} networks are on a fork (digest {}, activated {}) "
                    + "this build does not support — update required", label, current.peers(),
                    current.forkHashHex(),
                    current.activationTime() == 0 ? "at an unknown time" : Instant.ofEpochSecond(current.activationTime()));
        }
    }

    private long epochSeconds() {
        return (long) schedule.slotsPerEpoch() * secondsPerSlot;
    }

    private long wallEpoch(long now) {
        long es = epochSeconds();
        return es == 0 ? 0 : Math.max(0, now - genesisTime) / es;
    }

    /**
     * Unix seconds at which {@code epoch} starts; -1 past the plausible horizon (an
     * announcement that far out is garbage, and the multiply could wrap) or for a
     * negative (uint64 high-bit) epoch.
     */
    private long activationTime(long epoch, long now) {
        if (epoch < 0) return -1;
        try {
            long t = Math.addExact(genesisTime, Math.multiplyExact(epoch, epochSeconds()));
            return t <= now + MAX_HORIZON_SECONDS ? t : -1;
        } catch (ArithmeticException overflow) {
            return -1;
        }
    }

    /** A transition this build knows: a scheduled fork's activation or the blob-parameter epoch. */
    private boolean knownTransition(long epoch) {
        if (epoch == blobParamsEpoch) return true;
        for (ForkSchedule.Fork f : schedule.forks()) {
            if (f.epoch() == epoch) return true;
        }
        return false;
    }

    /** The advisory as of {@code now} (unix seconds), or null. */
    public synchronized ForkWatch.Advisory evaluate(long now) {
        long fresh = now - OBSERVATION_TTL_SECONDS;
        enrBySource.values().removeIf(o -> o.observedAt() < fresh);
        statusBySource.values().removeIf(o -> o.observedAt() < fresh);

        // Every digest this schedule can produce is "ours": a peer on an older scheduled
        // fork is behind, not news.
        int currentVersion = ForkIds.toInt(schedule.versionAtEpoch(wallEpoch(now)));

        // Pass 1: ENR evidence — the only kind that names the fork ahead.
        Map<String, Vote> votes = new HashMap<>();
        List<Integer> versionsInPlay = new ArrayList<>();
        for (Map.Entry<String, EnrObservation> e : enrBySource.entrySet()) {
            EnrObservation o = e.getValue();
            boolean onOurs = contains(knownDigests, o.digest());
            int nextVersion = ForkIds.toInt(o.nextVersion());
            Vote vote = null;
            if (knownTransition(o.nextEpoch())) {
                vote = new Vote(Vote.Kind.DISSENT, 0, 0);
            } else if (o.nextEpoch() == FAR_FUTURE_EPOCH) {
                if (onOurs) {
                    vote = new Vote(Vote.Kind.DISSENT, 0, 0);
                } else if (newerSelfConsistent(o, currentVersion)) {
                    vote = new Vote(Vote.Kind.PLACED, nextVersion, 0);
                }
            } else if (onOurs) {
                long t = activationTime(o.nextEpoch(), now);
                if (t >= 0 && (t > now || now - t < ACTIVATION_GRACE_SECONDS)) {
                    vote = new Vote(Vote.Kind.ANNOUNCED, nextVersion, o.nextEpoch());
                }
            } else if (newerSelfConsistent(o, currentVersion)) {
                vote = new Vote(Vote.Kind.PLACED, nextVersion, 0);
            }
            // else: a foreign digest announcing a further fork — placeable only against a
            // version someone announced (pass 2).
            if (vote != null) {
                if (vote.kind() != Vote.Kind.DISSENT && !versionsInPlay.contains(vote.version())) {
                    versionsInPlay.add(vote.version());
                }
                votes.put(e.getKey(), vote);
            }
        }
        // Deterministic order: a tie must resolve the same way on every evaluate and in
        // both engines.
        versionsInPlay.sort(Integer::compareUnsigned);
        List<byte[]> inPlayDigests = new ArrayList<>(versionsInPlay.size());
        for (int v : versionsInPlay) inPlayDigests.add(digestOf(versionBytes(v)));
        // Pass 2: digests alone (a Status, or an ENR that was not placeable above) place
        // against the versions in play. A digest this schedule produces is never placed —
        // it is ours (an announced blob-parameter fork keeps OUR version in play; peers on
        // our digest are not on it).
        for (Map.Entry<String, EnrObservation> e : enrBySource.entrySet()) {
            if (votes.containsKey(e.getKey())) continue;
            Integer v = place(versionsInPlay, inPlayDigests, e.getValue().digest());
            if (v != null) votes.put(e.getKey(), new Vote(Vote.Kind.PLACED, v, 0));
        }
        for (Map.Entry<String, StatusObservation> e : statusBySource.entrySet()) {
            if (votes.containsKey(e.getKey())) continue;
            Integer v = place(versionsInPlay, inPlayDigests, e.getValue().digest());
            if (v != null) votes.put(e.getKey(), new Vote(Vote.Kind.PLACED, v, 0));
        }

        // Tally per version; the activation epoch is the most-announced one (ties →
        // earliest), unknown when nobody announced it.
        int dissent = 0;
        Map<Long, Integer> announced = new HashMap<>();   // keyed by claimKey(version, epoch)
        Map<Integer, Integer> placed = new HashMap<>();
        for (Vote v : votes.values()) {
            switch (v.kind()) {
                case DISSENT -> dissent++;
                case ANNOUNCED -> announced.merge(claimKey(v.version(), v.epoch()), 1, Integer::sum);
                case PLACED -> placed.merge(v.version(), 1, Integer::sum);
            }
        }
        record Claim(int version, long epoch, int announced, int placed) {   // epoch -1 = unknown
            int total() { return announced + placed; }
        }
        Claim best = null;
        for (int version : versionsInPlay) {
            long bestEpoch = -1;
            int bestCount = 0;
            for (Map.Entry<Long, Integer> e : announced.entrySet()) {
                if (claimVersion(e.getKey()) != version) continue;
                long epoch = claimEpoch(e.getKey());
                int n = e.getValue();
                if (bestEpoch < 0 || n > bestCount || (n == bestCount && epoch < bestEpoch)) {
                    bestEpoch = epoch;
                    bestCount = n;
                }
            }
            Claim c = new Claim(version, bestEpoch, bestCount, placed.getOrDefault(version, 0));
            if (c.total() < MIN_PEERS || c.total() <= dissent) continue;
            // Most-backed fork; ties → more placed, a known epoch, the earliest epoch, then
            // the lowest version (versionsInPlay is ascending, so "first wins" does it).
            if (best == null || c.total() > best.total()
                    || (c.total() == best.total() && (c.placed() > best.placed()
                        || (c.placed() == best.placed() && (c.epoch() >= 0 && best.epoch() < 0
                            || (c.epoch() >= 0 && best.epoch() >= 0 && c.epoch() < best.epoch())))))) {
                best = c;
            }
        }
        if (best == null) return null;
        long activation = best.epoch() >= 0 ? Math.max(0, activationTime(best.epoch(), now)) : 0;
        ForkWatch.Phase phase = (activation != 0 && activation <= now) || best.placed() >= MIN_PEERS
                ? ForkWatch.Phase.ACTIVE : ForkWatch.Phase.SCHEDULED;
        // A fork announced under OUR version is a blob-parameter-only fork: it rotates the
        // digest to a value this build cannot compute (the new blob params are not on the
        // wire), so the fork id is unknown (0).
        int forkId = best.version() == currentVersion ? 0 : ForkIds.toInt(digestOf(versionBytes(best.version())));
        return new ForkWatch.Advisory(phase, activation, forkId, best.total());
    }

    /**
     * A record whose {@code next_fork_version} is newer than ours AND reproduces its own
     * digest: a peer on a later fork of THIS chain (with nothing further scheduled it
     * publishes its current version there; with a blob-parameter fork scheduled, still
     * its current version).
     */
    private boolean newerSelfConsistent(EnrObservation o, int currentVersion) {
        return Integer.compareUnsigned(ForkIds.toInt(o.nextVersion()), currentVersion) > 0
                && Arrays.equals(digestOf(o.nextVersion()), o.digest());
    }

    private Integer place(List<Integer> versionsInPlay, List<byte[]> inPlayDigests, byte[] digest) {
        if (contains(knownDigests, digest)) return null;
        for (int i = 0; i < versionsInPlay.size(); i++) {
            if (Arrays.equals(inPlayDigests.get(i), digest)) return versionsInPlay.get(i);
        }
        return null;
    }

    private static boolean contains(List<byte[]> digests, byte[] digest) {
        for (byte[] d : digests) {
            if (Arrays.equals(d, digest)) return true;
        }
        return false;
    }

    private static byte[] versionBytes(int version) {
        return new byte[]{(byte) (version >>> 24), (byte) (version >>> 16), (byte) (version >>> 8), (byte) version};
    }

    // A (version, epoch) claim key packed into one long: the epoch is a beacon epoch
    // (far below 2^32 for any real schedule), so 32 bits each is exact for every value
    // activationTime() accepts.
    private static long claimKey(int version, long epoch) {
        return ((long) version << 32) | (epoch & 0xFFFF_FFFFL);
    }

    private static int claimVersion(long key) {
        return (int) (key >>> 32);
    }

    private static long claimEpoch(long key) {
        return key & 0xFFFF_FFFFL;
    }

    private static boolean sameFork(ForkWatch.Advisory a, ForkWatch.Advisory b) {
        if (a == null || b == null) return a == b;
        return a.phase() == b.phase() && a.activationTime() == b.activationTime() && a.forkHash() == b.forkHash();
    }
}
