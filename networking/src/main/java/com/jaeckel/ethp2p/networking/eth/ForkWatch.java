package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.networking.NetworkConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

/**
 * EIP-2124 stale-software detection for a binary that PINS its fork id: notices, from
 * the fork ids peers present in their eth {@code Status}, that the network has scheduled
 * — or already activated — an execution-layer fork this build does not implement. Hosts
 * surface it as "update required" instead of letting the wallet go mute at the fork
 * (verification fails closed, so the only symptom would otherwise be a node that looks
 * stuck syncing — indistinguishable from an outage).
 *
 * <p>Evidence comes from peers already confirmed to be on our chain (network id +
 * genesis — {@link EthHandler} reports only those):
 * <ul>
 *   <li><b>Announced</b> — a peer presents OUR fork hash with {@code forkNext = T}, a
 *       timestamp this build does not know. Upgraded clients announce this from the day
 *       their release carries the fork, typically weeks ahead.</li>
 *   <li><b>Placed</b> — a peer presents the hash that FOLLOWS ours once a fork at some
 *       {@code T} has passed: {@link ForkIds#activationOf} recovers {@code T}, and a real
 *       one was announced or sits on the beacon epoch grid within the last
 *       {@value #LOOKBACK_DAYS} days — so a wallet that was offline for the whole
 *       announcement window still recognises the fork. (Upgraded peers send their Status
 *       before rejecting our stale one, so we see it.) Placing tells a successor apart
 *       from another chain's hash; it is NOT proof — any hash can be placed somewhere.</li>
 * </ul>
 *
 * <p>Peers can lie, so the vote is built to be expensive to fake:
 * <ul>
 *   <li>One vote per SOURCE network ({@link #sourceOf}: IPv4 /24, IPv6 /48), not per
 *       node id — node ids are free, and one host can present hundreds of them.</li>
 *   <li>An advisory needs {@value #MIN_PEERS} sources behind one activation, AND more of
 *       them than there are sources on our hash that announce no unknown fork.</li>
 *   <li>It is ADVISORY ONLY: nothing in verification reads it, so a false one is a wrong
 *       banner, never a wrong answer. (Hosts escalate ACTIVE to "can no longer verify"
 *       only when the node's own verified state agrees.)</li>
 * </ul>
 * A source's evidence stays fresh while one of its peers is still connected
 * ({@link #touch}) and for {@value #OBSERVATION_TTL_HOURS} h after. A fork this build
 * does know ({@code forkNext} in {@link NetworkConfig}) never raises one. Not covered: a
 * peer two or more forks ahead (placement is one step from our pin).
 *
 * <p>One instance per network stack, shared across pause/resume connector rebuilds
 * (like {@link ServeStats}). Thread-safe: observed from Netty event loops, read by
 * status surfaces. Mirrored by the Rust engine's {@code fork_watch} module (same
 * constants, same rules, same vectors).
 */
public final class ForkWatch {

    private static final Logger log = LoggerFactory.getLogger(ForkWatch.class);

    /** Distinct source networks that must agree before an advisory is raised. */
    public static final int MIN_PEERS = 3;
    static final int OBSERVATION_TTL_HOURS = 24;
    /** A source's last presented fork id stops counting this long after the source was
     *  last seen connected (observed, or {@link #touch touched}). */
    static final long OBSERVATION_TTL_SECONDS = OBSERVATION_TTL_HOURS * 3600L;
    /**
     * A passed announcement of {@code T} keeps counting this long past {@code T}: bridges
     * the rollover from "forkNext = T" to the successor hash, and ages out a rescheduled
     * date's stale announcements. Exempt: an announcement made before {@code T} by a
     * source still seen connected after it — that peer passed {@code T} with the fork
     * configured, so it keeps counting for as long as it stays fresh.
     */
    static final long ACTIVATION_GRACE_SECONDS = 6L * 3600;
    /** Announcements further out than this are treated as garbage. */
    static final long MAX_HORIZON_SECONDS = 400L * 24 * 3600;
    static final int LOOKBACK_DAYS = 400;
    /** How far back a placed activation that was never announced may lie. */
    static final long LOOKBACK_SECONDS = LOOKBACK_DAYS * 24L * 3600;
    /** Bound on tracked sources; the least recently seen is evicted. */
    static final int MAX_TRACKED = 512;

    /**
     * Networks the watch runs on. Staged rollout: Sepolia first — its Glamsterdam
     * activation (2026-10-06, epoch 353024) is the first fork this detector meets;
     * mainnet and Gnosis follow once it has been validated there. Keep in sync with the
     * Rust engine's {@code fork_watch::ENABLED_NETWORKS}.
     */
    private static final Set<String> ENABLED_NETWORKS = Set.of("sepolia");

    public enum Phase { SCHEDULED, ACTIVE }

    /**
     * @param phase          SCHEDULED (activation ahead) or ACTIVE (passed on the wall
     *                       clock, or placed from {@link #MIN_PEERS} successor hashes)
     * @param activationTime unix seconds of the fork's activation
     * @param forkHash       the fork hash upgraded peers use once it is active
     * @param peers          distinct source networks backing it
     */
    public record Advisory(Phase phase, long activationTime, int forkHash, int peers) {
        public String forkHashHex() { return ForkIds.toHex(forkHash); }
    }

    /** @param observedAt when the Status was presented; @param seenAt last seen connected */
    private record Observation(int hash, long next, long observedAt, long seenAt) {}

    /** Votes for one activation, in distinct sources. */
    private static final class Support {
        int placed;
        int announced;
        int total() { return placed + announced; }
    }

    private final String label;
    private final int localHash;
    private final long localNext;
    private final long genesisTime;
    private final long epochSeconds;
    private final LongSupplier clock;

    /** Latest observation per source, access-ordered so the LRU bound drops the stalest. */
    private final LinkedHashMap<String, Observation> bySource = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Observation> eldest) {
            return size() > MAX_TRACKED;
        }
    };
    /** Last advisory we logged (identity: phase + activation + hash), to log transitions only. */
    private Advisory lastLogged;

    /**
     * @param label         network name, for log lines
     * @param localForkHash our own pinned EIP-2124 fork hash (4 bytes)
     * @param localForkNext our own announced next fork (0 = none known)
     * @param genesisTime   beacon genesis time — anchors the epoch-aligned activation grid
     * @param epochSeconds  seconds per beacon epoch (0 = only announced activations place)
     * @param clock         wall clock, unix SECONDS (fork activations are wall-clock times)
     */
    public ForkWatch(String label, byte[] localForkHash, long localForkNext,
                     long genesisTime, long epochSeconds, LongSupplier clock) {
        this.label = label;
        this.localHash = ForkIds.toInt(localForkHash);
        this.localNext = localForkNext;
        this.genesisTime = genesisTime;
        this.epochSeconds = epochSeconds;
        this.clock = clock;
    }

    /** Whether the watch runs on this network (see {@link #ENABLED_NETWORKS}). */
    public static boolean enabledFor(NetworkConfig net) {
        return ENABLED_NETWORKS.contains(net.name());
    }

    /** A watch over {@code net}'s pinned fork id, on the system wall clock. */
    public static ForkWatch forNetwork(NetworkConfig net) {
        return new ForkWatch(net.name(), net.forkIdHash(), net.forkNext(), net.clGenesisTime(),
                (long) net.slotsPerEpoch() * net.secondsPerSlot(),
                () -> System.currentTimeMillis() / 1000);
    }

    /**
     * The vote key for a peer at {@code addr}: its IPv4 /24 or IPv6 /48 (an IPv4-mapped
     * IPv6 address counts as IPv4). Same strings as Rust {@code fork_watch::source_of}.
     */
    public static String sourceOf(InetAddress addr) {
        byte[] b = addr.getAddress();
        if (b.length == 16 && isV4Mapped(b)) b = Arrays.copyOfRange(b, 12, 16);
        if (b.length == 4) {
            return String.format(Locale.ROOT, "%d.%d.%d.0/24", b[0] & 0xff, b[1] & 0xff, b[2] & 0xff);
        }
        return String.format(Locale.ROOT, "%x:%x:%x::/48",
                (b[0] & 0xff) << 8 | (b[1] & 0xff), (b[2] & 0xff) << 8 | (b[3] & 0xff),
                (b[4] & 0xff) << 8 | (b[5] & 0xff));
    }

    private static boolean isV4Mapped(byte[] b) {
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) return false;
        }
        return b[10] == (byte) 0xff && b[11] == (byte) 0xff;
    }

    /**
     * Record the fork id a peer from {@code source} ({@link #sourceOf}) presented in its eth
     * Status. Cheap; logs when this changes the advisory (so the operator log carries it
     * even if nobody polls status). Malformed input is ignored.
     */
    public void observe(String source, byte[] forkHash, long forkNext) {
        if (source == null || forkHash == null || forkHash.length != 4) return;
        int hash = ForkIds.toInt(forkHash);
        update(now -> bySource.put(source, new Observation(hash, forkNext, now, now)));
    }

    /**
     * Mark {@code sources} as still connected now. Their evidence stays fresh for as long
     * as a peer of theirs is — a stable pool makes no new handshakes, and its peers' word
     * is exactly what matters across the fork. Sources never observed are ignored.
     */
    public void touch(Collection<String> sources) {
        update(now -> {
            for (String s : sources) {
                bySource.computeIfPresent(s, (k, o) ->
                        new Observation(o.hash(), o.next(), o.observedAt(), Math.max(o.seenAt(), now)));
            }
        });
    }

    /** Tracked sources — for tests of the {@link #MAX_TRACKED} bound. */
    synchronized int tracked() {
        return bySource.size();
    }

    /** The current advisory on the wall clock, or null. */
    public Advisory advisory() {
        return evaluate(clock.getAsLong());
    }

    /** The advisory as of {@code now} (unix seconds), or null. */
    public synchronized Advisory evaluate(long now) {
        bySource.values().removeIf(o -> o.seenAt() < now - OBSERVATION_TTL_SECONDS);

        Set<Long> announced = new HashSet<>();
        for (Observation o : bySource.values()) {
            if (o.hash() == localHash && isForeignActivation(o.next(), now)) announced.add(o.next());
        }
        Map<Long, Support> support = new HashMap<>();
        int dissent = 0;
        for (Observation o : bySource.values()) {   // one entry per source ⇒ counts are distinct sources
            if (o.hash() == localHash) {
                long t = o.next();
                if (t == 0 || t == localNext) {
                    dissent++;                          // on our hash, no unknown fork ahead
                } else if (isForeignActivation(t, now) && stillCounts(o, t, now)) {
                    support.computeIfAbsent(t, k -> new Support()).announced++;
                }
            } else {
                long t = ForkIds.activationOf(localHash, o.hash());
                if (localNext != 0 && t == localNext) {
                    dissent++;                          // past a fork we DO know: not news
                } else if (plausiblePlacement(t, announced, now)) {
                    support.computeIfAbsent(t, k -> new Support()).placed++;
                }
            }
        }

        // Most-backed activation; ties → more placed, then earliest. It must clear both the
        // absolute floor and the dissent: a minority can't outvote the peers it contradicts.
        long bestT = 0;
        Support best = null;
        for (Map.Entry<Long, Support> e : support.entrySet()) {
            Support s = e.getValue();
            if (s.total() < MIN_PEERS || s.total() <= dissent) continue;
            if (best == null || s.total() > best.total()
                    || (s.total() == best.total() && (s.placed > best.placed
                        || (s.placed == best.placed && e.getKey() < bestT)))) {
                best = s;
                bestT = e.getKey();
            }
        }
        if (best == null) return null;
        Phase phase = bestT <= now || best.placed >= MIN_PEERS ? Phase.ACTIVE : Phase.SCHEDULED;
        return new Advisory(phase, bestT, ForkIds.successor(localHash, bestT), best.total());
    }

    /** Apply {@code mutation} at the wall clock, then log if the advisory changed. */
    private void update(LongConsumer mutation) {
        Advisory current;
        synchronized (this) {
            long now = clock.getAsLong();
            mutation.accept(now);
            current = evaluate(now);
            if (sameFork(lastLogged, current)) return;
            lastLogged = current;
        }
        if (current == null) {
            log.info("[{}][fork-watch] upgrade advisory cleared", label);
        } else if (current.phase() == Phase.SCHEDULED) {
            log.warn("[{}][fork-watch] peers on {} networks announce a network upgrade at {} (fork id {}) "
                    + "that this build does not support — update before then", label, current.peers(),
                    Instant.ofEpochSecond(current.activationTime()), current.forkHashHex());
        } else {
            log.warn("[{}][fork-watch] peers on {} networks report the network upgraded at {} (fork id {}) — "
                    + "this build cannot follow it; update required", label, current.peers(),
                    Instant.ofEpochSecond(current.activationTime()), current.forkHashHex());
        }
    }

    /** A timestamp activation this build doesn't know, within a plausible horizon. */
    private boolean isForeignActivation(long t, long now) {
        return t != 0 && t != localNext && t >= ForkIds.TIMESTAMP_THRESHOLD && t <= now + MAX_HORIZON_SECONDS;
    }

    /**
     * Whether an announcement of {@code t} still counts: ahead; or made before {@code t}
     * by a source seen connected since (it passed the fork configured for it); or within
     * the grace. A long-passed {@code t} announced AFTER the fact is a peer far behind or
     * garbage, not evidence.
     */
    private static boolean stillCounts(Observation o, long t, long now) {
        return t > now || (o.observedAt() < t && o.seenAt() >= t) || now - t < ACTIVATION_GRACE_SECONDS;
    }

    /**
     * Whether {@code t}, where {@link ForkIds#activationOf} put a foreign hash, is a real
     * activation: announced by a source on our hash, or epoch-aligned within the lookback
     * (EL fork timestamps track the CL fork epoch; one epoch of slack for a clock behind).
     */
    private boolean plausiblePlacement(long t, Set<Long> announced, long now) {
        if (t < ForkIds.TIMESTAMP_THRESHOLD || t == localNext) return false;
        if (announced.contains(t)) return true;
        return epochSeconds > 0 && t >= genesisTime && (t - genesisTime) % epochSeconds == 0
                && t >= now - LOOKBACK_SECONDS && t <= now + epochSeconds;
    }

    private static boolean sameFork(Advisory a, Advisory b) {
        if (a == null || b == null) return a == b;
        return a.phase() == b.phase() && a.activationTime() == b.activationTime() && a.forkHash() == b.forkHash();
    }
}
