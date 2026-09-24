package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.networking.NetworkConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * EIP-2124 stale-software detection for a binary that PINS its fork id: notices, from
 * the fork ids peers present in their eth {@code Status}, that the network has scheduled
 * — or already activated — an execution-layer fork this build does not implement. Hosts
 * surface it as "update required" instead of letting the wallet go mute at the fork
 * (verification fails closed, so the only symptom would otherwise be a node that looks
 * stuck syncing — indistinguishable from an outage).
 *
 * <p>Both signals come from peers already confirmed to be on our chain (network id +
 * genesis — {@link EthHandler} reports only those):
 * <ul>
 *   <li><b>Scheduled</b> — a peer presents OUR fork hash with {@code forkNext = T}, a
 *       timestamp this build does not know. Upgraded clients announce this from the day
 *       their release carries the fork, typically weeks ahead.</li>
 *   <li><b>Active</b> — a peer presents the hash that FOLLOWS ours once a fork at some
 *       {@code T} has passed ({@link ForkIds#successor}). That is proof, not a guess: the
 *       CRC32 chain ties the peer's hash to ours and to the activation point. {@code T}
 *       comes from announcements seen earlier, else from a search over the epoch-aligned
 *       activation times of the last {@value #SEARCH_WINDOW_DAYS} days — so a wallet
 *       that was offline for the whole announcement window still recognises the fork.
 *       (Upgraded peers send their Status before rejecting our stale one, so we see it.)</li>
 * </ul>
 * An advisory needs {@value #MIN_PEERS} distinct peers. It is ADVISORY ONLY: nothing in
 * verification reads it, so a lying peer can at worst cause a false warning, never a
 * wrong answer. A fork this build does know ({@code forkNext} in {@link NetworkConfig})
 * never raises one. Not covered: a peer two or more forks ahead (the search proves a
 * single step).
 *
 * <p>One instance per network stack, shared across pause/resume connector rebuilds
 * (like {@link ServeStats}). Thread-safe: observed from Netty event loops, read by
 * status surfaces. Mirrored by the Rust engine's {@code fork_watch} module (same
 * constants, same vectors).
 */
public final class ForkWatch {

    private static final Logger log = LoggerFactory.getLogger(ForkWatch.class);

    /** Distinct peers that must agree before an advisory is raised. */
    public static final int MIN_PEERS = 3;
    /** A peer's last presented fork id stops counting after this long. */
    static final long OBSERVATION_TTL_SECONDS = 24L * 3600;
    /**
     * An announced activation keeps its advisory this long past {@code T} without a
     * successor proof: bridges the rollover from "forkNext = T" to the successor hash,
     * and ages out a rescheduled date's stale announcements.
     */
    static final long ACTIVATION_GRACE_SECONDS = 6L * 3600;
    /** Announcements further out than this are treated as garbage. */
    static final long MAX_HORIZON_SECONDS = 400L * 24 * 3600;
    static final int SEARCH_WINDOW_DAYS = 400;
    /** How far back the successor search looks for an activation never seen announced. */
    static final long SEARCH_WINDOW_SECONDS = SEARCH_WINDOW_DAYS * 24L * 3600;
    /** A hash the search could not place is searched again after this (clock corrections). */
    static final long NEGATIVE_RECHECK_SECONDS = 3600;
    /** Bound on tracked peers (LRU by last observation) and on cached placements. */
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
     * @param phase          SCHEDULED (activation ahead) or ACTIVE (passed: proven by
     *                       successor hashes, or announced and past its time)
     * @param activationTime unix seconds of the fork's activation
     * @param forkHash       the fork hash upgraded peers use once it is active
     * @param peers          distinct peers corroborating it
     */
    public record Advisory(Phase phase, long activationTime, int forkHash, int peers) {
        public String forkHashHex() { return ForkIds.toHex(forkHash); }
    }

    private record Observation(int hash, long next, long seenAt) {}

    /** Where the successor search placed a foreign hash; {@link #NONE} = nowhere. */
    private record Placement(long activation, long computedAt) {}

    private static final long NONE = Long.MIN_VALUE;

    private final String label;
    private final int localHash;
    private final long localNext;
    private final long genesisTime;
    private final long epochSeconds;
    private final LongSupplier clock;

    /** Latest observation per peer id, access-ordered so the LRU bound drops the stalest. */
    private final LinkedHashMap<String, Observation> byPeer = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Observation> eldest) {
            return size() > MAX_TRACKED;
        }
    };
    private final Map<Integer, Placement> placements = new HashMap<>();
    /** Last advisory we logged (identity: phase + activation + hash), to log transitions only. */
    private Advisory lastLogged;

    /**
     * @param label         network name, for log lines
     * @param localForkHash our own pinned EIP-2124 fork hash (4 bytes)
     * @param localForkNext our own announced next fork (0 = none known)
     * @param genesisTime   beacon genesis time — anchors the epoch-aligned activation grid
     * @param epochSeconds  seconds per beacon epoch (0 disables the grid search)
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
     * Record the fork id a peer presented in its eth Status. Cheap; logs when this
     * changes the advisory (so the operator log carries it even if nobody polls status).
     * Malformed input is ignored.
     */
    public void observe(String peerId, byte[] forkHash, long forkNext) {
        if (peerId == null || forkHash == null || forkHash.length != 4) return;
        Advisory previous;
        Advisory current;
        synchronized (this) {
            long now = clock.getAsLong();
            byPeer.put(peerId, new Observation(ForkIds.toInt(forkHash), forkNext, now));
            current = evaluate(now);
            previous = lastLogged;
            if (sameFork(previous, current)) return;
            lastLogged = current;
        }
        if (current == null) {
            log.info("[{}][fork-watch] upgrade advisory cleared", label);
        } else if (current.phase() == Phase.SCHEDULED) {
            log.warn("[{}][fork-watch] {} peers announce a network upgrade at {} (fork id {}) that this "
                    + "build does not support — update before then", label, current.peers(),
                    Instant.ofEpochSecond(current.activationTime()), current.forkHashHex());
        } else {
            log.warn("[{}][fork-watch] the network upgraded at {} (fork id {}, {} peers) — this build "
                    + "can no longer follow it; update required", label,
                    Instant.ofEpochSecond(current.activationTime()), current.forkHashHex(), current.peers());
        }
    }

    /** The current advisory on the wall clock, or null. */
    public Advisory advisory() {
        return evaluate(clock.getAsLong());
    }

    /** The advisory as of {@code now} (unix seconds), or null. */
    public synchronized Advisory evaluate(long now) {
        byPeer.values().removeIf(o -> o.seenAt() < now - OBSERVATION_TTL_SECONDS);

        // Announced activation times double as the fast path of the successor search.
        Set<Long> announced = new HashSet<>();
        for (Observation o : byPeer.values()) {
            if (o.hash() == localHash && isForeignActivation(o.next(), now)) announced.add(o.next());
        }
        Map<Long, Integer> proven = new HashMap<>();
        Map<Long, Integer> scheduled = new HashMap<>();
        for (Observation o : byPeer.values()) {   // one entry per peer ⇒ counts are distinct peers
            if (o.hash() == localHash) {
                if (isForeignActivation(o.next(), now) && o.next() > now - ACTIVATION_GRACE_SECONDS) {
                    scheduled.merge(o.next(), 1, Integer::sum);
                }
            } else {
                long t = place(o.hash(), announced, now);
                if (t != NONE) proven.merge(t, 1, Integer::sum);
            }
        }

        Map.Entry<Long, Integer> best = strongest(proven);
        if (best != null) {
            return new Advisory(Phase.ACTIVE, best.getKey(),
                    ForkIds.successor(localHash, best.getKey()), best.getValue());
        }
        best = strongest(scheduled);
        if (best != null) {
            long t = best.getKey();
            return new Advisory(t > now ? Phase.SCHEDULED : Phase.ACTIVE, t,
                    ForkIds.successor(localHash, t), best.getValue());
        }
        return null;
    }

    /** A timestamp activation this build doesn't know, within a plausible horizon. */
    private boolean isForeignActivation(long t, long now) {
        return t != 0 && t != localNext && t >= ForkIds.TIMESTAMP_THRESHOLD && t <= now + MAX_HORIZON_SECONDS;
    }

    /** Most-corroborated activation with at least {@link #MIN_PEERS}; ties → earliest. */
    private static Map.Entry<Long, Integer> strongest(Map<Long, Integer> counts) {
        Map.Entry<Long, Integer> best = null;
        for (Map.Entry<Long, Integer> e : counts.entrySet()) {
            if (e.getValue() < MIN_PEERS) continue;
            if (best == null || e.getValue() > best.getValue()
                    || (e.getValue().equals(best.getValue()) && e.getKey() < best.getKey())) {
                best = e;
            }
        }
        return best;
    }

    /** The activation that turns our hash into {@code hash}, cached; {@link #NONE} if none. */
    private long place(int hash, Set<Long> announced, long now) {
        Placement p = placements.get(hash);
        if (p != null && (p.activation() != NONE || now - p.computedAt() < NEGATIVE_RECHECK_SECONDS)) {
            return p.activation();
        }
        long t = search(hash, announced, now);
        if (placements.size() >= MAX_TRACKED) placements.clear();
        placements.put(hash, new Placement(t, now));
        return t;
    }

    private long search(int hash, Set<Long> announced, long now) {
        // A peer past a fork we DO know (our announced forkNext) is not news.
        if (localNext != 0 && ForkIds.successor(localHash, localNext) == hash) return NONE;
        for (long t : announced) {
            if (ForkIds.successor(localHash, t) == hash) return t;
        }
        if (epochSeconds <= 0) return NONE;
        // Forks activate on epoch boundaries (EL timestamps track the CL fork epoch), so
        // the grid genesis + k·epoch covers every real activation: ~9·10⁴ candidates for
        // 400 days of 384 s epochs, ~1 ms, once per foreign hash.
        long lo = Math.max(genesisTime, now - SEARCH_WINDOW_SECONDS);
        long kLo = (lo - genesisTime + epochSeconds - 1) / epochSeconds;
        long kHi = (now + epochSeconds - genesisTime) / epochSeconds;
        for (long k = kHi; k >= kLo; k--) {   // newest first: the likeliest match
            long t = genesisTime + k * epochSeconds;
            if (t != localNext && ForkIds.successor(localHash, t) == hash) return t;
        }
        return NONE;
    }

    private static boolean sameFork(Advisory a, Advisory b) {
        if (a == null || b == null) return a == b;
        return a.phase() == b.phase() && a.activationTime() == b.activationTime() && a.forkHash() == b.forkHash();
    }
}
