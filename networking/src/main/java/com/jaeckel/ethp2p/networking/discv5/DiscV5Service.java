package com.jaeckel.ethp2p.networking.discv5;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.core.enr.Enr;
import org.ethereum.beacon.discovery.DiscoverySystem;
import org.ethereum.beacon.discovery.DiscoverySystemBuilder;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordBuilder;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * discv5 peer discovery service.
 *
 * <p>Thin wrapper around ConsenSys' discv5 library (consumed as the
 * {@code com.github.biafra23:discovery} Android fork of
 * {@code io.consensys.protocols:discovery} — see gradle/libs.versions.toml) that exposes
 * the same callback shape as {@link com.jaeckel.ethp2p.networking.discv4.DiscV4Service}:
 * the caller hands in a {@link Consumer<Enr>} and receives every newly-observed
 * ENR exactly once. The library itself is pull-based ({@link DiscoverySystem#streamLiveNodes()});
 * we poll on a single-threaded daemon scheduler and diff against a seen-set to
 * surface new entries.
 *
 * <p>Unlike discv4 we do not expose the routing table — the library keeps its
 * own K-buckets and {@code searchForNewPeers()} / the internal recursive lookup
 * drive freshness.
 */
public final class DiscV5Service implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(DiscV5Service.class);

    private final NodeKey nodeKey;
    private final List<String> bootnodeEnrs;
    private final Consumer<Enr> onPeerDiscovered;
    /** discv5 node ids of the chain's PINNED peers (derived from their libp2p
     *  peer ids — {@code Enr.nodeIdForPeerId}). Lookups walk TOWARD these ids
     *  instead of hoping a random walk lands in their bucket, which on the
     *  mainnet DHT it rarely does. Same design as the Rust engine's
     *  {@code pinned_targets} (parity contract, #347): a stale pinned address
     *  heals through third-party tables in bounded time. */
    private final List<org.apache.tuweni.bytes.Bytes> pinnedNodeIds;

    private DiscoverySystem system;
    private ScheduledExecutorService scheduler;
    private final Set<String> seenEnrs = new HashSet<>();

    /** LC hunt boost: while true each poll tick fires extra random-target
     *  search rounds (set by the host when the beacon light client is starved
     *  of LC servers — see BeaconLightClient.setHuntBoostListener). */
    private volatile boolean huntBoost;

    /** Flip the hunt boost (idempotent; safe from any thread). */
    public void setHuntBoost(boolean on) {
        this.huntBoost = on;
    }

    // Empty-table re-seed: the library pings bootnodes exactly ONCE, inside
    // start(). If that initial round loses (device network not up yet, transient
    // UDP loss — both observed on-device), or the table later decays to empty
    // (mobile NAT liveness churn), searchForNewPeers() has no one to query and
    // discovery is dead until process restart: live=0 seen-total=0 forever
    // (Pixel 7, gnosis, 2026-07-06 — 2h wedge, instant recovery on restart).
    // So: after RESEED_EMPTY_POLLS consecutive empty polls (~1 min at the 15s
    // cadence), re-ping the bootnodes to refill the K-buckets, and keep doing
    // that every RESEED_EMPTY_POLLS-th empty poll until the table has nodes.
    // (DiscV4Service solves the same wedge by re-pinging on EVERY empty
    // refresh; here the throttle keeps a persistent wedge from pinging the
    // handful of public CL bootnodes 4x as often for the life of the process.)
    private static final int RESEED_EMPTY_POLLS = 4;
    private int consecutiveEmptyPolls;
    // Bootnode ENRs parsed once, on first use (malformed entries are logged
    // once and dropped, not re-swallowed every fire). Guarded by
    // bootnodeRecords()'s synchronization — poll thread and walker both call it.
    private List<NodeRecord> bootnodeRecords;

    public DiscV5Service(NodeKey nodeKey, List<String> bootnodeEnrs,
                         Consumer<Enr> onPeerDiscovered) {
        this(nodeKey, bootnodeEnrs, List.of(), onPeerDiscovered);
    }

    public DiscV5Service(NodeKey nodeKey, List<String> bootnodeEnrs,
                         List<org.apache.tuweni.bytes.Bytes> pinnedNodeIds,
                         Consumer<Enr> onPeerDiscovered) {
        this.nodeKey = nodeKey;
        this.bootnodeEnrs = bootnodeEnrs;
        this.pinnedNodeIds = List.copyOf(pinnedNodeIds);
        this.onPeerDiscovered = onPeerDiscovered;
    }

    /**
     * Bind UDP {@code udpPort} and start advertising / discovering.
     *
     * <p>Non-blocking: the library's bootstrap (UDP bind + Netty boot + initial
     * bootnode pings) runs asynchronously. If the caller blocks this method
     * daemon boot stalls the whole downstream chain (IPC server, etc.) waiting
     * for a network-dependent handshake, and a {@code status} query in that
     * window sees the daemon's file lock but no socket yet. We kick the library
     * off, schedule our poll task to fire only after it's ready, and let the
     * daemon continue booting immediately.
     *
     * <p>CL convention is to run discv5 on the libp2p port (9000), so the
     * caller typically passes that rather than the EL 30303.
     */
    public void start(int requestedUdpPort) {
        // discv5's UDP bind port. CL convention is 9000, but on some hosts that
        // port is already taken — notably ot-daemon (OpenThread) on Play-image
        // Android emulators, which holds 0.0.0.0:9000 and is unkillable without
        // root. A failed bind kills peer discovery and therefore beacon sync. A
        // light client never accepts inbound discv5, so if the requested port
        // isn't bindable we fall back to an OS-chosen free port; outbound
        // discovery (querying bootnodes) works identically.
        int udpPort = pickBindablePort(requestedUdpPort);
        if (udpPort != requestedUdpPort) {
            log.info("[discv5] UDP {} unavailable; binding free UDP {} instead (light client needs no inbound)",
                    requestedUdpPort, udpPort);
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "discv5-poll");
            t.setDaemon(true);
            return t;
        });

        startSystem(udpPort, /* retryOnBindConflict= */ true);
    }

    /**
     * Build the discovery system on {@code udpPort} and kick its async bootstrap.
     *
     * <p>{@link #pickBindablePort} leaves a TOCTOU window: the chosen port can be
     * taken between the probe closing and the library's real bind. If that bind
     * loses the race (and {@code retryOnBindConflict}), rebuild once on a fresh
     * OS-chosen free port so the fallback is robust under contention. The retry
     * never retries itself, so a persistently unbindable host fails cleanly.
     */
    private void startSystem(int udpPort, boolean retryOnBindConflict) {
        DefaultSigner signer = new DefaultSigner(nodeKey.secretKey());

        NodeRecord localRecord = new NodeRecordBuilder()
                .seq(1)
                .signer(signer)
                .address("0.0.0.0", udpPort)
                .build();

        system = new DiscoverySystemBuilder()
                .localNodeRecord(localRecord)
                .listen("0.0.0.0", udpPort)
                .signer(signer)
                .bootnodes(bootnodeEnrs.toArray(new String[0]))
                .build();

        // Kick the library's bootstrap off; arm the poll task from the
        // completion callback so it doesn't fire before the UDP bind is done.
        system.start().whenComplete((v, ex) -> {
            if (ex != null) {
                if (retryOnBindConflict && isBindConflict(ex)) {
                    int retryPort = freeEphemeralPort(udpPort);
                    log.warn("[discv5] bind on UDP {} lost a race ({}); retrying on free UDP {}",
                            udpPort, ex.toString(), retryPort);
                    try { system.stop(); } catch (Exception ignored) {}
                    startSystem(retryPort, /* retryOnBindConflict= */ false);
                    return;
                }
                log.warn("[discv5] start failed on UDP {}: {}", udpPort, ex.toString());
                scheduler.shutdownNow();
                return;
            }
            log.info("[discv5] Listening on UDP port {} with {} bootnode(s)",
                    udpPort, bootnodeEnrs.size());
            // First poll at 5s to pick up fast bootnode responses; then every
            // 15s (same cadence as discv4-refresh) to surface new peers.
            scheduler.scheduleAtFixedRate(this::pollAndNotify, 5, 15, TimeUnit.SECONDS);
            // Targeted lookups toward the pinned servers (#347) run on their
            // own thread — a full walk blocks for up to ~30 s worst-case, which
            // must not stall the poll cadence.
            startWalker();
        });
    }

    /**
     * Return {@code preferred} if a UDP socket can bind it, otherwise an
     * OS-chosen free UDP port. The bind probe mirrors what discv5's Netty
     * bootstrap does, so it detects the same conflicts (e.g. ot-daemon on 9000).
     *
     * <p>{@code preferred <= 0} already means "let the OS pick" (and a probe would
     * only add a TOCTOU gap), and out-of-range values would make the probe throw
     * {@link IllegalArgumentException}; in both cases we hand the value straight
     * back so the caller/library surfaces it rather than crashing here.
     */
    private static int pickBindablePort(int preferred) {
        if (preferred <= 0 || preferred > 65535) {
            return preferred;
        }
        try (java.net.DatagramSocket probe = new java.net.DatagramSocket(preferred)) {
            return probe.getLocalPort();
        } catch (Exception taken) { // SocketException + SecurityException etc.
            return freeEphemeralPort(preferred);
        }
    }

    /** An OS-chosen free UDP port, or {@code fallback} if one couldn't be probed. */
    private static int freeEphemeralPort(int fallback) {
        try (java.net.DatagramSocket free = new java.net.DatagramSocket(0)) {
            return free.getLocalPort();
        } catch (Exception e) {
            // Couldn't grab a free port either; let the real bind try + log.
            return fallback;
        }
    }

    /** True if {@code ex} (or any cause) is a UDP bind conflict ("address in use"). */
    private static boolean isBindConflict(Throwable ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof java.net.BindException) {
                return true;
            }
            String msg = t.getMessage();
            if (msg != null && msg.contains("Address already in use")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Expose the library's live-nodes view to callers that want the count
     * without subscribing (e.g. the Android status UI).
     */
    public int liveNodeCount() {
        return system == null ? 0 : (int) system.streamLiveNodes().count();
    }

    // -------------------------------------------------------------------------
    // Targeted lookups (#347) — walk TOWARD the pinned servers
    // -------------------------------------------------------------------------

    /** Total FINDNODE queries per walk's budgeted convergence loop. Termination
     *  is spec-Kademlia — stop when the frontier has no unqueried nodes — and
     *  this budget is the hard cap. Sized from live tuning: round-based
     *  variants with early "no progress" breaks stalled at logDistance
     *  ~244-252 of 256; a closest-first budgeted loop converges or proves
     *  absence well within it. (No near-window cutoff either: the records
     *  CLOSEST to a target are often stale/dead — 13 of 16 timed out on one
     *  run — and a closest-16 rule gave up with budget left while alive nodes
     *  slightly farther out held the record.) */
    private static final int WALK_QUERY_BUDGET = 32;
    /** Per-query answer budget; a silent node must not stall the walk. Live
     *  tuning: answers arrive in ~100 ms; wall time is dominated by timeouts
     *  on dead frontier entries, so a short budget beats a generous one. */
    private static final long WALK_QUERY_TIMEOUT_MS = 1_500;
    /** Sibling-phase cap. Mainnet pins ~19 peers; iterating every found
     *  sibling before the real walk would burn most of a walk's wall time on
     *  the front phase (the bootnode phase is capped for the same reason). */
    private static final int WALK_SIBLING_CAP = 4;
    /** Bootnode-phase cap (politeness toward the public seed set). */
    private static final int WALK_BOOTNODE_CAP = 6;
    /** Pause between opening-pass walks (each pinned id once, quickly). */
    private static final long WALK_OPENING_GAP_MS = 2_000;
    /** Pause between steady-state revisits (round-robin, one per gap). */
    private static final long WALK_REVISIT_GAP_MS = 60_000;

    /** Guards walker lifecycle: startWalker() runs on the discovery library's
     *  completion thread while close() runs on a host thread (ChainStack
     *  pause/resume cycles both routinely), and without a common lock two
     *  interleavings leak a walker that nothing will ever interrupt: close()
     *  landing between the poll scheduling and startWalker(), and close()'s
     *  read of the walker field simply not seeing the callback's write (no
     *  happens-before edge; Android/ARM is a first-class target). Both
     *  synchronize on this object, and closed is checked under the lock. */
    private final Object walkerLock = new Object();
    private boolean walkerClosed;
    private Thread walker;

    /** Closest records learned per target, carried across revisits so each
     *  walk resumes from the best-known frontier instead of the bootnodes.
     *  Walker-thread only. */
    private final java.util.Map<org.apache.tuweni.bytes.Bytes, List<NodeRecord>> learnedFrontier =
            new java.util.HashMap<>();
    /** Pinned records already FOUND, reused as first-query seeds for the other
     *  walks — the pinned servers know each other better than the wider DHT
     *  does (roost's discv5 bootstraps THROUGH the co-located beacon node).
     *  A sibling whose query fails is EVICTED and re-added on its next find,
     *  so a found-then-offline pin cannot become a permanent 1.5 s tax at the
     *  front of every walk. Walker-thread only. */
    private final java.util.Map<org.apache.tuweni.bytes.Bytes, NodeRecord> foundPinned =
            new java.util.HashMap<>();
    /** Last EMITTED seq per pinned id — the same strictly-newer gate the Rust
     *  engine applies to its pinned re-emissions (#348 review): ENR signatures
     *  do not expire, so a laggard or adversarial table can serve a pinned
     *  server's OLDER record, and the string-keyed seen-set alone would
     *  re-emit it (exact-string dedupe is direction-blind). Walker finds pass
     *  through this gate; the poll path is unchanged (it surfaces the local
     *  table, which keeps the highest seq it has seen). Walker-thread only. */
    private final java.util.Map<org.apache.tuweni.bytes.Bytes, Long> emittedPinnedSeq =
            new java.util.HashMap<>();

    /**
     * Milliseconds to sleep after the {@code completedWalks}-th walk. The first
     * {@code nTargets} walks are the OPENING PASS — each pinned id visited once,
     * near back-to-back, so a wallet finds its servers in the first minute even
     * on the mainnet DHT — then revisits go round-robin at a polite cadence
     * (the revisit is what heals a stale pinned address after the server
     * republishes). Package-private for tests.
     */
    static long walkDelayMs(int completedWalks, int nTargets) {
        return completedWalks < nTargets ? WALK_OPENING_GAP_MS : WALK_REVISIT_GAP_MS;
    }

    private void startWalker() {
        synchronized (walkerLock) {
            if (walkerClosed || pinnedNodeIds.isEmpty() || walker != null) {
                return;
            }
            walker = new Thread(this::walkForever, "discv5-target");
            walker.setDaemon(true);
            walker.start();
        }
    }

    private void walkForever() {
        // The opening pass is worthless against an empty table (observed:
        // walk 1 fired ~2 s after start, before any bootnode answered, and
        // burned the first slot on frontier=0). Wait briefly for the table.
        for (int w = 0; w < 20; w++) {
            DiscoverySystem sys = system;
            if (sys == null || sys.streamLiveNodes().findAny().isPresent()) {
                break;
            }
            try {
                Thread.sleep(1_000);
            } catch (InterruptedException gone) {
                return;
            }
        }
        int i = 0;
        while (!Thread.currentThread().isInterrupted()) {
            // Snapshot: close() nulls the system field on a host thread; a walk
            // against the snapshot either completes or fails fast, and the
            // interrupt (sent under walkerLock) ends the loop.
            DiscoverySystem sys = system;
            if (sys == null) {
                return;
            }
            org.apache.tuweni.bytes.Bytes target = pinnedNodeIds.get(i % pinnedNodeIds.size());
            try {
                targetedWalk(sys, target);
            } catch (Throwable e) {
                // Throwable, not Exception: a linkage error on the walker
                // thread would otherwise kill it with no trace, and the
                // walker never logging again reads as "working, no finds".
                log.warn("[discv5] targeted walk failed: {}", e.toString());
            }
            try {
                Thread.sleep(walkDelayMs(i, pinnedNodeIds.size()));
            } catch (InterruptedException gone) {
                return;
            }
            i++;
        }
    }

    /** Outcome of one {@link #queryToward} call. */
    private enum QueryOutcome { FOUND, MERGED, FAILED, INTERRUPTED }

    /**
     * Query one node for {@code target}'s bucket neighborhood and merge what it
     * returns into {@code frontier}. THE one copy of the query rules, kept
     * together because each is load-bearing:
     *
     * <ul>
     *   <li>Distances {@code d-4..d}: the bucket at d contains the target's
     *       neighborhood as the queried node sees it, the lower buckets sample
     *       strictly closer halves, and the responder caps the reply at 16
     *       records total — a wider ask mines each RESPONSIVE node harder,
     *       which matters when the target's nearest neighbors are dead.</li>
     *   <li>{@code InterruptedException} must re-interrupt and surface as
     *       {@link QueryOutcome#INTERRUPTED}: swallowing it (the generic catch
     *       would) clears the flag, and the walker then keeps walking a
     *       stopped system forever — one leaked thread per ChainStack restart.
     *       Caught once by the internal review; kept in one place since.</li>
     *   <li>A found record passes the strictly-newer seq gate before emission
     *       (see {@link #emittedPinnedSeq}).</li>
     * </ul>
     */
    private QueryOutcome queryToward(DiscoverySystem sys, NodeRecord node,
                                     org.apache.tuweni.bytes.Bytes target,
                                     java.util.Map<org.apache.tuweni.bytes.Bytes, NodeRecord> frontier,
                                     String foundWhere) {
        int d = org.ethereum.beacon.discovery.util.Functions.logDistance(node.getNodeId(), target);
        List<Integer> distances = java.util.stream.IntStream.rangeClosed(d - 4, d)
                .filter(x -> x >= 1 && x <= 256).boxed()
                .sorted(java.util.Collections.reverseOrder()).toList();
        java.util.Collection<NodeRecord> answers;
        try {
            answers = sys.findNodes(node, distances)
                    .get(WALK_QUERY_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException shutdown) {
            Thread.currentThread().interrupt();
            return QueryOutcome.INTERRUPTED;
        } catch (Exception unresponsive) {
            return QueryOutcome.FAILED;
        }
        if (log.isDebugEnabled()) {
            java.util.IntSummaryStatistics stats = answers.stream()
                    .mapToInt(nr -> org.ethereum.beacon.discovery.util.Functions.logDistance(
                            nr.getNodeId(), target))
                    .summaryStatistics();
            log.debug("[discv5] walk query: candidateDist={} asked={} answers={} answerDistToTarget=[{}..{}]",
                    d, distances, answers.size(),
                    stats.getCount() == 0 ? -1 : stats.getMin(),
                    stats.getCount() == 0 ? -1 : stats.getMax());
        }
        for (NodeRecord nr : answers) {
            if (nr.getNodeId().equals(target)) {
                foundTarget(nr, foundWhere);
                return QueryOutcome.FOUND;
            }
            frontier.putIfAbsent(nr.getNodeId(), nr);
        }
        return QueryOutcome.MERGED;
    }

    /** Record + (seq-gated) emit a found pinned record. Walker thread. */
    private void foundTarget(NodeRecord nr, String where) {
        long seq = nr.getSeq().toLong();
        Long last = emittedPinnedSeq.get(nr.getNodeId());
        if (last != null && seq <= last) {
            log.debug("[discv5] targeted walk: {} record seq={} not newer than emitted {} — not re-emitted",
                    where, seq, last);
            foundPinned.put(nr.getNodeId(), nr);
            return;
        }
        log.info("[discv5] targeted walk: FOUND pinned server {} (seq={}, {})",
                nr.getNodeId().slice(0, 4), seq, where);
        emittedPinnedSeq.put(nr.getNodeId(), seq);
        foundPinned.put(nr.getNodeId(), nr);
        emitFromWalker(nr);
    }

    /**
     * One bounded iterative Kademlia walk toward {@code target}: seed from
     * sibling pins and bootnodes, then repeatedly query the closest unqueried
     * frontier node, merging what each returns. Runs entirely on the walker
     * thread; queries are sequential with a short timeout each.
     *
     * <p>A found record is handed to the poll scheduler for emission, so the
     * seen-set and the caller's consumer stay single-threaded. Walker finds
     * are gated on a STRICTLY NEWER seq per pinned id ({@link #emittedPinnedSeq}
     * — the Rust engine's gate, #348 review); the poll path's string-keyed
     * dedupe is unchanged. The pool side is naturally name-wins: {@code addPeer}
     * only ever ADDS a new multiaddr entry; the configured {@code /dns4} pin is
     * never overwritten (parity contract, #347/#348 review).
     */
    private void targetedWalk(DiscoverySystem sys, org.apache.tuweni.bytes.Bytes target) {
        // NOT Functions.distance: that helper reads the XOR as LITTLE-endian
        // (toUnsignedBigInteger(LITTLE_ENDIAN)), so ordering by it sorts on the
        // XOR's LOW bytes — near-random with respect to actual closeness, which
        // scrambled the closest-first selection on the first live runs (the
        // walk queried 256-distance nodes while 249s sat in the frontier).
        // logDistance is the spec bucket index and interops with the wire.
        java.util.Comparator<NodeRecord> byDistance = java.util.Comparator
                .comparingInt((NodeRecord nr) -> org.ethereum.beacon.discovery.util.Functions
                        .logDistance(nr.getNodeId(), target))
                .thenComparing(nr -> new java.math.BigInteger(
                        1, nr.getNodeId().xor(target).toArray()));
        java.util.Map<org.apache.tuweni.bytes.Bytes, NodeRecord> frontier = new java.util.HashMap<>();
        sys.streamLiveNodes().forEach(nr -> frontier.put(nr.getNodeId(), nr));
        for (NodeRecord nr : learnedFrontier.getOrDefault(target, List.of())) {
            frontier.putIfAbsent(nr.getNodeId(), nr);
        }
        Set<org.apache.tuweni.bytes.Bytes> queried = new HashSet<>();
        int answered = 0;
        int failed = 0;

        // Phase -1 — the CLOSEST few sibling pins already found: session-
        // verified responders, and the likeliest tables to hold a sibling's
        // young record (observed live: every walk toward the young roost pin
        // stalled while the established pin had the record all along). Capped,
        // and closest-to-target first: on a ~19-pin network an uncapped pass
        // would burn most of the walk on this phase.
        List<NodeRecord> siblings = foundPinned.values().stream()
                .filter(nr -> !nr.getNodeId().equals(target))
                .sorted(byDistance)
                .limit(WALK_SIBLING_CAP)
                .toList();
        for (NodeRecord sibling : siblings) {
            if (!queried.add(sibling.getNodeId())) {
                continue;
            }
            QueryOutcome outcome = queryToward(sys, sibling, target, frontier, "at a sibling pin");
            if (outcome == QueryOutcome.FOUND || outcome == QueryOutcome.INTERRUPTED) {
                rememberFrontier(target, frontier.values(), byDistance);
                return;
            }
            if (outcome == QueryOutcome.FAILED) {
                failed++;
                // Evict: a dead sibling must not tax the front of every walk;
                // its next find re-adds it.
                foundPinned.remove(sibling.getNodeId());
            } else {
                answered++;
            }
        }

        // Phase 0 — a few BOOTNODES, at the target's bucket as each sees it.
        // Their tables are the largest and freshest in the network, and a
        // server that pinged them at startup is often in them directly: the
        // closest-first loop below would never ask them (they sit at random
        // distance from any target), which is how a walk can converge to
        // logDistance ~237 through a cluster of stale near-records and still
        // miss a record a bootnode is holding (observed live).
        for (NodeRecord bootnode : bootnodeRecords()) {
            if (queried.size() >= WALK_SIBLING_CAP + WALK_BOOTNODE_CAP) {
                break;
            }
            if (bootnode.getNodeId().equals(target) || !queried.add(bootnode.getNodeId())) {
                continue;
            }
            QueryOutcome outcome = queryToward(sys, bootnode, target, frontier, "at a bootnode");
            if (outcome == QueryOutcome.FOUND || outcome == QueryOutcome.INTERRUPTED) {
                rememberFrontier(target, frontier.values(), byDistance);
                return;
            }
            if (outcome == QueryOutcome.FAILED) {
                failed++;
            } else {
                answered++;
            }
        }

        // Budgeted closest-first convergence: always query the closest node not
        // yet asked, stop when the frontier is exhausted or the budget is spent.
        for (int q = 0; q < WALK_QUERY_BUDGET; q++) {
            NodeRecord candidate = frontier.values().stream()
                    .filter(nr -> !queried.contains(nr.getNodeId()))
                    .min(byDistance)
                    .orElse(null);
            if (candidate == null) {
                break; // frontier exhausted — the target is not reachable today
            }
            if (candidate.getNodeId().equals(target)) {
                // The frontier already HOLDS the target's record (e.g. it sits
                // in the local live table) — that IS the find.
                foundTarget(candidate, "in local frontier");
                rememberFrontier(target, frontier.values(), byDistance);
                return;
            }
            queried.add(candidate.getNodeId());
            QueryOutcome outcome = queryToward(sys, candidate, target, frontier, "via the walk");
            if (outcome == QueryOutcome.FOUND || outcome == QueryOutcome.INTERRUPTED) {
                rememberFrontier(target, frontier.values(), byDistance);
                return;
            }
            if (outcome == QueryOutcome.FAILED) {
                failed++;
            } else {
                answered++;
            }
        }
        rememberFrontier(target, frontier.values(), byDistance);
        // One line per completed walk, kept at INFO deliberately: with the
        // found-path logging living behind the emit dedupe, a silent walker is
        // indistinguishable from a dead one (observed on the first live run).
        int closest = frontier.keySet().stream()
                .mapToInt(id -> org.ethereum.beacon.discovery.util.Functions.logDistance(id, target))
                .min().orElse(-1);
        log.info("[discv5] targeted walk toward {}… : not found (answered={} failed={} frontier={} closestLogDist={})",
                target.slice(0, 4), answered, failed, frontier.size(), closest);
    }

    /** Keep the closest few learned records so the next revisit resumes there. */
    private void rememberFrontier(org.apache.tuweni.bytes.Bytes target,
                                  java.util.Collection<NodeRecord> frontier,
                                  java.util.Comparator<NodeRecord> byDistance) {
        learnedFrontier.put(target,
                frontier.stream().sorted(byDistance).limit(8).toList());
    }

    /** Marshal a walker-found record onto the poll thread: the seen-set and the
     *  downstream consumer are single-threaded by design. */
    private void emitFromWalker(NodeRecord nr) {
        String enrStr = nr.asEnr();
        ScheduledExecutorService s = scheduler;
        if (s == null || s.isShutdown()) {
            return;
        }
        try {
            s.execute(() -> {
                if (!seenEnrs.add(enrStr)) {
                    return; // same record already surfaced (poll or earlier walk)
                }
                try {
                    Enr parsed = Enr.fromEnrString(enrStr);
                    onPeerDiscovered.accept(parsed);
                } catch (Exception e) {
                    log.warn("[discv5] failed to parse walked ENR: {}", e.getMessage());
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException shutdownRace) {
            // close() won the race between the isShutdown check and execute —
            // the record is simply dropped, like every other in-flight find.
        }
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    private void pollAndNotify() {
        try {
            int[] newThisTick = {0};
            int[] withEth2 = {0};
            int[] live = {0};
            system.streamLiveNodes().forEach(nr -> {
                live[0]++;
                String enrStr = nr.asEnr();
                if (seenEnrs.add(enrStr)) {
                    newThisTick[0]++;
                    try {
                        Enr parsed = Enr.fromEnrString(enrStr);
                        if (parsed.eth2().isPresent()) withEth2[0]++;
                        onPeerDiscovered.accept(parsed);
                    } catch (Exception e) {
                        log.warn("[discv5] failed to parse library ENR: {}", e.getMessage());
                    }
                }
            });
            // Kick a background search so the table keeps expanding between
            // polls rather than stalling at whatever the bootnodes returned.
            system.searchForNewPeers();
            // LC hunt boost: extra random-target rounds per tick while the
            // light client is starved of servers — each walks a different DHT
            // region, so rounds-per-tick is the enumeration throttle (the Rust
            // twin shortens its lookup sleep to the same effect).
            if (huntBoost) {
                system.searchForNewPeers();
                system.searchForNewPeers();
            }
            reseedIfWedged(live[0]);
            // One INFO line per 15s poll so the daemon log makes it obvious
            // whether the library is making progress. The library itself logs
            // through log4j which our logback pipeline doesn't route — this is
            // the only visibility we have at the slf4j layer.
            log.info("[discv5] poll: live={} seen-total={} new-this-tick={} with-eth2-this-tick={}",
                    live[0], seenEnrs.size(),
                    newThisTick[0], withEth2[0]);
        } catch (Exception e) {
            log.warn("[discv5] poll failed: {}", e.getMessage());
        }
    }

    /**
     * Re-ping the bootnodes when the live table has been empty for
     * {@link #RESEED_EMPTY_POLLS} consecutive polls (see the field comment for
     * why the table can wedge empty). Pings are fire-and-forget: any one
     * response repopulates a bucket and the next {@code searchForNewPeers()}
     * takes it from there. Runs on the poll thread; ping() itself is async.
     */
    private void reseedIfWedged(int liveNodes) {
        if (!reseedDue(liveNodes)) {
            return;
        }
        List<NodeRecord> bootnodes = bootnodeRecords();
        if (bootnodes.isEmpty()) {
            // Every configured ENR was malformed (each warned once at parse
            // time): nothing to ping, so don't log a "re-pinged 0" line that
            // reads as recovery where none is possible (the configured-empty
            // case is already never-due in reseedDue).
            return;
        }
        for (NodeRecord bootnode : bootnodes) {
            // Fire-and-forget: any one response repopulates a bucket and the
            // next searchForNewPeers() takes it from there.
            system.ping(bootnode).exceptionally(ex -> null);
        }
        log.info("[discv5] live table empty for {} polls — re-pinged {} bootnode(s)",
                RESEED_EMPTY_POLLS, bootnodes.size());
    }

    /** The bootnode ENRs parsed to records, once; malformed entries warn once
     *  and drop. Synchronized: the re-seed path calls this on the poll thread
     *  and the walker's bootnode phase calls it on the walker thread — an
     *  unsynchronized lazy init would race the two into an unsafe publication. */
    private synchronized List<NodeRecord> bootnodeRecords() {
        if (bootnodeRecords == null) {
            bootnodeRecords = new java.util.ArrayList<>(bootnodeEnrs.size());
            for (String enr : bootnodeEnrs) {
                try {
                    bootnodeRecords.add(NodeRecordFactory.DEFAULT.fromEnr(enr));
                } catch (Exception malformed) {
                    log.warn("[discv5] skipping unparseable bootnode ENR for re-seed: {}",
                            malformed.getMessage());
                }
            }
        }
        return bootnodeRecords;
    }

    /**
     * The stateful counter step behind {@link #reseedIfWedged} — poll-thread
     * only (it mutates {@link #consecutiveEmptyPolls}); package-private for
     * tests. Any live node resets the streak; with no bootnodes configured a
     * re-seed is never due (nothing to ping — sepolia pins an empty discv5
     * list, and repeating "re-pinged 0 bootnode(s)" would read as recovery
     * where none is possible). Otherwise a re-seed is due on every
     * {@link #RESEED_EMPTY_POLLS}-th consecutive empty poll (the counter
     * resets when due, so the re-seed repeats while the table stays empty).
     */
    boolean reseedDue(int liveNodes) {
        if (liveNodes > 0 || bootnodeEnrs.isEmpty()) {
            consecutiveEmptyPolls = 0;
            return false;
        }
        if (++consecutiveEmptyPolls < RESEED_EMPTY_POLLS) {
            return false;
        }
        consecutiveEmptyPolls = 0;
        return true;
    }

    @Override
    public void close() {
        // Under walkerLock, and closed is set FIRST: a startWalker() racing on
        // the library's completion thread either sees closed and refuses, or
        // finishes first and its walker is interrupted here — no interleaving
        // leaves a walker that nothing will ever stop (see walkerLock's doc).
        synchronized (walkerLock) {
            walkerClosed = true;
            if (walker != null) {
                walker.interrupt();
                walker = null;
            }
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        if (system != null) {
            try { system.stop(); } catch (Exception ignored) {}
            system = null;
        }
    }
}
