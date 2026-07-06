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
 * <p>Thin wrapper around {@code io.consensys.protocols:discovery} that exposes
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

    private DiscoverySystem system;
    private ScheduledExecutorService scheduler;
    private final Set<String> seenEnrs = new HashSet<>();

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
    // Bootnode ENRs parsed once, on the first re-seed (malformed entries are
    // logged once and dropped, not re-swallowed every fire). Poll-thread only.
    private List<NodeRecord> bootnodeRecords;

    public DiscV5Service(NodeKey nodeKey, List<String> bootnodeEnrs,
                         Consumer<Enr> onPeerDiscovered) {
        this.nodeKey = nodeKey;
        this.bootnodeEnrs = bootnodeEnrs;
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

    /** The bootnode ENRs parsed to records, once; malformed entries warn once and drop. */
    private List<NodeRecord> bootnodeRecords() {
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
