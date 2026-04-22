package com.jaeckel.ethp2p.networking.discv5;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.core.enr.Enr;
import org.ethereum.beacon.discovery.DiscoverySystem;
import org.ethereum.beacon.discovery.DiscoverySystemBuilder;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordBuilder;
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

    public DiscV5Service(NodeKey nodeKey, List<String> bootnodeEnrs,
                         Consumer<Enr> onPeerDiscovered) {
        this.nodeKey = nodeKey;
        this.bootnodeEnrs = bootnodeEnrs;
        this.onPeerDiscovered = onPeerDiscovered;
    }

    /**
     * Bind UDP {@code udpPort} and start advertising / discovering.
     * CL convention is to run discv5 on the libp2p port (9000), so the caller
     * typically passes that rather than the EL 30303.
     */
    public void start(int udpPort) throws Exception {
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

        // start() returns a CompletableFuture that completes when the UDP bind
        // + Netty boot is done. Block briefly; matches DiscV4Service.start().
        system.start().get(30, TimeUnit.SECONDS);
        log.info("[discv5] Listening on UDP port {} with {} bootnode(s)", udpPort, bootnodeEnrs.size());

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "discv5-poll");
            t.setDaemon(true);
            return t;
        });
        // First poll at 5s to pick up fast bootnode responses; then every 15s
        // (same cadence as discv4-refresh) to surface newly-discovered peers.
        scheduler.scheduleAtFixedRate(this::pollAndNotify, 5, 15, TimeUnit.SECONDS);
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
            system.streamLiveNodes().forEach(nr -> {
                String enrStr = nr.asEnr();
                if (seenEnrs.add(enrStr)) {
                    try {
                        onPeerDiscovered.accept(Enr.fromEnrString(enrStr));
                    } catch (Exception e) {
                        log.warn("[discv5] failed to parse library ENR: {}", e.getMessage());
                    }
                }
            });
            // Kick a background search so the table keeps expanding between
            // polls rather than stalling at whatever the bootnodes returned.
            system.searchForNewPeers();
        } catch (Exception e) {
            log.warn("[discv5] poll failed: {}", e.getMessage());
        }
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
