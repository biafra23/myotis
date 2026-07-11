package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService;
import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.consensus.lightclient.LightClientProcessor;
import com.jaeckel.ethp2p.consensus.lightclient.LightClientStore;
import com.jaeckel.ethp2p.consensus.lightclient.LightClientStoreSnapshot;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockParser;
import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import com.jaeckel.ethp2p.consensus.types.StatusMessage;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Top-level orchestrator for the Ethereum consensus-layer light client.
 *
 * <p>Lifecycle:
 * <ol>
 *   <li>Call {@link #start()} to start the libp2p host and the background sync loop.</li>
 *   <li>The sync loop bootstraps from the first responsive peer, then polls for finality
 *       updates every 12 seconds (one slot duration).</li>
 *   <li>Each successfully applied update refreshes the {@link BeaconSyncState}, making the
 *       beacon-verified execution state root available to the rest of the application.</li>
 *   <li>Call {@link #close()} (or use try-with-resources) to stop the sync loop and the
 *       libp2p host cleanly.</li>
 * </ol>
 *
 * <p>Thread safety: {@code start()} and {@code close()} must be called from the same thread.
 * {@link BeaconSyncState} is itself thread-safe for concurrent reads.
 */
public class BeaconLightClient implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(BeaconLightClient.class);

    private final BeaconP2PService p2pService;
    private final LightClientStore store;
    /**
     * Serializes CATCH-UP APPLIERS (racing per-peer updates_by_range responses;
     * first apply-success wins) WITHOUT holding the {@link LightClientStore}
     * monitor across BLS verification. Diagnosed on-device (Pixel 7, 2026-07-06):
     * synchronizing the whole batch on {@code store} starved every status reader —
     * the UI snapshot poll ({@code isInitialized}) and {@code rpc-head-build}
     * ({@code getFinalizedHeader}) blocked for the entire multi-minute catch-up,
     * because each update's sync-aggregate verify held the monitor for seconds
     * (10-16 s/update under the Milagro/compare backend). Two invariants replace
     * the old whole-batch store lock: (1) ALL store writers — catch-up appliers
     * AND the live finality poll — take THIS lock, so verify-then-apply sequences
     * never interleave (a finality apply slipping between a catch-up verify and
     * its apply could re-arm a stale next committee); (2) the multi-step
     * apply-mutations inside {@link LightClientProcessor} hold the store monitor
     * for just those memory writes, so readers ({@code snapshot()} for
     * persistence, status getters) never observe a torn state.
     */
    private final Object catchUpApplyLock = new Object();
    private final LightClientProcessor processor;
    private final BeaconSyncState syncState;
    private final List<String> clPeerMultiaddrs;  // mutable, synchronized
    private final Set<String> knownPeerAddrs;     // dedup set for discovered peers
    private final String beaconApiUrl;            // nullable; HTTP API for peer discovery
    private final byte[] checkpointRoot;      // 32-byte trusted checkpoint block root
    private final long checkpointSlot;        // slot of trusted checkpoint (for pre-bootstrap Status)
    private final byte[] forkVersion;         // 4-byte fork version
    /**
     * Active BPO parameters per EIP-7892: {@code (epoch, max_blobs_per_block)}.
     * Folded into {@link #computeForkDigest(byte[])} via the XOR-mix-in
     * formula from the Fulu spec. {@code epoch == 0} means no BPO is active
     * and the legacy {@code base_digest[:4]} formula is used (testnets).
     */
    private volatile long activeBlobParamsEpoch;
    private volatile long activeBlobParamsMaxBlobs;
    /**
     * Network slot-timing preset. Mainnet (and the mainnet-preset testnets) use 12s
     * slots / 32 slots-per-epoch; Gnosis Beacon Chain uses 5s slots / 16. Used for
     * wall-clock sync-committee period estimation (catch-up targeting) and the Status
     * {@code finalized_epoch}. Defaults to mainnet; override with
     * {@link #setBeaconPreset(int, int)} before {@link #start()}.
     */
    private volatile int secondsPerSlot = BeaconChainSpec.SECONDS_PER_SLOT;
    private volatile int slotsPerEpoch = BeaconChainSpec.SLOTS_PER_EPOCH;
    private final byte[] genesisValidatorsRoot; // 32-byte genesis validators root
    private final long clGenesisTime;         // beacon chain genesis time (seconds since epoch)
    private final java.util.function.Consumer<String> onPeerSuccess; // nullable; called with multiaddr on success
    private final java.util.function.Consumer<String> onPeerFailure; // nullable; called with multiaddr on failure

    private volatile String lastBootstrapPeer; // multiaddr of the peer that last served a bootstrap; prioritized by catch-up

    private volatile Thread syncThread;
    private volatile boolean running;

    // Peers proven NOT to serve light_client_updates_by_range (protocol
    // negotiation failed). They match our fork digest and may have deep history,
    // so neither the agent nor earliest-slot filter excludes them — but they
    // can't serve catch-up, so every batch wastes a stream negotiating a
    // protocol they don't have. Remember and skip them.
    private final Set<String> peersNoLcUpdates = java.util.concurrent.ConcurrentHashMap.newKeySet();

    // Peers proven to serve catch-up, multiaddr -> {low, high} sync-committee period
    // range they served. Seeded from the CL peer cache at startup so a cold start can
    // immediately prefer peers that actually retained the period we need last time,
    // instead of fanning out across discovery peers (most of which don't serve
    // light-client updates at all). Updated live on every catch-up success. Tracking
    // both ends (not just the floor) lets prioritization ask "does this peer's range
    // cover period N?" instead of assuming monotonic-forward coverage from the floor.
    private final Map<String, long[]> provenCatchUpRanges =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** Notified (multiaddr, low, high) whenever a peer advances catch-up, for cache persistence. */
    private volatile ServedRangeListener onCatchUpServed;

    // Peers proven to serve a LightClientBootstrap, multiaddr -> the (deepest) checkpoint
    // period they served. Seeded from the cache; also seeds lastBootstrapPeer so a cold
    // start front-loads a peer that demonstrably retained the checkpoint committee.
    private final Map<String, Long> provenBootstrapPeers =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** Notified (multiaddr, bootstrapPeriod) whenever a peer serves a bootstrap, for cache persistence. */
    private volatile java.util.function.BiConsumer<String, Long> onBootstrapServed;

    /** Listener for a peer that served catch-up across the period range {@code [low, high]}.
     *  A 3-arg shape (Java has no {@code TriConsumer}) kept on plain types so the API stays
     *  multiplatform-friendly (no {@code CompletableFuture}). */
    @FunctionalInterface
    public interface ServedRangeListener {
        void accept(String peer, long low, long high);
    }

    /** Seed proven catch-up servers (multiaddr -> {low, high} served range) from a cache. */
    public void setProvenCatchUpServers(Map<String, long[]> seed) {
        if (seed == null) return;
        // Defensive copy to a fixed length-2 array: the map is caller-owned and arrays are
        // mutable, so storing references directly would let later mutation (or a short array)
        // corrupt prioritization or throw AIOOBE on the r[0]/r[1] reads.
        seed.forEach((ma, r) -> {
            if (ma == null || r == null || r.length < 2) return;
            provenCatchUpRanges.put(ma, new long[]{r[0], r[1]});
        });
    }

    /** Set the callback persisting (multiaddr, low, high) when a peer advances catch-up. */
    public void setOnCatchUpServed(ServedRangeListener cb) {
        this.onCatchUpServed = cb;
    }

    /** Seed proven bootstrap peers (multiaddr -> bootstrap period) from a cache. Also seeds
     *  {@link #lastBootstrapPeer} (highest-period entry) so it is tried first on a cold start. */
    public void setProvenBootstrapPeers(Map<String, Long> seed) {
        if (seed == null || seed.isEmpty()) return;
        provenBootstrapPeers.putAll(seed);
        if (lastBootstrapPeer == null) {
            provenBootstrapPeers.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .ifPresent(e -> lastBootstrapPeer = e.getKey());
        }
    }

    /** Set the callback persisting (multiaddr, bootstrapPeriod) when a peer serves a bootstrap. */
    public void setOnBootstrapServed(java.util.function.BiConsumer<String, Long> cb) {
        this.onBootstrapServed = cb;
    }

    // Peers whose Identify confirmed light_client protocol support — dialed first by
    // copyPeers(). Seeded from the CL cache so a restart prioritizes known light-client
    // servers instead of re-Identifying the whole fork-matched set (most of which are
    // full nodes without the light-client server).
    private final Set<String> provenLightClient = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** Notified (confirmedLcMultiaddrs, deniedLcMultiaddrs) once per Identify round or finality-poll round, batched so
     *  the host persists the whole round in a single rewrite rather than once per peer. */
    private volatile java.util.function.BiConsumer<java.util.Collection<String>, java.util.Collection<String>> onLightClientVerdict;

    /** Seed peers confirmed to support light_client (dial first) from a cache. */
    public void setProvenLightClient(java.util.Collection<String> seed) {
        if (seed != null) provenLightClient.addAll(seed);
    }

    /** Seed peers proven NOT to serve light_client (dial last) from a cache. */
    public void setProvenNonLightClient(java.util.Collection<String> seed) {
        if (seed != null) peersNoLcUpdates.addAll(seed);
    }

    /** Set the callback persisting each Identify round's light_client verdicts
     *  (confirmed multiaddrs, denied multiaddrs) — invoked once per round, batched. */
    public void setOnLightClientVerdict(
            java.util.function.BiConsumer<java.util.Collection<String>, java.util.Collection<String>> cb) {
        this.onLightClientVerdict = cb;
    }

    // Persisted verified-store snapshot (day-to-day resume). Null disables persistence.
    private volatile java.nio.file.Path snapshotFile;
    // Period last written, to avoid rewriting the (~50KB) snapshot when nothing advanced.
    private volatile long lastPersistedPeriod = -1L;

    /** File to persist/restore the verified light-client store. Set before {@link #start()}. */
    public void setSnapshotFile(java.nio.file.Path file) {
        this.snapshotFile = file;
    }

    /**
     * Restore the store from a persisted snapshot if one exists, is for this chain,
     * and is newer than the embedded checkpoint. Returns true if we resumed (and a
     * fresh bootstrap should be skipped).
     */
    private boolean tryResumeFromSnapshot() {
        java.nio.file.Path file = snapshotFile;
        if (file == null) return false;
        try {
            if (!java.nio.file.Files.exists(file)) return false;
            byte[] data = java.nio.file.Files.readAllBytes(file);
            LightClientStore.Snapshot snap =
                    LightClientStoreSnapshot.deserialize(data, genesisValidatorsRoot);
            if (snap == null) {
                log.info("[beacon] Ignoring sync snapshot (absent/corrupt/foreign) — bootstrapping fresh");
                return false;
            }
            long checkpointPeriod = BeaconChainSpec.computeSyncCommitteePeriod(checkpointSlot);
            if (snap.currentSyncCommitteePeriod() <= checkpointPeriod) {
                // Not newer than the checkpoint we'd bootstrap from anyway — no benefit.
                return false;
            }
            store.restore(snap);
            lastPersistedPeriod = snap.currentSyncCommitteePeriod();
            // Sidecar first: its roots predate the snapshot's finalized/optimistic roots
            // that updateSyncState() records, and the window deque must stay oldest→newest
            // (eviction polls the front; export/findStateRoot treat the tail as freshest).
            restoreStateRootsSidecar(file);
            updateSyncState();
            warmBlsPubkeyCache();
            log.info("[beacon] Resumed from persisted snapshot at period {} (slot {}) — "
                            + "catching up only periods since",
                    snap.currentSyncCommitteePeriod(), snap.finalizedSlot());
            return true;
        } catch (Exception e) {
            log.warn("[beacon] Snapshot resume failed ({}) — bootstrapping fresh", e.getMessage());
            return false;
        }
    }

    /**
     * Persist the verified store to disk so the next launch resumes from here.
     * Atomic (temp file + move) so a crash mid-write can't leave a torn snapshot.
     * No-op when nothing advanced since the last write.
     */
    private void persistSnapshot() {
        java.nio.file.Path file = snapshotFile;
        if (file == null) return;
        // The known-state-roots window advances on every finality poll, so persist it
        // each call — independent of the period-change gate below that throttles the
        // (large) committee snapshot to ~once per period.
        persistStateRootsSidecar(file);
        LightClientStore.Snapshot snap = store.snapshot();
        if (snap == null) return;
        if (snap.currentSyncCommitteePeriod() == lastPersistedPeriod) return;
        byte[] data = LightClientStoreSnapshot.serialize(snap, genesisValidatorsRoot);
        if (data == null) return;
        try {
            java.nio.file.Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            java.nio.file.Files.write(tmp, data);
            try {
                java.nio.file.Files.move(tmp, file,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException amnse) {
                java.nio.file.Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            lastPersistedPeriod = snap.currentSyncCommitteePeriod();
            log.debug("[beacon] Persisted sync snapshot at period {} ({} bytes)",
                    snap.currentSyncCommitteePeriod(), data.length);
        } catch (Exception e) {
            log.debug("[beacon] Snapshot persist failed: {}", e.getMessage());
        }
    }

    // Sidecar persistence for BeaconSyncState's known-state-roots window. Kept beside the
    // committee snapshot ("<snapshot>.roots") rather than folded into the SSZ store
    // snapshot, so the window can be rewritten cheaply every finality poll without
    // touching the committee format. Compact format: version(1) + count(4) then per
    // entry slot(8) + root(32) + verified(1). Only the freshest entries are kept.
    private static final String ROOTS_SIDECAR_SUFFIX = ".roots";
    private static final int ROOTS_SIDECAR_VERSION = 1;
    private static final int ROOTS_SIDECAR_MAX = 64;
    /** (newestSlot, count) of the last sidecar write, one immutable unit behind a
     *  single volatile so concurrent persist calls can't pair a new slot with an old
     *  count (torn read). Used to skip the flash write when the window hasn't
     *  advanced — the 12s poll loop calls persistSnapshot every cycle. */
    private record SidecarMark(long newestSlot, int count) {}
    private volatile SidecarMark rootsSidecarLastWritten;

    private java.nio.file.Path rootsSidecarPath(java.nio.file.Path snapshot) {
        return snapshot.resolveSibling(snapshot.getFileName() + ROOTS_SIDECAR_SUFFIX);
    }

    private void persistStateRootsSidecar(java.nio.file.Path snapshot) {
        try {
            java.util.List<BeaconSyncState.SlottedStateRoot> all = syncState.exportKnownStateRoots();
            if (all.isEmpty()) return;
            // Keep only the freshest ROOTS_SIDECAR_MAX (export is oldest→newest).
            int from = Math.max(0, all.size() - ROOTS_SIDECAR_MAX);
            java.util.List<BeaconSyncState.SlottedStateRoot> keep = all.subList(from, all.size());
            long newestSlot = keep.get(keep.size() - 1).slot();
            SidecarMark last = rootsSidecarLastWritten;
            if (last != null && newestSlot == last.newestSlot() && keep.size() == last.count()) {
                return; // window unchanged since the last write
            }
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(1 + 4 + keep.size() * 41);
            buf.put((byte) ROOTS_SIDECAR_VERSION);
            buf.putInt(keep.size());
            for (BeaconSyncState.SlottedStateRoot r : keep) {
                buf.putLong(r.slot());
                buf.put(r.stateRoot());                 // exactly 32 bytes (validated on record)
                buf.put((byte) (r.blsVerified() ? 1 : 0));
            }
            java.nio.file.Path file = rootsSidecarPath(snapshot);
            java.nio.file.Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            java.nio.file.Files.write(tmp, buf.array());
            try {
                java.nio.file.Files.move(tmp, file,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException amnse) {
                java.nio.file.Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            rootsSidecarLastWritten = new SidecarMark(newestSlot, keep.size());
        } catch (Exception e) {
            log.debug("[beacon] roots sidecar persist failed: {}", e.getMessage());
        }
    }

    private void restoreStateRootsSidecar(java.nio.file.Path snapshot) {
        try {
            java.nio.file.Path file = rootsSidecarPath(snapshot);
            if (!java.nio.file.Files.exists(file)) return;
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(java.nio.file.Files.readAllBytes(file));
            if (buf.remaining() < 5 || buf.get() != ROOTS_SIDECAR_VERSION) return;
            int count = buf.getInt();
            if (count < 0 || count > ROOTS_SIDECAR_MAX || buf.remaining() < count * 41) return;
            java.util.List<BeaconSyncState.SlottedStateRoot> roots = new java.util.ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                long slot = buf.getLong();
                byte[] root = new byte[32];
                buf.get(root);
                boolean verified = buf.get() != 0;
                roots.add(new BeaconSyncState.SlottedStateRoot(slot, root, verified));
            }
            syncState.importKnownStateRoots(roots);
            log.info("[beacon] Restored {} known state root(s) from sidecar — SYNCED needs "
                    + "one fresh finality poll, not {}", roots.size(), BeaconSyncState.FILL_THRESHOLD);
        } catch (Exception e) {
            log.debug("[beacon] roots sidecar restore failed: {}", e.getMessage());
        }
    }

    /**
     * Pre-decompress the current (and next, if known) sync committee's pubkeys into
     * BlsVerifier's cache on a background thread, so the first finality-update verify
     * after a resume pays only the pairing instead of ~512 G1 square roots (~35-55s
     * on Android/ART). Safe to call repeatedly — already-cached keys are no-ops.
     */
    private void warmBlsPubkeyCache() {
        Thread t = new Thread(() -> {
            try {
                java.util.List<byte[]> keys = new java.util.ArrayList<>();
                SyncCommittee current = store.getCurrentSyncCommittee();
                if (current != null) keys.addAll(java.util.Arrays.asList(current.pubkeys()));
                SyncCommittee next = store.getNextSyncCommittee();
                if (next != null) keys.addAll(java.util.Arrays.asList(next.pubkeys()));
                if (keys.isEmpty()) return;
                long t0 = System.nanoTime();
                com.jaeckel.ethp2p.consensus.bls.BlsBackends.active().warmPubkeyCache(keys);
                log.info("[beacon] BLS pubkey cache warmed: {} keys in {}ms",
                        keys.size(), (System.nanoTime() - t0) / 1_000_000);
            } catch (Exception e) {
                log.debug("[beacon] BLS cache warm failed: {}", e.getMessage());
            }
        }, "bls-cache-warmer");
        t.setDaemon(true);
        t.start();
    }

    /** Remember a peer that served catch-up across {@code [low, high]} (range widens) and persist it. */
    private void recordCatchUpServer(String peer, long low, long high) {
        if (peer == null) return;
        provenCatchUpRanges.merge(peer, new long[]{low, high},
                (a, b) -> new long[]{Math.min(a[0], b[0]), Math.max(a[1], b[1])});
        ServedRangeListener cb = onCatchUpServed;
        if (cb != null) {
            try { cb.accept(peer, low, high); }
            catch (Exception e) { log.debug("[beacon] onCatchUpServed failed: {}", e.getMessage()); }
        }
    }

    /** Remember a peer that served a LightClientBootstrap for {@code period} (deepest wins) and persist it. */
    private void recordBootstrapServer(String peer, long period) {
        if (peer == null) return;
        provenBootstrapPeers.merge(peer, period, Math::max);
        java.util.function.BiConsumer<String, Long> cb = onBootstrapServed;
        if (cb != null) {
            try { cb.accept(peer, period); }
            catch (Exception e) { log.debug("[beacon] onBootstrapServed failed: {}", e.getMessage()); }
        }
    }

    // Catch-up update verification (BLS sync-aggregate verify) is CPU-heavy —
    // ~17s per update on Android/ART even after parallelizing pubkey
    // decompression. It must NOT run on a netty event loop thread: that both
    // blocks libp2p I/O on that loop and ties the verify to stream timers.
    // Single-threaded because the apply path serializes on the store monitor
    // anyway and the per-verify parallelStream already fans out across cores;
    // a wider pool would just oversubscribe.
    private final java.util.concurrent.ExecutorService catchUpExecutor =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "beacon-catchup-apply");
                t.setDaemon(true);
                return t;
            });

    /**
     * Construct a BeaconLightClient.
     *
     * @param clPeerMultiaddrs       list of multiaddr strings for Consensus Layer peers
     * @param checkpointRoot         32-byte trusted checkpoint block root (weak subjectivity)
     * @param forkVersion            4-byte current fork version
     * @param genesisValidatorsRoot  32-byte genesis validators root
     * @param syncState              shared state holder updated as finality advances
     * @param beaconApiUrl           nullable HTTP API URL for local beacon node peer discovery
     */
    public BeaconLightClient(List<String> clPeerMultiaddrs,
                              byte[] checkpointRoot,
                              byte[] forkVersion,
                              byte[] genesisValidatorsRoot,
                              BeaconSyncState syncState,
                              String beaconApiUrl) {
        this(clPeerMultiaddrs, checkpointRoot, forkVersion, genesisValidatorsRoot,
                syncState, beaconApiUrl, null, null, BeaconChainSpec.MAINNET_GENESIS_TIME);
    }

    /**
     * Construct a BeaconLightClient with a peer success callback.
     *
     * @param clPeerMultiaddrs       list of multiaddr strings for Consensus Layer peers
     * @param checkpointRoot         32-byte trusted checkpoint block root (weak subjectivity)
     * @param forkVersion            4-byte current fork version
     * @param genesisValidatorsRoot  32-byte genesis validators root
     * @param syncState              shared state holder updated as finality advances
     * @param beaconApiUrl           nullable HTTP API URL for local beacon node peer discovery
     * @param onPeerSuccess          nullable callback invoked with peer multiaddr on successful response
     */
    public BeaconLightClient(List<String> clPeerMultiaddrs,
                              byte[] checkpointRoot,
                              byte[] forkVersion,
                              byte[] genesisValidatorsRoot,
                              BeaconSyncState syncState,
                              String beaconApiUrl,
                              java.util.function.Consumer<String> onPeerSuccess) {
        this(clPeerMultiaddrs, checkpointRoot, forkVersion, genesisValidatorsRoot,
                syncState, beaconApiUrl, onPeerSuccess, null, BeaconChainSpec.MAINNET_GENESIS_TIME);
    }

    /**
     * Construct a BeaconLightClient with peer success + failure callbacks.
     *
     * @param onPeerFailure nullable callback invoked with peer multiaddr on protocol failure
     *                      (timeout, reset, InvalidRemotePubKey, etc.). Used to evict dead
     *                      peers from the cache.
     */
    public BeaconLightClient(List<String> clPeerMultiaddrs,
                              byte[] checkpointRoot,
                              byte[] forkVersion,
                              byte[] genesisValidatorsRoot,
                              BeaconSyncState syncState,
                              String beaconApiUrl,
                              java.util.function.Consumer<String> onPeerSuccess,
                              java.util.function.Consumer<String> onPeerFailure) {
        this(clPeerMultiaddrs, checkpointRoot, forkVersion, genesisValidatorsRoot,
                syncState, beaconApiUrl, onPeerSuccess, onPeerFailure,
                BeaconChainSpec.MAINNET_GENESIS_TIME);
    }

    /**
     * Construct a BeaconLightClient with network-specific beacon chain genesis time.
     *
     * @param clGenesisTime beacon chain genesis time in seconds since epoch. Used to
     *                      estimate the current wall-clock sync-committee period for
     *                      catch-up targeting; must match the network the checkpointRoot
     *                      was taken from.
     */
    public BeaconLightClient(List<String> clPeerMultiaddrs,
                              byte[] checkpointRoot,
                              byte[] forkVersion,
                              byte[] genesisValidatorsRoot,
                              BeaconSyncState syncState,
                              String beaconApiUrl,
                              java.util.function.Consumer<String> onPeerSuccess,
                              java.util.function.Consumer<String> onPeerFailure,
                              long clGenesisTime) {
        this(clPeerMultiaddrs, checkpointRoot, 0L, forkVersion, genesisValidatorsRoot,
                syncState, beaconApiUrl, onPeerSuccess, onPeerFailure, clGenesisTime);
    }

    /**
     * Full constructor including the trusted-checkpoint slot, which is used
     * to populate Status.finalized_epoch before bootstrap completes.
     * Sending Status with {@code finalized_epoch=0} + {@code finalized_root=0}
     * causes Lighthouse (and other clients that replicate its check) to
     * reply with Goodbye(IrrelevantNetwork=2) and disconnect, because their
     * block_root_at_epoch(0) = mainnet genesis root ≠ zero. Claiming the
     * known checkpoint {epoch, root} lets us pass that check.
     */
    public BeaconLightClient(List<String> clPeerMultiaddrs,
                              byte[] checkpointRoot,
                              long checkpointSlot,
                              byte[] forkVersion,
                              byte[] genesisValidatorsRoot,
                              BeaconSyncState syncState,
                              String beaconApiUrl,
                              java.util.function.Consumer<String> onPeerSuccess,
                              java.util.function.Consumer<String> onPeerFailure,
                              long clGenesisTime) {
        if (checkpointRoot == null || checkpointRoot.length != 32) {
            throw new IllegalArgumentException("checkpointRoot must be 32 bytes");
        }
        if (forkVersion == null || forkVersion.length != 4) {
            throw new IllegalArgumentException("forkVersion must be 4 bytes");
        }
        if (genesisValidatorsRoot == null || genesisValidatorsRoot.length != 32) {
            throw new IllegalArgumentException("genesisValidatorsRoot must be 32 bytes");
        }
        this.clPeerMultiaddrs = Collections.synchronizedList(new ArrayList<>(clPeerMultiaddrs));
        this.knownPeerAddrs = Collections.synchronizedSet(new LinkedHashSet<>(clPeerMultiaddrs));
        this.beaconApiUrl = beaconApiUrl;
        this.checkpointRoot = checkpointRoot.clone();
        this.checkpointSlot = checkpointSlot;
        this.forkVersion = forkVersion.clone();
        this.genesisValidatorsRoot = genesisValidatorsRoot.clone();
        this.clGenesisTime = clGenesisTime;
        this.syncState = syncState;
        this.onPeerSuccess = onPeerSuccess;
        this.onPeerFailure = onPeerFailure;

        this.store = new LightClientStore();
        this.processor = new LightClientProcessor(store, this.forkVersion, genesisValidatorsRoot);
        // Supply the local Status on demand so BeaconP2PService can serve
        // inbound /status/{1,2} streams opened by peers — modern CL clients
        // drop us if we don't respond within RESP_TIMEOUT (~5 s).
        this.p2pService = new BeaconP2PService(this::buildLocalStatus);
    }

    /**
     * Add a newly-discovered CL peer to the live pool so the next sync cycle
     * sees it. Dedup'd via {@link #knownPeerAddrs}. Safe to call from any
     * thread (discv5 callback, beacon API polling, etc.).
     *
     * <p>Inserted near the front of the pool so freshly-discovered peers are
     * tried before possibly-rotten hardcoded seed entries.
     *
     * @return true if the peer was new (added to the pool); false if it was
     *         already known
     */
    public boolean addPeer(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return false;
        if (!knownPeerAddrs.add(multiaddr)) return false;
        synchronized (clPeerMultiaddrs) {
            clPeerMultiaddrs.add(Math.min(1, clPeerMultiaddrs.size()), multiaddr);
            // Bound the discovered pool. discv5 feeds peers continuously, so an
            // unbounded list grew to thousands — most fork-matched nodes that don't
            // run a light-client server — making every period-rotation catch-up fan
            // out across all of them. Over cap, evict from the tail (oldest add) but
            // never a peer with positive signal (proven catch-up server / LC-confirmed).
            // Drop it from knownPeerAddrs too so it can be re-discovered later.
            if (clPeerMultiaddrs.size() > MAX_CL_PEERS) {
                for (int i = clPeerMultiaddrs.size() - 1; i >= 0; i--) {
                    String cand = clPeerMultiaddrs.get(i);
                    if (!provenCatchUpRanges.containsKey(cand)
                            && !provenBootstrapPeers.containsKey(cand)
                            && !provenLightClient.contains(cand)) {
                        clPeerMultiaddrs.remove(i);
                        knownPeerAddrs.remove(cand);
                        break;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Start the libp2p host and launch the background sync loop on a virtual thread.
     *
     * @throws IllegalStateException if already started
     */
    public void start() {
        if (running) {
            throw new IllegalStateException("BeaconLightClient is already running");
        }
        log.info("[beacon] Starting with forkVersion={}", bytesToHex(forkVersion));
        p2pService.start();
        running = true;
        syncThread = new Thread(this::syncLoop, "beacon-sync");
        syncThread.setDaemon(true);
        syncThread.start();
        log.info("[beacon] Light client started with {} peer(s)", clPeerMultiaddrs.size());
    }

    /**
     * Stop the sync thread and the libp2p host but KEEP the verified store, the
     * catch-up executor, and the peer-knowledge maps warm for {@link #resume()}.
     * Persists the snapshot so a process kill while asleep loses nothing.
     * Idempotent; a no-op unless running.
     */
    public synchronized void pause() {
        if (!running) return;
        running = false;
        Thread t = syncThread;
        if (t != null) {
            t.interrupt();
            try {
                t.join(2_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        syncThread = null;
        persistSnapshot();
        try {
            p2pService.close();
        } catch (Throwable e) {
            log.warn("[beacon] p2p close on pause: {}", e.toString());
        }
        log.info("[beacon] Light client paused (store retained, period {})",
                store.isInitialized() ? store.getCurrentSyncCommitteePeriod() : -1);
    }

    /**
     * Restart the libp2p host and sync loop after {@link #pause()}. The warm
     * in-memory store makes {@code syncLoop} skip snapshot-restore and bootstrap
     * and go straight to Identify + committee catch-up (which covers any periods
     * missed while asleep). Idempotent; a no-op when already running.
     */
    public synchronized void resume() {
        if (running) return;
        p2pService.start();
        warmBlsPubkeyCache();
        running = true;
        syncThread = new Thread(this::syncLoop, "beacon-sync");
        syncThread.setDaemon(true);
        syncThread.start();
        log.info("[beacon] Light client resumed with {} peer(s)", clPeerMultiaddrs.size());
    }

    // -------------------------------------------------------------------------
    // Sync loop
    // -------------------------------------------------------------------------

    private void syncLoop() {
        // Phase 0: discover peers from beacon API before attempting connections
        discoverPeersFromBeaconApi();

        // Phase 1: resume from a persisted snapshot (day-to-day fast path) — if we
        // have verified state newer than the embedded checkpoint from a prior run,
        // pick up there and only catch up the periods since. Falls through to a
        // fresh bootstrap from the embedded checkpoint when there's no usable
        // snapshot (first run, wiped cache, or a corrupt/foreign file).
        // Runs BEFORE the network pre-connect: it's disk-only, and it kicks off the
        // background BLS pubkey-cache warm so decompression overlaps the Identify
        // round instead of stalling the first finality verify after it.
        // An already-initialized store means this loop is re-entered by resume()
        // after a pause: the live in-memory state is strictly newer than (or equal
        // to) the snapshot pause() just wrote — restoring over it would go backward.
        boolean resumed = store.isInitialized() || tryResumeFromSnapshot();

        // Pre-connect to peers and query Identify to learn protocol support.
        // This lets bootstrap() prioritize peers advertising light_client protocols.
        preConnectAndIdentify();

        if (!resumed) {
            // Bootstrap with BLS verification from the embedded checkpoint.
            bootstrap();
        }

        // Phase 1b: catch up sync committee if bootstrap is from an older period
        if (store.isInitialized()) {
            catchUpSyncCommittee();
            // Fill state roots immediately so verification works before the first finality update
            fillChainStateRootsFromAnyPeer(true);
        }

        // Phase 2: fall back to seeding without BLS if bootstrap failed
        if (!store.isInitialized()) {
            seedFromBeaconApi();
            if (!syncState.isSynced()) {
                seedFromFinalityUpdate();
            }
        }

        // Phase 2: steady-state poll loop — one slot (mainnet 12s, Gnosis 5s).
        // If not yet synced, each cycle disconnects stale connections and retries.
        // Using the network slot time matters on Gnosis: a hardcoded 12s polled
        // finality 2.4x too slowly there, prolonging CATCHING_UP and staling the head.
        // Guard a misconfigured preset: a non-positive slot time would make
        // Thread.sleep() throw (negative) or busy-loop the network (zero), so fall
        // back to the mainnet default rather than crash or spin.
        int slotSeconds = secondsPerSlot > 0 ? secondsPerSlot : BeaconChainSpec.SECONDS_PER_SLOT;
        long pollIntervalMs = slotSeconds * 1000L;
        int cycleCount = 0;
        while (running) {
            try {
                // Every 5 cycles (~60s), log pool stats so it's easy to see
                // whether LC-capable peers are accumulating or bleeding off.
                if (++cycleCount % 5 == 0) logPeerPoolStats();
                pollFinalityUpdate();
                // Background classification of untried pool peers (fire-and-forget;
                // never blocks the cycle) — drains the cache's untried bucket.
                classifyUntriedPeers();
                Thread.sleep(pollIntervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.warn("[beacon] Sync loop error: {}", e.getMessage());
                try {
                    Thread.sleep(30_000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        log.info("[beacon] Sync loop exited");
    }

    /**
     * Query the local beacon node's HTTP API to discover connected CL peers.
     * Discovered peer multiaddrs are appended to the peer list for libp2p connections.
     */
    private void discoverPeersFromBeaconApi() {
        if (beaconApiUrl == null || beaconApiUrl.isEmpty()) return;
        try {
            // All java.net.http usage is isolated in BeaconApiHttp so a NoClassDefFoundError on
            // Android is thrown HERE (first touch of that class) and caught below, never at this
            // method's resolution / class verification. See BeaconApiHttp.
            BeaconApiHttp.Response response = BeaconApiHttp.get(
                    beaconApiUrl + "/eth/v1/node/peers?state=connected", null, 5, 10);
            if (response.statusCode() != 200) {
                log.warn("[beacon] Beacon API returned status {}", response.statusCode());
                return;
            }

            // Extract peer entries from JSON using regex (avoids adding a JSON library dependency).
            // Each peer object has "peer_id" and "last_seen_p2p_address" fields.
            // Many addresses lack the /p2p/<peer_id> suffix, so we construct it.
            String body = new String(response.body(), java.nio.charset.StandardCharsets.UTF_8);
            // Match each peer object: extract peer_id and last_seen_p2p_address together
            Pattern peerPattern = Pattern.compile(
                    "\"peer_id\"\\s*:\\s*\"([^\"]+)\"[^}]*?\"last_seen_p2p_address\"\\s*:\\s*\"([^\"]+)\"");
            Matcher matcher = peerPattern.matcher(body);
            int added = 0;
            while (matcher.find()) {
                String peerId = matcher.group(1);
                String addr = matcher.group(2);
                // Only include TCP peers (skip QUIC/UDP-only)
                if (!addr.contains("/tcp/")) continue;
                // Ensure address ends with /p2p/<peer_id>
                String multiaddr = addr.contains("/p2p/") ? addr : addr + "/p2p/" + peerId;
                if (knownPeerAddrs.add(multiaddr)) {
                    // Insert after the local peer (index 0) so discovered peers
                    // are tried before unreachable hardcoded bootstrap ENRs.
                    // Synchronize on the same monitor as addPeer's eviction loop and
                    // copyPeers' snapshot so a concurrent add can't interleave with the
                    // eviction iteration (ConcurrentModificationException).
                    synchronized (clPeerMultiaddrs) {
                        clPeerMultiaddrs.add(Math.min(1, clPeerMultiaddrs.size()), multiaddr);
                    }
                    added++;
                }
            }
            if (added > 0) {
                log.info("[beacon] Discovered {} new CL peer(s) from beacon API (total: {})",
                        added, clPeerMultiaddrs.size());
            }
        } catch (LinkageError e) {
            // java.net.http is absent on Android (not desugared, unavailable below API 33 and
            // not shipped at all on the Android runtime). This local-beacon-API peer discovery
            // is a JVM-only *debug* aid — the real, trust-minimised peer discovery is libp2p/
            // discv5 — so degrade gracefully instead of crashing the sync thread. NoClassDefFound
            // is an Error, not an Exception, which is why it slipped past the catch below before.
            log.debug("[beacon] Beacon API peer discovery unavailable on this runtime "
                    + "(java.net.http absent — Android); using libp2p/discv5 discovery: {}", e.getMessage());
        } catch (Exception e) {
            log.debug("[beacon] Beacon API peer discovery failed: {}", e.getMessage());
        }
    }

    /**
     * Pre-connect to all peers and run Identify to discover protocol support.
     * Waits up to 8 seconds for connections + Identify to complete.
     * This ensures bootstrap() can prioritize light-client-capable peers.
     */
    /** Boot Identify fan-out cap. The CL cache can hold hundreds of fork-matched peers;
     *  dialing them all at once cost ~60s of connection churn before the first poll
     *  could start. copyPeers() orders confirmed-LC peers first, so a bounded slice
     *  still reaches the peers that matter, and verdict learning for the rest
     *  continues organically as later polls touch them. */
    private static final int PRECONNECT_MAX_PEERS = 64;
    /** Stop waiting on the Identify round once this many LC-capable peers are
     *  connected — enough to start polling finality updates immediately. */
    private static final int PRECONNECT_LC_EARLY_EXIT = 3;

    private void preConnectAndIdentify() {
        List<String> peers = copyPeers();
        if (peers.isEmpty()) return;
        if (peers.size() > PRECONNECT_MAX_PEERS) {
            peers = peers.subList(0, PRECONNECT_MAX_PEERS);
        }

        log.info("[beacon] Pre-connecting to {} peer(s) for Identify...", peers.size());
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (String peer : peers) {
            if (!running) return;
            // Only run Identify here. The CL-spec-required Status exchange is
            // fired automatically by {@link BeaconP2PService#autoStatus} on
            // every outbound connection; duplicating it here would create two
            // concurrent /status/2 streams that race and cause one side to
            // fail with "Stream closed by peer".
            futures.add(p2pService.queryIdentify(peer).handle((v, ex) -> null));
        }

        // Wait up to 10s, but bail as soon as a few LC-capable peers are connected —
        // that's all the first finality poll needs; stragglers keep Identifying in
        // the background and get picked up by later polls.
        CompletableFuture<Void> all =
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
        long identifyDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < identifyDeadline && !all.isDone()) {
            long lcSoFar = p2pService.getConnectedPeers().stream()
                    .filter(BeaconP2PService.PeerInfo::supportsLightClient).count();
            if (lcSoFar >= PRECONNECT_LC_EARLY_EXIT) {
                log.info("[beacon] {} LC peer(s) identified — starting without waiting for the rest",
                        lcSoFar);
                break;
            }
            try {
                all.get(500, TimeUnit.MILLISECONDS);
            } catch (java.util.concurrent.TimeoutException te) {
                // keep polling
            } catch (Exception e) {
                break; // interrupted or all-failed — proceed with what we have
            }
        }

        List<BeaconP2PService.PeerInfo> connected = p2pService.getConnectedPeers();
        long lcCount = connected.stream().filter(BeaconP2PService.PeerInfo::supportsLightClient).count();
        log.info("[beacon] Identify complete: {}/{} connected peers support light_client",
                lcCount, connected.size());
        for (BeaconP2PService.PeerInfo pi : connected) {
            if (pi.supportsLightClient()) {
                log.info("[beacon]   LC peer: {} agent={}", pi.peerId(), pi.agentVersion());
            }
        }

        applyIdentifyVerdicts(connected);
    }

    /**
     * Record each connected peer's light_client verdict (keyed by multiaddr) for
     * in-session prioritization + cache persistence, so a restart dials known
     * light-client servers first. Identify is per-peerId; map it back to our
     * multiaddrs. Shared by the boot Identify round and the steady-state
     * {@link #classifyUntriedPeers} sweep.
     */
    private void applyIdentifyVerdicts(List<BeaconP2PService.PeerInfo> connected) {
        java.util.Map<String, Boolean> lcByPeerId = new java.util.HashMap<>();
        for (BeaconP2PService.PeerInfo pi : connected) {
            lcByPeerId.put(pi.peerId(), pi.supportsLightClient());
        }
        List<String> newConfirmed = new ArrayList<>();
        List<String> newDenied = new ArrayList<>();
        for (String ma : copyPeers(false)) {
            String pid = peerIdOf(ma);
            Boolean lc = pid != null ? lcByPeerId.get(pid) : null;
            if (lc == null) continue; // not Identified this round
            if (lc) { provenLightClient.add(ma); peersNoLcUpdates.remove(ma); newConfirmed.add(ma); }
            else { peersNoLcUpdates.add(ma); provenLightClient.remove(ma); newDenied.add(ma); }
        }
        // Persist the whole round's verdicts in one shot — a per-peer callback would
        // trigger a disk rewrite for each of dozens of peers identified in parallel.
        java.util.function.BiConsumer<java.util.Collection<String>, java.util.Collection<String>> verdictCb =
                onLightClientVerdict;
        if (verdictCb != null && (!newConfirmed.isEmpty() || !newDenied.isEmpty())) {
            verdictCb.accept(newConfirmed, newDenied);
        }
    }

    /** Untried peers Identified per sync cycle by the background classification
     *  sweep — small enough to be invisible next to the fan-out's dials, big
     *  enough to classify the whole in-pool backlog in tens of minutes. */
    private static final int CLASSIFY_SWEEP_BATCH = 4;
    /** Rotating cursor over the untried peers so consecutive sweeps walk the
     *  backlog instead of re-probing the same head. */
    private int classifySweepCursor = 0;

    /**
     * Steady-state classification sweep: Identify a small rotating batch of
     * UNTRIED pool peers (no lc/nolc verdict yet) per sync cycle, so the cache's
     * untried mass drains into proven/nolc instead of waiting for a fan-out
     * probe to happen to hit each peer. Fire-and-forget: the Identify batch runs
     * async and applies verdicts on the catch-up executor; the sync loop never
     * blocks on it. Verdicts persist through the same batched callback the boot
     * Identify round uses.
     */
    private void classifyUntriedPeers() {
        List<String> untried = new ArrayList<>();
        for (String ma : copyPeers(false)) {
            if (!provenLightClient.contains(ma) && !peersNoLcUpdates.contains(ma)) {
                untried.add(ma);
            }
        }
        if (untried.isEmpty()) return;
        List<CompletableFuture<Void>> batch = new ArrayList<>(CLASSIFY_SWEEP_BATCH);
        int start = classifySweepCursor % untried.size();
        classifySweepCursor += CLASSIFY_SWEEP_BATCH;
        for (int i = 0; i < Math.min(CLASSIFY_SWEEP_BATCH, untried.size()); i++) {
            if (!running) return;
            String peer = untried.get((start + i) % untried.size());
            batch.add(p2pService.queryIdentify(peer).handle((v, ex) -> null));
        }
        CompletableFuture.allOf(batch.toArray(new CompletableFuture[0]))
                .whenCompleteAsync((v, ex) -> {
                    if (!running) return;
                    // A failed/timed-out Identify yields no PeerInfo entry and stays
                    // untried — deliberately: unreachable ≠ not-an-LC-server.
                    applyIdentifyVerdicts(p2pService.getConnectedPeers());
                }, catchUpExecutor);
    }

    /**
     * Build the local Status we send on each connection.
     *
     * <p>Light-client semantics: we do not yet have a verified view of the
     * chain head. Per the eth2 p2p-interface spec, a client that has not
     * finalized any block MUST send {@code finalized_root = 0x00..00} and
     * {@code finalized_epoch = 0}; an inconsistent pairing
     * (non-zero root with epoch 0) is treated as malformed by Lighthouse
     * v8+, which silently disconnects and blacklists us. The only thing
     * that actually gates peer acceptance is a matching
     * {@code fork_digest}.
     */
    private StatusMessage buildLocalStatus() {
        return buildLocalStatusFor(forkVersion);
    }

    /**
     * Build a Status the peer will accept (see {@link #BeaconLightClient(List,
     * byte[], long, byte[], byte[], BeaconSyncState, String, java.util.function.Consumer,
     * java.util.function.Consumer, long)}).
     *
     * <p>Lighthouse's relevance check maps out as:
     * <pre>
     *   if remote.finalized_epoch &lt;= local.finalized_epoch:
     *     local_root_at_remote_epoch = chain.root_at_epoch(remote.finalized_epoch)
     *     if local_root_at_remote_epoch != remote.finalized_root:
     *       goodbye IrrelevantNetwork
     * </pre>
     * So sending {@code epoch=0, root=0} fails: they look up their own
     * {@code root_at_epoch(0)} = genesis block root, which is not zero.
     *
     * <p>We send the trusted checkpoint once we know its epoch, and the
     * bootstrap-verified finalized header afterwards. Both values are valid
     * block roots on the real chain, so the peer's ancestry check passes.
     */
    private StatusMessage buildLocalStatusFor(byte[] fv) {
        byte[] finalizedRoot;
        long finalizedEpoch;
        byte[] headRoot;
        long headSlot;
        if (store != null && store.isInitialized()) {
            // finalized_* come from the bootstrap-verified finalized header —
            // the trust anchor peers run their ancestor/relevance check against.
            var fh = store.getFinalizedHeader();
            finalizedEpoch = fh.beacon().slot() / slotsPerEpoch;
            finalizedRoot = fh.beacon().hashTreeRoot();
            // head_* must reflect our latest known block, not finalized: the
            // optimistic (attested) header trails wall-clock by ~1-2 slots vs
            // ~2 epochs for finalized. Reporting finalized as head made us look
            // 64+ slots stale and depressed peer scoring. The attested header
            // shares the same sync-committee trust anchor. Fall back to
            // finalized if optimistic is somehow behind (shouldn't happen).
            var oh = store.getOptimisticHeader();
            if (oh != null && oh.beacon().slot() >= fh.beacon().slot()) {
                headSlot = oh.beacon().slot();
                headRoot = oh.beacon().hashTreeRoot();
            } else {
                headSlot = fh.beacon().slot();
                headRoot = fh.beacon().hashTreeRoot();
            }
        } else if (checkpointSlot > 0) {
            // Pre-bootstrap: claim the trusted weak-subjectivity checkpoint.
            // We haven't BLS-verified it yet, but it's a real mainnet block
            // root at a known slot, so peers' root_at_epoch check succeeds.
            finalizedEpoch = checkpointSlot / slotsPerEpoch;
            finalizedRoot = checkpointRoot.clone();
            headSlot = checkpointSlot;
            headRoot = checkpointRoot.clone();
        } else {
            // Fallback: spec-default genesis. Some peers (Lighthouse) will
            // goodbye us; others (Lodestar, Nimbus) tolerate this.
            finalizedRoot = new byte[32];
            finalizedEpoch = 0L;
            headRoot = new byte[32];
            headSlot = 0L;
        }
        return new StatusMessage(
                computeForkDigest(fv),
                finalizedRoot,
                finalizedEpoch,
                headRoot,
                headSlot,
                0L); // earliest_available_slot — we serve nothing historical
    }

    /**
     * EIP-7892 {@code compute_fork_digest}:
     * <pre>
     *   base_digest = sha256(pad(fork_version, 32) || gvr)  // fork_data_root
     *   bp_hash     = sha256(u64_le(epoch) || u64_le(max_blobs))
     *   fork_digest = (base_digest XOR bp_hash)[0..4]
     * </pre>
     * When no BPO is active ({@link #activeBlobParamsEpoch} == 0) we return
     * {@code base_digest[0..4]} — the pre-Fulu formula. See
     * consensus-specs/specs/fulu/beacon-chain.md.
     */
    private byte[] computeForkDigest(byte[] fv) {
        byte[] base = computeForkDataRoot(fv);
        if (activeBlobParamsEpoch == 0) {
            byte[] out = new byte[4];
            System.arraycopy(base, 0, out, 0, 4);
            return out;
        }
        byte[] bpInput = new byte[16];
        longToLeBytes(activeBlobParamsEpoch, bpInput, 0);
        longToLeBytes(activeBlobParamsMaxBlobs, bpInput, 8);
        byte[] bpHash;
        try {
            bpHash = java.security.MessageDigest.getInstance("SHA-256").digest(bpInput);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) out[i] = (byte) (base[i] ^ bpHash[i]);
        return out;
    }

    /** Legacy (pre-Fulu) fork_data_root: sha256(pad(fork_version) || gvr). */
    private byte[] computeForkDataRoot(byte[] fv) {
        try {
            byte[] buf = new byte[64];
            System.arraycopy(fv, 0, buf, 0, 4);
            System.arraycopy(genesisValidatorsRoot, 0, buf, 32, 32);
            return java.security.MessageDigest.getInstance("SHA-256").digest(buf);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 missing", e);
        }
    }

    private static void longToLeBytes(long v, byte[] out, int offset) {
        for (int i = 0; i < 8; i++) out[offset + i] = (byte) (v >>> (8 * i));
    }

    /**
     * Set the active EIP-7892 BPO parameters. Must be called before
     * {@link #start()}. Pass {@code epoch = 0} to disable (use legacy
     * fork_digest formula).
     */
    public void setBlobParameters(long epoch, long maxBlobsPerBlock) {
        this.activeBlobParamsEpoch = epoch;
        this.activeBlobParamsMaxBlobs = maxBlobsPerBlock;
    }

    /**
     * Set the network's beacon slot-timing preset. Must be called before
     * {@link #start()}. Mainnet/mainnet-preset testnets: {@code (12, 32)};
     * Gnosis Beacon Chain: {@code (5, 16)}. Affects wall-clock period estimation
     * (catch-up targeting) and the Status {@code finalized_epoch}.
     */
    public void setBeaconPreset(int secondsPerSlot, int slotsPerEpoch) {
        this.secondsPerSlot = secondsPerSlot;
        this.slotsPerEpoch = slotsPerEpoch;
    }

    /**
     * Enable gossipsub subscription to the light-client topics. Off by
     * default because short-session clients (Android app that runs ~2 min
     * once per day) don't benefit from mesh participation and churn the
     * mesh by joining-then-disappearing. Must be called before
     * {@link #start()}.
     */
    public void setGossipsubEnabled(boolean enabled) {
        p2pService.setGossipsubEnabled(enabled);
    }

    /**
     * Send Status to a peer, trying {@code /status/2} first and falling back
     * to {@code /status/1} if the peer doesn't support v2. Each protocol is
     * additionally tried with each candidate fork version in sequence.
     *
     * <p>The mainnet CL network has a split: some peers (current Lodestar)
     * advertise only v2, others (current Nimbus) advertise only v1. Trying
     * both catches both populations.
     */
    private CompletableFuture<StatusMessage> tryStatusWithFallback(
            String peer, List<byte[]> forkVersions, int idx) {
        byte[] fv = forkVersions.get(idx);
        CompletableFuture<StatusMessage> outer = new CompletableFuture<>();
        // Try /status/2 first, then /status/1.
        p2pService.exchangeStatus(peer, buildLocalStatusFor(fv))
                .whenComplete((status, ex) -> {
                    if (ex == null && status != null) {
                        outer.complete(status);
                        return;
                    }
                    String msg = ex != null ? ex.getMessage() : "empty response";
                    boolean protoUnsupported = msg != null && (
                            msg.contains("Protocol negotiation failed")
                            || msg.contains("ProtocolNegotiation"));
                    if (protoUnsupported) {
                        // Peer only speaks /status/1 — retry on that protocol,
                        // still with the same fork version.
                        p2pService.exchangeStatusV1(peer, buildLocalStatusFor(fv))
                                .whenComplete((s1, e1) -> {
                                    if (e1 == null && s1 != null) {
                                        outer.complete(s1);
                                    } else {
                                        retryOrFail(peer, forkVersions, idx, e1 != null ? e1 : ex,
                                                e1 != null ? e1.getMessage() : msg, outer);
                                    }
                                });
                    } else {
                        retryOrFail(peer, forkVersions, idx, ex, msg, outer);
                    }
                });
        return outer;
    }

    /**
     * After an exchange attempt fails, decide whether to retry the next fork
     * version or propagate the error. Extracted so both v2 and v1 paths share it.
     */
    private void retryOrFail(String peer, List<byte[]> forkVersions, int idx,
                             Throwable ex, String msg,
                             CompletableFuture<StatusMessage> outer) {
        boolean forkDigestIsh = msg != null && (
                msg.contains("requires 92 bytes")
                || msg.contains("requires 84 bytes")
                || msg.contains("Channel closed")
                || msg.contains("Connection reset")
                || msg.contains("closed"));
        if (forkDigestIsh && idx + 1 < forkVersions.size()) {
            log.debug("[beacon] Status attempt {} (fork=0x{}) for {}: {}; retry next fv",
                    idx, bytesToHex(forkVersions.get(idx)), peer, msg);
            tryStatusWithFallback(peer, forkVersions, idx + 1)
                    .whenComplete((s2, e2) -> {
                        if (e2 == null) outer.complete(s2);
                        else outer.completeExceptionally(e2);
                    });
        } else if (ex != null) {
            outer.completeExceptionally(ex);
        } else {
            outer.complete(null);
        }
    }

    /** Fork versions to try for Status. Currently just the one we're configured for. */
    private java.util.List<byte[]> acceptedForkVersions() {
        return java.util.List.of(forkVersion);
    }

    /**
     * Attempt to bootstrap from the beacon HTTP API.
     * Uses GET /eth/v1/beacon/light_client/bootstrap/{block_root} with SSZ encoding.
     * Returns true if bootstrap succeeded.
     */
    private boolean bootstrapFromBeaconApi() {
        if (beaconApiUrl == null || beaconApiUrl.isEmpty()) return false;
        try {
            String rootHex = "0x" + bytesToHex(checkpointRoot);
            String url = beaconApiUrl + "/eth/v1/beacon/light_client/bootstrap/" + rootHex;
            log.info("[beacon] Attempting HTTP bootstrap from {}", url);

            // java.net.http isolated in BeaconApiHttp — see the note in discoverPeersFromBeaconApi.
            BeaconApiHttp.Response response = BeaconApiHttp.get(url, "application/octet-stream", 5, 15);
            if (response.statusCode() != 200) {
                log.warn("[beacon] HTTP bootstrap returned status {} from {}", response.statusCode(), url);
                return false;
            }

            byte[] ssz = response.body();
            log.info("[beacon] HTTP bootstrap received {} bytes", ssz.length);

            com.jaeckel.ethp2p.consensus.lightclient.VectorDump.maybeDump("bootstrap", ssz);
            LightClientBootstrap bootstrap = LightClientBootstrap.decode(ssz);

            try {
                verifyCheckpointPin(bootstrap.header().beacon(), checkpointRoot);
            } catch (IllegalStateException e) {
                log.warn("[beacon] HTTP bootstrap rejected: {}", e.getMessage());
                return false;
            }

            int branchDepth = bootstrap.currentSyncCommitteeBranch().length;
            int gindex = BeaconChainSpec.syncCommitteeGindex(branchDepth);
            boolean branchValid = SszUtil.verifyMerkleBranch(
                    bootstrap.currentSyncCommittee().hashTreeRoot(),
                    bootstrap.currentSyncCommitteeBranch(),
                    branchDepth,
                    gindex,
                    bootstrap.header().beacon().stateRoot());

            if (!branchValid) {
                log.warn("[beacon] HTTP bootstrap sync committee branch invalid (depth={}, gindex={})",
                        branchDepth, gindex);
                return false;
            }

            if (!LightClientProcessor.verifyExecutionBranch(bootstrap.header())) {
                log.warn("[beacon] HTTP bootstrap execution branch invalid");
                return false;
            }

            store.initialize(bootstrap.header(), bootstrap.currentSyncCommittee());
            updateSyncState();
            log.info("[beacon] HTTP bootstrap complete, slot={}", bootstrap.header().beacon().slot());
            return true;

        } catch (LinkageError e) {
            // java.net.http is absent on the Android runtime (not desugared, not shipped at all).
            // NoClassDefFoundError is an Error, not an Exception, so it slips past the catch below
            // and would otherwise kill the beacon-sync thread. HTTP bootstrap is a JVM-only debug
            // convenience; the real bootstrap path is P2P (see bootstrap()), so degrade gracefully.
            log.debug("[beacon] HTTP bootstrap unavailable on this runtime "
                    + "(java.net.http absent — Android); falling back to P2P bootstrap: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            Throwable root = e;
            while (root.getCause() != null) root = root.getCause();
            log.warn("[beacon] HTTP bootstrap failed: {} ({})", root.getMessage(),
                    root.getClass().getSimpleName());
            return false;
        }
    }

    /**
     * Attempt to bootstrap from each peer in order. Stops at the first success.
     * Tries HTTP API first, then falls back to P2P peers.
     * Logs a warning if all peers fail.
     */
    private void bootstrap() {
        // Try HTTP API first — much more reliable than P2P
        if (bootstrapFromBeaconApi()) return;

        List<String> peers = copyPeers();
        log.info("[beacon] Attempting parallel bootstrap from {} peer(s)", peers.size());

        // Fire bootstrap requests to ALL peers in parallel — first valid response wins.
        // This avoids the 5+ minute sequential timeout cascade (18 peers × 30s each).
        CompletableFuture<byte[]> winnerFuture = new CompletableFuture<>();
        java.util.concurrent.atomic.AtomicInteger remaining =
                new java.util.concurrent.atomic.AtomicInteger(peers.size());

        for (String peer : peers) {
            if (!running) return;
            p2pService.requestBootstrap(peer, checkpointRoot)
                    .whenComplete((response, ex) -> {
                        if (ex != null) {
                            Throwable root = ex;
                            while (root.getCause() != null) root = root.getCause();
                            String msg = root.getMessage() != null ? root.getMessage()
                                    : root.getClass().getSimpleName();
                            log.debug("[beacon] Bootstrap failed from {}: {} ({})",
                                    peer, msg, root.getClass().getSimpleName());
                            notifyPeerFailure(peer);
                            if (remaining.decrementAndGet() == 0 && !winnerFuture.isDone()) {
                                winnerFuture.completeExceptionally(
                                        new RuntimeException("All peers failed bootstrap"));
                            }
                            return;
                        }
                        log.info("[beacon] Bootstrap response: {} bytes from {}", response.length, peer);
                        try {
                            com.jaeckel.ethp2p.consensus.lightclient.VectorDump.maybeDump("bootstrap", response);
                            LightClientBootstrap bootstrap = LightClientBootstrap.decode(response);

                            try {
                                verifyCheckpointPin(bootstrap.header().beacon(), checkpointRoot);
                            } catch (IllegalStateException e) {
                                log.warn("[beacon] Bootstrap from {} rejected: {}", peer, e.getMessage());
                                notifyPeerFailure(peer);
                                if (remaining.decrementAndGet() == 0 && !winnerFuture.isDone()) {
                                    winnerFuture.completeExceptionally(
                                            new RuntimeException("All peers failed bootstrap"));
                                }
                                return;
                            }

                            int bDepth = bootstrap.currentSyncCommitteeBranch().length;
                            int bGindex = BeaconChainSpec.syncCommitteeGindex(bDepth);
                            boolean branchValid = SszUtil.verifyMerkleBranch(
                                    bootstrap.currentSyncCommittee().hashTreeRoot(),
                                    bootstrap.currentSyncCommitteeBranch(),
                                    bDepth,
                                    bGindex,
                                    bootstrap.header().beacon().stateRoot());

                            if (!branchValid) {
                                log.warn("[beacon] Bootstrap sync committee branch invalid from {}", peer);
                                if (remaining.decrementAndGet() == 0 && !winnerFuture.isDone()) {
                                    winnerFuture.completeExceptionally(
                                            new RuntimeException("All peers failed bootstrap"));
                                }
                                return;
                            }

                            if (!LightClientProcessor.verifyExecutionBranch(bootstrap.header())) {
                                log.warn("[beacon] Bootstrap execution branch invalid from {}", peer);
                                notifyPeerFailure(peer);
                                if (remaining.decrementAndGet() == 0 && !winnerFuture.isDone()) {
                                    winnerFuture.completeExceptionally(
                                            new RuntimeException("All peers failed bootstrap"));
                                }
                                return;
                            }

                            // First valid bootstrap wins — initialize store BEFORE completing
                            // the future so that catchUpSyncCommittee() sees the initialized state.
                            String successPeer = null;
                            synchronized (store) {
                                // isInitialized guard: requestBootstrap has no per-request
                                // deadline, so a straggler response from an EARLIER bootstrap
                                // attempt (whose winnerFuture timed out un-completed) can land
                                // here long after catch-up started. Re-initializing would rewind
                                // the store to the checkpoint MID catch-up batch and mis-pair the
                                // committee/period label — a wedge that persists via the snapshot.
                                // An initialized store is never re-initialized; isInitialized can
                                // never go false within a store's lifetime, so this is safe.
                                if (!winnerFuture.isDone() && !store.isInitialized()) {
                                    store.initialize(bootstrap.header(), bootstrap.currentSyncCommittee());
                                    updateSyncState();
                                    winnerFuture.complete(response);
                                    successPeer = peer;
                                    lastBootstrapPeer = peer;
                                    // Remember (and persist) that this peer served the
                                    // bootstrap for this checkpoint period, so a restart
                                    // front-loads it as a proven light-client server.
                                    recordBootstrapServer(peer, BeaconChainSpec.computeSyncCommitteePeriod(
                                            bootstrap.header().beacon().slot()));
                                    // Cache the bootstrap so we can relay it to any peer
                                    // that asks us for the same block root.
                                    p2pService.cacheBootstrap(checkpointRoot, response);
                                    log.info("[beacon] Bootstrap complete from {}, slot={}",
                                            peer, bootstrap.header().beacon().slot());
                                }
                            }
                            if (successPeer != null) {
                                notifyPeerSuccess(successPeer);
                            }
                        } catch (Exception e) {
                            log.warn("[beacon] Bootstrap decode failed from {}: {}", peer, e.getMessage());
                            if (remaining.decrementAndGet() == 0 && !winnerFuture.isDone()) {
                                winnerFuture.completeExceptionally(e);
                            }
                        }
                    });
        }

        // Wait for first success or all failures — max 30 seconds total
        try {
            winnerFuture.get(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            Throwable root = e;
            while (root.getCause() != null) root = root.getCause();
            log.warn("[beacon] Could not bootstrap from any peer: {} — will retry on next sync cycle",
                    root.getMessage());
        }
    }

    /**
     * After bootstrap, the store's sync committee may be from an older period than the
     * current chain head. Fetch LightClientUpdates via updates_by_range to obtain the
     * nextSyncCommittee for each intermediate period and rotate until we reach the
     * current period.
     */
    /** Cap on the live discovered CL peer pool ({@link #clPeerMultiaddrs}). discv5 feeds
     *  it continuously; left unbounded it grew to thousands of mostly-dead/non-LC nodes. */
    private static final int MAX_CL_PEERS = 1024;
    /** Max 128-period batches per catch-up call. Bounds wall-clock on very old checkpoints. */
    private static final int MAX_CATCHUP_BATCHES = 8;
    /** LC serve-quota window. Live LC servers (Lighthouse) serve ~one update per
     *  ~10 s request-quota window; re-asking instantly after a served batch always
     *  came back empty, wasting the round as "no progress — will retry on next
     *  sync cycle" (measured on-device with the Rust twin: 20-95 s/period
     *  collapsed to ~11 s once paced; same value as the Rust engine's
     *  UPDATES_SERVE_COOLDOWN). The pace is the REMAINDER of this window since
     *  the last batch request FIRED, not a flat sleep: BLS apply time — minutes
     *  on-device for big batches — already refills the window (a flat sleep
     *  would add up to ~77 s of dead time per 8-batch call), and the fire stamp
     *  lives on an instance field so the NEXT call's batch 0 can't re-ask
     *  inside the window either (Gnosis's 5 s poll cycle would otherwise do
     *  exactly that at every batch-cap call boundary). */
    private static final long CATCHUP_QUOTA_PACE_MS = 11_000;
    /** nanoTime (monotonic — an NTP step must not skew the pace, same rule as
     *  the uptime stamps) of the last catch-up batch request fire — the quota
     *  consumption point (every fan-out consumes serving peers' windows,
     *  advancing or not). Spans catchUpSyncCommittee calls by design.
     *  Initialized one window in the past so the first-ever batch never pays
     *  a pace against nanoTime's arbitrary origin. */
    private volatile long lastCatchupBatchFireNanos =
            System.nanoTime() - CATCHUP_QUOTA_PACE_MS * 1_000_000L;
    /** Max peers dialed per catch-up batch. The discovered CL pool runs to thousands of
     *  fork-matched nodes, most of which don't run a light-client server — fanning
     *  updates_by_range at all of them burned minutes of ProtocolNegotiation/Timeout
     *  churn at every period rotation. We always include the positive-signal peers
     *  (proven catch-up servers + LC-confirmed) and fill the rest of this budget from a
     *  rotating window of the unknown pool, so cold pools still get swept across cycles. */
    private static final int CATCHUP_FANOUT_MAX = 48;
    /** Rolling offset into the unknown-peer pool so successive catch-up batches sweep
     *  different peers instead of re-dialing the same dead window every cycle. */
    private final java.util.concurrent.atomic.AtomicInteger catchUpSweepOffset =
            new java.util.concurrent.atomic.AtomicInteger();

    private void catchUpSyncCommittee() {
        // Estimate current period from wall clock, using the network's CL genesis time.
        long now = System.currentTimeMillis() / 1000;
        long currentSlotEstimate = (now - clGenesisTime) / secondsPerSlot;
        long currentPeriod = BeaconChainSpec.computeSyncCommitteePeriod(currentSlotEstimate);

        for (int batch = 0; batch < MAX_CATCHUP_BATCHES && running; batch++) {
            // Use the committee's own period, not the finalized slot's. After
            // forceRotate the two diverge by one period and starting from
            // finalizedPeriod re-requests a period whose signing committee we
            // no longer hold — every response then fails BLS verify.
            long committeePeriod = store.getCurrentSyncCommitteePeriod();
            if (currentPeriod <= committeePeriod) {
                if (batch == 0) {
                    log.info("[beacon] Sync committee is current (period {}), no catch-up needed", committeePeriod);
                }
                return;
            }

            // Pace AFTER the done-check (a finished catch-up must not pay a
            // pointless pause): sleep only the REMAINDER of the serve-quota
            // window since the last batch request fired — see the constant's
            // javadoc for why remainder-based and why the stamp spans calls.
            long sinceLastFireMs = (System.nanoTime() - lastCatchupBatchFireNanos) / 1_000_000L;
            long paceMs = CATCHUP_QUOTA_PACE_MS - sinceLastFireMs;
            if (paceMs > 0) {
                // Explicit stall marker: this code path's history (#132/#133)
                // earns making every deliberate pause self-explanatory in logs.
                log.debug("[beacon] Pacing {} ms for the LC serve quota before the next batch", paceMs);
                try {
                    Thread.sleep(paceMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (!running) return;
            }

            long periodsToFetch = currentPeriod - committeePeriod;
            log.info("[beacon] Sync committee catch-up batch {}: committee period={}, current period={}, fetching {} update(s)",
                    batch, committeePeriod, currentPeriod, periodsToFetch);

            if (!attemptCatchUpBatch(committeePeriod, periodsToFetch, currentSlotEstimate)) {
                log.warn("[beacon] Catch-up batch {} made no progress — will retry on next sync cycle", batch);
                persistSnapshot(); // checkpoint whatever progress this call did make
                return;
            }
            // Persist after each advancing batch so a restart resumes near here
            // rather than redoing the whole catch-up from the embedded checkpoint.
            persistSnapshot();
        }

        long finalPeriod = store.getCurrentSyncCommitteePeriod();
        if (finalPeriod < currentPeriod) {
            log.warn("[beacon] Catch-up hit batch cap ({}) at period {} (target {}); further progress on next cycle",
                    MAX_CATCHUP_BATCHES, finalPeriod, currentPeriod);
        }
    }

    /**
     * Run one parallel 128-period fetch across all peers; return true if the store advanced.
     */
    private boolean attemptCatchUpBatch(long bootstrapPeriod, long periodsToFetch, long slotEstimate) {
        // Fire requests to all peers in parallel — first peer to deliver a response that
        // actually advances the store wins. Serial iteration with 30s timeouts meant ~9
        // minutes worst case with a list full of dead peers.
        //
        // Honor the agent-exclusion filter: we're still debugging whether
        // Lighthouse/Teku/Prysm peers serve updates_by_range reliably, and
        // bypassing the Lodestar exclusion here masks those failures.
        List<String> peers = peersPrioritized(lastBootstrapPeer);
        int count = (int) Math.min(periodsToFetch, 128);
        // Skip peers whose advertised earliest_available_slot proves they can't
        // serve the period we need — their light-client-update history starts
        // later, so they'd only return far-future updates the period-gate
        // discards. This turns catch-up from "fan out to every peer and hope one
        // retains period N" into "ask the peers that actually have it", which is
        // the difference between stalling at an old checkpoint and progressing.
        // Peers that cover the period OR haven't completed a Status exchange yet
        // (earliest == -1) are kept; we never starve the batch.
        long neededSlot = bootstrapPeriod * BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        List<String> capable = new ArrayList<>(peers.size());
        int skippedShallow = 0;
        int skippedNoLc = 0;
        for (String p : peers) {
            // Skip peers proven not to serve light_client_updates_by_range, OR
            // whose Identify protocol list shows they don't advertise it. Both
            // catch the dominant failure on a cold pool: fork-digest-matching CL
            // nodes that simply don't serve light-client data, which otherwise
            // burn the whole batch on ProtocolNegotiationFailed.
            if (peersNoLcUpdates.contains(p)
                    || Boolean.FALSE.equals(p2pService.servesLightClientUpdates(p))) {
                skippedNoLc++;
                continue;
            }
            long earliest = p2pService.earliestAvailableSlot(p);
            if (earliest >= 0 && earliest > neededSlot) {
                skippedShallow++;
                continue;
            }
            capable.add(p);
        }
        if (capable.isEmpty()) capable = peers; // never starve the batch

        // Split the capable pool into positive-signal peers (worth asking) and the
        // unknown rest. Positive signal = proven (last session) to serve catch-up for
        // this period, OR Identify-confirmed light-client support / advertises
        // updates_by_range. These are the peers that actually retained light-client
        // data; everything else is a fork-matched node that probably doesn't serve it.
        java.util.LinkedHashSet<String> priority = new java.util.LinkedHashSet<>();
        // Tier 1: proven last session to serve a range that actually COVERS this period.
        // The range check (not just floor <= period) avoids the false positive where a peer
        // that only served [100,110] was assumed to cover period 900.
        for (String p : capable) {
            long[] r = provenCatchUpRanges.get(p);
            if (r != null && r[0] <= bootstrapPeriod && bootstrapPeriod <= r[1]) priority.add(p);
        }
        // Tier 2: proven to serve a bootstrap at/below this period — it retained at least
        // the checkpoint committee that deep, a strong signal it also serves catch-up here.
        for (String p : capable) {
            if (priority.contains(p)) continue;
            Long bp = provenBootstrapPeers.get(p);
            if (bp != null && bp <= bootstrapPeriod) priority.add(p);
        }
        // Tier 3: Identify-confirmed light-client support / advertises updates_by_range.
        for (String p : capable) {
            if (priority.contains(p)) continue;
            if (provenLightClient.contains(p)
                    || Boolean.TRUE.equals(p2pService.servesLightClientUpdates(p))) {
                priority.add(p);
            }
        }
        int provenCount = priority.size();
        List<String> rest = new ArrayList<>(capable.size());
        for (String p : capable) {
            if (!priority.contains(p)) rest.add(p);
        }

        // Cap the fan-out: all positive-signal peers, then fill the remaining budget
        // from a ROTATING window of the unknown pool so each retry cycle tries fresh
        // peers (a cold pool of thousands still gets swept over a handful of cycles)
        // instead of re-dialing the same dead window and re-burning minutes.
        List<String> fanout = new ArrayList<>(priority);
        int budget = CATCHUP_FANOUT_MAX - fanout.size();
        if (budget > 0 && !rest.isEmpty()) {
            int off = Math.floorMod(catchUpSweepOffset.getAndAdd(budget), rest.size());
            int take = Math.min(budget, rest.size());
            for (int i = 0; i < take; i++) {
                fanout.add(rest.get((off + i) % rest.size()));
            }
        }
        peers = fanout;
        if (peers.isEmpty()) {
            // No peers to ask (e.g. before discovery has populated the pool). Bail now —
            // otherwise remaining starts at 0, winner never completes, and winner.get(600s)
            // below blocks the whole sync loop for 10 minutes.
            log.warn("[beacon] Catch-up: no capable peers for period {} — retry next cycle", bootstrapPeriod);
            return false;
        }
        // Quota consumption point: stamp only when a fan-out actually FIRES —
        // the empty-pool early return above consumed nobody's window, and
        // pacing after it would delay the next attempt for nothing.
        lastCatchupBatchFireNanos = System.nanoTime();
        // {@link BeaconP2PService#doReqResp} detects a dying connection and
        // retries with a fresh one, so we no longer pre-emptively disconnect
        // every peer here — that was costing us Lighthouse/Teku connections
        // that would otherwise have stayed alive and kept our peer score up.
        log.info("[beacon] Catch-up: requesting {} update(s) from period {} across {} peer(s) "
                        + "({} proven/LC, {}/{} unknown pool; skipped {} too-shallow, {} no-LC)",
                count, bootstrapPeriod, peers.size(), provenCount,
                peers.size() - provenCount, rest.size(), skippedShallow, skippedNoLc);

        CompletableFuture<Boolean> winner = new CompletableFuture<>();
        java.util.concurrent.atomic.AtomicInteger remaining =
                new java.util.concurrent.atomic.AtomicInteger(peers.size());
        java.util.concurrent.atomic.AtomicInteger failCount = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger emptyCount = new java.util.concurrent.atomic.AtomicInteger();

        for (String peer : peers) {
            if (!running) return false;
            // Per-attempt timeout: libp2p reqresp has no inherent deadline, so a
            // peer that accepts the stream but never responds leaves the future
            // hanging forever. That keeps `remaining` non-zero and forces the
            // outer winner.get(60s) wall to fire on every batch where any peer
            // is a silent hanger — the dominant cost in the catch-up timeline.
            // 15s is generous for a real LC peer to deliver a 15-update batch.
            // Pass the deadline into the req/resp layer (not orTimeout out here)
            // so it can actually close the underlying libp2p stream when it
            // fires — otherwise channelRead0 would keep buffering bytes.
            p2pService.requestUpdatesByRange(peer, bootstrapPeriod, count, 15_000L)
                    .whenCompleteAsync((responses, ex) -> {
                        if (ex != null) {
                            Throwable root = ex;
                            while (root.getCause() != null) root = root.getCause();
                            failCount.incrementAndGet();
                            String rmsg = root.getMessage() != null ? root.getMessage()
                                    : root.getClass().getSimpleName();
                            // A protocol-negotiation failure means this peer does
                            // not serve light_client_updates_by_range at all —
                            // remember it so future batches skip it instead of
                            // re-negotiating a protocol it doesn't have.
                            if (rmsg.contains("ProtocolNegotiation")
                                    || rmsg.contains("Protocol negotiation")) {
                                peersNoLcUpdates.add(peer);
                            }
                            log.debug("[beacon] Catch-up updates_by_range failed from {}: {}", peer, rmsg);
                            notifyPeerFailure(peer);
                            if (remaining.decrementAndGet() == 0 && !winner.isDone()) {
                                winner.complete(false);
                            }
                            return;
                        }
                        // Serialize state mutation among appliers; first apply-success
                        // wins. Deliberately NOT synchronized(store) — see catchUpApplyLock.
                        synchronized (catchUpApplyLock) {
                            if (winner.isDone()) return;
                            if (responses == null || responses.isEmpty()) {
                                emptyCount.incrementAndGet();
                                log.debug("[beacon] No updates returned from {}", peer);
                                if (remaining.decrementAndGet() == 0 && !winner.isDone()) {
                                    winner.complete(false);
                                }
                                return;
                            }
                            // Records the peer as a proven catch-up server on its
                            // first applied update (see recordCatchUpServer).
                            int applied = applyCatchUpResponses(responses, slotEstimate, peer, bootstrapPeriod);
                            if (applied > 0) {
                                long newPeriod = BeaconChainSpec.computeSyncCommitteePeriod(store.getFinalizedSlot());
                                notifyPeerSuccess(peer);
                                log.info("[beacon] Sync committee catch-up: applied {} update(s) from {}, now at period {} (slot {})",
                                        applied, peer, newPeriod, store.getFinalizedSlot());
                                winner.complete(true);
                            } else {
                                emptyCount.incrementAndGet();
                                log.debug("[beacon] Catch-up: peer {} returned {} update(s), none applied",
                                        peer, responses.size());
                                if (remaining.decrementAndGet() == 0 && !winner.isDone()) {
                                    winner.complete(false);
                                }
                            }
                        }
                    }, catchUpExecutor);
        }

        try {
            // Generous outer wall — a pure backstop, NOT the normal completion
            // path. A batch where no peer serves the needed period now fails
            // fast: with the cheap signature-period gate in processUpdate,
            // non-applicable responses reject in ~ms, so every peer settles
            // (network timeout ≤15s) and `remaining` hits 0 → winner=false in
            // ~15s. Only the batch whose peer DOES serve the store period runs
            // long, because it BLS-verifies and applies each update it advances
            // — ~17s per update on Android/ART (vs ~0.5s on the JVM daemon), and
            // a single updates_by_range response can carry dozens of periods.
            // The wall must not cut that genuine progress off mid-apply.
            boolean result = winner.get(600, TimeUnit.SECONDS);
            if (!result) {
                log.warn("[beacon] Catch-up batch: no peer advanced store (tried {}, {} failed, {} returned empty/unusable)",
                        peers.size(), failCount.get(), emptyCount.get());
            }
            return result;
        } catch (Exception e) {
            log.warn("[beacon] Catch-up wait aborted: {} (tried {}, {} failed, {} empty)",
                    e.getMessage(), peers.size(), failCount.get(), emptyCount.get());
            return false;
        }
    }

    /**
     * Decode and process a list of catch-up response SSZ blobs, returning the number applied.
     * Must be called while holding {@code catchUpApplyLock} (writer serialization).
     */
    private int applyCatchUpResponses(List<byte[]> responses, long currentSlotEstimate,
                                      String peer, long servedFromPeriod) {
        int applied = 0;
        for (byte[] responseSsz : responses) {
            try {
                com.jaeckel.ethp2p.consensus.lightclient.VectorDump.maybeDump("update", responseSsz);
                LightClientUpdate update = LightClientUpdate.decode(responseSsz);
                if (processor.processUpdate(update)) {
                    applied++;
                    if (applied == 1) {
                        // First update applied from this peer — it demonstrably
                        // serves catch-up from servedFromPeriod. Record it NOW (not
                        // after the whole response, which can be dozens of updates
                        // ≈ minutes of BLS verifies) so the proof survives even if
                        // we restart mid-catch-up. The range is widened to the deepest
                        // period actually delivered after the loop below.
                        recordCatchUpServer(peer, servedFromPeriod, servedFromPeriod);
                    }
                    // Rotate BEFORE updateSyncState so the committee-period pushed to
                    // BeaconSyncState reflects the post-rotation value — otherwise
                    // beacon-status' SYNCED gate flips late by one update cycle.
                    store.forceRotateIfPastPeriod(currentSlotEstimate);
                    updateSyncState();
                    log.debug("[beacon] Catch-up: applied update slot={}, committee period now={}",
                            update.finalizedHeader().beacon().slot(),
                            store.getCurrentSyncCommitteePeriod());
                } else {
                    log.debug("[beacon] Catch-up update not applied (slot={})",
                            update.finalizedHeader().beacon().slot());
                }
            } catch (Exception e) {
                log.debug("[beacon] Failed to decode/process catch-up update: {}", e.getMessage());
            }
        }
        if (applied > 0) {
            // Widen the served range to the deepest period this peer actually delivered.
            // Read the store (the source of truth) rather than computing start+applied-1,
            // which would mis-count if any update in the batch was skipped as inapplicable.
            recordCatchUpServer(peer, servedFromPeriod, store.getCurrentSyncCommitteePeriod());
        }
        return applied;
    }

    /**
     * Fallback when bootstrap fails: request a finality update directly from a trusted
     * peer and use it to seed the sync state without full BLS verification.
     * This trusts the local beacon node but allows the state root to be used immediately.
     */
    private void seedFromFinalityUpdate() {
        // Honor the Lodestar exclusion here too so we're forced to
        // verify that non-Lodestar peers actually serve finality updates.
        List<String> peers = copyPeers();
        log.info("[beacon] Attempting to seed from finality update ({} peer(s))", peers.size());

        // Diagnostic: query first peer's supported protocols via Identify
        if (!peers.isEmpty()) {
            try {
                p2pService.queryIdentify(peers.get(0)).get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.debug("[beacon] Identify query failed: {}", e.getMessage());
            }
        }

        for (int i = 0; i < peers.size(); i++) {
            String peer = peers.get(i);
            if (!running) return;
            log.debug("[beacon] Trying finality update peer {}/{}: {}", i + 1, peers.size(), peer);
            try {
                byte[] response = p2pService
                        .requestFinalityUpdate(peer)
                        .get(5, TimeUnit.SECONDS);
                p2pService.cacheFinalityUpdate(response);

                com.jaeckel.ethp2p.consensus.lightclient.VectorDump.maybeDump("finality", response);
                LightClientFinalityUpdate update = LightClientFinalityUpdate.decode(response);
                LightClientHeader finalizedHeader = update.finalizedHeader();
                long finalizedSlot = finalizedHeader.beacon().slot();
                byte[] executionStateRoot = finalizedHeader.execution().stateRoot();

                if (executionStateRoot == null || executionStateRoot.length != 32) {
                    log.warn("[beacon] Finality update from {} has no execution state root", peer);
                    continue;
                }

                // Seed the sync state directly (trusted peer, no BLS verification)
                long execBlockNum = finalizedHeader.execution().blockNumber();
                byte[] execBlockHash = finalizedHeader.execution().blockHash();
                syncState.update(finalizedSlot, executionStateRoot, update.signatureSlot(), execBlockNum, execBlockHash);
                syncState.recordStateRoot(finalizedSlot, executionStateRoot, false);
                // Also record the attested header's execution state root
                long attestedSlot = update.attestedHeader().beacon().slot();
                byte[] attestedRoot = update.attestedHeader().execution().stateRoot();
                if (attestedRoot != null && attestedRoot.length == 32) {
                    syncState.recordStateRoot(attestedSlot, attestedRoot, false);
                }
                // Fill intermediate blocks between finalized and attested to cover recent state roots
                byte[] attestedBlockRoot = update.attestedHeader().beacon().hashTreeRoot();
                log.info("[beacon] Seeded: finalizedSlot={}, attestedSlot={}, signatureSlot={}, filling {} slots",
                        finalizedSlot, attestedSlot, update.signatureSlot(), attestedSlot - finalizedSlot);
                fillChainStateRoots(peer, false, finalizedSlot, attestedSlot, attestedBlockRoot);
                notifyPeerSuccess(peer);
                log.info("[beacon] Seeded from finality update via {}, finalizedSlot={}, knownRoots={}",
                        peer, finalizedSlot, syncState.getKnownStateRootCount());
                return;

            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage()
                        : e.getClass().getSimpleName()
                          + (e.getCause() != null ? ": " + e.getCause().getMessage() : "");
                log.warn("[beacon] Finality update seed failed from {}: {}", peer, msg);
                notifyPeerFailure(peer);
            }
        }
        log.warn("[beacon] Could not seed from any peer — will retry on next sync cycle");
    }

    /**
     * Fetch finality update from the local beacon node's HTTP API and seed sync state.
     * This is a fallback when P2P-based seeding fails (e.g. peer returns empty response).
     */
    private void seedFromBeaconApi() {
        if (beaconApiUrl == null || beaconApiUrl.isEmpty()) return;
        try {
            log.info("[beacon] Attempting seed from beacon HTTP API: {}", beaconApiUrl);
            // java.net.http isolated in BeaconApiHttp — see the note in discoverPeersFromBeaconApi.
            BeaconApiHttp.Response response = BeaconApiHttp.get(
                    beaconApiUrl + "/eth/v1/beacon/light_client/finality_update", null, 5, 10);
            if (response.statusCode() != 200) {
                log.warn("[beacon] Beacon API finality update returned status {}", response.statusCode());
                return;
            }

            String body = new String(response.body(), java.nio.charset.StandardCharsets.UTF_8);

            // Extract finalized_header.execution.state_root from JSON
            Pattern stateRootPattern = Pattern.compile(
                    "\"finalized_header\"\\s*:\\s*\\{.*?\"execution\"\\s*:\\s*\\{.*?\"state_root\"\\s*:\\s*\"(0x[0-9a-fA-F]{64})\"",
                    Pattern.DOTALL);
            Matcher srMatcher = stateRootPattern.matcher(body);
            if (!srMatcher.find()) {
                log.warn("[beacon] Could not extract execution state root from beacon API response");
                return;
            }
            String stateRootHex = srMatcher.group(1);
            byte[] executionStateRoot = hexToBytes(stateRootHex);

            // Extract finalized_header.beacon.slot
            Pattern slotPattern = Pattern.compile(
                    "\"finalized_header\"\\s*:\\s*\\{\\s*\"beacon\"\\s*:\\s*\\{.*?\"slot\"\\s*:\\s*\"(\\d+)\"",
                    Pattern.DOTALL);
            Matcher slotMatcher = slotPattern.matcher(body);
            if (!slotMatcher.find()) {
                log.warn("[beacon] Could not extract finalized slot from beacon API response");
                return;
            }
            long finalizedSlot = Long.parseLong(slotMatcher.group(1));

            // Extract signature_slot
            Pattern sigSlotPattern = Pattern.compile("\"signature_slot\"\\s*:\\s*\"(\\d+)\"");
            Matcher sigSlotMatcher = sigSlotPattern.matcher(body);
            long signatureSlot = sigSlotMatcher.find() ? Long.parseLong(sigSlotMatcher.group(1)) : finalizedSlot + 1;

            // Extract finalized execution block_number
            Pattern blockNumPattern = Pattern.compile(
                    "\"finalized_header\"\\s*:\\s*\\{.*?\"execution\"\\s*:\\s*\\{.*?\"block_number\"\\s*:\\s*\"(\\d+)\"",
                    Pattern.DOTALL);
            Matcher blockNumMatcher = blockNumPattern.matcher(body);
            long execBlockNum = blockNumMatcher.find() ? Long.parseLong(blockNumMatcher.group(1)) : 0;

            // Extract finalized execution block_hash
            Pattern blockHashPattern = Pattern.compile(
                    "\"finalized_header\"\\s*:\\s*\\{.*?\"execution\"\\s*:\\s*\\{.*?\"block_hash\"\\s*:\\s*\"(0x[0-9a-fA-F]{64})\"",
                    Pattern.DOTALL);
            Matcher blockHashMatcher = blockHashPattern.matcher(body);
            byte[] execBlockHash = blockHashMatcher.find() ? hexToBytes(blockHashMatcher.group(1)) : null;

            syncState.update(finalizedSlot, executionStateRoot, signatureSlot, execBlockNum, execBlockHash);
            syncState.recordStateRoot(finalizedSlot, executionStateRoot, false);

            // Also extract attested_header execution state root if present
            Pattern attestedSrPattern = Pattern.compile(
                    "\"attested_header\"\\s*:\\s*\\{.*?\"execution\"\\s*:\\s*\\{.*?\"state_root\"\\s*:\\s*\"(0x[0-9a-fA-F]{64})\"",
                    Pattern.DOTALL);
            Matcher attestedSrMatcher = attestedSrPattern.matcher(body);
            if (attestedSrMatcher.find()) {
                byte[] attestedRoot = hexToBytes(attestedSrMatcher.group(1));
                Pattern attestedSlotPattern = Pattern.compile(
                        "\"attested_header\"\\s*:\\s*\\{\\s*\"beacon\"\\s*:\\s*\\{.*?\"slot\"\\s*:\\s*\"(\\d+)\"",
                        Pattern.DOTALL);
                Matcher attestedSlotMatcher = attestedSlotPattern.matcher(body);
                if (attestedSlotMatcher.find()) {
                    long attestedSlot = Long.parseLong(attestedSlotMatcher.group(1));
                    syncState.recordStateRoot(attestedSlot, attestedRoot, false);
                }
            }

            log.info("[beacon] Seeded from beacon HTTP API, finalizedSlot={}, stateRoot={}",
                    finalizedSlot, stateRootHex);

        } catch (LinkageError e) {
            // java.net.http is absent on the Android runtime — NoClassDefFoundError (an Error, not an
            // Exception) would otherwise escape this method. This HTTP seed is a JVM-only debug
            // fallback; P2P seeding is the real path, so degrade gracefully instead of crashing.
            log.debug("[beacon] Beacon API finality seed unavailable on this runtime "
                    + "(java.net.http absent — Android): {}", e.getMessage());
        } catch (Exception e) {
            log.warn("[beacon] Beacon API finality seed failed: {}", e.getMessage());
        }
    }

    private static byte[] hexToBytes(String hex) {
        String clean = hex.startsWith("0x") ? hex.substring(2) : hex;
        byte[] bytes = new byte[clean.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    /**
     * Poll for a finality update from each peer in order. Stops at the first
     * successfully applied update. Logs debug-level failures for individual peers.
     */
    private void pollFinalityUpdate() {
        if (!store.isInitialized()) {
            // Not bootstrapped yet — try bootstrap, then fall back to seeding.
            // We used to disconnect all peers here to force fresh connections,
            // but doReqResp now handles stale connections automatically and
            // staying connected lets us keep our peer score up.
            discoverPeersFromBeaconApi();
            bootstrap();
            if (!store.isInitialized() && !syncState.isSynced()) {
                seedFromBeaconApi();
                if (!syncState.isSynced()) {
                    seedFromFinalityUpdate();
                }
            }
            if (!store.isInitialized()) {
                // Seeded but not bootstrapped — still poll for finality updates below,
                // and retry bootstrap on the next cycle
                log.debug("[beacon] Bootstrap pending, continuing with seeded mode");
            } else {
                // Bootstrap just succeeded via retry. Mirror the syncLoop phase-1b work
                // so the sync committee is caught up to wall-clock before we start
                // verifying finality updates against a stale committee.
                catchUpSyncCommittee();
                fillChainStateRootsFromAnyPeer(true);
                return;
            }
        } else {
            // Steady-state: the initial catchUpSyncCommittee() runs once at startup,
            // but light_client_finality_update does NOT carry nextSyncCommittee —
            // only LightClientUpdate (from updates_by_range) does. So once wall-clock
            // crosses the next period boundary, finality updates are signed by a
            // committee we don't have and BLS verify fails indefinitely. We must
            // re-fetch a LightClientUpdate to rotate. This is a cheap no-op when
            // the committee is current.
            long wallPeriod = BeaconChainSpec.currentPeriod(clGenesisTime, secondsPerSlot);
            if (wallPeriod > store.getCurrentSyncCommitteePeriod()) {
                catchUpSyncCommittee();
                // If still behind, skip the finality poll below. While the
                // committee is stale, every finality update is signed by a
                // committee we don't hold and fails BLS verify — iterating 16
                // such peers (up to ~10s each) burns the whole 12s cycle and
                // starves the next catch-up retry, which is exactly what leaves
                // CATCHING_UP stuck for minutes. Returning here lets the sync
                // loop fire another catch-up batch in ~12s instead of ~90s.
                if (wallPeriod > store.getCurrentSyncCommitteePeriod()) {
                    return;
                }
            }
        }

        // Honor the Lodestar exclusion — finality polling is part of the
        // debug surface for Lighthouse/Teku/Prysm reliability.
        //
        // Parallel fan-out, first VERIFIED apply wins — the Rust engine's
        // poll_finality shape, replacing the old sequential loop. Sequentially,
        // a round burned 1-10s per dead candidate before reaching a live server
        // (on-device: ~28s rounds, verified-head age spiking past 2 minutes
        // whenever a round found no server at all). The cap still bounds the
        // per-cycle dial count; copyPeers() puts the proven tier first and
        // sorts it most-recently-served first (every decodable responder gets
        // confirmed into the tier — see the classification harvest below), so
        // a known-live server stays inside the fan-out window.
        final int POLL_FINALITY_FANOUT = 16;
        // Heal a late winner from a PREVIOUS round: if its BLS verify outlasted
        // that round's 12s deadline, the store advanced but the poll thread had
        // moved on, skipping updateSyncState/persistSnapshot — and re-polling the
        // same update reports "no advance", so the lag would otherwise persist
        // until a NEW update publishes.
        if (store.isInitialized() && store.getFinalizedSlot() > syncState.getFinalizedSlot()) {
            updateSyncState();
            persistSnapshot();
        }
        List<String> peers = copyPeers();
        if (peers.size() > POLL_FINALITY_FANOUT) {
            peers = peers.subList(0, POLL_FINALITY_FANOUT);
        }
        if (peers.isEmpty()) return;

        final CompletableFuture<FinalityPollWin> winner = new CompletableFuture<>();
        final java.util.concurrent.atomic.AtomicInteger remaining =
                new java.util.concurrent.atomic.AtomicInteger(peers.size());
        // Round-scoped strike buffer (parity with the Rust poll_finality
        // accounting, which learned this on-device): a parallel fan-out mints
        // up to N-1 speculative losses per round, and feeding each into the
        // host's strike-based cache eviction empties it of every proven server.
        // A round WITH a winner discards the buffered failures (the losers
        // merely raced a success); a fully-failed round strikes every failed
        // peer once. Deliberate divergence from the OLD sequential loop, same
        // trade the Rust side made: a dead peer AHEAD of the winner used to
        // accrue a strike per round and cache-evict in ~3 polls; now it is
        // never struck while rounds keep winning — the recency sort in
        // orderByLightClient demotes it instead.
        final java.util.Queue<String> roundFailures = new java.util.concurrent.ConcurrentLinkedQueue<>();
        // Classification harvest — independent of the round outcome and of the
        // strike buffer above. With few proven servers the fan-out fills with
        // UNTRIED cache candidates anyway; record what each dial teaches us so
        // the probe isn't wasted: a decodable finality update (winner or loser)
        // proves the peer serves light-client data; a NoSuchRemoteProtocol
        // rejection proves it doesn't (deliberately NOT the connection-closed /
        // timeout failures — that's how genuine-but-at-capacity servers fail).
        // NOTE cross-engine divergence: the Rust poll treats UnsupportedProtocol
        // as neutral and never persists lc for decode-only responders — both
        // engines share the cache file, so align Rust when it grows a sweep.
        final java.util.Queue<String> lcConfirmed = new java.util.concurrent.ConcurrentLinkedQueue<>();
        final java.util.Queue<String> lcDenied = new java.util.concurrent.ConcurrentLinkedQueue<>();

        for (String peer : peers) {
            if (!running) return;
            // Per-attempt deadline via the req/resp layer (closes the stream on
            // expiry — an outer orTimeout would leave it accumulating; see the
            // requestFinalityUpdate javadoc). Completion hops to catchUpExecutor:
            // the BLS sync-aggregate verify inside processFinalityUpdate must NOT
            // run on a netty event loop thread (see the catchUpExecutor comment —
            // the catch-up fan-out honors the same rule), and its single thread
            // both serializes the up-to-16 verifies and makes the isDone bail
            // free for every response behind the winner.
            p2pService.requestFinalityUpdate(peer, 10_000L)
                    .whenCompleteAsync((response, ex) -> {
                        // A finished round ignores stragglers entirely: no strike
                        // (they raced a success), no apply (the winner advanced us).
                        if (winner.isDone()) return;
                        if (ex != null) {
                            Throwable root = ex;
                            while (root.getCause() != null) root = root.getCause();
                            log.debug("[beacon] Finality update failed from {}: {}", peer,
                                    root.getMessage() != null ? root.getMessage()
                                            : root.getClass().getSimpleName());
                            // Definitive non-server: the peer's mux said it has no such
                            // protocol. Matched by simple name to avoid pinning libp2p's
                            // internal package layout.
                            if ("NoSuchRemoteProtocolException".equals(root.getClass().getSimpleName())) {
                                lcDenied.add(peer);
                            }
                            roundFailures.add(peer);
                        } else {
                            try {
                                com.jaeckel.ethp2p.consensus.lightclient.VectorDump.maybeDump("finality", response);
                                LightClientFinalityUpdate update = LightClientFinalityUpdate.decode(response);
                                // Decodable update ⇒ the peer serves the LC protocol,
                                // whether or not it wins the round. Dial-priority signal
                                // only — trust still requires the verified apply below.
                                lcConfirmed.add(peer);

                                final boolean finalityApplied;
                                // Writers serialize on catchUpApplyLock (see its javadoc): without
                                // this a straggler catch-up applier's gate-check→store-next sequence
                                // can interleave with this finality apply's rotation and re-arm a
                                // stale next committee. Two same-round appliers also serialize here;
                                // the second usually reports no-advance and simply doesn't win.
                                synchronized (catchUpApplyLock) {
                                    finalityApplied = store.isInitialized()
                                            && processor.processFinalityUpdate(update);
                                }
                                if (finalityApplied) {
                                    winner.complete(new FinalityPollWin(peer, response, update, true));
                                    return;
                                }
                                if (!store.isInitialized()) {
                                    // Seeded mode: any decodable update with a plausible exec
                                    // state root wins; the poll thread runs the seed branch.
                                    byte[] sr = update.finalizedHeader().execution().stateRoot();
                                    if (sr != null && sr.length == 32) {
                                        winner.complete(new FinalityPollWin(peer, response, update, false));
                                        return;
                                    }
                                }
                                // Decoded but did not advance: not a strike (sequential parity —
                                // the old loop just moved on), simply not a win either.
                                log.debug("[beacon] Finality update from {} did not advance state", peer);
                            } catch (Exception e) {
                                log.debug("[beacon] Finality update decode/apply failed from {}: {}",
                                        peer, e.getMessage());
                                roundFailures.add(peer);
                            }
                        }
                        if (remaining.decrementAndGet() == 0 && !winner.isDone()) {
                            winner.completeExceptionally(new java.util.concurrent.TimeoutException(
                                    "no finality advance from " + roundFailures.size() + " failed peers"));
                        }
                    }, catchUpExecutor);
        }

        FinalityPollWin win;
        try {
            // 10s per-request timeout + decode/apply slack; the 12s sync cycle
            // re-fires either way.
            win = winner.get(12, TimeUnit.SECONDS);
        } catch (Exception e) {
            // Future.get can surface InterruptedException: restore the flag so
            // shutdown propagation isn't silently swallowed (the sync loop's
            // sleep then exits promptly).
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            // Close the round BEFORE harvesting: on a get() timeout the winner
            // future is still open, so straggler callbacks would pass the
            // isDone gate and enqueue verdicts into queues we've already
            // drained — silently losing exactly the classifications this
            // harvest exists to keep. completeExceptionally is a no-op if a
            // late winner already completed it, preserving the lateWin check.
            winner.completeExceptionally(new java.util.concurrent.TimeoutException("round closed"));
            // A late winner (a BLS verify outlasting the deadline on the
            // catch-up executor) must still void the round's strikes — strikes
            // are only for rounds that truly found no server. Its follow-ups
            // are skipped; the store already advanced and the store-ahead check
            // at the top of the next poll heals BeaconSyncState/snapshot.
            boolean lateWin = winner.isDone() && !winner.isCompletedExceptionally();
            if (!lateWin) {
                for (String p : roundFailures) notifyPeerFailure(p);
            }
            recordLcVerdicts(lcConfirmed, lcDenied);
            log.debug("[beacon] pollFinalityUpdate: fan-out of {} peer(s), no advance this cycle{}",
                    peers.size(), lateWin ? " (late winner, follow-ups next round)" : "");
            return;
        }

        // Winner follow-ups run HERE, on the poll thread: fillChainStateRoots does
        // its own blocking req/resp round-trips, which must stay off the (single)
        // catch-up executor thread the fan-out callbacks run on.
        // Relay-cache the WINNER's raw SSZ (last write wins in the relay cache, so
        // caching per-response from concurrent callbacks could leave a losing,
        // staler update as what we serve peers — the sequential loop always ended
        // on the winner's bytes).
        p2pService.cacheFinalityUpdate(win.raw());
        // Classification harvest (covers the winner too — a decodable response
        // queued it as confirmed — dial-priority signal only, unlike Rust's
        // verified-apply-gated mark_proven; Java's provenLightClient is the
        // Identify-grade tier).
        recordLcVerdicts(lcConfirmed, lcDenied);
        if (win.applied()) {
            updateSyncState();
            fillChainStateRoots(win.peer(), true);
            notifyPeerSuccess(win.peer());
            // Steady-state advance — persist so a restart resumes here
            // (no-op unless the committee period actually moved).
            persistSnapshot();
            log.debug("[beacon] Finality update applied from {}, finalizedSlot={}",
                    win.peer(), store.getFinalizedSlot());
            return;
        }

        // Seeded mode: update sync state directly from the winning finality update.
        LightClientHeader fh = win.update().finalizedHeader();
        byte[] sr = fh.execution().stateRoot();
        long slot = fh.beacon().slot();
        syncState.recordStateRoot(slot, sr, false);
        // Also record the attested header's execution state root
        long attestedSlot = win.update().attestedHeader().beacon().slot();
        byte[] attestedRoot = win.update().attestedHeader().execution().stateRoot();
        if (attestedRoot != null && attestedRoot.length == 32) {
            syncState.recordStateRoot(attestedSlot, attestedRoot, false);
        }
        // Fill intermediate blocks to cover recent state roots
        byte[] attestedBlockRoot = win.update().attestedHeader().beacon().hashTreeRoot();
        log.debug("[beacon] Seeded poll: finalizedSlot={}, attestedSlot={}, filling {} slots",
                slot, attestedSlot, attestedSlot - slot);
        fillChainStateRoots(win.peer(), false, slot, attestedSlot, attestedBlockRoot);
        notifyPeerSuccess(win.peer());
        if (slot > syncState.getFinalizedSlot()) {
            long execBlockNum = fh.execution().blockNumber();
            byte[] execBlockHash = fh.execution().blockHash();
            syncState.update(slot, sr, win.update().signatureSlot(), execBlockNum, execBlockHash);
            log.debug("[beacon] Finality update refreshed from {}, finalizedSlot={}", win.peer(), slot);
        }
    }

    /** A finality-poll round's winning response: the peer, the raw SSZ (for the
     *  relay cache — cached on the poll thread so the winner's bytes are what we
     *  serve), the decoded update, and whether it was a VERIFIED store apply
     *  ({@code applied}) or a seeded-mode candidate the poll thread still has to
     *  run the seed branch for. */
    private record FinalityPollWin(
            String peer, byte[] raw, LightClientFinalityUpdate update, boolean applied) {}

    /**
     * Apply a poll round's classification harvest (poll thread, once per round):
     * confirmed peers join the proven tier (recency-ordered by copyPeers) and
     * denied peers the nolc tier — mirroring the Identify-round verdicts — and
     * ONLY the peers whose state actually changed are pushed to the host's
     * verdict callback, so a round that merely re-confirms the same winner
     * doesn't trigger a cache-file rewrite every 12s. A peer somehow in both
     * queues counts as confirmed (it served; the rejection was transient).
     */
    private void recordLcVerdicts(java.util.Queue<String> confirmed, java.util.Queue<String> denied) {
        List<String> newConfirmed = new ArrayList<>();
        List<String> newDenied = new ArrayList<>();
        java.util.Set<String> confirmedSet = new java.util.HashSet<>();
        for (String p; (p = confirmed.poll()) != null; ) {
            confirmedSet.add(p);
            // Deliberately NO recentServes stamp here: that map means "last
            // SUCCESSFUL (verified) light-client response" — it backs the
            // servedPeersLastMinute health signal and the recency ordering.
            // Stamping decode-only losers would show ~16 peers "serving"
            // during a stale-committee stall (the exact stall the metric
            // exists to expose) and recency-rank unverifiable responders
            // first. The round's WINNER gets its stamp via notifyPeerSuccess.
            boolean changed = peersNoLcUpdates.remove(p) | provenLightClient.add(p);
            if (changed) newConfirmed.add(p);
        }
        for (String p; (p = denied.poll()) != null; ) {
            if (confirmedSet.contains(p)) continue;
            provenLightClient.remove(p);
            if (peersNoLcUpdates.add(p)) newDenied.add(p);
        }
        java.util.function.BiConsumer<java.util.Collection<String>, java.util.Collection<String>> cb =
                onLightClientVerdict;
        if (cb != null && (!newConfirmed.isEmpty() || !newDenied.isEmpty())) {
            cb.accept(newConfirmed, newDenied);
        }
    }

    /**
     * Push the current store state into the shared {@link BeaconSyncState}.
     * Only called after a successful bootstrap or finality update.
     *
     * <p>Records both the finalized and optimistic execution state roots
     * into the rolling window so that peer state roots from recent blocks
     * can be verified against beacon-attested headers.
     */
    private void updateSyncState() {
        LightClientHeader finalizedHeader = store.getFinalizedHeader();
        if (finalizedHeader != null) {
            byte[] stateRoot = finalizedHeader.execution().stateRoot();
            long execBlockNum = finalizedHeader.execution().blockNumber();
            byte[] execBlockHash = finalizedHeader.execution().blockHash();
            syncState.update(store.getFinalizedSlot(), stateRoot, store.getOptimisticSlot(), execBlockNum, execBlockHash);
            syncState.recordStateRoot(store.getFinalizedSlot(), stateRoot, true);
        }
        LightClientHeader optimisticHeader = store.getOptimisticHeader();
        if (optimisticHeader != null) {
            byte[] optRoot = optimisticHeader.execution().stateRoot();
            syncState.recordStateRoot(store.getOptimisticSlot(), optRoot, true);
            syncState.updateOptimisticExecution(
                    optimisticHeader.execution().blockNumber(),
                    optimisticHeader.execution().blockHash(),
                    optRoot);
        }
        // Mirror the store's committee period into the observable sync state so
        // beacon-status' SYNCED gate and verification callers don't need a store
        // reference to detect "wall-clock crossed into a period we don't hold."
        syncState.setCurrentSyncCommitteePeriod(store.getCurrentSyncCommitteePeriod());
    }

    // -------------------------------------------------------------------------
    // Chain fill: fetch intermediate blocks and verify hash chain
    // -------------------------------------------------------------------------

    /**
     * Try to fill chain state roots from any available peer.
     * Used after bootstrap to populate the state root window immediately.
     *
     * @param blsVerified true if the bootstrap was BLS-verified
     */
    private void fillChainStateRootsFromAnyPeer(boolean blsVerified) {
        // Honor the Lodestar exclusion — chain-fill uses blocks_by_range,
        // and we want to prove the non-Lodestar peers can serve it.
        for (String peer : copyPeers()) {
            if (!running) return;
            try {
                fillChainStateRoots(peer, blsVerified);
                return; // success
            } catch (Exception e) {
                log.debug("[beacon] Post-bootstrap chain fill failed from {}: {}", peer, e.getMessage());
            }
        }
    }

    /**
     * After a successful finality update, fetch all beacon blocks between the
     * finalized slot and the attested slot via {@code beacon_blocks_by_range},
     * verify the parent hash chain back to the attested header, and record each
     * block's execution state root as BLS-verified.
     *
     * <p>This fills the gap between the finalized root (~13 min old) and the
     * attested header (1-2 slots old), giving full coverage of recent state roots.
     *
     * @param peer           the CL peer multiaddr to fetch blocks from
     * @param blsVerified    true if the finality update was BLS-verified
     */
    private void fillChainStateRoots(String peer, boolean blsVerified) {
        long finalizedSlot = store.getFinalizedSlot();
        long optimisticSlot = store.getOptimisticSlot();
        LightClientHeader attestedHeader = store.getOptimisticHeader();
        byte[] attestedBlockRoot = attestedHeader != null
                ? attestedHeader.beacon().hashTreeRoot() : null;
        fillChainStateRoots(peer, blsVerified, finalizedSlot, optimisticSlot, attestedBlockRoot);
    }

    /**
     * Fill execution state roots for blocks between finalizedSlot and attestedSlot.
     * Works in both bootstrapped and seeded mode by accepting explicit parameters.
     *
     * @param peer               the CL peer multiaddr to fetch blocks from
     * @param blsVerified        true if the finality update was BLS-verified
     * @param finalizedSlot      the finalized slot (start of range)
     * @param attestedSlot       the attested/optimistic slot (end of range)
     * @param attestedBlockRoot  hash tree root of the attested beacon block header (for chain verification), or null
     */
    private void fillChainStateRoots(String peer, boolean blsVerified,
                                      long finalizedSlot, long attestedSlot,
                                      byte[] attestedBlockRoot) {
        if (attestedSlot <= finalizedSlot + 1) return; // nothing to fill

        long startSlot = finalizedSlot + 1;
        long count = attestedSlot - finalizedSlot; // includes the attested slot

        try {
            List<byte[]> blockSszList = p2pService
                    .requestBlocksByRange(peer, startSlot, count)
                    .get(30, TimeUnit.SECONDS);

            if (blockSszList.isEmpty()) {
                log.debug("[beacon] Chain fill: no blocks returned for slots {}-{}",
                        startSlot, attestedSlot);
                return;
            }

            // Parse all blocks
            List<BeaconBlockParser.ParsedBlock> blocks = new java.util.ArrayList<>();
            for (byte[] ssz : blockSszList) {
                if (ssz.length == 0) continue;
                try {
                    blocks.add(BeaconBlockParser.parse(ssz));
                } catch (Exception e) {
                    log.debug("[beacon] Chain fill: failed to parse block: {}", e.getMessage());
                }
            }

            if (blocks.isEmpty()) return;

            // Verify hash chain: walk from newest to oldest.
            // The attested header's blockHeaderRoot should match the last block,
            // and each block's parentRoot should match the previous block's headerRoot.
            byte[] expectedHash = attestedBlockRoot;

            int verified = 0;
            // Process blocks in reverse (newest first) to verify chain from attested header
            for (int i = blocks.size() - 1; i >= 0; i--) {
                BeaconBlockParser.ParsedBlock block = blocks.get(i);

                if (expectedHash != null) {
                    if (!java.util.Arrays.equals(block.blockHeaderRoot(), expectedHash)) {
                        log.debug("[beacon] Chain fill: hash mismatch at slot {} (expected {}, got {})",
                                block.slot(),
                                bytesToHex(expectedHash),
                                bytesToHex(block.blockHeaderRoot()));
                        break; // stop verifying at first mismatch
                    }
                }

                // This block is verified — record its execution state root
                if (block.executionStateRoot() != null && block.executionStateRoot().length == 32) {
                    syncState.recordStateRoot(block.slot(), block.executionStateRoot(), blsVerified);
                    verified++;
                }

                // Next iteration should match this block's parentRoot
                expectedHash = block.parentRoot();
            }

            log.info("[beacon] Chain fill: recorded {} verified state roots for slots {}-{} from {}",
                    verified, startSlot, blocks.get(blocks.size() - 1).slot(), peer);

        } catch (Exception e) {
            log.debug("[beacon] Chain fill failed from {}: {}", peer, e.getMessage());
        }
    }

    /**
     * One-line snapshot of the peer pool to the log. Intended for periodic
     * calls while debugging why SYNCED isn't being reached — surfaces how many
     * peers are in the pool total, how many libp2p has a live connection to,
     * how many of those connected are LC-capable, and how many are Lodestar
     * (currently excluded from use for debugging purposes).
     */
    private void logPeerPoolStats() {
        int poolTotal;
        int excludedPool = 0;
        synchronized (clPeerMultiaddrs) {
            poolTotal = clPeerMultiaddrs.size();
            if (EXCLUDED_AGENT_SUBSTRING != null) {
                for (String p : clPeerMultiaddrs) {
                    String a = p2pService.cachedAgent(p);
                    if (a != null && a.toLowerCase().contains(EXCLUDED_AGENT_SUBSTRING)) excludedPool++;
                }
            }
        }
        List<BeaconP2PService.PeerInfo> connected = p2pService.getConnectedPeers();
        long lcConnected = connected.stream().filter(BeaconP2PService.PeerInfo::supportsLightClient).count();
        long lodestarConnected = connected.stream()
                .filter(p -> p.agentVersion() != null
                        && p.agentVersion().toLowerCase().contains("lodestar"))
                .count();
        log.info("[beacon] peer-pool: total={} excluded={} connected={} connected-lc={} connected-lodestar={}",
                poolTotal, excludedPool, connected.size(), lcConnected, lodestarConnected);
    }

    /** Thread-safe snapshot of the peer list, with the agent-exclusion filter applied. */
    private List<String> copyPeers() {
        return copyPeers(true);
    }

    /**
     * Thread-safe snapshot of the peer list.
     *
     * @param applyAgentFilter when false, the {@link #EXCLUDED_AGENT_SUBSTRING}
     *     agent filter is bypassed. Used by catch-up / finality polling so
     *     that the one Lodestar peer we keep as a reliable fallback can
     *     actually serve us after the Lighthouse/Teku handshake debug is
     *     done — excluding it there just causes beaconStale on a stale
     *     hardcoded seed list.
     */
    private List<String> copyPeers(boolean applyAgentFilter) {
        synchronized (clPeerMultiaddrs) {
            List<String> all = List.copyOf(clPeerMultiaddrs);
            if (!applyAgentFilter || EXCLUDED_AGENT_SUBSTRING == null) {
                return orderByLightClient(all);
            }
            // Drop peers whose Identify agent matches the exclusion substring.
            // Useful for isolating debugging: pretending Lodestar doesn't exist
            // forces us to actually get Lighthouse/Teku/Nimbus/Prysm working.
            List<String> filtered = new ArrayList<>(all.size());
            for (String p : all) {
                String agent = p2pService.cachedAgent(p);
                if (agent != null && agent.toLowerCase().contains(EXCLUDED_AGENT_SUBSTRING)) {
                    continue;
                }
                filtered.add(p);
            }
            return orderByLightClient(filtered);
        }
    }

    /** Confirmed light_client servers first, proven non-LC peers last, rest in between —
     *  so finality polls / bootstrap hit peers that actually serve light-client first.
     *  Within the confirmed tier, most-recently-served first: a server that answered
     *  seconds ago is almost certainly still good, so any bounded slice (the finality
     *  fan-out window, catch-up batches) contains it even when the proven set is large
     *  and littered with servers that are flagged LC-capable but currently at capacity. */
    private List<String> orderByLightClient(List<String> peers) {
        if (provenLightClient.isEmpty() && peersNoLcUpdates.isEmpty()) return peers;
        List<String> first = new ArrayList<>(), mid = new ArrayList<>(), last = new ArrayList<>();
        for (String p : peers) {
            if (provenLightClient.contains(p)) first.add(p);
            else if (peersNoLcUpdates.contains(p)) last.add(p);
            else mid.add(p);
        }
        if (first.size() > 1 && !recentServes.isEmpty()) {
            // recentServes prunes to a 60s window, so "recently served" decays on its
            // own; never-served proven peers sort after all recent servers, keeping
            // their existing relative order (sort is stable). Snapshot the timestamps
            // BEFORE sorting: recentServes mutates concurrently (bootstrap-callback
            // successes, status-thread prunes), and a comparator over live state can
            // trip TimSort's consistency check mid-sort.
            final java.util.HashMap<String, Long> at = new java.util.HashMap<>();
            for (String p : first) {
                String pid = peerIdOf(p);
                Long t = recentServes.get(pid != null ? pid : p);
                if (t != null) at.put(p, t);
            }
            first.sort(java.util.Comparator.comparingLong(
                    (String p) -> at.getOrDefault(p, Long.MIN_VALUE)).reversed());
        }
        List<String> out = new ArrayList<>(peers.size());
        out.addAll(first); out.addAll(mid); out.addAll(last);
        return out;
    }

    /** The peerId in a {@code .../p2p/<peerId>[/...]} multiaddr, or null. Strips any
     *  trailing components (e.g. circuit-relay) after the peerId, like
     *  {@code BeaconP2PService.extractPeerId}. */
    private static String peerIdOf(String multiaddr) {
        int i = multiaddr.lastIndexOf("/p2p/");
        if (i < 0) return null;
        String pid = multiaddr.substring(i + 5);
        int slash = pid.indexOf('/');
        return slash >= 0 ? pid.substring(0, slash) : pid;
    }

    /**
     * Case-insensitive substring that excludes a peer from the usable pool if
     * its Identify agent string contains it. Set to {@code null} to disable.
     * Was temporarily set to {@code "lodestar"} to force catch-up / finality
     * through Lighthouse/Teku/Prysm/Nimbus while debugging why non-Lodestar
     * peers wouldn't talk to us — root cause turned out to be the EIP-7892
     * fork_digest mismatch (fixed via NetworkConfig.currentForkDigestOverride).
     * Filter is now off; all clients are usable.
     */
    private static final String EXCLUDED_AGENT_SUBSTRING = null;

    /**
     * Return peers with {@code preferred} moved to the front if it is in the list.
     * Used by catch-up and finality-update polling to try the last bootstrap-success
     * peer first — it just proved it is reachable and serves light-client protocols.
     */
    private List<String> peersPrioritized(String preferred) {
        return peersPrioritized(preferred, true);
    }

    private List<String> peersPrioritized(String preferred, boolean applyAgentFilter) {
        List<String> peers = copyPeers(applyAgentFilter);
        if (preferred == null || !peers.contains(preferred)) return peers;
        List<String> reordered = new java.util.ArrayList<>(peers.size());
        reordered.add(preferred);
        for (String p : peers) {
            if (!p.equals(preferred)) reordered.add(p);
        }
        return reordered;
    }

    private void notifyPeerFailure(String peer) {
        if (onPeerFailure != null && peer != null) {
            try {
                onPeerFailure.accept(peer);
            } catch (Exception e) {
                log.debug("[beacon] Peer failure callback failed: {}", e.getMessage());
            }
        }
    }

    /** peerId (or the full multiaddr when it has no /p2p/ component) → nanoTime of the
     *  last successful light-client response. Backs {@link #recentlyServedPeerCount()};
     *  pruned on both read and write so it stays bounded even when nothing polls status.
     *  nanoTime, not currentTimeMillis: an NTP step / user clock change must not empty
     *  or inflate the window. */
    private final java.util.concurrent.ConcurrentHashMap<String, Long> recentServes =
            new java.util.concurrent.ConcurrentHashMap<>();
    private static final long SERVED_WINDOW_NANOS = 60_000_000_000L;

    /**
     * Distinct peers that successfully served a light-client response (bootstrap,
     * updates-by-range, finality update) within the last minute. Connections are
     * short-lived on the serve path, so this — not the instantaneous connection
     * count — is the "is anyone feeding us updates?" signal status surfaces show.
     */
    public int recentlyServedPeerCount() {
        pruneRecentServes();
        return recentServes.size();
    }

    private void pruneRecentServes() {
        long cutoff = System.nanoTime() - SERVED_WINDOW_NANOS;
        // Two-arg remove, not values().removeIf: Android's libcore CHM (< API 33) falls
        // back to iterator removal there, which could drop an entry a concurrent
        // notifyPeerSuccess just refreshed.
        for (var e : recentServes.entrySet()) {
            Long t = e.getValue();
            if (t - cutoff < 0) recentServes.remove(e.getKey(), t);
        }
    }

    private void notifyPeerSuccess(String peer) {
        if (peer != null) {
            String pid = peerIdOf(peer);
            recentServes.put(pid != null ? pid : peer, System.nanoTime());
            pruneRecentServes();
        }
        if (onPeerSuccess != null) {
            try {
                onPeerSuccess.accept(peer);
            } catch (Exception e) {
                log.debug("[beacon] Peer success callback failed: {}", e.getMessage());
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * Enforce the trust anchor: the bootstrap header we're about to pin our
     * sync-committee belief on must hash to the committed checkpointRoot.
     *
     * <p>Without this, an adversary-controlled endpoint (or a peer ignoring
     * our request argument) could serve an internally-consistent bootstrap
     * for a different block they control, and every subsequent merkle/BLS
     * verification would be anchored to that forged header. Compare against
     * {@code hash_tree_root(header)} before any other processing.
     *
     * @throws IllegalStateException if the header root does not match
     */
    static void verifyCheckpointPin(BeaconBlockHeader header, byte[] checkpointRoot) {
        byte[] headerRoot = header.hashTreeRoot();
        if (!Arrays.equals(headerRoot, checkpointRoot)) {
            throw new IllegalStateException(
                    "bootstrap header root 0x" + bytesToHex(headerRoot)
                            + " does not match checkpointRoot 0x" + bytesToHex(checkpointRoot));
        }
    }

    // -------------------------------------------------------------------------
    // AutoCloseable
    // -------------------------------------------------------------------------

    /**
     * Stop the sync loop and shut down the libp2p host.
     */
    @Override
    public void close() {
        running = false;
        Thread t = syncThread;
        if (t != null) {
            t.interrupt();
            // Wait briefly for the sync thread to notice the interrupt
            try {
                t.join(2_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        // Persist final verified state so the next launch resumes from here.
        persistSnapshot();
        try {
            p2pService.close();
        } catch (Throwable e) {
            // close-after-pause: the libp2p host is already stopped — not fatal.
            log.warn("[beacon] p2p close: {}", e.toString());
        }
        catchUpExecutor.shutdownNow();
        log.info("[beacon] Light client stopped");
    }

    // -------------------------------------------------------------------------
    // Accessors (for testing / status reporting)
    // -------------------------------------------------------------------------

    /** Returns the underlying light client store. */
    public LightClientStore getStore() {
        return store;
    }

    /** Returns true if the light client has successfully bootstrapped. */
    public boolean isBootstrapped() {
        return store.isInitialized();
    }

    /** Returns true if the sync loop is running. */
    public boolean isRunning() {
        return running;
    }

    /** Returns info about connected CL peers including their protocol support. */
    public List<BeaconP2PService.PeerInfo> getConnectedPeers() {
        return p2pService.getConnectedPeers();
    }
}
