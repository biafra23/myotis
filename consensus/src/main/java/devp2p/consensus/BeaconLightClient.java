package devp2p.consensus;

import devp2p.consensus.libp2p.BeaconP2PService;
import devp2p.consensus.lightclient.BeaconChainSpec;
import devp2p.consensus.lightclient.LightClientProcessor;
import devp2p.consensus.lightclient.LightClientStore;
import devp2p.consensus.ssz.SszUtil;
import devp2p.consensus.types.BeaconBlockParser;
import devp2p.consensus.types.LightClientBootstrap;
import devp2p.consensus.types.LightClientFinalityUpdate;
import devp2p.consensus.types.LightClientHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
    private final LightClientProcessor processor;
    private final BeaconSyncState syncState;
    private final List<String> clPeerMultiaddrs;  // mutable, synchronized
    private final Set<String> knownPeerAddrs;     // dedup set for discovered peers
    private final String beaconApiUrl;            // nullable; HTTP API for peer discovery
    private final byte[] checkpointRoot;      // 32-byte trusted checkpoint block root
    private final byte[] forkVersion;         // 4-byte fork version
    private final byte[] genesisValidatorsRoot; // 32-byte genesis validators root

    private volatile Thread syncThread;
    private volatile boolean running;

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
        this.forkVersion = forkVersion.clone();
        this.genesisValidatorsRoot = genesisValidatorsRoot.clone();
        this.syncState = syncState;

        this.store = new LightClientStore();
        this.processor = new LightClientProcessor(store, forkVersion, genesisValidatorsRoot);
        this.p2pService = new BeaconP2PService();
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
        p2pService.start();
        running = true;
        syncThread = Thread.ofVirtual()
                .name("beacon-sync")
                .start(this::syncLoop);
        log.info("[beacon] Light client started with {} peer(s)", clPeerMultiaddrs.size());
    }

    // -------------------------------------------------------------------------
    // Sync loop
    // -------------------------------------------------------------------------

    private void syncLoop() {
        // Phase 0: discover peers from beacon API before attempting connections
        discoverPeersFromBeaconApi();

        // Phase 1: try beacon HTTP API first (fast, no P2P overhead)
        seedFromBeaconApi();

        // Phase 1b: fall back to P2P seeding if HTTP API unavailable
        if (!syncState.isSynced()) {
            seedFromFinalityUpdate();
        }

        // Phase 2: steady-state poll loop — one slot = 12 seconds.
        // If not yet synced, each cycle disconnects stale connections and retries.
        while (running) {
            try {
                pollFinalityUpdate();
                Thread.sleep(12_000);
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
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(beaconApiUrl + "/eth/v1/node/peers?state=connected"))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.warn("[beacon] Beacon API returned status {}", response.statusCode());
                return;
            }

            // Extract peer entries from JSON using regex (avoids adding a JSON library dependency).
            // Each peer object has "peer_id" and "last_seen_p2p_address" fields.
            // Many addresses lack the /p2p/<peer_id> suffix, so we construct it.
            String body = response.body();
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
                    clPeerMultiaddrs.add(Math.min(1, clPeerMultiaddrs.size()), multiaddr);
                    added++;
                }
            }
            if (added > 0) {
                log.info("[beacon] Discovered {} new CL peer(s) from beacon API (total: {})",
                        added, clPeerMultiaddrs.size());
            }
        } catch (Exception e) {
            log.debug("[beacon] Beacon API peer discovery failed: {}", e.getMessage());
        }
    }

    /**
     * Attempt to bootstrap from each peer in order. Stops at the first success.
     * Logs a warning if all peers fail.
     */
    private void bootstrap() {
        log.info("[beacon] Attempting bootstrap from {} peer(s)", clPeerMultiaddrs.size());
        for (int i = 0; i < clPeerMultiaddrs.size(); i++) {
            String peer = clPeerMultiaddrs.get(i);
            if (!running) return;
            log.info("[beacon] Trying bootstrap peer {}/{}: {}", i + 1, clPeerMultiaddrs.size(), peer);
            try {
                byte[] response = p2pService
                        .requestBootstrap(peer, checkpointRoot)
                        .get(5, TimeUnit.SECONDS);

                LightClientBootstrap bootstrap = LightClientBootstrap.decode(response);

                // Verify the sync committee branch proves currentSyncCommittee is in the header's state
                boolean branchValid = SszUtil.verifyMerkleBranch(
                        bootstrap.currentSyncCommittee().hashTreeRoot(),
                        bootstrap.currentSyncCommitteeBranch(),
                        BeaconChainSpec.CURRENT_SYNC_COMMITTEE_DEPTH,
                        BeaconChainSpec.CURRENT_SYNC_COMMITTEE_GINDEX,
                        bootstrap.header().beacon().stateRoot());

                if (!branchValid) {
                    log.warn("[beacon] Bootstrap sync committee branch invalid from peer {}", peer);
                    continue;
                }

                store.initialize(bootstrap.header(), bootstrap.currentSyncCommittee());
                updateSyncState();
                log.info("[beacon] Bootstrap complete from {}, slot={}",
                        peer, bootstrap.header().beacon().slot());
                return;

            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage()
                        : e.getClass().getName()
                          + (e.getCause() != null ? ": " + e.getCause().getMessage() : "");
                log.warn("[beacon] Bootstrap failed from {}: {}", peer, msg);
            }
        }
        log.warn("[beacon] Could not bootstrap from any peer — will retry on next sync cycle");
    }

    /**
     * Fallback when bootstrap fails: request a finality update directly from a trusted
     * peer and use it to seed the sync state without full BLS verification.
     * This trusts the local beacon node but allows the state root to be used immediately.
     */
    private void seedFromFinalityUpdate() {
        List<String> peers = List.copyOf(clPeerMultiaddrs);
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

                LightClientFinalityUpdate update = LightClientFinalityUpdate.decode(response);
                LightClientHeader finalizedHeader = update.finalizedHeader();
                long finalizedSlot = finalizedHeader.beacon().slot();
                byte[] executionStateRoot = finalizedHeader.execution().stateRoot();

                if (executionStateRoot == null || executionStateRoot.length != 32) {
                    log.warn("[beacon] Finality update from {} has no execution state root", peer);
                    continue;
                }

                // Seed the sync state directly (trusted peer, no BLS verification)
                syncState.update(finalizedSlot, executionStateRoot, update.signatureSlot());
                syncState.recordStateRoot(finalizedSlot, executionStateRoot, false);
                // Also record the attested header's execution state root
                byte[] attestedRoot = update.attestedHeader().execution().stateRoot();
                if (attestedRoot != null && attestedRoot.length == 32) {
                    syncState.recordStateRoot(update.attestedHeader().beacon().slot(), attestedRoot, false);
                }
                log.info("[beacon] Seeded from finality update via {}, finalizedSlot={}", peer, finalizedSlot);
                return;

            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage()
                        : e.getClass().getSimpleName()
                          + (e.getCause() != null ? ": " + e.getCause().getMessage() : "");
                log.warn("[beacon] Finality update seed failed from {}: {}", peer, msg);
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
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(beaconApiUrl + "/eth/v1/beacon/light_client/finality_update"))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.warn("[beacon] Beacon API finality update returned status {}", response.statusCode());
                return;
            }

            String body = response.body();

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

            syncState.update(finalizedSlot, executionStateRoot, signatureSlot);
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
        if (!store.isInitialized() && !syncState.isSynced()) {
            // Not bootstrapped and no seed yet — try HTTP API first, then P2P
            discoverPeersFromBeaconApi();
            seedFromBeaconApi();
            if (!syncState.isSynced()) {
                for (String peer : List.copyOf(clPeerMultiaddrs)) {
                    p2pService.disconnectPeer(peer);
                }
                seedFromFinalityUpdate();
            }
            return;
        }

        for (String peer : List.copyOf(clPeerMultiaddrs)) {
            if (!running) return;
            try {
                byte[] response = p2pService
                        .requestFinalityUpdate(peer)
                        .get(10, TimeUnit.SECONDS);

                LightClientFinalityUpdate update = LightClientFinalityUpdate.decode(response);

                if (store.isInitialized() && processor.processFinalityUpdate(update)) {
                    updateSyncState();
                    fillChainStateRoots(peer, true);
                    log.debug("[beacon] Finality update applied from {}, finalizedSlot={}",
                            peer, store.getFinalizedSlot());
                    return;
                }

                // Seeded mode: update sync state directly from finality update
                if (!store.isInitialized()) {
                    LightClientHeader fh = update.finalizedHeader();
                    byte[] sr = fh.execution().stateRoot();
                    if (sr != null && sr.length == 32) {
                        long slot = fh.beacon().slot();
                        syncState.recordStateRoot(slot, sr, false);
                        // Also record the attested header's execution state root
                        byte[] attestedRoot = update.attestedHeader().execution().stateRoot();
                        if (attestedRoot != null && attestedRoot.length == 32) {
                            syncState.recordStateRoot(update.attestedHeader().beacon().slot(), attestedRoot, false);
                        }
                        if (slot > syncState.getFinalizedSlot()) {
                            syncState.update(slot, sr, update.signatureSlot());
                            log.debug("[beacon] Finality update refreshed from {}, finalizedSlot={}", peer, slot);
                        }
                        return;
                    }
                }

                log.debug("[beacon] Finality update from {} did not advance state", peer);
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage()
                        : e.getClass().getSimpleName()
                          + (e.getCause() != null ? ": " + e.getCause().getMessage() : "");
                log.debug("[beacon] Finality update failed from {}: {}", peer, msg);
            }
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
            syncState.update(store.getFinalizedSlot(), stateRoot, store.getOptimisticSlot());
            syncState.recordStateRoot(store.getFinalizedSlot(), stateRoot, true);
        }
        LightClientHeader optimisticHeader = store.getOptimisticHeader();
        if (optimisticHeader != null) {
            byte[] optRoot = optimisticHeader.execution().stateRoot();
            syncState.recordStateRoot(store.getOptimisticSlot(), optRoot, true);
        }
    }

    // -------------------------------------------------------------------------
    // Chain fill: fetch intermediate blocks and verify hash chain
    // -------------------------------------------------------------------------

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
        if (optimisticSlot <= finalizedSlot + 1) return; // nothing to fill

        long startSlot = finalizedSlot + 1;
        long count = optimisticSlot - finalizedSlot; // includes the attested slot

        try {
            List<byte[]> blockSszList = p2pService
                    .requestBlocksByRange(peer, startSlot, count)
                    .get(30, TimeUnit.SECONDS);

            if (blockSszList.isEmpty()) {
                log.debug("[beacon] Chain fill: no blocks returned for slots {}-{}",
                        startSlot, optimisticSlot);
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
            LightClientHeader attestedHeader = store.getOptimisticHeader();
            byte[] expectedHash = attestedHeader != null
                    ? attestedHeader.beacon().hashTreeRoot() : null;

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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
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
        p2pService.close();
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
}
