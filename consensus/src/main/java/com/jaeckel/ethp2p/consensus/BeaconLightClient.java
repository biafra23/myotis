package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService;
import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.consensus.lightclient.LightClientProcessor;
import com.jaeckel.ethp2p.consensus.lightclient.LightClientStore;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockParser;
import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import com.jaeckel.ethp2p.consensus.types.StatusMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
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
    private final LightClientProcessor processor;
    private final BeaconSyncState syncState;
    private final List<String> clPeerMultiaddrs;  // mutable, synchronized
    private final Set<String> knownPeerAddrs;     // dedup set for discovered peers
    private final String beaconApiUrl;            // nullable; HTTP API for peer discovery
    private final byte[] checkpointRoot;      // 32-byte trusted checkpoint block root
    private final long checkpointSlot;        // slot of trusted checkpoint (for pre-bootstrap Status)
    private final byte[] forkVersion;         // 4-byte fork version
    /**
     * Optional 4-byte override that bypasses the standard fork_digest
     * computation (see {@link #computeForkDigest(byte[])}). Needed post
     * EIP-7892 BPO forks, which change the digest function in a way we
     * haven't implemented yet. Null = compute per legacy formula. Must be
     * set via {@link #setForkDigestOverride(byte[])} before {@link #start()}.
     */
    private volatile byte[] forkDigestOverride;
    private final byte[] genesisValidatorsRoot; // 32-byte genesis validators root
    private final long clGenesisTime;         // beacon chain genesis time (seconds since epoch)
    private final java.util.function.Consumer<String> onPeerSuccess; // nullable; called with multiaddr on success
    private final java.util.function.Consumer<String> onPeerFailure; // nullable; called with multiaddr on failure

    private volatile String lastBootstrapPeer; // multiaddr of the peer that last served a bootstrap; prioritized by catch-up

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
        clPeerMultiaddrs.add(Math.min(1, clPeerMultiaddrs.size()), multiaddr);
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

    // -------------------------------------------------------------------------
    // Sync loop
    // -------------------------------------------------------------------------

    private void syncLoop() {
        // Phase 0: discover peers from beacon API before attempting connections
        discoverPeersFromBeaconApi();

        // Pre-connect to peers and query Identify to learn protocol support.
        // This lets bootstrap() prioritize peers advertising light_client protocols.
        preConnectAndIdentify();

        // Phase 1: bootstrap with BLS verification (strongest trust)
        bootstrap();

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

        // Phase 2: steady-state poll loop — one slot = 12 seconds.
        // If not yet synced, each cycle disconnects stale connections and retries.
        int cycleCount = 0;
        while (running) {
            try {
                // Every 5 cycles (~60s), log pool stats so it's easy to see
                // whether LC-capable peers are accumulating or bleeding off.
                if (++cycleCount % 5 == 0) logPeerPoolStats();
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
     * Pre-connect to all peers and run Identify to discover protocol support.
     * Waits up to 8 seconds for connections + Identify to complete.
     * This ensures bootstrap() can prioritize light-client-capable peers.
     */
    private void preConnectAndIdentify() {
        List<String> peers = copyPeers();
        if (peers.isEmpty()) return;

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

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            // Some peers may have timed out — that's fine
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
            // Use the bootstrap-verified finalized header — the most
            // trustworthy values we have and what peers actually run
            // ancestor-match against.
            var fh = store.getFinalizedHeader();
            headSlot = fh.beacon().slot();
            headRoot = fh.beacon().hashTreeRoot();
            finalizedEpoch = headSlot / 32;
            finalizedRoot = headRoot;
        } else if (checkpointSlot > 0) {
            // Pre-bootstrap: claim the trusted weak-subjectivity checkpoint.
            // We haven't BLS-verified it yet, but it's a real mainnet block
            // root at a known slot, so peers' root_at_epoch check succeeds.
            finalizedEpoch = checkpointSlot / 32;
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
     * {@code fork_digest = SHA256( (fork_version || 28 zero bytes) || genesis_validators_root )[:4]}.
     * Matches {@code NetworkConfig.currentForkDigest()} but computed locally
     * to avoid a networking-module dep inside consensus.
     *
     * <p>If {@link #forkDigestOverride} has been set, returns that instead —
     * needed on mainnet post-EIP-7892 (BPO forks) where the spec's
     * {@code compute_fork_digest} function no longer matches this formula.
     */
    private byte[] computeForkDigest(byte[] fv) {
        if (forkDigestOverride != null) {
            return forkDigestOverride.clone();
        }
        try {
            byte[] buf = new byte[64];
            System.arraycopy(fv, 0, buf, 0, 4);
            System.arraycopy(genesisValidatorsRoot, 0, buf, 32, 32);
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(buf);
            byte[] digest = new byte[4];
            System.arraycopy(hash, 0, digest, 0, 4);
            return digest;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 missing", e);
        }
    }

    /**
     * Set a hardcoded fork_digest to use instead of computing it from
     * {@code fork_version + gvr}. Must be called before {@link #start()}.
     * Pass {@code null} to restore the default computation.
     */
    public void setForkDigestOverride(byte[] digest) {
        if (digest != null && digest.length != 4) {
            throw new IllegalArgumentException("forkDigestOverride must be 4 bytes");
        }
        this.forkDigestOverride = digest == null ? null : digest.clone();
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

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/octet-stream")
                    .GET()
                    .build();
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                log.warn("[beacon] HTTP bootstrap returned status {} from {}", response.statusCode(), url);
                return false;
            }

            byte[] ssz = response.body();
            log.info("[beacon] HTTP bootstrap received {} bytes", ssz.length);

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

            store.initialize(bootstrap.header(), bootstrap.currentSyncCommittee());
            updateSyncState();
            log.info("[beacon] HTTP bootstrap complete, slot={}", bootstrap.header().beacon().slot());
            return true;

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

                            // First valid bootstrap wins — initialize store BEFORE completing
                            // the future so that catchUpSyncCommittee() sees the initialized state.
                            String successPeer = null;
                            synchronized (store) {
                                if (!winnerFuture.isDone()) {
                                    store.initialize(bootstrap.header(), bootstrap.currentSyncCommittee());
                                    updateSyncState();
                                    winnerFuture.complete(response);
                                    successPeer = peer;
                                    lastBootstrapPeer = peer;
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
    /** Max 128-period batches per catch-up call. Bounds wall-clock on very old checkpoints. */
    private static final int MAX_CATCHUP_BATCHES = 8;

    private void catchUpSyncCommittee() {
        // Estimate current period from wall clock, using the network's CL genesis time.
        long now = System.currentTimeMillis() / 1000;
        long currentSlotEstimate = (now - clGenesisTime) / 12;
        long currentPeriod = BeaconChainSpec.computeSyncCommitteePeriod(currentSlotEstimate);

        for (int batch = 0; batch < MAX_CATCHUP_BATCHES && running; batch++) {
            long bootstrapPeriod = BeaconChainSpec.computeSyncCommitteePeriod(store.getFinalizedSlot());
            if (currentPeriod <= bootstrapPeriod) {
                if (batch == 0) {
                    log.info("[beacon] Sync committee is current (period {}), no catch-up needed", bootstrapPeriod);
                }
                return;
            }

            long periodsToFetch = currentPeriod - bootstrapPeriod;
            log.info("[beacon] Sync committee catch-up batch {}: bootstrap period={}, current period={}, fetching {} update(s)",
                    batch, bootstrapPeriod, currentPeriod, periodsToFetch);

            if (!attemptCatchUpBatch(bootstrapPeriod, periodsToFetch, currentSlotEstimate)) {
                log.warn("[beacon] Catch-up batch {} made no progress — will retry on next sync cycle", batch);
                return;
            }
        }

        long finalPeriod = BeaconChainSpec.computeSyncCommitteePeriod(store.getFinalizedSlot());
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
        // {@link BeaconP2PService#doReqResp} detects a dying connection and
        // retries with a fresh one, so we no longer pre-emptively disconnect
        // every peer here — that was costing us Lighthouse/Teku connections
        // that would otherwise have stayed alive and kept our peer score up.
        log.info("[beacon] Catch-up: requesting {} update(s) from period {} across {} usable peer(s)",
                count, bootstrapPeriod, peers.size());

        CompletableFuture<Boolean> winner = new CompletableFuture<>();
        java.util.concurrent.atomic.AtomicInteger remaining =
                new java.util.concurrent.atomic.AtomicInteger(peers.size());
        java.util.concurrent.atomic.AtomicInteger failCount = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger emptyCount = new java.util.concurrent.atomic.AtomicInteger();

        for (String peer : peers) {
            if (!running) return false;
            p2pService.requestUpdatesByRange(peer, bootstrapPeriod, count)
                    .whenComplete((responses, ex) -> {
                        if (ex != null) {
                            Throwable root = ex;
                            while (root.getCause() != null) root = root.getCause();
                            failCount.incrementAndGet();
                            log.debug("[beacon] Catch-up updates_by_range failed from {}: {}",
                                    peer, root.getMessage());
                            notifyPeerFailure(peer);
                            if (remaining.decrementAndGet() == 0 && !winner.isDone()) {
                                winner.complete(false);
                            }
                            return;
                        }
                        // Serialize state mutation; first apply-success wins.
                        synchronized (store) {
                            if (winner.isDone()) return;
                            if (responses == null || responses.isEmpty()) {
                                emptyCount.incrementAndGet();
                                log.debug("[beacon] No updates returned from {}", peer);
                                if (remaining.decrementAndGet() == 0 && !winner.isDone()) {
                                    winner.complete(false);
                                }
                                return;
                            }
                            int applied = applyCatchUpResponses(responses, slotEstimate);
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
                    });
        }

        try {
            boolean result = winner.get(60, TimeUnit.SECONDS);
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
     * Must be called while holding the {@code store} monitor.
     */
    private int applyCatchUpResponses(List<byte[]> responses, long currentSlotEstimate) {
        int applied = 0;
        for (byte[] responseSsz : responses) {
            try {
                LightClientUpdate update = LightClientUpdate.decode(responseSsz);
                if (processor.processUpdate(update)) {
                    applied++;
                    updateSyncState();
                    // Rotate sync committee between updates: finality lags attestation,
                    // so the finalized slot in the update may not cross the period
                    // boundary even though the next update is signed by the new committee.
                    store.forceRotateIfPastPeriod(currentSlotEstimate);
                    log.debug("[beacon] Catch-up: applied update slot={}, store period now={}",
                            update.finalizedHeader().beacon().slot(),
                            BeaconChainSpec.computeSyncCommitteePeriod(store.getFinalizedSlot()));
                } else {
                    log.debug("[beacon] Catch-up update not applied (slot={})",
                            update.finalizedHeader().beacon().slot());
                }
            } catch (Exception e) {
                log.debug("[beacon] Failed to decode/process catch-up update: {}", e.getMessage());
            }
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
        }

        // Honor the Lodestar exclusion — finality polling is part of the
        // debug surface for Lighthouse/Teku/Prysm reliability.
        for (String peer : copyPeers()) {
            if (!running) return;
            try {
                byte[] response = p2pService
                        .requestFinalityUpdate(peer)
                        .get(10, TimeUnit.SECONDS);
                // Relay-cache the raw SSZ so peers who query us get the
                // latest finality update we just received, without having to
                // re-ask upstream.
                p2pService.cacheFinalityUpdate(response);

                LightClientFinalityUpdate update = LightClientFinalityUpdate.decode(response);

                if (store.isInitialized() && processor.processFinalityUpdate(update)) {
                    updateSyncState();
                    fillChainStateRoots(peer, true);
                    notifyPeerSuccess(peer);
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
                        long attestedSlot = update.attestedHeader().beacon().slot();
                        byte[] attestedRoot = update.attestedHeader().execution().stateRoot();
                        if (attestedRoot != null && attestedRoot.length == 32) {
                            syncState.recordStateRoot(attestedSlot, attestedRoot, false);
                        }
                        // Fill intermediate blocks to cover recent state roots
                        byte[] attestedBlockRoot = update.attestedHeader().beacon().hashTreeRoot();
                        log.debug("[beacon] Seeded poll: finalizedSlot={}, attestedSlot={}, filling {} slots",
                                slot, attestedSlot, attestedSlot - slot);
                        fillChainStateRoots(peer, false, slot, attestedSlot, attestedBlockRoot);
                        notifyPeerSuccess(peer);
                        if (slot > syncState.getFinalizedSlot()) {
                            long execBlockNum = fh.execution().blockNumber();
                            byte[] execBlockHash = fh.execution().blockHash();
                            syncState.update(slot, sr, update.signatureSlot(), execBlockNum, execBlockHash);
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
                notifyPeerFailure(peer);
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
            long execBlockNum = finalizedHeader.execution().blockNumber();
            byte[] execBlockHash = finalizedHeader.execution().blockHash();
            syncState.update(store.getFinalizedSlot(), stateRoot, store.getOptimisticSlot(), execBlockNum, execBlockHash);
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
            if (!applyAgentFilter || EXCLUDED_AGENT_SUBSTRING == null) return all;
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
            return filtered;
        }
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

    private void notifyPeerSuccess(String peer) {
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

    /** Returns info about connected CL peers including their protocol support. */
    public List<BeaconP2PService.PeerInfo> getConnectedPeers() {
        return p2pService.getConnectedPeers();
    }
}
