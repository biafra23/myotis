package com.jaeckel.ethp2p.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService;
import com.jaeckel.ethp2p.consensus.proof.MerklePatriciaVerifier;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv5.DiscV5Service;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;

import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Foreground service that runs the ethp2p node — a stripped-down port of
 * {@code Main.runDaemon}: discv4 discovery + RLPx connector, no IPC, no beacon
 * client. Enough to verify peer discovery and handshakes work on Android.
 */
public final class NodeService extends Service {

    private static final String TAG = "ethp2p.node";
    private static final String CHANNEL_ID = "ethp2p_node";
    private static final int NOTIFICATION_ID = 1;
    private static final int DEFAULT_PORT = 30303;
    private static final long BACKOFF_INCOMPATIBLE_MS = 10 * 60 * 1000L;
    private static final long BACKOFF_TRANSIENT_MS = 30 * 1000L;
    // Dial cap: the JVM daemon allows 2000, which is fine on a workstation but
    // abusive on a phone (battery, data, NAT table, file descriptors). attempted
    // is removed only when a peer drops, so this bounds in-flight dial churn.
    private static final int MAX_ATTEMPTED = 200;

    // Static so MainActivity can reflect the correct button state after a
    // configuration change — the activity instance is recreated, but the
    // service process (and this flag) outlive it.
    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);

    public static boolean isRunning() {
        return RUNNING.get();
    }

    // Promoted from startNode() locals so snapshot() can read them while the
    // Netty threads mutate them concurrently. All three are thread-safe.
    private final Set<String> attempted = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> backoff = new ConcurrentHashMap<>();
    private final Set<String> blacklistedNodeIds = ConcurrentHashMap.newKeySet();

    private DiscV4Service discV4;
    private DiscV5Service discV5;
    private RLPxConnector connector;
    private AndroidPeerCache peerCache;
    private AndroidCLPeerCache clPeerCache;
    private BeaconLightClient beaconLightClient;
    private BeaconSyncState beaconSyncState;
    private long clGenesisTime;
    private volatile int cachedPeerCount;
    private volatile int cachedClPeerCount;
    private volatile long startTimeMs;
    // Eth2-fork-digest-matching peers seen via discv5 since start. Bumped on
    // each ENR match so we can show fork-digest filter progress in the UI even
    // before BLC has connected to anything.
    private final java.util.concurrent.atomic.AtomicInteger clPeersDiscovered =
            new java.util.concurrent.atomic.AtomicInteger();

    private final IBinder binder = new LocalBinder();

    public final class LocalBinder extends Binder {
        public NodeService service() { return NodeService.this; }
    }

    public record Snapshot(
            boolean running,
            long startTimeMs,
            int discoveredPeers,
            int connectedPeers,
            int readyPeers,
            int snapPeers,
            int cachedPeers,
            int attemptedPeers,
            int backedOffPeers,
            int blacklistedPeers,
            int discv5Peers,          // total live nodes in the discv5 routing table
            int clPeersDiscovered,    // discv5 peers whose eth2 field matches our fork digest
            // Beacon light client status (filled in only when BLC is wired up)
            String beaconState,       // "STOPPED", "SYNCING", "CATCHING_UP", "SYNCED"
            boolean beaconBootstrapped,
            int clPeersConnected,
            int clPeersLightClient,
            int clPeersCached,
            long finalizedSlot,
            long executionBlockNumber,
            String executionBlockHashHex, // null until first finality update
            List<RLPxConnector.PeerInfo> readyPeerList) {}

    /** Result of a get-account query. Mirrors the JVM daemon's JSON response shape. */
    public record AccountQueryResult(
            String address,                  // 0x-prefixed checksum-form input
            boolean exists,                  // false when the account isn't in the trie
            long nonce,                      // -1 when !exists
            String balanceWei,               // decimal string (BigInteger.toString); null when !exists
            String storageRootHex,           // null when !exists
            String codeHashHex,              // null when !exists
            long blockNumber,                // peer-reported block number the proof is anchored to
            String peerStateRootHex,         // 0x… root the proof was built against
            boolean peerProofValid,          // proof verifies against peerStateRoot
            boolean beaconChainVerified,     // peerStateRoot matches a beacon-attested root
            boolean blsVerified,             // beacon match was BLS-signed (vs. unverified header)
            long matchedBeaconSlot,          // -1 when not matched
            String verifyMethod,             // "stateRootMatch" or null
            String failReason                // null when verified
    ) {}

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    /**
     * Run a get-account query against any active READY+snap peer and verify
     * the returned proof against the beacon-attested state root window.
     *
     * <p>Only the {@code stateRootMatch} verification path is implemented —
     * the JVM daemon also tries a header-chain fallback when the peer's block
     * is ahead of finalized, but that requires fetching headers via eth/68
     * and verifying their parent chain back to a beacon-known anchor; not
     * worth the porting effort for the POC.
     */
    public CompletableFuture<AccountQueryResult> requestAccount(String hexAddress) {
        if (!RUNNING.get() || connector == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Node is not running"));
        }
        if (hexAddress == null) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Address is required"));
        }
        String hex = hexAddress.strip();
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.length() != 40) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Address must be 20 bytes (40 hex chars)"));
        }
        final String hexAddrFinal = hex;
        Bytes address;
        try {
            address = Bytes.fromHexString(hex);
        } catch (Exception e) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Invalid hex address: " + e.getMessage()));
        }
        Bytes32 accountHash = Hash.keccak256(address);
        BeaconSyncState bss = beaconSyncState;
        return connector.requestAccount(address).thenApply(result ->
                buildAccountResult("0x" + hexAddrFinal, address, accountHash, result, bss));
    }

    private static AccountQueryResult buildAccountResult(String addr,
                                                          Bytes address,
                                                          Bytes32 accountHash,
                                                          AccountRangeMessage.DecodeResult result,
                                                          BeaconSyncState bss) {
        AccountRangeMessage.AccountData found = null;
        for (AccountRangeMessage.AccountData a : result.accounts()) {
            if (a.accountHash().equals(accountHash)) {
                found = a;
                break;
            }
        }
        long nonce = found != null ? found.nonce() : -1;
        String balance = found != null ? found.balance().toString() : null;

        boolean peerProofValid = false;
        if (result.stateRoot() != null && !result.proof().isEmpty()) {
            List<byte[]> proofBytes = new ArrayList<>(result.proof().size());
            for (Bytes b : result.proof()) proofBytes.add(b.toArrayUnsafe());
            peerProofValid = MerklePatriciaVerifier.verify(
                    result.stateRoot().toArrayUnsafe(),
                    address.toArrayUnsafe(),
                    proofBytes, nonce, balance);
        }

        boolean beaconChainVerified = false;
        boolean blsVerified = false;
        long matchedSlot = -1;
        String verifyMethod = null;
        if (bss != null && result.stateRoot() != null) {
            BeaconSyncState.SlottedStateRoot match =
                    bss.findStateRoot(result.stateRoot().toArrayUnsafe());
            if (match != null) {
                beaconChainVerified = true;
                matchedSlot = match.slot();
                blsVerified = match.blsVerified();
                verifyMethod = "stateRootMatch";
            }
        }

        String failReason = null;
        if (!beaconChainVerified) {
            if (result.stateRoot() == null) failReason = "noPeerStateRoot";
            else if (!peerProofValid) failReason = "peerProofInvalid";
            else if (bss == null || !bss.isSynced()) failReason = "beaconNotSynced";
            else failReason = "stateRootMismatch";
        }

        return new AccountQueryResult(
                addr,
                found != null,
                nonce,
                balance,
                found != null ? found.storageRoot().toHexString() : null,
                found != null ? found.codeHash().toHexString() : null,
                result.blockNumber(),
                result.stateRoot() != null ? result.stateRoot().toHexString() : null,
                peerProofValid,
                beaconChainVerified,
                blsVerified,
                matchedSlot,
                verifyMethod,
                failReason);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The system may redeliver onStartCommand (e.g. repeated taps, or a
        // restart race with stopService). Guard so we don't boot two copies
        // of the node racing for the same UDP/TCP ports.
        if (!RUNNING.compareAndSet(false, true)) {
            Log.i(TAG, "start requested but node is already running");
            return START_NOT_STICKY;
        }
        startTimeMs = System.currentTimeMillis();
        // API 34+ requires the foregroundServiceType to be passed here and
        // to match the manifest's <service android:foregroundServiceType="...">
        // declaration. API 29-33 ignore the third arg. minSdk is 29.
        startForeground(NOTIFICATION_ID, buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);

        // Netty boot is blocking-ish; punt off the main thread.
        new Thread(this::startNode, "ethp2p-boot").start();
        return START_NOT_STICKY;
    }

    private void startNode() {
        AndroidPeerCache localCache = null;
        AndroidCLPeerCache localClCache = null;
        RLPxConnector localConnector = null;
        DiscV4Service localDisc = null;
        DiscV5Service localDiscV5 = null;
        BeaconLightClient localBlc = null;
        BeaconSyncState localBeaconState = null;
        int localCachedCount = 0;
        int localCachedClCount = 0;
        long localGenesisTime = 0L;
        try {
            NetworkConfig network = NetworkConfig.byName("mainnet");
            localGenesisTime = network.clGenesisTime();
            Path keyFile = new java.io.File(getFilesDir(), "nodekey.hex").toPath();
            NodeKey nodeKey = NodeKey.loadOrGenerate(keyFile);
            Log.i(TAG, "Node ID: " + nodeKey.nodeId().toHexString());

            Path cacheFile = new java.io.File(getFilesDir(), "peers.cache").toPath();
            localCache = new AndroidPeerCache(cacheFile);
            List<AndroidPeerCache.CachedPeer> cached = localCache.load();
            localCachedCount = cached.size();

            final AndroidPeerCache cacheRef = localCache;
            localConnector = new RLPxConnector(nodeKey, DEFAULT_PORT, network,
                    headers -> {
                        if (!headers.isEmpty()) {
                            Log.i(TAG, "Received " + headers.size() + " block header(s)");
                        }
                    },
                    cacheRef::add);
            final RLPxConnector connectorRef = localConnector;

            // Reconnect cached peers first.
            for (AndroidPeerCache.CachedPeer peer : cached) {
                String peerKey = peer.address().getHostString() + ":" + peer.address().getPort();
                attempted.add(peerKey);
                try {
                    SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(
                            Bytes.fromHexString(peer.publicKeyHex()));
                    connectorRef.connect(peer.address(), pubKey, (incompatible, nodeIdHex) -> {
                        if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                        long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                        backoff.putIfAbsent(peerKey, System.currentTimeMillis() + ms);
                        attempted.remove(peerKey);
                    });
                } catch (Exception e) {
                    Log.w(TAG, "cached peer connect failed: " + e.getMessage());
                    attempted.remove(peerKey);
                }
            }

            localDisc = new DiscV4Service(nodeKey, network.bootnodes(), entry -> {
                if (entry.tcpPort() <= 0 || attempted.size() >= MAX_ATTEMPTED) return;
                String nodeIdHex = entry.nodeId().toHexString();
                if (blacklistedNodeIds.contains(nodeIdHex)) return;
                String peerKey = entry.udpAddr().getHostString() + ":" + entry.tcpPort();
                Long expiry = backoff.get(peerKey);
                if (expiry != null) {
                    if (System.currentTimeMillis() < expiry) return;
                    backoff.remove(peerKey);
                }
                if (!attempted.add(peerKey)) return;
                try {
                    Bytes nodeId = entry.nodeId();
                    if (nodeId.size() != 64) {
                        attempted.remove(peerKey);
                        return;
                    }
                    // discv4 node IDs are the 64-byte uncompressed SECP256K1
                    // public key bytes without the 0x04 prefix.
                    SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(nodeId);
                    InetSocketAddress peerTcp = new InetSocketAddress(
                            entry.udpAddr().getAddress(), entry.tcpPort());
                    connectorRef.connect(peerTcp, pubKey, (incompatible, idHex) -> {
                        if (incompatible) blacklistedNodeIds.add(idHex);
                        long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                        backoff.putIfAbsent(peerKey, System.currentTimeMillis() + ms);
                        attempted.remove(peerKey);
                    });
                } catch (Exception e) {
                    Log.w(TAG, "discovered peer connect failed: " + e.getMessage());
                    attempted.remove(peerKey);
                }
            });

            // discv5 — CL peer discovery. Runs on a separate UDP port from discv4.
            // Callback filters ENRs by eth2 fork digest (current OR prior — same
            // dual-accept behaviour the JVM daemon uses so a mis-pinned current
            // fork doesn't silently discard every peer). Matches are counted,
            // saved to the on-disk CL peer cache, and (once BLC is up) added to
            // its live peer pool via blcRef.
            List<byte[]> acceptedForkDigests = network.acceptedForkDigests();
            // Seed CL peer cache before BLC is constructed so cached peers are
            // available at startup. Cache file lives next to nodekey/peers.cache
            // in the app's filesDir; same eviction-on-failure semantics as JVM.
            Path clCacheFile = new java.io.File(getFilesDir(), "cl-peers.cache").toPath();
            localClCache = new AndroidCLPeerCache(clCacheFile);
            List<String> clCached = localClCache.load();
            localCachedClCount = clCached.size();

            final AndroidCLPeerCache clCacheRef = localClCache;
            final java.util.concurrent.atomic.AtomicReference<BeaconLightClient> blcRef =
                    new java.util.concurrent.atomic.AtomicReference<>();
            localDiscV5 = new DiscV5Service(nodeKey, network.clDiscv5Bootnodes(), enr -> {
                var eth2 = enr.eth2();
                if (eth2.isEmpty()) return;
                byte[] peerDigest = eth2.get().forkDigest();
                boolean match = false;
                for (byte[] accepted : acceptedForkDigests) {
                    if (java.util.Arrays.equals(peerDigest, accepted)) {
                        match = true;
                        break;
                    }
                }
                if (!match) return;
                clPeersDiscovered.incrementAndGet();
                enr.toLibp2pMultiaddr().ifPresent(ma -> {
                    clCacheRef.add(ma);
                    BeaconLightClient blc = blcRef.get();
                    if (blc != null) blc.addPeer(ma);
                });
            });

            // Beacon light client. Same construction shape as Main.runDaemon:
            // seed with cached peers + network's configured CL multiaddrs,
            // attach the cache as success/failure callbacks so live updates
            // reach disk, apply EIP-7892 BPO parameters. Gossipsub stays off
            // (battery cost is steeper on a phone).
            localBeaconState = new BeaconSyncState();
            List<String> clPeers = new ArrayList<>(clCached);
            for (String peer : network.clPeerMultiaddrs()) {
                if (!clPeers.contains(peer)) clPeers.add(peer);
            }
            localBlc = new BeaconLightClient(
                    clPeers,
                    network.checkpointRoot(),
                    network.checkpointSlot(),
                    network.currentForkVersion(),
                    network.genesisValidatorsRoot(),
                    localBeaconState,
                    null,                     // beaconApiUrl: no local beacon node on a phone
                    clCacheRef::add,          // onPeerSuccess
                    clCacheRef::markFailure,  // onPeerFailure
                    network.clGenesisTime());
            localBlc.setBlobParameters(
                    network.activeBlobParamsEpoch(),
                    network.activeBlobParamsMaxBlobs());
            blcRef.set(localBlc);

            // Publish atomically vs. shutdown() — if shutdown won the race
            // while we were constructing, we own every resource above, so we
            // have to close them ourselves instead of letting shutdown do it.
            // disc.start() / blc.start() run inside the same synchronized block
            // so shutdown cannot close the service between publish and start.
            if (!startAndPublish(localCache, localClCache, localConnector, localDisc, localDiscV5,
                    localBlc, localBeaconState, localGenesisTime,
                    localCachedCount, localCachedClCount)) {
                Log.i(TAG, "shutdown raced boot; tearing down constructed resources");
                closeQuietly(localBlc);
                closeQuietly(localDiscV5);
                closeQuietly(localDisc);
                closeQuietly(localConnector);
                return;
            }
            Log.i(TAG, "discv4 started on UDP " + DEFAULT_PORT
                    + (this.discV5 != null ? ", discv5 on UDP 9000" : " (discv5 unavailable)")
                    + ", beacon LC seeded with " + clPeers.size() + " CL peer(s)");
        } catch (Exception e) {
            Log.e(TAG, "node boot failed", e);
            closeQuietly(localBlc);
            closeQuietly(localDiscV5);
            closeQuietly(localDisc);
            closeQuietly(localConnector);
            // Reset state so the button flips back to Start and the user can
            // retry; otherwise RUNNING stays true and the bound Service shell
            // keeps the stale foreground notification visible.
            attempted.clear();
            backoff.clear();
            blacklistedNodeIds.clear();
            cachedPeerCount = 0;
            cachedClPeerCount = 0;
            clGenesisTime = 0L;
            startTimeMs = 0L;
            RUNNING.set(false);
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
        }
    }

    private synchronized boolean startAndPublish(AndroidPeerCache cache,
                                                 AndroidCLPeerCache clCache,
                                                 RLPxConnector conn,
                                                 DiscV4Service disc,
                                                 DiscV5Service disc5,
                                                 BeaconLightClient blc,
                                                 BeaconSyncState beaconState,
                                                 long genesisTime,
                                                 int cachedCount,
                                                 int cachedClCount) throws Exception {
        if (!RUNNING.get()) return false;
        disc.start(DEFAULT_PORT);
        // discv5 only feeds the CL peer cache on Android (BLC also reads from
        // hardcoded multiaddrs and the cached pool), so a start failure
        // (UDP 9000 busy, permission denied, …) must not take down EL or BLC:
        // log and keep going with discV5=null.
        DiscV5Service startedDiscV5 = disc5;
        try {
            disc5.start(9000);
        } catch (Throwable t) {
            Log.w(TAG, "discv5 start failed, continuing without CL discovery: " + t.getMessage());
            closeQuietly(disc5);
            startedDiscV5 = null;
        }
        // blc.start() spins up the libp2p host (TCP) and a sync thread that
        // bootstraps from the first responsive peer, then polls finality every
        // 12s. Throws IllegalStateException if already running, which can't
        // happen here (we just constructed it) — but propagate any startup
        // failure so the caller can tear down cleanly.
        blc.start();
        this.peerCache = cache;
        this.clPeerCache = clCache;
        this.connector = conn;
        this.discV4 = disc;
        this.discV5 = startedDiscV5;
        this.beaconLightClient = blc;
        this.beaconSyncState = beaconState;
        this.clGenesisTime = genesisTime;
        this.cachedPeerCount = cachedCount;
        this.cachedClPeerCount = cachedClCount;
        return true;
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c == null) return;
        try { c.close(); } catch (Exception ignored) {}
    }

    /**
     * Tear down the node from the UI.
     * <p>
     * {@code stopService()} alone does not shut us down, because MainActivity
     * holds a binding with {@code BIND_AUTO_CREATE}: Android keeps the service
     * alive as long as such a binding exists, even after stopService. So we
     * close networking here and drop the foreground notification immediately;
     * the service instance may linger until the activity unbinds, but the node
     * is no longer running.
     */
    public synchronized void shutdown() {
        Log.i(TAG, "shutdown requested from UI");
        RUNNING.set(false);
        // Close BLC first: its libp2p host's outbound dials hold references
        // through to the discv5 callback's blcRef, and the sync thread can
        // be in the middle of an addPeer call when shutdown fires.
        closeQuietly(beaconLightClient);
        beaconLightClient = null;
        beaconSyncState = null;
        closeQuietly(connector);
        connector = null;
        closeQuietly(discV5);
        discV5 = null;
        closeQuietly(discV4);
        discV4 = null;
        peerCache = null;
        clPeerCache = null;
        attempted.clear();
        backoff.clear();
        blacklistedNodeIds.clear();
        cachedPeerCount = 0;
        cachedClPeerCount = 0;
        clGenesisTime = 0L;
        startTimeMs = 0L;
        clPeersDiscovered.set(0);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    /**
     * Wipe the in-memory backoff + blacklist sets and delete the on-disk peer
     * cache. Safe to call while the node is running; the next discv4 hit will
     * refill backoff/blacklist from scratch, and {@link AndroidPeerCache} will
     * recreate the file on the next successful RLPx handshake.
     *
     * <p>Does not touch {@code attempted} — those are live in-flight dials, not
     * a cache, and clearing them would race with the per-peer close callback.
     */
    public void clearCaches() {
        Log.i(TAG, "clearing peer caches from UI");
        backoff.clear();
        blacklistedNodeIds.clear();
        cachedPeerCount = 0;
        cachedClPeerCount = 0;
        if (peerCache != null) {
            peerCache.clear();
        } else {
            // Node is stopped: no live AndroidPeerCache instance exists, so
            // delete the on-disk file directly.
            java.io.File cacheFile = new java.io.File(getFilesDir(), "peers.cache");
            if (cacheFile.exists() && !cacheFile.delete()) {
                Log.w(TAG, "failed to delete " + cacheFile);
            }
        }
        if (clPeerCache != null) {
            clPeerCache.clear();
        } else {
            java.io.File clCacheFile = new java.io.File(getFilesDir(), "cl-peers.cache");
            if (clCacheFile.exists() && !clCacheFile.delete()) {
                Log.w(TAG, "failed to delete " + clCacheFile);
            }
        }
    }

    public Snapshot snapshot() {
        boolean running = RUNNING.get();
        int discv5Live = discV5 != null ? discV5.liveNodeCount() : 0;
        BeaconStats bs = beaconStatsSnapshot();
        if (!running || connector == null) {
            return new Snapshot(running, startTimeMs, 0, 0, 0, 0,
                    cachedPeerCount, attempted.size(), countActiveBackoff(),
                    blacklistedNodeIds.size(), discv5Live, clPeersDiscovered.get(),
                    bs.state, bs.bootstrapped, bs.connected, bs.lc,
                    cachedClPeerCount, bs.finalizedSlot, bs.execBlockNum, bs.execBlockHashHex,
                    List.of());
        }
        List<RLPxConnector.PeerInfo> active = connector.getActivePeers();
        List<RLPxConnector.PeerInfo> ready = new ArrayList<>();
        int snapCount = 0;
        for (RLPxConnector.PeerInfo p : active) {
            if ("READY".equals(p.state())) {
                ready.add(p);
                if (p.snapSupported()) snapCount++;
            }
        }
        // snap peers first, then by clientId. Mirrors peers.sh.
        ready.sort(Comparator
                .comparing(RLPxConnector.PeerInfo::snapSupported).reversed()
                .thenComparing(p -> p.clientId() == null ? "" : p.clientId()));
        int tableSize = discV4 != null ? discV4.table().size() : 0;
        return new Snapshot(true, startTimeMs, tableSize, active.size(), ready.size(), snapCount,
                cachedPeerCount, attempted.size(), countActiveBackoff(),
                blacklistedNodeIds.size(), discv5Live, clPeersDiscovered.get(),
                bs.state, bs.bootstrapped, bs.connected, bs.lc,
                cachedClPeerCount, bs.finalizedSlot, bs.execBlockNum, bs.execBlockHashHex,
                ready);
    }

    /** Per-snapshot beacon view, computed once so the record fields stay consistent. */
    private record BeaconStats(String state, boolean bootstrapped, int connected, int lc,
                               long finalizedSlot, long execBlockNum, String execBlockHashHex) {}

    private BeaconStats beaconStatsSnapshot() {
        BeaconLightClient blc = beaconLightClient;
        BeaconSyncState bss = beaconSyncState;
        if (blc == null || bss == null) {
            return new BeaconStats("STOPPED", false, 0, 0, 0L, 0L, null);
        }
        List<BeaconP2PService.PeerInfo> peers = blc.getConnectedPeers();
        int lc = 0;
        for (BeaconP2PService.PeerInfo p : peers) {
            if (p.supportsLightClient()) lc++;
        }
        byte[] execHash = bss.getExecutionBlockHash();
        String execHashHex = execHash == null ? null
                : org.apache.tuweni.bytes.Bytes.wrap(execHash).toHexString();
        return new BeaconStats(
                bss.getSyncState(clGenesisTime).name(),
                blc.isBootstrapped(),
                peers.size(),
                lc,
                bss.getFinalizedSlot(),
                bss.getExecutionBlockNumber(),
                execHashHex);
    }

    private int countActiveBackoff() {
        // Piggyback a prune on every count: the discv4 callback only clears a
        // backoff entry if the same peer is discovered again, so peers we
        // never see again would leak slots forever. snapshot() polls this
        // every ~2s while the UI is visible, which is plenty of cleanup cadence.
        long now = System.currentTimeMillis();
        int active = 0;
        java.util.Iterator<Map.Entry<String, Long>> it = backoff.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Long> e = it.next();
            if (e.getValue() <= now) it.remove();
            else active++;
        }
        return active;
    }

    @Override
    public synchronized void onDestroy() {
        Log.i(TAG, "Stopping node");
        closeQuietly(beaconLightClient);
        closeQuietly(connector);
        closeQuietly(discV5);
        closeQuietly(discV4);
        RUNNING.set(false);
        super.onDestroy();
    }

    private Notification buildNotification() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "ethp2p node",
                NotificationManager.IMPORTANCE_LOW);
        nm.createNotificationChannel(channel);
        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("ethp2p node running")
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setOngoing(true)
                .build();
    }
}
