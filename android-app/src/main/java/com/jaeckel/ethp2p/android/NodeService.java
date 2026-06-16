package com.jaeckel.ethp2p.android;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Binder;
import android.os.IBinder;
import com.jaeckel.ethp2p.android.log.LogBuffer;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService;
import com.jaeckel.ethp2p.consensus.proof.MerklePatriciaVerifier;
import com.jaeckel.ethp2p.consensus.proof.OrderedTrieRoot;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv5.DiscV5Service;
import com.jaeckel.ethp2p.networking.eth.messages.BlockBodiesMessage;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.eth.messages.Receipt;
import com.jaeckel.ethp2p.networking.eth.messages.TxFeeFields;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;

import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
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
    // Keep a working set of snap peers connected so a verified request almost
    // always finds one even as peers churn. Below this we proactively re-dial
    // known snap peers from the cache (CONFIRMED-quality first, via snapDialRank).
    //
    // 12, not 4: being a snap peer is NOT the same as retaining the state at the
    // head root we anchor. Geth prunes trie state beyond ~128 blocks and snap-serves
    // from a flat layer that lags the head, so at any moment only SOME connected snap
    // peers can serve the current root — the rest fail with StateUnavailable. On-device
    // captures showed eth_call/the confirm-screen Multicall3 sim failing for minutes
    // with several snap peers connected: 4 wasn't a deep enough pool to reliably hold
    // one peer whose retained state covers the head. A deeper pool makes the
    // probe-and-pin build (firstPeerServing / the PEER_HEAD race) far likelier to find
    // a state-servable peer. The daemon holds ~36 organically with no ill effect;
    // 12 lightweight eth/snap connections is a fine bound for a phone actively serving
    // a wallet in the foreground.
    /** Default node snap-peer target; overridable via settings ({@link #snapTarget}). */
    public static final int DEFAULT_SNAP_TARGET = 32;
    /** Live snap-peer target, read from settings at boot; the maintainer reads it each tick
     *  so a settings change applies without a restart. */
    private volatile int targetSnapPeers = DEFAULT_SNAP_TARGET;
    // Same bound the JVM daemon uses (CommandHandler.MAX_HEADER_CHAIN_GAP).
    // Caps how many headers we'll fetch to bridge from the beacon-finalized
    // block to the peer's head — i.e. the maximum gap the headerChain
    // verification path will tolerate. In normal operation the gap is small
    // (snap peers track head, BLC finality lags by ~12.8 minutes ≈ 64 blocks),
    // but the bound has to cover catch-up after the phone wakes from doze.
    private static final int MAX_HEADER_CHAIN_GAP = 8192;
    private static final long HEADER_CHAIN_TIMEOUT_SEC = 60;
    // How many recent blocks below the verified head to scan for a tx in
    // eth_getTransactionReceipt. Kept small to bound the bandwidth/battery cost of the
    // (trustless) body scan on mobile: ~8 blocks ≈ 1.5 min covers a wallet polling a
    // just-submitted tx. A pending/older tx isn't found here and falls through to the
    // proxy. Bodies within the window are fetched concurrently, so latency ≈ one
    // round-trip regardless of the count.
    private static final int RECEIPT_LOOKBACK_BLOCKS = 8;
    // Permissionless mode: do NOT fall back to the (permissioned) upstream proxy. A
    // method we can't answer from cryptographically-verified data ERRORS instead of
    // silently returning unverified upstream data — that is the whole point of Myotis.
    // The proxy was only ever a transition aid to learn what MetaMask calls; the
    // MethodLogger / myotis_rpcCoverage still records every rejected method, so we keep
    // that discovery signal without serving unverified data. Flip to false only for
    // local debugging against an injected upstream.
    private static final boolean STRICT_NO_PROXY = true;
    // Max blocks below the verified head we'll fetch+verify headers for to answer
    // eth_getBlockByNumber by number. "latest" is 1 header; older numbers cost a header
    // range, so bound it (MetaMask asks for "latest" for the fee market anyway).
    private static final int BLOCK_LOOKBACK_MAX = 256;

    // Static so MainActivity can reflect the correct button state after a
    // configuration change — the activity instance is recreated, but the
    // service process (and this flag) outlive it.
    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);

    public static boolean isRunning() {
        return RUNNING.get();
    }

    // ----- Settings (SharedPreferences "ethp2p"), shared by the service + Compose UI -----
    private static final String PREFS_NAME = "ethp2p";
    private static final String K_NETWORK = "network";
    private static final String K_RPC_PORT = "rpcPort";
    private static final String K_SNAP_TARGET = "snapTarget";
    private static final String K_DEEP_POOL = "deepPoolThreshold";
    public static final int DEFAULT_RPC_PORT = 8545;
    // Gnosis defaults to a distinct port so both networks can be added to MetaMask
    // at once: MetaMask refuses to save two RPC endpoints that share the same URL
    // (host:port), so mainnet and Gnosis must not collide on 8545.
    public static final int DEFAULT_RPC_PORT_GNOSIS = 8546;
    public static final int DEFAULT_DEEP_POOL = 16;

    // Active config of the running node, set at boot so the UI can show what's live.
    private volatile String activeNetwork = "mainnet";
    private volatile int activeRpcPort = DEFAULT_RPC_PORT;
    // When true, doShutdown() restarts the service after teardown (network switch /
    // rpc-port change). Set via restartWithCurrentSettings(); avoids the
    // start-before-teardown race against onStartCommand's RUNNING guard.
    private volatile boolean restartAfterShutdown = false;

    private static int clampInt(int v, int lo, int hi, int dflt) {
        if (v < lo || v > hi) return (dflt < lo || dflt > hi) ? lo : dflt;
        return v;
    }
    private static android.content.SharedPreferences prefs(android.content.Context c) {
        return c.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE);
    }
    /**
     * Canonicalize a network name to one {@link NetworkConfig#byName} accepts AND that
     * the per-network helpers (which test {@code "gnosis".equals(network)}) handle
     * consistently. Unknown/corrupt/empty values fall back to mainnet so a bad pref can
     * never crash node startup (byName throws on unknown names) or silently desync the
     * RPC-port/preset selection from the resolved chain.
     */
    private static String canonicalNetwork(String n) {
        if (n == null) return "mainnet";
        switch (n.toLowerCase(java.util.Locale.ROOT)) {
            case "gnosis": case "gbc": case "xdai": return "gnosis";
            case "sepolia": return "sepolia";
            default: return "mainnet";
        }
    }
    /** Selected chain ("mainnet"/"gnosis"/"sepolia"); defaults to mainnet. */
    public static String selectedNetwork(android.content.Context c) {
        return canonicalNetwork(prefs(c).getString(K_NETWORK, "mainnet"));
    }
    public static void setSelectedNetwork(android.content.Context c, String n) {
        prefs(c).edit().putString(K_NETWORK, canonicalNetwork(n)).apply();
    }
    /** Per-network default RPC port: Gnosis → 8546, every other chain → 8545. */
    public static int defaultRpcPort(String network) {
        return "gnosis".equals(network) ? DEFAULT_RPC_PORT_GNOSIS : DEFAULT_RPC_PORT;
    }
    // The RPC port is stored per network so mainnet and Gnosis keep independent
    // ports — a single shared key would force the same URL on both, which is
    // exactly what MetaMask rejects. Mainnet keeps the legacy key (no migration);
    // other chains get a "<key>_<network>" suffix.
    private static String rpcPortKey(String network) {
        return "gnosis".equals(network) ? K_RPC_PORT + "_gnosis" : K_RPC_PORT;
    }
    /** JSON-RPC server port for {@code network} (1024–65535; default per {@link #defaultRpcPort}). */
    public static int rpcPortFor(android.content.Context c, String network) {
        int dflt = defaultRpcPort(network);
        return clampInt(prefs(c).getInt(rpcPortKey(network), dflt), 1024, 65535, dflt);
    }
    /** JSON-RPC server port for the currently selected network. */
    public static int rpcPort(android.content.Context c) {
        return rpcPortFor(c, selectedNetwork(c));
    }
    public static void setRpcPort(android.content.Context c, int p) {
        String net = selectedNetwork(c);
        int dflt = defaultRpcPort(net);
        prefs(c).edit().putInt(rpcPortKey(net), clampInt(p, 1024, 65535, dflt)).apply();
    }
    /** Node snap-peer target (1–128, default 32). */
    public static int snapTarget(android.content.Context c) {
        return clampInt(prefs(c).getInt(K_SNAP_TARGET, DEFAULT_SNAP_TARGET), 1, 128, DEFAULT_SNAP_TARGET);
    }
    public static void setSnapTargetPref(android.content.Context c, int v) {
        prefs(c).edit().putInt(K_SNAP_TARGET, clampInt(v, 1, 128, DEFAULT_SNAP_TARGET)).apply();
    }
    /** UI readiness "deep pool" threshold (1–128, default 16). */
    public static int deepPoolThreshold(android.content.Context c) {
        return clampInt(prefs(c).getInt(K_DEEP_POOL, DEFAULT_DEEP_POOL), 1, 128, DEFAULT_DEEP_POOL);
    }
    public static void setDeepPoolThreshold(android.content.Context c, int v) {
        prefs(c).edit().putInt(K_DEEP_POOL, clampInt(v, 1, 128, DEFAULT_DEEP_POOL)).apply();
    }
    /** Active chain of the running node (for UI display). */
    public String activeNetwork() { return activeNetwork; }

    /** Live-update the snap-peer target (no restart) and persist it. */
    public void setTargetSnapPeers(int v) {
        int c = clampInt(v, 1, 128, DEFAULT_SNAP_TARGET);
        this.targetSnapPeers = c;
        setSnapTargetPref(this, c);
        io.myotis.node.ChainStack s = this.stack;
        if (s != null) s.setTargetSnapPeers(c);   // live-update without a restart
    }
    /** Switch the active chain: persist + restart on the new network. No-op if unchanged & running. */
    public void switchNetwork(String name) {
        setSelectedNetwork(this, name);
        if (RUNNING.get()) {
            if (name.equals(activeNetwork)) return;
            restartWithCurrentSettings();
        } else {
            startForegroundService(new Intent(this, NodeService.class));
        }
    }
    /** Restart the node to pick up settings that bind at boot (e.g. RPC port). */
    public void restartNode() {
        if (RUNNING.get()) restartWithCurrentSettings();
        else startForegroundService(new Intent(this, NodeService.class));
    }
    private void restartWithCurrentSettings() {
        // In-service restart: tear down on a worker but do NOT stopSelf()/stopForeground().
        // Calling startForegroundService() from a background teardown can hit Android 12+
        // background-start restrictions and flickers the notification; instead doShutdown()
        // reboots startNode() in-process once teardown completes (service stays foreground).
        restartAfterShutdown = true;
        RUNNING.set(false);
        new Thread(this::doShutdown, "ethp2p-shutdown").start();
    }
    /** Cache file in getCacheDir(), suffixed by the active (non-mainnet) network so chains don't share state. */
    private java.io.File netCache(String base, String ext) {
        // While running use the booted network; when stopped fall back to the selected
        // network so a clear-cache / reset-sync targets the right files (not mainnet's).
        String n = RUNNING.get() ? activeNetwork : selectedNetwork(this);
        String suffix = (n == null || n.equals("mainnet")) ? "" : "-" + n;
        return new java.io.File(getCacheDir(), base + suffix + ext);
    }


    // The per-network node stack (EL + discv4/5 + beacon LC + verified RPC + the
    // snap-peer maintainer), shared with the :app daemon via :node-core. This replaces
    // the old inline startNode()/startAndPublish()/maintainSnapPeers() copy. Single-
    // network for now (Step 8b); a Map<String,ChainStack> + per-network UI is Step 9.
    private volatile io.myotis.node.ChainStack stack;
    // Serializes a stack's start() against a prior stack's shutdown() so a fast
    // Stop -> Start waits for ports (UDP 30303/9000, RPC) to free instead of failing
    // with bind-in-use — the cross-instance equivalent of the old synchronized
    // startAndPublish()/doShutdown() pair (PR #82's Stop->Start race).
    private final Object bootLock = new Object();

    // Service-lifecycle component handles, populated from the live ChainStack after
    // start() so snapshot()/requestAccount()/resolveEns() keep reading them directly.
    // volatile so readers never see a stale/null reference.
    private volatile DiscV4Service discV4;
    private volatile DiscV5Service discV5;
    private volatile RLPxConnector connector;
    /** Shared verified-RPC backend (head anchoring, snap-proof reads, ENS, fees).
     *  Owned by the ChainStack; mirrored here so resolveEns()/snapshot() read it directly. */
    private volatile io.myotis.rpc.VerifiedRpcBackend rpcBackend;
    // volatile: written on the boot thread, read on the ethp2p-clear-caches worker
    // (doClearCaches) without holding bootLock — without the barrier that thread could
    // see null while the node is running and fall back to deleting live cache files.
    private volatile AndroidPeerCache peerCache;
    private volatile AndroidCLPeerCache clPeerCache;
    private volatile BeaconLightClient beaconLightClient;
    private volatile BeaconSyncState beaconSyncState;
    private volatile long clGenesisTime;
    private volatile int cachedPeerCount;
    private volatile int cachedClPeerCount;
    private volatile long startTimeMs;
    // Eth2-fork-digest-matching peers seen via discv5 since start. Bumped on
    // each ENR match so we can show fork-digest filter progress in the UI even
    // before BLC has connected to anything.
    private final java.util.concurrent.atomic.AtomicInteger clPeersDiscovered =
            new java.util.concurrent.atomic.AtomicInteger();

    // CCIP-Read gateway HTTP is blocking; keep it off the single EVM thread.
    private final java.util.concurrent.ExecutorService ccipPool =
            java.util.concurrent.Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "android-ccip");
                t.setDaemon(true);
                return t;
            });

    // Query-tab history. Lazily created from getFilesDir() so it works even
    // when the node is stopped (the UI can browse/re-run past queries anytime).
    private AndroidQueryHistory queryHistory;

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
            // Sync-committee-period catch-up progress; all -1 until known. UI draws a
            // determinate progress bar from (current - start) / (target - start).
            long syncStartPeriod,
            long syncCurrentPeriod,
            long syncTargetPeriod,
            // Age (ms) of the last verified RPC head, Long.MAX_VALUE if none built yet.
            // The readiness traffic-light's green gate: a recent head means wallet
            // calls serve instead of hitting "no verified head".
            long verifiedHeadAgeMs,
            List<RLPxConnector.PeerInfo> readyPeerList,
            String network) {}            // active chain ("mainnet"/"gnosis")

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
     * the returned proof against the beacon-attested state root.
     *
     * <p>Two verification methods, mirroring the JVM daemon
     * ({@code CommandHandler#buildVerificationJson} for {@code get-account}):
     * <ul>
     *   <li><b>headerChain</b> (load-bearing path) — fetch the contiguous
     *       header range {@code [finalizedBlock .. peerBlock]} via eth/68
     *       from the same peer that served the proof, verify the
     *       parent-hash chain, and require the first header's stateRoot
     *       to equal the BLC-finalized execution stateRoot and the last
     *       header's stateRoot to equal the peer-reported stateRoot. This
     *       is what succeeds in normal operation, because snap peers serve
     *       proofs at their head while the BLC's attested-root window
     *       trails finalized + a few recent optimistic slots.</li>
     *   <li><b>stateRootMatch</b> (fast-path shortcut) — if the peer's
     *       reported stateRoot happens to be one the BLC has already
     *       attested ({@link BeaconSyncState#findStateRoot}), skip the
     *       header fetch entirely. Rare in practice: only fires when the
     *       peer's head briefly aligns with a slot the BLC has just seen.</li>
     * </ul>
     * The shortcut is checked first so that when it does fire we save a
     * round-trip; otherwise we fall through to the headerChain path.
     */
    // CompletableFuture.failedFuture (Java 9, hidden behind Android API 31)
    // and orTimeout (also gated to API 31) are backported to minSdk 29 via
    // desugar_jdk_libs 2.1.3 — see android-app/build.gradle.kts. Lint flags
    // them anyway because its API database doesn't track desugar coverage
    // for every CF method. Suppress at the method level rather than file —
    // a future use of a *genuinely* unbackported API should still trip.
    @SuppressLint("NewApi")
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
        RLPxConnector conn = connector;
        return connector.requestAccount(address).thenCompose(result ->
                buildAccountResult("0x" + hexAddrFinal, address, accountHash, result, bss, conn));
    }

    /**
     * Mutable verification scratchpad. Keeps the two verification methods
     * (headerChain + stateRootMatch) from threading 5 separate parameters
     * through the async chain.
     */
    private static final class Verification {
        boolean beaconChainVerified;
        boolean blsVerified;
        long matchedSlot = -1;
        String verifyMethod;
        String failReason;
    }

    private static CompletableFuture<AccountQueryResult> buildAccountResult(
            String addr,
            Bytes address,
            Bytes32 accountHash,
            AccountRangeMessage.DecodeResult result,
            BeaconSyncState bss,
            RLPxConnector connector) {
        AccountRangeMessage.AccountData found = null;
        for (AccountRangeMessage.AccountData a : result.accounts()) {
            if (a.accountHash().equals(accountHash)) {
                found = a;
                break;
            }
        }
        final AccountRangeMessage.AccountData foundFinal = found;
        long nonce = found != null ? found.nonce() : -1;
        String balance = found != null ? found.balance().toString() : null;

        boolean peerProofValid = false;
        MerklePatriciaVerifier.VerifiedAccount verifiedAcct = null;
        if (result.stateRoot() != null && !result.proof().isEmpty()) {
            List<byte[]> proofBytes = new ArrayList<>(result.proof().size());
            for (Bytes b : result.proof()) proofBytes.add(b.toArrayUnsafe());
            // verifyAndExtractAccount returns the storageRoot/codeHash from the
            // proof-verified leaf — NOT the peer's slim body — so a peer can't
            // forge those two fields while keeping nonce/balance honest.
            verifiedAcct = MerklePatriciaVerifier.verifyAndExtractAccount(
                    result.stateRoot().toArrayUnsafe(),
                    address.toArrayUnsafe(),
                    proofBytes, nonce, balance);
            peerProofValid = (verifiedAcct != null);
        }
        final boolean peerProofValidFinal = peerProofValid;
        final MerklePatriciaVerifier.VerifiedAccount verifiedAcctFinal = verifiedAcct;

        Verification v = new Verification();

        // Fast-path shortcut: if the BLC has already attested the peer's
        // exact stateRoot, we're done — no header fetch needed. Rare, but
        // free to check.
        if (bss != null && result.stateRoot() != null) {
            BeaconSyncState.SlottedStateRoot match =
                    bss.findStateRoot(result.stateRoot().toArrayUnsafe());
            if (match != null) {
                v.beaconChainVerified = true;
                v.matchedSlot = match.slot();
                v.blsVerified = match.blsVerified();
                v.verifyMethod = "stateRootMatch";
                return CompletableFuture.completedFuture(
                        finalizeResult(addr, foundFinal, result, peerProofValidFinal, verifiedAcctFinal, v));
            }
        }

        // Main verification path: headerChain. Walk the failure ladder
        // (mirrors CommandHandler.buildVerificationJson) — only run the
        // fetch + chain verification if every prerequisite holds.
        if (result.stateRoot() == null) {
            v.failReason = "noPeerStateRoot";
        } else if (!peerProofValid) {
            v.failReason = "peerProofInvalid";
        } else if (bss == null || !bss.isSynced()) {
            v.failReason = "beaconNotSynced";
        } else {
            long peerBlockNumber = result.blockNumber();
            // Read block number + state root from one atomic snapshot — reading them via
            // two separate getters can pair a block number with a state root from a
            // different finalized payload if an update lands between the calls.
            BeaconSyncState.FinalizedExecution fin = bss.getFinalizedExecution();
            long finalizedBlock = fin.blockNumber();
            byte[] beaconRoot = fin.stateRoot();

            if (peerBlockNumber <= 0) {
                v.failReason = "noPeerBlockNumber";
            } else if (finalizedBlock <= 0 || beaconRoot == null) {
                v.failReason = "beaconBlockUnavailable";
            } else if (peerBlockNumber <= finalizedBlock) {
                v.failReason = "peerBlockBehindFinalized";
            } else if (peerBlockNumber - finalizedBlock > MAX_HEADER_CHAIN_GAP) {
                v.failReason = "headerChainGapTooLarge";
            } else {
                // headerChain: fetch [finalized .. peerBlock] inclusive
                // from a single peer and verify the chain end-to-end.
                final long finalizedSlot = bss.getFinalizedSlot();
                LogBuffer.i(TAG, "[verify] headerChain: peerBlock=" + peerBlockNumber
                        + ", finalizedBlock=" + finalizedBlock
                        + ", gap=" + (peerBlockNumber - finalizedBlock));
                return verifyHeaderChainBatched(
                                connector, finalizedBlock, peerBlockNumber,
                                beaconRoot, result.stateRoot().toArrayUnsafe())
                        .handle((chainValid, ex) -> {
                            if (ex != null) {
                                LogBuffer.i(TAG, "[verify] headerChain error: " + ex.getMessage());
                                v.failReason = "headerChainError";
                            } else if (Boolean.TRUE.equals(chainValid)) {
                                v.beaconChainVerified = true;
                                v.matchedSlot = finalizedSlot;
                                v.blsVerified = true;
                                v.verifyMethod = "headerChain";
                                v.failReason = null;
                            } else {
                                v.failReason = "headerChainInvalid";
                            }
                            return finalizeResult(addr, foundFinal, result, peerProofValidFinal, verifiedAcctFinal, v);
                        });
            }
        }

        return CompletableFuture.completedFuture(
                finalizeResult(addr, foundFinal, result, peerProofValidFinal, verifiedAcctFinal, v));
    }

    private static AccountQueryResult finalizeResult(String addr,
                                                      AccountRangeMessage.AccountData found,
                                                      AccountRangeMessage.DecodeResult result,
                                                      boolean peerProofValid,
                                                      MerklePatriciaVerifier.VerifiedAccount verified,
                                                      Verification v) {
        long nonce = found != null ? found.nonce() : -1;
        String balance = found != null ? found.balance().toString() : null;
        // storageRoot/codeHash come from the proof-verified leaf when we have it,
        // so they're cryptographically anchored rather than peer-claimed. Fall
        // back to the slim body only when the proof didn't verify — in which case
        // the result is already flagged beaconChainVerified=false.
        String storageRootHex = verified != null
                ? Bytes.wrap(verified.storageRoot()).toHexString()
                : (found != null ? found.storageRoot().toHexString() : null);
        String codeHashHex = verified != null
                ? Bytes.wrap(verified.codeHash()).toHexString()
                : (found != null ? found.codeHash().toHexString() : null);
        return new AccountQueryResult(
                addr,
                found != null,
                nonce,
                balance,
                storageRootHex,
                codeHashHex,
                result.blockNumber(),
                result.stateRoot() != null ? result.stateRoot().toHexString() : null,
                peerProofValid,
                v.beaconChainVerified,
                v.blsVerified,
                v.matchedSlot,
                v.verifyMethod,
                v.failReason);
    }

    /**
     * Fetch headers in a single batch and verify the chain end-to-end.
     * Returns a future that completes with {@code true} iff:
     * <ul>
     *   <li>the first header's stateRoot equals the beacon-finalized root,</li>
     *   <li>the last header's stateRoot equals the peer's reported root,</li>
     *   <li>and every header's hash equals the next header's parentHash.</li>
     * </ul>
     */
    @SuppressLint("NewApi") // CompletableFuture.orTimeout — see requestAccount
    private static CompletableFuture<Boolean> verifyHeaderChainBatched(
            RLPxConnector connector, long finalizedBlock, long peerBlock,
            byte[] beaconStateRoot, byte[] peerStateRoot) {
        long totalLong = peerBlock - finalizedBlock + 1;
        if (totalLong < 2 || totalLong > MAX_HEADER_CHAIN_GAP) {
            LogBuffer.i(TAG, "[verify] headerChain gap " + totalLong
                    + " out of range [2, " + MAX_HEADER_CHAIN_GAP + "]");
            return CompletableFuture.completedFuture(false);
        }
        int total = (int) totalLong;
        LogBuffer.i(TAG, "[verify] Fetching " + total + " headers from #"
                + finalizedBlock + " to #" + peerBlock);
        return connector.requestBlockHeadersBatched(finalizedBlock, total)
                .orTimeout(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS)
                .thenApply(headers -> {
                    boolean valid = verifyHeaderChain(headers, beaconStateRoot, peerStateRoot);
                    LogBuffer.i(TAG, "[verify] Full header chain (" + headers.size()
                            + " blocks) valid: " + valid);
                    return valid;
                });
    }

    /**
     * Pure verification of a contiguous header range. Identical algorithm to
     * {@code CommandHandler#verifyHeaderChain} in the JVM daemon.
     */
    private static boolean verifyHeaderChain(List<BlockHeadersMessage.VerifiedHeader> headers,
                                              byte[] expectedFirstStateRoot,
                                              byte[] expectedLastStateRoot) {
        if (headers.isEmpty()) return false;

        byte[] firstStateRoot = headers.get(0).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(firstStateRoot, expectedFirstStateRoot)) return false;

        byte[] lastStateRoot = headers.get(headers.size() - 1).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(lastStateRoot, expectedLastStateRoot)) return false;

        for (int i = 0; i < headers.size() - 1; i++) {
            Bytes32 currentHash = headers.get(i).hash();
            Bytes32 nextParent = headers.get(i + 1).header().parentHash;
            if (!currentHash.equals(nextParent)) {
                LogBuffer.i(TAG, "[verify] hash chain break at index " + i
                        + ": block #" + headers.get(i).header().number
                        + " hash=" + currentHash.toShortHexString()
                        + " != block #" + headers.get(i + 1).header().number
                        + " parentHash=" + nextParent.toShortHexString());
                return false;
            }
        }
        return true;
    }

    // ---------------------------------------------------------------------
    // ENS resolution + query history
    // ---------------------------------------------------------------------

    private static final long ENS_TIMEOUT_SEC = 60;

    /** Lazily-created, file-backed history of Query-tab inputs. */
    public synchronized AndroidQueryHistory queryHistory() {
        if (queryHistory == null) {
            queryHistory = new AndroidQueryHistory(
                    new java.io.File(getFilesDir(), "query-history.tsv").toPath());
        }
        return queryHistory;
    }

    /**
     * Heuristic: is {@code input} an ENS name (vs a hex address)? A 40-hex
     * string (with or without {@code 0x}) is an address; anything else is an
     * ENS name. Addresses never contain a dot; ENS names do.
     */
    public static boolean looksLikeEnsName(String input) {
        if (input == null) return false;
        String s = input.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        if (s.length() != 40) return true;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return true;
        }
        return false;
    }

    /**
     * Outcome of an ENS forward resolution. {@code addressHex} null if unresolved.
     * {@code beaconVerified} is true when the resolution ran against the
     * beacon-verified finalized state (default), so the name→address mapping is
     * cryptographically anchored; false in PEER_HEAD mode (peer-claimed mapping).
     */
    public record EnsResolution(String name, String addressHex, long blockNumber,
                                boolean beaconVerified, String error) {}

    /**
     * Which state ENS resolution runs against. Defaults to the beacon-verified
     * finalized root so resolved mappings are verified end-to-end; switch to
     * {@link io.myotis.ens.EnsResolutionRoot#PEER_HEAD} for freshest (unverified)
     * data. Library consumers can override via {@link #setEnsResolutionRoot}.
     */
    private volatile io.myotis.ens.EnsResolutionRoot ensResolutionRoot =
            io.myotis.ens.EnsResolutionRoot.AUTO;

    public void setEnsResolutionRoot(io.myotis.ens.EnsResolutionRoot root) {
        if (root != null) this.ensResolutionRoot = root;
    }

    public io.myotis.ens.EnsResolutionRoot getEnsResolutionRoot() {
        return ensResolutionRoot;
    }

    /**
     * Resolve an ENS name to an address by running the ENS contracts in a local
     * Besu EVM over SNAP-verified state — the same stack as the JVM daemon's
     * {@code resolve-ens}. Never throws; failures come back in
     * {@link EnsResolution#error}.
     *
     * <p>In {@link io.myotis.ens.EnsResolutionRoot#AUTO} (default) we resolve
     * against the beacon-verified finalized state first; only if that yields no
     * address (record not yet in finalized state) or errors do we fall back to
     * the peer head (returned marked unverified). See {@link EnsResolutionRoot}.
     */
    @SuppressLint("NewApi") // CompletableFuture.orTimeout — see requestAccount
    public CompletableFuture<EnsResolution> resolveEns(String name) {
        final String trimmed = name == null ? "" : name.trim();
        // Delegate to the shared backend — the AUTO → FINALIZED → PEER_HEAD policy,
        // snap-heavy pause, and CCIP handling all live there now (one impl for daemon
        // + Android). Map its neutral io.myotis.rpc.EnsResolution back to the public
        // NodeService.EnsResolution the UI (MainActivity) consumes.
        io.myotis.rpc.VerifiedRpcBackend b = rpcBackend;
        if (!RUNNING.get() || b == null) {
            return CompletableFuture.completedFuture(
                    new EnsResolution(trimmed, null, -1, false, "node not running"));
        }
        return b.resolveEns(trimmed, ensResolutionRoot)
                .thenApply(r -> new EnsResolution(
                        r.name(), r.addressHex(), r.blockNumber(), r.verified(), r.error()));
    }


    /** DNS server IPs for the active network, for EIP-1459 ENR-tree TXT lookups.
     *  dnsjava has no system resolver config on Android, so we feed it these
     *  explicitly. Returns empty (→ resolver uses public-DNS fallback) on any error. */
    private List<String> activeNetworkDnsServers() {
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            if (cm == null) return List.of();
            Network active = cm.getActiveNetwork();
            if (active == null) return List.of();
            LinkProperties lp = cm.getLinkProperties(active);
            if (lp == null) return List.of();
            List<String> ips = new ArrayList<>();
            for (InetAddress dns : lp.getDnsServers()) {
                ips.add(dns.getHostAddress());
            }
            return ips;
        } catch (Exception e) {
            LogBuffer.w(TAG, "could not read active-network DNS servers: " + e.getMessage());
            return List.of();
        }
    }


    /**
     * Render the whole cause chain, deepest cause included. Library wrappers
     * (e.g. Caffeine throwing {@code IllegalStateException(className)} around a
     * reflective failure) otherwise mask the real Android-incompatibility under
     * a misleading top-level message.
     */
    private static String unwrap(Throwable t) {
        StringBuilder sb = new StringBuilder();
        java.util.Set<Throwable> seen =
                java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (Throwable c = t; c != null && seen.add(c); c = c.getCause()) {
            if (sb.length() > 0) sb.append(" <- ");
            sb.append(c.getClass().getSimpleName());
            if (c.getMessage() != null) sb.append(": ").append(c.getMessage());
        }
        return sb.toString();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The system may redeliver onStartCommand (e.g. repeated taps, or a
        // restart race with stopService). Guard so we don't boot two copies
        // of the node racing for the same UDP/TCP ports.
        if (!RUNNING.compareAndSet(false, true)) {
            LogBuffer.i(TAG, "start requested but node is already running");
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
        io.myotis.node.ChainStack s = null;
        try {
            String netName = selectedNetwork(this);
            NetworkConfig network = NetworkConfig.byName(netName);
            this.activeNetwork = network.name();
            this.activeRpcPort = rpcPort(this);
            LogBuffer.i(TAG, "Booting on network=" + network.name()
                    + " (snap target " + snapTarget(this) + ", rpc port " + activeRpcPort + ")");

            // Identity: legacy mainnet keeps nodekey.hex; other chains get a per-network key
            // so two chains in one process (Step 9) never share an identity.
            Path keyFile = new java.io.File(getFilesDir(),
                    network.name().equals("mainnet") ? "nodekey.hex" : "nodekey-" + network.name() + ".hex").toPath();
            NodeKey nodeKey = NodeKey.loadOrGenerate(keyFile);
            LogBuffer.i(TAG, "Node ID: " + nodeKey.nodeId().toHexString());

            // Reconstructible network state lives in getCacheDir() so "Clear cache" wipes the
            // peer caches + sync snapshot while identity / query history in getFilesDir() survive.
            AndroidPeerCache pc = new AndroidPeerCache(netCache("peers", ".cache").toPath());
            AndroidCLPeerCache cl = new AndroidCLPeerCache(netCache("cl-peers", ".cache").toPath());
            this.peerCache = pc;
            this.clPeerCache = cl;
            this.cachedPeerCount = pc.load().size();
            this.cachedClPeerCount = cl.load().size();

            // Single-network keeps the legacy ports (EL 30303 / discv5 9000) + the per-network
            // RPC port. ChainStack owns discv4/discv5/beacon/RPC and the snap-peer maintainer —
            // the shared :node-core lifecycle, replacing this service's old inline copy.
            io.myotis.node.ChainPorts ports =
                    new io.myotis.node.ChainPorts(DEFAULT_PORT, 9000, activeRpcPort);
            s = new io.myotis.node.ChainStack(
                    network, ports, nodeKey,
                    new AndroidPeerCacheAdapter(pc),
                    new AndroidClPeerCacheAdapter(cl),
                    new com.jaeckel.ethp2p.android.ens.AndroidCcipGateway(ccipPool),
                    netCache("sync-state", ".snapshot").toPath(),
                    /*gossipsub*/ false);
            // Keep snap peers topped up (the discv4-independent path NAT'd mobile needs);
            // Android supplies the active network's DNS servers for EIP-1459 resolution.
            s.configureSnapMaintainer(snapTarget(this), this::activeNetworkDnsServers);
            this.stack = s;

            // Serialize start() against any prior stack's shutdown() so ports are free
            // (the Stop -> Start race PR #82 fixed, now cross-ChainStack-instance).
            boolean started;
            synchronized (bootLock) {
                if (!RUNNING.get()) {            // a Stop raced in while we were constructing
                    LogBuffer.i(TAG, "shutdown raced boot; tearing down constructed stack");
                    s.shutdown();
                    this.stack = null;
                    return;
                }
                started = s.start();
                if (started) {
                    // Publish component handles inside bootLock so they can't be overwritten by a
                    // doShutdown() that raced in after start() returned: doShutdown() nulls these same
                    // fields under bootLock, so either it ran first (we'd see RUNNING==false above and
                    // never get here) or it blocks until we finish — no stale refs to a closed stack.
                    this.connector = s.connector();
                    this.discV4 = s.discV4();
                    this.discV5 = s.discV5();
                    this.beaconLightClient = s.beaconLightClient();
                    this.beaconSyncState = s.beaconSyncState();
                    this.rpcBackend = s.rpcBackend();
                    this.clGenesisTime = network.clGenesisTime();
                }
            }
            if (!started) {
                LogBuffer.e(TAG, "node stack failed to start");
                this.stack = null;
                this.peerCache = null;
                this.clPeerCache = null;
                RUNNING.set(false);
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
                return;
            }
            LogBuffer.i(TAG, "node stack started on " + network.name()
                    + " (EL " + DEFAULT_PORT + ", RPC " + activeRpcPort + ")");
        } catch (Exception e) {
            LogBuffer.e(TAG, "node boot failed", e);
            if (s != null) { try { s.shutdown(); } catch (Throwable ignored) {} }
            this.stack = null;
            this.peerCache = null;
            this.clPeerCache = null;
            RUNNING.set(false);
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
        }
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
    public void shutdown() {
        LogBuffer.i(TAG, "shutdown requested from UI");
        // Flip RUNNING + clear the foreground notification synchronously so
        // the UI button flips and the notification disappears immediately.
        // The expensive close chain (libp2p host.stop().join(), Netty
        // shutdownGracefully, syncThread.join) runs on a worker — doing it
        // on the UI thread blocks main for seconds and ANRs.
        RUNNING.set(false);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
        new Thread(this::doShutdown, "ethp2p-shutdown").start();
    }

    /**
     * Worker-thread close chain. Synchronized so it serializes against
     * {@link #startAndPublish}: a fast Stop → Start sequence will block
     * boot at {@code startAndPublish} until UDP 30303 / 9000 are released,
     * instead of failing with bind-in-use.
     */
    private synchronized void doShutdown() {
        // Tear down the whole stack (RPC server + backend, beacon LC, connector, discv4/5,
        // peer caches) in one call — ChainStack owns the close order. bootLock serializes
        // against a racing startNode() so a Stop -> Start waits for the ports to free.
        io.myotis.node.ChainStack s = this.stack;
        if (s != null) {
            // Null the published handles under the same lock the boot thread publishes them on, so a
            // doShutdown() racing a still-running startNode() can't leave stale refs to a closed stack.
            synchronized (bootLock) {
                try { s.shutdown(); } catch (Throwable ignored) {}
                this.stack = null;
                rpcBackend = null;
                beaconLightClient = null;
                beaconSyncState = null;
                connector = null;
                discV5 = null;
                discV4 = null;
                peerCache = null;
                clPeerCache = null;
            }
        }
        cachedPeerCount = 0;
        cachedClPeerCount = 0;
        clGenesisTime = 0L;
        // NB: do NOT clear startTimeMs here. doShutdown() runs on a worker thread
        // and its teardown takes seconds; a quick Stop -> Start has onStartCommand()
        // flip RUNNING back to true and stamp a fresh startTimeMs while we're still
        // mid-teardown (startNode()'s synchronized startAndPublish blocks on the lock
        // we hold). Writing startTimeMs = 0L here would clobber that fresh stamp, and
        // since the UI shows the uptime row whenever running==true, uptime would jump
        // to now - 0 (~epoch millis) and freeze. startTimeMs is owned by the next
        // start (onStartCommand / the restart branch below both stamp it); the UI
        // only reads it when running, so leaving the old value here is harmless.
        clPeersDiscovered.set(0);
        LogBuffer.i(TAG, "node shutdown complete");
        if (restartAfterShutdown) {
            restartAfterShutdown = false;
            LogBuffer.i(TAG, "restarting node in-service to apply new settings (network/rpc port)");
            // In-service reboot: the foreground service stayed up, so just re-run startNode()
            // — no startForegroundService (avoids Android 12+ background-start limits + notif flicker).
            startTimeMs = System.currentTimeMillis();
            RUNNING.set(true);
            new Thread(this::startNode, "ethp2p-boot").start();
        }
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
        LogBuffer.i(TAG, "clearing peer caches from UI");
        // File deletes are fast in the happy case but still IO; keep the UI
        // thread off them so a slow flash + cache-file fsync can't ANR.
        new Thread(this::doClearCaches, "ethp2p-clear-caches").start();
    }

    private void doClearCaches() {
        // Backoff/blacklist live in the stack now; clear them there so "Clear caches"
        // gives discovery a fresh slate (the on-disk peer caches are wiped below).
        io.myotis.node.ChainStack s = this.stack;
        if (s != null) { s.backoff().clear(); s.blacklistedNodeIds().clear(); }
        cachedPeerCount = 0;
        cachedClPeerCount = 0;
        // Capture references — doShutdown can null these out concurrently
        // if the user taps Clear and Stop in quick succession.
        AndroidPeerCache pc = peerCache;
        if (pc != null) {
            pc.clear();
        } else {
            // Node is stopped: no live AndroidPeerCache instance exists, so
            // delete the on-disk file directly.
            java.io.File cacheFile = netCache("peers", ".cache");
            if (cacheFile.exists() && !cacheFile.delete()) {
                LogBuffer.w(TAG, "failed to delete " + cacheFile);
            }
        }
        AndroidCLPeerCache clpc = clPeerCache;
        if (clpc != null) {
            clpc.clear();
        } else {
            java.io.File clCacheFile = netCache("cl-peers", ".cache");
            if (clCacheFile.exists() && !clCacheFile.delete()) {
                LogBuffer.w(TAG, "failed to delete " + clCacheFile);
            }
        }
    }

    /**
     * Delete the persisted sync-committee snapshot so the next start re-bootstraps
     * from the embedded checkpoint and re-runs the full catch-up. For debugging the
     * bootstrap/catch-up path without wiping peer caches. The running store keeps
     * its in-memory state; this only affects the NEXT start.
     */
    public void resetSyncState() {
        LogBuffer.i(TAG, "resetting persisted sync state from UI");
        new Thread(() -> {
            java.io.File snap = netCache("sync-state", ".snapshot");
            if (snap.exists() && !snap.delete()) {
                LogBuffer.w(TAG, "failed to delete " + snap);
            } else {
                LogBuffer.i(TAG, "sync snapshot cleared; restart to re-bootstrap from checkpoint");
            }
        }, "ethp2p-reset-sync").start();
    }

    public Snapshot snapshot() {
        boolean running = RUNNING.get();
        // Peer-dial bookkeeping moved into ChainStack; read it from the live stack.
        io.myotis.node.ChainStack s = this.stack;
        int attemptedN = s != null ? s.attemptedCount() : 0;
        int backoffN = s != null ? s.backoff().size() : 0;
        int blacklistedN = s != null ? s.blacklistedNodeIds().size() : 0;
        int discv5Live = discV5 != null ? discV5.liveNodeCount() : 0;
        BeaconStats bs = beaconStatsSnapshot();
        if (!running || connector == null) {
            return new Snapshot(running, startTimeMs, 0, 0, 0, 0,
                    cachedPeerCount, attemptedN, backoffN,
                    blacklistedN, discv5Live, clPeersDiscovered.get(),
                    bs.state, bs.bootstrapped, bs.connected, bs.lc,
                    cachedClPeerCount, bs.finalizedSlot, bs.execBlockNum, bs.execBlockHashHex,
                    bs.syncStartPeriod, bs.syncCurrentPeriod, bs.syncTargetPeriod,
                    Long.MAX_VALUE, List.of(), selectedNetwork(this));
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
        io.myotis.rpc.VerifiedRpcBackend backend = rpcBackend;
        long headAge = backend != null ? backend.verifiedHeadAgeMs() : Long.MAX_VALUE;
        return new Snapshot(true, startTimeMs, tableSize, active.size(), ready.size(), snapCount,
                cachedPeerCount, attemptedN, backoffN,
                blacklistedN, discv5Live, clPeersDiscovered.get(),
                bs.state, bs.bootstrapped, bs.connected, bs.lc,
                cachedClPeerCount, bs.finalizedSlot, bs.execBlockNum, bs.execBlockHashHex,
                bs.syncStartPeriod, bs.syncCurrentPeriod, bs.syncTargetPeriod,
                headAge, ready, activeNetwork);
    }

    /** Per-snapshot beacon view, computed once so the record fields stay consistent. */
    private record BeaconStats(String state, boolean bootstrapped, int connected, int lc,
                               long finalizedSlot, long execBlockNum, String execBlockHashHex,
                               // Sync-committee-period catch-up progress (all -1 until known):
                               // start = period catch-up began from, current = period the store
                               // holds now, target = wall-clock period. Lets the UI draw a
                               // determinate progress bar during CATCHING_UP.
                               long syncStartPeriod, long syncCurrentPeriod, long syncTargetPeriod) {}

    private BeaconStats beaconStatsSnapshot() {
        BeaconLightClient blc = beaconLightClient;
        BeaconSyncState bss = beaconSyncState;
        // clGenesisTime is set last in startAndPublish (after blc/bss are visible), so a
        // snapshot can race in with blc/bss non-null but genesis time still 0. Passing 0 to
        // getSyncState computes the period from epoch 0 → a wildly wrong (huge) wall period
        // → misclassified sync state. Treat genesis-not-ready as still STARTING.
        long genesis = clGenesisTime;
        if (blc == null || bss == null) {
            return new BeaconStats("STOPPED", false, 0, 0, 0L, 0L, null, -1, -1, -1);
        }
        if (genesis <= 0L) {
            return new BeaconStats("STARTING", false, 0, 0, 0L, 0L, null, -1, -1, -1);
        }
        List<BeaconP2PService.PeerInfo> peers = blc.getConnectedPeers();
        int lc = 0;
        for (BeaconP2PService.PeerInfo p : peers) {
            if (p.supportsLightClient()) lc++;
        }
        byte[] execHash = bss.getExecutionBlockHash();
        String execHashHex = execHash == null ? null
                : org.apache.tuweni.bytes.Bytes.wrap(execHash).toHexString();
        // Network slot time (Gnosis is 5s, not 12) drives the wall-clock period; without
        // it the target period — and thus the CATCHING_UP/SYNCED classification — is wrong.
        RLPxConnector conn = connector;
        int secondsPerSlot = conn != null ? conn.getNetwork().secondsPerSlot() : 12;
        return new BeaconStats(
                bss.getSyncState(genesis, secondsPerSlot).name(),
                blc.isBootstrapped(),
                peers.size(),
                lc,
                bss.getFinalizedSlot(),
                bss.getExecutionBlockNumber(),
                execHashHex,
                bss.getCatchUpStartPeriod(),
                bss.getCurrentSyncCommitteePeriod(),
                com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec.currentPeriod(genesis, secondsPerSlot));
    }

    @Override
    public void onDestroy() {
        LogBuffer.i(TAG, "Stopping node (onDestroy)");
        // Same fire-and-forget pattern as shutdown(): the system gives us a
        // brief window to return from onDestroy and we don't want to spend
        // it blocking on libp2p host shutdown / Netty graceful drain. The
        // worker holds the same lock as startAndPublish, so a subsequent
        // service start can't race with a half-finished close.
        RUNNING.set(false);
        ccipPool.shutdownNow();
        new Thread(this::doShutdown, "ethp2p-shutdown").start();
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
