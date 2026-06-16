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
import com.jaeckel.ethp2p.core.enr.Enr;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv5.DiscV5Service;
import com.jaeckel.ethp2p.networking.dns.DnsEnrResolver;
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
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
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
    private static final long BACKOFF_INCOMPATIBLE_MS = 10 * 60 * 1000L;
    private static final long BACKOFF_TRANSIENT_MS = 30 * 1000L;
    // Dial cap: the JVM daemon allows 2000, which is fine on a workstation but
    // abusive on a phone (battery, data, NAT table, file descriptors). attempted
    // is removed only when a peer drops, so this bounds in-flight dial churn.
    private static final int MAX_ATTEMPTED = 200;
    // How many DNS-resolved (EIP-1459) EL enodes to RLPx-dial directly at startup,
    // bypassing discv4. This is the EL discovery path that works on the Android
    // emulator: QEMU/SLIRP user-mode NAT drops the unsolicited inbound discv4 PING
    // that endpoint-proof needs, but allows the outbound RLPx TCP connection these
    // direct dials make. Kept small to bound dial churn on a phone.
    private static final int DNS_DIRECT_DIAL_LIMIT = 30;
    // Per-maintenance-cycle cap for topping up dials from the DNS ENR pool when below
    // the snap-peer target. Keeps churning through the pool (like discv4 would) without
    // a flood; over several 10s cycles it works through the resolved list.
    private static final int DNS_MAINTAIN_DIAL_BATCH = 15;
    // Hard ceiling on sustained DNS-pool dials per rolling minute. The maintainer only
    // tops up while below the snap target, but a NAT-restricted node (mobile CGNAT,
    // emulator) can sit below target indefinitely — without this cap it would dial
    // continuously and drain battery/data and pressure the carrier's NAT table (the
    // very NAT that broke discv4). 60/min keeps progress while staying phone-friendly.
    private static final int DNS_DIALS_PER_MIN = 60;
    // Max ENRs retained in the rolling DNS candidate pool (bounds memory; the mainnet
    // tree has thousands of entries but we only need enough turnover to find open slots).
    private static final int DNS_POOL_MAX = 600;
    // Re-walk the ENR tree at most this often (only while below target) to grow and
    // refresh the candidate pool without hammering DNS.
    private static final long DNS_REFRESH_INTERVAL_MS = 4 * 60 * 1000L;
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
    /** Selected chain ("mainnet"/"gnosis"); defaults to mainnet. */
    public static String selectedNetwork(android.content.Context c) {
        String n = prefs(c).getString(K_NETWORK, "mainnet");
        return (n == null || n.isEmpty()) ? "mainnet" : n;
    }
    public static void setSelectedNetwork(android.content.Context c, String n) {
        prefs(c).edit().putString(K_NETWORK, n).apply();
    }
    /** JSON-RPC server port (1024–65535, default 8545). */
    public static int rpcPort(android.content.Context c) {
        return clampInt(prefs(c).getInt(K_RPC_PORT, DEFAULT_RPC_PORT), 1024, 65535, DEFAULT_RPC_PORT);
    }
    public static void setRpcPort(android.content.Context c, int p) {
        prefs(c).edit().putInt(K_RPC_PORT, clampInt(p, 1024, 65535, DEFAULT_RPC_PORT)).apply();
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

    // Promoted from startNode() locals so snapshot() can read them while the
    // Netty threads mutate them concurrently. All three are thread-safe.
    private final Set<String> attempted = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> backoff = new ConcurrentHashMap<>();
    private final Set<String> blacklistedNodeIds = ConcurrentHashMap.newKeySet();

    // EIP-1459 DNS-resolved EL enodes — a rolling, fork-filtered candidate pool the
    // snap-peer maintainer keeps dialing from. This is the discv4 substitute whenever
    // snap peers run low: on NAT'd hosts (mobile CGNAT, the emulator) discv4 can't
    // bootstrap, so without a replenishing pool the node would never reach enough
    // current-fork mainnet snap peers. Refreshed (re-walked + merged) only while below
    // the snap target, throttled by DNS_REFRESH_INTERVAL_MS, capped at DNS_POOL_MAX.
    private volatile List<Enr> dnsElEnrs = List.of();
    private final AtomicBoolean dnsResolving = new AtomicBoolean(false);
    private volatile long lastDnsResolveMs = 0L;
    private volatile NetworkConfig dnsNetwork;
    // Rolling-minute rate limit for DNS-pool dials (see DNS_DIALS_PER_MIN).
    private volatile long dnsDialWindowStartMs = 0L;
    private final java.util.concurrent.atomic.AtomicInteger dnsDialsInWindow =
            new java.util.concurrent.atomic.AtomicInteger(0);

    // Service-lifecycle fields: written on the start/shutdown worker, read from
    // the Netty event loop, the Ktor IO dispatcher (JSON-RPC backend), and the UI
    // thread (snapshot()). volatile so readers never see a stale/null reference.
    private volatile DiscV4Service discV4;
    private volatile DiscV5Service discV5;
    private volatile RLPxConnector connector;
    private io.myotis.jsonrpc.MyotisRpcServer rpcServer;
    /** Shared verified-RPC backend (head anchoring, snap-proof reads, ENS, fees).
     *  Hosts the RPC server's MyotisRpcBackend and serves resolveEns(). */
    private volatile io.myotis.rpc.VerifiedRpcBackend rpcBackend;
    private java.util.concurrent.ScheduledExecutorService peerMaintainer;
    private AndroidPeerCache peerCache;
    private AndroidCLPeerCache clPeerCache;
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

    /**
     * Keep a working set of snap peers connected ({@link #targetSnapPeers}) so a
     * verified request almost always finds one — the main cause of proxy fallbacks
     * is windows with too few snap peers. When below target we re-dial known snap
     * peers from the cache (discovery refills the rest). NOT gated by isSnapHeavy:
     * we want to maintain peers even while reads are in flight.
     */
    private void startPeerMaintainer() {
        if (peerMaintainer != null) return;
        peerMaintainer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "snap-peer-maintainer");
            t.setDaemon(true);
            return t;
        });
        peerMaintainer.scheduleWithFixedDelay(this::maintainSnapPeers, 5, 10, TimeUnit.SECONDS);
    }

    private void maintainSnapPeers() {
        if (!RUNNING.get()) return;
        // Guard the whole body: an uncaught throw here would make
        // scheduleWithFixedDelay silently stop all future runs.
        try {
            RLPxConnector conn = connector;
            AndroidPeerCache pc = peerCache;
            if (conn == null) return;
            int snapPeers = conn.activeSnapHandlers().size();
            if (snapPeers >= targetSnapPeers) return;
            long now = System.currentTimeMillis();
            LogBuffer.i(TAG, "[peers] " + snapPeers + " snap peer(s) < target " + targetSnapPeers
                    + "; re-dialing cached snap peers + DNS pool");
            // 1) Re-dial known snap peers from the cache, proven snap-servers first
            //    (same ordering as cold start) so a starved node reconnects a
            //    working snap peer before retrying known hangers.
            if (pc != null) {
                List<AndroidPeerCache.CachedPeer> snapCached = new ArrayList<>();
                for (AndroidPeerCache.CachedPeer p : pc.load()) {
                    if (p.snap()) snapCached.add(p);
                }
                snapCached.sort(java.util.Comparator.comparingInt(NodeService::snapDialRank));
                for (AndroidPeerCache.CachedPeer p : snapCached) {
                    try {
                        if (conn.activeSnapHandlers().size() >= targetSnapPeers) break;
                        dialCachedSnapPeer(conn, p, now);
                    } catch (Exception e) {
                        LogBuffer.w(TAG, "[peers] skipping cached peer: " + e.getMessage());
                    }
                }
            }
            // 2) Top up from the DNS-resolved ENR pool — the discv4 substitute whenever
            //    snap peers run low (mobile CGNAT / emulator, where discv4 can't bootstrap
            //    and the cache is thin). Per-cycle batch + a rolling-minute rate cap keep
            //    a permanently-starved node from draining battery/data and pressuring the
            //    carrier NAT; the pool is fork-filtered so dials land on viable peers.
            List<Enr> pool = dnsElEnrs;
            if (!pool.isEmpty() && conn.activeSnapHandlers().size() < targetSnapPeers) {
                int budget = Math.min(DNS_MAINTAIN_DIAL_BATCH, dnsDialBudget());
                int dialed = 0;
                for (Enr enr : pool) {
                    if (dialed >= budget || attempted.size() >= MAX_ATTEMPTED) break;
                    if (dialEnr(conn, enr, now)) {
                        dialed++;
                        dnsDialsInWindow.incrementAndGet();
                    }
                }
                if (dialed > 0) {
                    LogBuffer.i(TAG, "[peers] topped up " + dialed + " dial(s) from DNS ENR pool ("
                            + pool.size() + " known)");
                }
            }
            // 3) Grow/refresh the candidate pool by re-walking the tree — only while
            //    still below target and no more often than DNS_REFRESH_INTERVAL_MS.
            if (conn.activeSnapHandlers().size() < targetSnapPeers
                    && !dnsResolving.get()
                    && System.currentTimeMillis() - lastDnsResolveMs > DNS_REFRESH_INTERVAL_MS) {
                Thread t = new Thread(this::refreshDnsPool, "dns-el-refresh");
                t.setDaemon(true);
                t.start();
            }
        } catch (Throwable t) {
            LogBuffer.e(TAG, "[peers] maintenance loop error", t);
        }
    }

    /**
     * Re-walk the EL ENR trees, fork-filter the result, and merge it into the rolling
     * candidate pool (dedup by enode address, capped at {@link #DNS_POOL_MAX}). Guarded
     * so only one walk runs at a time. forkID filtering keeps the limited dial budget
     * off wrong-chain / stale-fork nodes that would reject us at the eth Status exchange.
     */
    private void refreshDnsPool() {
        NetworkConfig net = dnsNetwork;
        if (net == null || !dnsResolving.compareAndSet(false, true)) return;
        try {
            DnsEnrResolver resolver = new DnsEnrResolver();
            // dnsjava has no system resolver config on Android, so feed it the active
            // network's DNS servers; it falls back to public DNS over TCP if those are
            // dead (the emulator: 10.0.2.3 UDP relay broken, outbound TCP:53 works).
            resolver.setDnsServerIps(activeNetworkDnsServers());
            List<Enr> resolved = resolver.resolveAllFromStrings(
                    net.elEnrTreeUrls(), Duration.ofSeconds(25));
            lastDnsResolveMs = System.currentTimeMillis();

            byte[] ourFork = net.forkIdHash();
            // Keep existing pool entries (keyed by enode address), then merge in newly
            // resolved, fork-compatible ones up to the cap.
            LinkedHashMap<String, Enr> merged = new LinkedHashMap<>();
            for (Enr e : dnsElEnrs) {
                e.tcpAddress().ifPresent(a ->
                        merged.put(a.getHostString() + ":" + a.getPort(), e));
            }
            int added = 0, dropped = 0;
            for (Enr e : resolved) {
                if (merged.size() >= DNS_POOL_MAX) break;
                try {
                    Optional<InetSocketAddress> tcp = e.tcpAddress();
                    if (tcp.isEmpty() || e.publicKey().isEmpty()) continue;
                    // Keep enodes whose advertised fork matches ours, plus those that don't
                    // advertise one (unknown — worth a try). Drop clearly different forks
                    // (wrong chain or stale): they reject us at the eth Status exchange.
                    Optional<byte[]> fork = e.ethForkIdHash();
                    if (fork.isPresent() && !Arrays.equals(fork.get(), ourFork)) { dropped++; continue; }
                    String key = tcp.get().getHostString() + ":" + tcp.get().getPort();
                    if (merged.putIfAbsent(key, e) == null) added++;
                } catch (Exception ex) {
                    dropped++; // malformed ENR — skip, don't abort the refresh
                }
            }
            dnsElEnrs = new ArrayList<>(merged.values());
            LogBuffer.i(TAG, "DNS EL pool: +" + added + " new, " + dropped
                    + " off-fork dropped, " + dnsElEnrs.size() + " total");
        } catch (Exception e) {
            LogBuffer.w(TAG, "DNS EL pool refresh failed: " + e.getMessage());
        } finally {
            dnsResolving.set(false);
        }
    }

    /** Remaining DNS-pool dials allowed in the current rolling minute (see
     *  {@link #DNS_DIALS_PER_MIN}). Resets the window lazily. */
    private int dnsDialBudget() {
        long now = System.currentTimeMillis();
        if (now - dnsDialWindowStartMs >= 60_000L) {
            dnsDialWindowStartMs = now;
            dnsDialsInWindow.set(0);
        }
        return Math.max(0, DNS_DIALS_PER_MIN - dnsDialsInWindow.get());
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

    /** Dial one DNS-resolved (EIP-1459) EL enode over RLPx — the discv4-independent
     *  peer source used on NAT'd hosts (the emulator). Same attempted/backoff/blacklist
     *  bookkeeping as the other dial paths; returns true if a connect was started. */
    private boolean dialEnr(RLPxConnector conn, Enr enr, long now) {
        // Fully guarded (including the ENR accessors below) so a single malformed
        // entry can never abort a caller's dial loop — callers can ignore exceptions.
        String peerKey = null;
        try {
            Optional<InetSocketAddress> tcp = enr.tcpAddress();
            Optional<SECP256K1.PublicKey> pub = enr.publicKey();
            if (tcp.isEmpty() || pub.isEmpty()) return false;
            InetSocketAddress peerTcp = tcp.get();
            peerKey = peerTcp.getHostString() + ":" + peerTcp.getPort();
            Long expiry = backoff.get(peerKey);
            if (expiry != null) {
                if (now < expiry) return false;
                backoff.remove(peerKey);
            }
            if (attempted.size() >= MAX_ATTEMPTED || !attempted.add(peerKey)) return false;
            final String key = peerKey;
            conn.connect(peerTcp, pub.get(), (incompatible, idHex) -> {
                if (incompatible) blacklistedNodeIds.add(idHex);
                long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                backoff.putIfAbsent(key, System.currentTimeMillis() + ms);
                attempted.remove(key);
            }).addListener(future -> {
                // TCP-level failure (timeout/refused): free the slot and back off briefly
                // so a dead enode doesn't pin `attempted` and starve the pool.
                if (!future.isSuccess()) {
                    backoff.putIfAbsent(key, System.currentTimeMillis() + BACKOFF_TRANSIENT_MS);
                    attempted.remove(key);
                }
            });
            return true;
        } catch (Exception e) {
            LogBuffer.w(TAG, "DNS EL dial failed: " + e.getMessage());
            if (peerKey != null) attempted.remove(peerKey);
            return false;
        }
    }

    /** Dial a cached snap peer with the same backoff/blacklist/attempted bookkeeping
     *  the discovery path uses. A dup dial to an already-connected peer is rejected
     *  by the remote and backs off — harmless. */
    private void dialCachedSnapPeer(RLPxConnector conn, AndroidPeerCache.CachedPeer p, long now) {
        String peerKey = p.address().getHostString() + ":" + p.address().getPort();
        Long expiry = backoff.get(peerKey);
        if (expiry != null) {
            if (now < expiry) return;
            backoff.remove(peerKey);
        }
        if (attempted.size() >= MAX_ATTEMPTED || !attempted.add(peerKey)) return;
        try {
            SECP256K1.PublicKey pubKey =
                    SECP256K1.PublicKey.fromBytes(Bytes.fromHexString(p.publicKeyHex()));
            conn.connect(p.address(), pubKey, (incompatible, idHex) -> {
                if (incompatible) blacklistedNodeIds.add(idHex);
                long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                backoff.putIfAbsent(peerKey, System.currentTimeMillis() + ms);
                attempted.remove(peerKey);
            });
        } catch (Exception e) {
            attempted.remove(peerKey);
        }
    }

    /**

    /**
     * Dial-priority rank for a cached peer (lower = dialed first): proven
     * snap-servers, then snap-capable-but-unproven, then known snap hangers, then
     * plain-eth peers. Denied snap peers still outrank non-snap peers — state
     * roots change, so a peer that couldn't serve an old pivot may serve the
     * current head, and it's still snap-capable.
     */
    private static int snapDialRank(AndroidPeerCache.CachedPeer p) {
        if (!p.snap()) return 3;
        return switch (p.snapQuality()) {
            case CONFIRMED -> 0;
            case UNKNOWN -> 1;
            case DENIED -> 2;
        };
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
            NetworkConfig network = NetworkConfig.byName(selectedNetwork(this));
            this.activeNetwork = network.name();
            this.targetSnapPeers = snapTarget(this);
            this.activeRpcPort = rpcPort(this);
            LogBuffer.i(TAG, "Booting on network=" + network.name()
                    + " (snap target " + targetSnapPeers + ", rpc port " + activeRpcPort + ")");
            localGenesisTime = network.clGenesisTime();
            Path keyFile = new java.io.File(getFilesDir(), "nodekey.hex").toPath();
            NodeKey nodeKey = NodeKey.loadOrGenerate(keyFile);
            LogBuffer.i(TAG, "Node ID: " + nodeKey.nodeId().toHexString());

            // Reconstructible network state lives in getCacheDir() (not getFilesDir())
            // so the OS / user "Clear cache" wipes peer caches + sync snapshot and
            // resets bootstrapping, while identity (nodekey) and query history in
            // getFilesDir() survive. cacheDir can also be evicted under storage
            // pressure — harmless, we fall back to the embedded checkpoint.
            Path cacheFile = netCache("peers", ".cache").toPath();
            localCache = new AndroidPeerCache(cacheFile);
            List<AndroidPeerCache.CachedPeer> cached = localCache.load();
            localCachedCount = cached.size();
            // Reconnect snap/1-capable peers first: state queries (get-account /
            // ENS) need a snap peer, and snap peers are a minority of eth peers,
            // so dialing them ahead of plain-eth peers makes queries work sooner
            // after a restart instead of waiting for re-discovery. Within the snap
            // set, peers proven to serve proofs (CONFIRMED) come ahead of unproven
            // ones, and known hangers (DENIED) come last — so a restart converges
            // on a working snap peer instead of re-timing-out the bad ones first.
            cached.sort(java.util.Comparator.comparingInt(NodeService::snapDialRank));

            final AndroidPeerCache cacheRef = localCache;
            localConnector = new RLPxConnector(nodeKey, DEFAULT_PORT, network,
                    headers -> {
                        if (!headers.isEmpty()) {
                            LogBuffer.i(TAG, "Received " + headers.size() + " block header(s)");
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
                    LogBuffer.w(TAG, "cached peer connect failed: " + e.getMessage());
                    attempted.remove(peerKey);
                }
            }

            // EIP-1459 DNS discovery + direct RLPx dial — the discv4-independent peer
            // source used whenever snap peers run low. discv4 can't bootstrap behind a
            // restrictive NAT (mobile CGNAT, the emulator's QEMU/SLIRP): its endpoint
            // proof needs the remote to send us an *unsolicited* inbound PING, which
            // such NATs drop. But the ENR trees give us EL enodes (key + TCP endpoint)
            // directly, and an RLPx dial is an *outbound* TCP connection the NAT allows.
            // Runs on its own thread (resolution can take many seconds) so it never
            // delays discv4/discv5/beacon startup; the maintainer keeps it topped up.
            this.dnsNetwork = network;
            final RLPxConnector dnsConnector = connectorRef;
            Thread dnsDialThread = new Thread(() -> {
                refreshDnsPool();
                long now = System.currentTimeMillis();
                int directDialed = 0;
                for (Enr enr : dnsElEnrs) {
                    if (directDialed >= DNS_DIRECT_DIAL_LIMIT
                            || attempted.size() >= MAX_ATTEMPTED) break;
                    if (dialEnr(dnsConnector, enr, now)) directDialed++;
                }
                LogBuffer.i(TAG, "DNS EL discovery: direct-dialed " + directDialed
                        + " of " + dnsElEnrs.size() + " pooled enode(s) (discv4-independent path)");
            }, "dns-el-dial");
            dnsDialThread.setDaemon(true);
            dnsDialThread.start();

            localDisc = new DiscV4Service(nodeKey, network.bootnodes(), entry -> {
                // Pause acquiring new peers while an ENS resolution runs: its snap
                // round-trips share the event loop with outbound dials, and a dial
                // burst inflates resolution latency. Existing peers stay.
                if (connectorRef.isSnapHeavy()) return;
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
                    LogBuffer.w(TAG, "discovered peer connect failed: " + e.getMessage());
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
            Path clCacheFile = netCache("cl-peers", ".cache").toPath();
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
            // Seed peers proven to serve catch-up last session (with the period
            // they served) and persist new ones, so a cold start prefers the
            // peers that actually retained the checkpoint's light-client updates
            // instead of fanning out across discovery peers that don't serve LC.
            localBlc.setProvenCatchUpServers(clCacheRef.servedRanges());
            localBlc.setOnCatchUpServed(clCacheRef::recordServed);
            // Persist which peer served the bootstrap (and for which period) so a restart
            // front-loads a proven light-client server instead of re-fanning discovery.
            localBlc.setProvenBootstrapPeers(clCacheRef.bootstrapPeers());
            localBlc.setOnBootstrapServed(clCacheRef::recordBootstrap);
            // Seed light_client-capability verdicts from last session and persist new ones,
            // so a restart dials confirmed light-client servers first and deprioritizes peers
            // proven not to serve LC — instead of re-Identifying the whole fork-matched cache
            // (most of which are full nodes without the light-client server). Cuts the
            // SYNCING->SYNCED churn after a warm restart.
            localBlc.setProvenLightClient(clCacheRef.lightClientConfirmed());
            localBlc.setProvenNonLightClient(clCacheRef.lightClientDenied());
            localBlc.setOnLightClientVerdict(clCacheRef::markLightClientBatch);
            // Persist/resume verified sync-committee state across restarts (day-to-day
            // fast path): next launch resumes from here and only catches up the delta
            // instead of re-bootstrapping from the embedded checkpoint. In getCacheDir()
            // so "Clear cache" / Reset sync state wipes it.
            localBlc.setSnapshotFile(netCache("sync-state", ".snapshot").toPath());
            blcRef.set(localBlc);

            // Publish atomically vs. shutdown() — if shutdown won the race
            // while we were constructing, we own every resource above, so we
            // have to close them ourselves instead of letting shutdown do it.
            // disc.start() / blc.start() run inside the same synchronized block
            // so shutdown cannot close the service between publish and start.
            if (!startAndPublish(localCache, localClCache, localConnector, localDisc, localDiscV5,
                    localBlc, localBeaconState, localGenesisTime,
                    localCachedCount, localCachedClCount)) {
                LogBuffer.i(TAG, "shutdown raced boot; tearing down constructed resources");
                closeQuietly(localBlc);
                closeQuietly(localDiscV5);
                closeQuietly(localDisc);
                closeQuietly(localConnector);
                return;
            }
            LogBuffer.i(TAG, "discv4 started on UDP " + DEFAULT_PORT
                    + (this.discV5 != null ? ", discv5 on UDP 9000" : " (discv5 unavailable)")
                    + ", beacon LC seeded with " + clPeers.size() + " CL peer(s)");
        } catch (Exception e) {
            LogBuffer.e(TAG, "node boot failed", e);
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
            LogBuffer.w(TAG, "discv5 start failed, continuing without CL discovery: " + t.getMessage());
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
        // JSON-RPC server (Phase-A scaffold): start the embedded Ktor endpoint so a
        // wallet can reach the node (LAN, or host via `adb forward tcp:8545 tcp:8545`).
        // Starts immediately — does not wait for beacon sync. Router/proxy land next.
        try {
            // Upstream proxy URL (DEBUG/dev only) comes from BuildConfig.RPC_UPSTREAM
            // (set in gitignored local.properties); blank → strict (no proxy). In
            // permissionless mode we force it off regardless, so unverifiable methods
            // error instead of proxying.
            String upstream = STRICT_NO_PROXY ? null : BuildConfig.RPC_UPSTREAM;
            // Verified-read backend: the SHARED VerifiedRpcBackend — the very class the
            // :app daemon constructs — wired to this node's connector + beacon state via
            // the host seams below. Every verified read/call AND ENS resolution delegates
            // here, so the verified machinery (head anchoring, snap-proof reads, fee
            // snapshots, the confirm-screen resilience) lives once for both Android and
            // the daemon instead of a drifting inline copy.
            final AndroidPeerCache snapCache = cache;
            io.myotis.rpc.SnapQualitySink snapQualitySink = new io.myotis.rpc.SnapQualitySink() {
                @Override public void recordSnapServed(java.net.InetSocketAddress address) {
                    snapCache.recordSnapServed(address);
                }
                @Override public void recordSnapFailure(java.net.InetSocketAddress address) {
                    snapCache.recordSnapFailure(address);
                }
            };
            io.myotis.rpc.RpcLogger rpcLogger = new io.myotis.rpc.RpcLogger() {
                @Override public void info(String message) { LogBuffer.i(TAG, message); }
                @Override public void warn(String message) { LogBuffer.w(TAG, message); }
            };
            // Deep-sleep-aware monotonic clock: unlike the daemon, a phone dozes, and
            // elapsedRealtime keeps counting while suspended — so a head/fee snapshot that
            // aged across a sleep is correctly seen as stale (System.nanoTime would not).
            io.myotis.rpc.RpcClock rpcClock = new io.myotis.rpc.RpcClock() {
                @Override public long elapsedMillis() { return android.os.SystemClock.elapsedRealtime(); }
            };
            io.myotis.rpc.VerifiedRpcBackend backend = new io.myotis.rpc.VerifiedRpcBackend(
                    conn, blc, beaconState,
                    new com.jaeckel.ethp2p.android.ens.AndroidCcipGateway(ccipPool),
                    rpcLogger, rpcClock, snapQualitySink);
            // start() spins up the head warmer (replaces the old startHeadWarmer()).
            backend.start();
            this.rpcBackend = backend;
            // DEBUG builds: arm MyotisRpcServer's request-capture tap (same JSONL the
            // daemon records with -Dmyotis.rpc.capture) so a wallet session on-device
            // can be pulled and diffed against a desktop capture / fed to the replay
            // harness:  adb pull /sdcard/Android/data/<pkg>/files/rpc-capture.jsonl
            // app-private external storage, debug-only — release builds never capture.
            if (BuildConfig.DEBUG && System.getProperty("myotis.rpc.capture") == null) {
                // getExternalFilesDir(null) returns null when external storage is
                // unavailable (unmounted/emulated-but-not-ready); new File(null, name)
                // would resolve to a relative path in the process CWD. Skip arming the
                // tap rather than write somewhere unexpected — it's a debug aid.
                java.io.File dir = getExternalFilesDir(null);
                if (dir != null) {
                    java.io.File cap = new java.io.File(dir, "rpc-capture.jsonl");
                    System.setProperty("myotis.rpc.capture", cap.getAbsolutePath());
                    LogBuffer.i(TAG, "[rpc] capture tap -> " + cap.getAbsolutePath());
                } else {
                    LogBuffer.w(TAG, "[rpc] capture tap NOT armed: external files dir unavailable");
                }
            }
            // Bind loopback-only: the wallet (MetaMask) runs on the same device and
            // reaches us via localhost. Binding 0.0.0.0 would expose an unauthenticated,
            // TLS-less RPC — incl. eth_sendRawTransaction relay — to the whole LAN.
            io.myotis.jsonrpc.MyotisRpcServer s =
                    new io.myotis.jsonrpc.MyotisRpcServer(activeRpcPort, upstream, "127.0.0.1", backend);
            s.start();
            this.rpcServer = s;
            startPeerMaintainer();
        } catch (Throwable t) {
            LogBuffer.w(TAG, "[rpc] failed to start JSON-RPC server: " + t);
        }
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
        // Stop the JSON-RPC server + backend first so the port frees and no warm-tick
        // builds against torn-down state (the head warmer lives in the backend now).
        if (peerMaintainer != null) {
            peerMaintainer.shutdownNow();
            peerMaintainer = null;
        }
        if (rpcServer != null) {
            try { rpcServer.stop(); } catch (Throwable ignored) {}
            rpcServer = null;
        }
        // Close the shared backend AFTER the server: stops its head warmer + EVM pools
        // and drops its cached head/pin state, so a later Start doesn't reuse a context
        // pinned to a now-dead peer (the backend fails safe to error regardless).
        if (rpcBackend != null) {
            try { rpcBackend.close(); } catch (Throwable ignored) {}
            rpcBackend = null;
        }
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
        // Flush + stop the peer cache's async writer before dropping the reference.
        if (peerCache != null) {
            try { peerCache.close(); } catch (Exception ignored) {}
            peerCache = null;
        }
        clPeerCache = null;
        attempted.clear();
        backoff.clear();
        blacklistedNodeIds.clear();
        cachedPeerCount = 0;
        cachedClPeerCount = 0;
        clGenesisTime = 0L;
        startTimeMs = 0L;
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
        backoff.clear();
        blacklistedNodeIds.clear();
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
        int discv5Live = discV5 != null ? discV5.liveNodeCount() : 0;
        BeaconStats bs = beaconStatsSnapshot();
        if (!running || connector == null) {
            return new Snapshot(running, startTimeMs, 0, 0, 0, 0,
                    cachedPeerCount, attempted.size(), countActiveBackoff(),
                    blacklistedNodeIds.size(), discv5Live, clPeersDiscovered.get(),
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
                cachedPeerCount, attempted.size(), countActiveBackoff(),
                blacklistedNodeIds.size(), discv5Live, clPeersDiscovered.get(),
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
