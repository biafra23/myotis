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
    /** Persisted verified sync-committee snapshot filename (in getCacheDir()). */
    private static final String SYNC_SNAPSHOT_FILE = "sync-state.snapshot";
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
    // known snap peers from the cache; 4 leaves headroom so transient churn
    // doesn't drop us below the ~2 a request realistically needs.
    private static final int TARGET_SNAP_PEERS = 4;
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
    private java.util.concurrent.ScheduledExecutorService headWarmer;
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

    // --- ENS resolution (local Besu EVM over SNAP-verified state) ---------
    // Mirrors the JVM daemon's CommandHandler.prepareEnsCall stack. Bytecode
    // cache + EVM pool are service-lifecycle (not node-lifecycle) so they
    // survive Stop/Start; shut down in onDestroy.
    private final io.myotis.evm.world.BytecodeCache ensBytecodeCache =
            io.myotis.evm.world.BytecodeCache.inMemory();
    // Single thread: Besu EVM execution is CPU-bound and the oracle is pinned
    // to one peer, so serializing avoids contention. Daemon thread so it never
    // blocks process exit.
    private final java.util.concurrent.ExecutorService evmPool =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "android-evm");
                t.setDaemon(true);
                return t;
            });
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
        if (!RUNNING.get() || connector == null) {
            return CompletableFuture.completedFuture(
                    new EnsResolution(trimmed, null, -1, false, "node not running"));
        }
        if (trimmed.isEmpty()) {
            return CompletableFuture.completedFuture(
                    new EnsResolution(trimmed, null, -1, false, "empty name"));
        }
        io.myotis.ens.EnsResolutionRoot mode = ensResolutionRoot;
        // Pause acquiring new peers for the duration of the resolution so its snap
        // round-trips aren't starved by outbound-dial bursts on the shared event
        // loop. Released when the (async) resolution completes. See isSnapHeavy().
        final RLPxConnector conn = connector;
        conn.enterSnapHeavy();
        final CompletableFuture<EnsResolution> result;
        if (mode == io.myotis.ens.EnsResolutionRoot.AUTO) {
            result = attemptResolve(trimmed, io.myotis.ens.EnsResolutionRoot.FINALIZED)
                    .thenCompose(fin -> {
                        // Verified hit → done.
                        if (fin.resolution().addressHex() != null) {
                            return CompletableFuture.completedFuture(fin.resolution());
                        }
                        // If finalized already consumed an ERC-3668 offchain (CCIP)
                        // answer, the result is determined by the gateway, not by
                        // which EL state root we ran against — re-resolving at the
                        // peer head would just repeat the same slow, multi-round-trip
                        // gateway calls for the same (non-)answer. Don't fall back.
                        if (fin.usedOffchain()) {
                            return CompletableFuture.completedFuture(fin.resolution());
                        }
                        // Otherwise (no record at the finalized block, or finalized
                        // couldn't be served) fall back to the peer head for a
                        // fresher, peer-claimed answer.
                        return attemptResolve(trimmed, io.myotis.ens.EnsResolutionRoot.PEER_HEAD)
                                .thenApply(Attempt::resolution);
                    });
        } else {
            result = attemptResolve(trimmed, mode).thenApply(Attempt::resolution);
        }
        return result.whenComplete((r, ex) -> conn.exitSnapHeavy());
    }

    /** One resolution attempt against a specific root. Never throws. */
    @SuppressLint("NewApi")
    private CompletableFuture<Attempt> attemptResolve(String trimmed,
                                                      io.myotis.ens.EnsResolutionRoot root) {
        // prepareEnsCall is blocking — it probes peer heads (up to ~10s of network
        // round-trips) before pinning one. Run it on the EVM pool, never on the
        // caller's thread, so resolveEns is safe to invoke from the UI thread
        // without risking an ANR. The probe and the EVM execution that follows
        // share the single EVM thread, which keeps the pinned-peer oracle
        // contention-free (see evmPool's rationale above).
        return CompletableFuture.<EnsCall>supplyAsync(() -> {
            try {
                return prepareEnsCall(root);
            } catch (Exception e) {
                throw new java.util.concurrent.CompletionException(e);
            }
        }, evmPool).thenCompose(call -> {
            final boolean verified = call.beaconVerified();
            return call.resolver().resolveAddress(trimmed, call.blockCtx())
                    .orTimeout(ENS_TIMEOUT_SEC, TimeUnit.SECONDS)
                    .handle((opt, ex) -> {
                        final boolean usedOffchain = call.offchainExecutor().usedOffchain();
                        if (ex != null) {
                            // Log the full stack: library wrappers (e.g. Caffeine's
                            // IllegalStateException(className)) mask the real
                            // Android-incompat cause, which unwrap() now chains.
                            LogBuffer.e(TAG, "[ens] resolveAddress failed for " + trimmed, ex);
                            return new Attempt(new EnsResolution(
                                    trimmed, null, call.blockNumber(), verified, unwrap(ex)), usedOffchain);
                        }
                        if (opt == null || opt.isEmpty()) {
                            return new Attempt(new EnsResolution(trimmed, null, call.blockNumber(), verified,
                                    "name does not resolve"), usedOffchain);
                        }
                        return new Attempt(new EnsResolution(
                                trimmed, opt.get().toHex(), call.blockNumber(), verified, null), usedOffchain);
                    });
        }).exceptionally(ex -> {
            // Only prepareEnsCall reaches here — the handle() above never throws.
            // FINALIZED can fail (no finalized header yet, snap peer can't serve the
            // block); return a null-address result so AUTO can fall back. Peel the
            // CompletionException wrapper so the surfaced error matches the cause.
            Throwable cause = (ex instanceof java.util.concurrent.CompletionException
                    && ex.getCause() != null) ? ex.getCause() : ex;
            return new Attempt(
                    new EnsResolution(trimmed, null, -1,
                            root == io.myotis.ens.EnsResolutionRoot.FINALIZED, unwrap(cause)),
                    false);
        });
    }

    // -------------------------------------------------------------------------
    // JSON-RPC verified reads (Phase B). These bridge the Kotlin MyotisRpcBackend
    // to the same verified machinery the Query tab uses: requestAccount() for
    // balances/nonces (head-anchored via headerChain) and the prepareEnsCall EVM
    // stack for eth_call. All blocking — called off the Ktor IO dispatcher.
    // -------------------------------------------------------------------------

    /** Reuse one beacon-anchored head context across a burst of reads (a MetaMask
     *  page load fires hundreds of eth_calls + account reads) instead of re-probing
     *  peers + re-anchoring per call. ~12s keeps "latest" within ~1 block while
     *  amortizing the expensive (and fallback-prone) peer-probe + headerChain anchor
     *  across the whole burst. */
    private static final long RPC_HEAD_TTL_MS = 12_000;
    /** Per-read/-call budget (snap round-trips; CCIP can add one for eth_call). */
    private static final long RPC_CALL_TIMEOUT_SEC = 30;
    /** Snap-oracle per-fetch retry budget. Each attempt rotates to a different ready
     *  snap peer (the probed peer first), so a slow/dead peer fails over instead of
     *  burning the whole RPC_CALL_TIMEOUT on one peer. */
    private static final int SNAP_ORACLE_MAX_ATTEMPTS = 8;
    /** Head-build budget — includes the headerChain anchoring fetch. */
    private static final long RPC_ACCOUNT_TIMEOUT_SEC = HEADER_CHAIN_TIMEOUT_SEC + 10;
    /** Overall budget for the (parallel) snap-peer head probe. */
    private static final long PEER_PROBE_TIMEOUT_SEC = 15;
    /** Keep serving the last successfully-built head up to this age while a refresh
     *  is in flight. It's still beacon-anchored, just a few blocks stale — serving
     *  it bridges transient rebuild gaps (head just advanced, peers' flat state not
     *  yet caught up) instead of proxying. The warmer keeps it fresh (~5-15s). */
    private static final long RPC_HEAD_MAX_STALE_MS = 30_000;
    /** When there's no usable head at all (cold start / long outage) and no build is
     *  in flight, wait only this long before giving up — a node with no snap peer can't
     *  build a head, so blocking the caller longer just delays the inevitable error. */
    private static final long RPC_HEAD_WAIT_MS = 5_000;
    /** When an anchored-head build IS already in flight (warmer or a prior read), ride
     *  it up to this longer cap instead of erroring at {@link #RPC_HEAD_WAIT_MS}. A cold
     *  anchored build on a phone (fetch+verify ~30 headers from beacon-finalized to head,
     *  then the first snap account fetch) routinely takes 10-30s; giving up at 5s makes a
     *  wallet's first read error even though the verified result is seconds away. Kept
     *  under typical wallet RPC timeouts so the call returns verified-but-slow, not failed. */
    private static final long RPC_HEAD_BUILD_WAIT_MS = 25_000;
    /** How far ABOVE the verified head a number-pinned read may sit and still be served
     *  (a wallet that just saw a newer block than our context). Small: a pin far above
     *  head is a genuinely future/unknown block. */
    private static final long RPC_BLOCK_NUM_TOLERANCE = 16;
    /** How far BELOW the context a number-pinned read may sit and still be served from
     *  the context's (newer) state. Wallets pin "latest"-intent reads to the last block
     *  they saw; when our calls are slow the chain advances past that pin before the read
     *  lands, leaving it tens of blocks behind. Serving the context's state for such a
     *  recent pin gives current-ish data (what the wallet wants) — far better than the
     *  instant error that emptied MetaMask's asset list. Beyond this (~13 min) the pin is
     *  genuinely historical and we can't represent it, so reject. */
    private static final long RPC_BLOCK_NUM_LAG_TOLERANCE = 64;

    private final Object rpcCallCtxLock = new Object();
    private CompletableFuture<EnsCall> rpcCallCtx;   // in-flight/fresh build (dedup)
    private long rpcCallCtxAtMs;
    // Last successfully-built anchored head + its build time, as one immutable
    // record behind a single volatile ref so head and timestamp are read/written
    // atomically together (no torn read of new head with old timestamp).
    private volatile HeadWithTimestamp lastGoodHead;
    /** Runs the blocking, network-bound head build off the caller's thread so a
     *  request blocks only up to its own timeout. Single-thread: the future
     *  dedup means at most one build runs at a time. */
    private final java.util.concurrent.ExecutorService headBuildPool =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "rpc-head-build");
                t.setDaemon(true);
                return t;
            });

    /** keccak256("") — an account with this codeHash is an EOA (no contract code). */
    private static final byte[] EMPTY_CODE_HASH = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();

    /** Only fresh-head tags are served verified for now; others → proxy. */
    private static boolean isLatestTag(String block) {
        return block == null || block.isEmpty()
                || block.equals("latest") || block.equals("pending");
    }

    /**
     * The shared beacon-anchored head context for "latest"-ish reads, or null
     * (→ proxy, logged). Every verified RPC read/call resolves the head HERE so
     * the head is anchored to the beacon-finalized root once per {@link
     * #RPC_HEAD_TTL_MS} window and reused — instead of each call independently
     * re-fetching a head + re-running the headerChain anchor (the slow, fragile
     * step that produced the high proxy-fallback rate). The context's stateRoot
     * is beacon-anchored, so reads against its {@code oracle} stay fully verified.
     */
    private EnsCall verifiedHeadFor(String block) {
        // Resolve the requested block. Latest-ish tags (and safe/finalized, which we
        // don't track separately) serve the anchored head. A specific block NUMBER is
        // served from the anchored head iff it's within RPC_BLOCK_NUM_TOLERANCE of it:
        // we can only serve the head's snap state, but wallets (MetaMask) pin reads to
        // the just-fetched latest number, which is at/near the head. Without this every
        // number-pinned eth_getBalance/eth_call was rejected instantly (the empty-list bug).
        long requestedNum = -1; // -1 = latest-ish
        if (!isLatestTag(block)) {
            if (!"safe".equals(block) && !"finalized".equals(block)) {
                try {
                    requestedNum = Long.decode(block);
                } catch (Exception e) {
                    LogBuffer.i(TAG, "[rpc] unsupported block tag '" + block + "' -> not served");
                    return null;
                }
                if (requestedNum < 0) return null;
            }
        }
        EnsCall ctx = anchoredHeadOrWait();
        if (ctx == null) return null;
        if (requestedNum >= 0) {
            // A pinned number means "the latest block I saw" — wallets fetch
            // eth_blockNumber (our beacon OPTIMISTIC head) and pin the very next reads
            // to it. The serving context can legitimately sit behind that number: the
            // finalized fallback is ~2 epochs older, a snap peer's head a few blocks.
            // So accept anything between the context and the optimistic head (+slack):
            // those reads get the same verified state a "latest" call would get from
            // this context — rejecting them just because the context lags the chain
            // turned every number-pinned call into an instant error whenever snap fell
            // back to finalized (MetaMask: empty asset list, stuck confirm screen).
            // Numbers BELOW the context keep the strict tolerance: the caller asked
            // for genuinely older state, which this context cannot represent.
            BeaconSyncState bss = beaconSyncState;
            long optimistic = bss != null ? bss.getOptimisticBlockNumber() : 0;
            long upperBound = Math.max(ctx.blockNumber(), optimistic) + RPC_BLOCK_NUM_TOLERANCE;
            long lowerBound = ctx.blockNumber() - RPC_BLOCK_NUM_LAG_TOLERANCE;
            if (requestedNum < lowerBound || requestedNum > upperBound) {
                LogBuffer.i(TAG, "[rpc] requested block " + requestedNum + " outside servable ["
                        + lowerBound + ".." + upperBound + "] (ctx=" + ctx.blockNumber()
                        + ", optimistic=" + optimistic + ") -> not served");
                return null;
            }
        }
        return ctx;
    }

    /** Resolve the shared beacon-anchored head context, waiting briefly for a fresh
     *  build if none is available. Returns null if no verified head can be produced. */
    private EnsCall anchoredHeadOrWait() {
        // Fast path: serve the last good head if it's recent enough. It stays
        // beacon-anchored; a few seconds stale beats proxying, and it bridges the
        // brief windows where a TTL-expiry rebuild can't yet anchor the just-
        // advanced head. The background warmer keeps this fresh (~5-15s).
        HeadWithTimestamp good = lastGoodHead;
        if (good != null
                && android.os.SystemClock.elapsedRealtime() - good.builtAtMs() < RPC_HEAD_MAX_STALE_MS) {
            return good.head();
        }
        // No usable head (cold start / sustained outage): wait for a build before
        // giving up. The deadline is adaptive — recomputed each iteration: while an
        // anchored-head build is actually in flight (warmer or a prior read), ride it
        // up to RPC_HEAD_BUILD_WAIT_MS so a read arriving mid-build returns verified-
        // but-slow; with no build possible (no snap peer) it falls back at the short
        // RPC_HEAD_WAIT_MS. Each build attempt is capped at the remaining time.
        long start = android.os.SystemClock.elapsedRealtime();
        Exception last = null;
        while (true) {
            long now = android.os.SystemClock.elapsedRealtime();
            long deadline = start + (headBuildInFlight() ? RPC_HEAD_BUILD_WAIT_MS : RPC_HEAD_WAIT_MS);
            long remainingMs = deadline - now;
            if (remainingMs <= 0) break;
            try {
                return verifiedHeadCallContext(remainingMs, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                last = e;
                HeadWithTimestamp g = lastGoodHead;   // a concurrent build may have just succeeded
                if (g != null && android.os.SystemClock.elapsedRealtime() - g.builtAtMs() < RPC_HEAD_MAX_STALE_MS) {
                    return g.head();
                }
                try { Thread.sleep(300); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        LogBuffer.i(TAG, "[rpc] no verified head after "
                + (android.os.SystemClock.elapsedRealtime() - start) + "ms -> proxy: "
                + (last != null ? unwrap(last) : "timeout"));
        return null;
    }

    /** True while an anchored-head build is in flight (warmer or a prior read), so a
     *  waiting read can ride it instead of erroring early. */
    private boolean headBuildInFlight() {
        CompletableFuture<EnsCall> f;
        synchronized (rpcCallCtxLock) { f = rpcCallCtx; }
        return f != null && !f.isDone();
    }

    /** eth_call over the shared anchored head. Returns raw ABI bytes, or null to proxy. */
    private byte[] rpcCall(byte[] to, byte[] data, String block) {
        // Identify the call up front: target + 4-byte selector + calldata size + block
        // tag. eth_call failures were undiagnosable as "eth_call -> proxy: Timeout" —
        // with hundreds of MetaMask poll variants we need to know WHICH contract/method
        // is being asked for (e.g. its confirm-screen simulation multicall).
        String desc = (to != null && to.length == 20 ? Bytes.wrap(to).toHexString() : "?")
                + " sel=" + (data != null && data.length >= 4
                        ? Bytes.wrap(data, 0, 4).toHexString() : "0x")
                + " dataLen=" + (data == null ? 0 : data.length)
                + " block=" + block;
        EnsCall h = verifiedHeadFor(block);
        if (h == null || to == null || to.length != 20) {
            LogBuffer.i(TAG, "[rpc] eth_call " + desc + " -> no verified head for block tag");
            return null;
        }
        long t0 = android.os.SystemClock.elapsedRealtime();
        try {
            byte[] out = h.offchainExecutor()
                    .callView(io.myotis.evm.Address.of(to), data == null ? new byte[0] : data,
                            h.blockCtx())
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            LogBuffer.i(TAG, "[rpc] eth_call " + desc + " ok in "
                    + (android.os.SystemClock.elapsedRealtime() - t0) + "ms");
            return out;
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_call " + desc + " -> error after "
                    + (android.os.SystemClock.elapsedRealtime() - t0) + "ms: "
                    + describeEvmError(e));
            return null;
        }
    }

    /** Verified account record at the shared anchored head, or null (→ proxy). The
     *  oracle hash-verifies the account against the anchored stateRoot (storageRoot
     *  + codeHash come from the proven trie leaf), and verifies account ABSENCE via
     *  an exclusion proof — so a missing account is a verified zero, not a proxy. */
    private io.myotis.evm.world.AccountState rpcAccountState(byte[] address, String block) {
        EnsCall h = verifiedHeadFor(block);
        if (h == null || address == null || address.length != 20) return null;
        try {
            return h.oracle()
                    .fetchAccount(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(address))
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] account read -> proxy: " + unwrap(e));
            return null;
        }
    }

    /** eth_getCode: bytecode verified (keccak256(code)==proven codeHash), or null to proxy. */
    private byte[] rpcCode(byte[] address, String block) {
        EnsCall h = verifiedHeadFor(block);
        if (h == null || address == null || address.length != 20) return null;
        try {
            byte[] codeHash = h.oracle()
                    .fetchAccount(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(address))
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS).codeHash();
            if (java.util.Arrays.equals(codeHash, EMPTY_CODE_HASH)) return new byte[0];  // EOA
            return h.oracle().fetchBytecode(codeHash).get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_getCode -> proxy: " + unwrap(e));
            return null;
        }
    }

    /** eth_getStorageAt: the 32-byte value at {@code slot32}, proven against the
     *  account's verified storageRoot (absent slots verify as zero via the oracle's
     *  exclusion proof). Null → proxy. */
    private byte[] rpcStorageAt(byte[] address, byte[] slot32, String block) {
        EnsCall h = verifiedHeadFor(block);
        if (h == null || address == null || address.length != 20
                || slot32 == null || slot32.length != 32) return null;
        try {
            java.math.BigInteger value = h.oracle()
                    .fetchStorage(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(address),
                            new java.math.BigInteger(1, slot32))
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            return word32(value);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_getStorageAt -> proxy: " + unwrap(e));
            return null;
        }
    }

    /** eth_sendRawTransaction: gossip the user-signed tx to peers; return its hash
     *  (keccak256 of the raw bytes), or null (→ proxy) if no peer took it. Myotis
     *  never signs or originates a tx — this only relays bytes the user submitted. */
    /** Raw bytes of transactions this node broadcast, keyed by lowercase 0x tx hash, so
     *  eth_getTransactionByHash can answer a just-sent tx as "pending" before it's mined
     *  (we hold the signed bytes — serving them is not a trust assumption). Bounded LRU;
     *  entries fall out as they age (they're served from verified blocks once mined). */
    private final Map<String, byte[]> sentTxCache = java.util.Collections.synchronizedMap(
            new java.util.LinkedHashMap<>(64, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, byte[]> e) {
                    return size() > 256;
                }
            });

    private byte[] rpcSendRawTransaction(byte[] rawTx) {
        RLPxConnector conn = connector;
        if (conn == null || rawTx == null || rawTx.length == 0) return null;
        try {
            int sent = conn.broadcastTransaction(rawTx);
            if (sent == 0) return null;   // no peer reached → let the proxy relay it
            byte[] txHash = Hash.keccak256(Bytes.wrap(rawTx)).toArrayUnsafe();
            sentTxCache.put(Bytes.wrap(txHash).toHexString(), rawTx.clone());
            LogBuffer.i(TAG, "[rpc] eth_sendRawTransaction broadcast to " + sent
                    + " peer(s), hash=" + Bytes.wrap(txHash).toHexString());
            return txHash;
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_sendRawTransaction failed: " + unwrap(e));
            return null;
        }
    }

    /**
     * eth_getTransactionByHash. Scans the recent beacon-verified block window for the tx
     * (body verified vs transactionsRoot); if found, returns it with block context. If not
     * yet mined but this node broadcast it, returns it as pending (blockNumber null) from
     * the sent-tx cache. "null" for a verified-unknown tx; Kotlin null when not verifiable.
     */
    private String rpcGetTransactionByHash(byte[] txHash) {
        RLPxConnector conn = connector;
        if (conn == null || txHash == null || txHash.length != 32) return null;
        Bytes32 want = Bytes32.wrap(txHash);
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) {
                // Can't verify chain inclusion right now — but if it's our own just-sent tx
                // we can still honestly answer "pending" from the signed bytes we hold.
                byte[] ourRaw = sentTxCache.get(want.toHexString());
                return ourRaw != null ? buildTxJson(ourRaw, want, null, -1, -1) : null;
            }
            long headNum = anchor.number();
            int count = (int) Math.min(RECEIPT_LOOKBACK_BLOCKS, headNum + 1);
            long start = headNum - count + 1;
            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(start, count)
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!anchor.anchors(window)) return null;

            List<CompletableFuture<List<BlockBodiesMessage.BlockBody>>> bodyFutures =
                    new ArrayList<>(window.size());
            for (BlockHeadersMessage.VerifiedHeader vh : window) {
                bodyFutures.add(conn.requestBlockBodies(vh.hash()));
            }
            for (int hi = window.size() - 1; hi >= 0; hi--) {
                BlockHeader h = window.get(hi).header();
                Bytes32 blockHash = window.get(hi).hash();
                List<BlockBodiesMessage.BlockBody> bodies;
                try {
                    bodies = bodyFutures.get(hi).get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
                } catch (Exception e) { continue; }
                if (bodies.isEmpty()) continue;
                List<Bytes> txs = bodies.get(0).transactions();
                if (!OrderedTrieRoot.verify(txs, h.transactionsRoot)) continue;
                for (int i = 0; i < txs.size(); i++) {
                    if (Hash.keccak256(txs.get(i)).equals(want)) {
                        LogBuffer.i(TAG, "[rpc] eth_getTransactionByHash found in block #"
                                + h.number + " index " + i);
                        return buildTxJson(txs.get(i).toArrayUnsafe(), want, blockHash, h.number, i);
                    }
                }
            }
            // Verified head + anchored window, not in it. If it's our own broadcast, it's
            // pending; otherwise a verified "unknown tx".
            byte[] ourRaw = sentTxCache.get(want.toHexString());
            return ourRaw != null ? buildTxJson(ourRaw, want, null, -1, -1) : "null";
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_getTransactionByHash failed: " + unwrap(e));
            return null;
        }
    }

    /** Build the eth_getTransactionByHash JSON. blockHash null + blockNum/index < 0 = pending.
     *  Returns Java null (NOT the literal "null") when the tx can't be decoded: the tx WAS
     *  found/held, so this is "can't render it verified" → the caller errors, never a
     *  misleading "tx not found". */
    private static String buildTxJson(byte[] rawTx, Bytes32 txHash,
                                      Bytes32 blockHash, long blockNum, int index) {
        com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.DecodedTx t =
                com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder.decode(Bytes.wrap(rawTx));
        if (t == null) return null; // unrenderable tx type — can't-serve, not unknown-tx
        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"hash\":\"").append(txHash.toHexString()).append("\"");
        if (blockHash != null) {
            sb.append(",\"blockHash\":\"").append(blockHash.toHexString()).append("\"");
            sb.append(",\"blockNumber\":\"").append(hexQuantity(blockNum)).append("\"");
            sb.append(",\"transactionIndex\":\"").append(hexQuantity(index)).append("\"");
        } else {
            sb.append(",\"blockHash\":null,\"blockNumber\":null,\"transactionIndex\":null");
        }
        sb.append(",\"type\":\"").append(hexQuantity(t.type())).append("\"");
        if (t.chainId() != null) sb.append(",\"chainId\":\"").append(hexQuantity(t.chainId())).append("\"");
        sb.append(",\"nonce\":\"").append(hexQuantity(t.nonce())).append("\"");
        if (t.from() != null) sb.append(",\"from\":\"").append(t.from().toHexString()).append("\"");
        if (!t.to().isEmpty()) sb.append(",\"to\":\"").append(t.to().toHexString()).append("\"");
        else sb.append(",\"to\":null");
        sb.append(",\"value\":\"0x").append(t.value().toString(16)).append("\"");
        sb.append(",\"gas\":\"").append(hexQuantity(t.gas())).append("\"");
        if (t.gasPrice() != null) {
            sb.append(",\"gasPrice\":\"0x").append(t.gasPrice().toString(16)).append("\"");
        }
        if (t.maxFeePerGas() != null) {
            sb.append(",\"maxFeePerGas\":\"0x").append(t.maxFeePerGas().toString(16)).append("\"");
            sb.append(",\"maxPriorityFeePerGas\":\"0x")
              .append(t.maxPriorityFeePerGas().toString(16)).append("\"");
        }
        sb.append(",\"input\":\"").append(t.input().isEmpty() ? "0x" : t.input().toHexString()).append("\"");
        // v is a QUANTITY (recovery id / EIP-155 v); typed txs also carry yParity (0/1).
        sb.append(",\"v\":\"0x").append(t.v().toString(16)).append("\"");
        if (t.type() >= 1) {
            sb.append(",\"yParity\":\"0x").append(t.v().toString(16)).append("\"");
        }
        // r and s are 32-byte DATA — left-pad, never QUANTITY (odd-length / unpadded
        // breaks clients expecting exactly 32 bytes).
        sb.append(",\"r\":\"").append(Bytes.wrap(word32(t.r())).toHexString()).append("\"");
        sb.append(",\"s\":\"").append(Bytes.wrap(word32(t.s())).toHexString()).append("\"");
        sb.append("}");
        return sb.toString();
    }

    /**
     * eth_getTransactionReceipt — trustlessly. Scans a bounded window of recent blocks
     * below the beacon-anchored verified head: for each, fetches the block body and
     * verifies it against the header's {@code transactionsRoot} (rebuilding the tx trie)
     * before trusting that the tx is in that block at a given index; then fetches the
     * block's receipts and verifies them against the header's {@code receiptsRoot} before
     * returning the matching receipt as JSON. Returns null (→ proxy / pending) if the tx
     * isn't found verified in the window. Peer data is never trusted unverified.
     *
     * <p>Returns the verified core fields (status, gasUsed, logs, block context, type);
     * from / to / contractAddress / effectiveGasPrice (which need tx decode + sender
     * recovery) are a follow-up.
     */
    private String rpcGetTransactionReceipt(byte[] txHash, String block) {
        RLPxConnector conn = connector;
        if (conn == null || txHash == null || txHash.length != 32) return null;
        try {
            // Headers-only anchor (snap head preferred, beacon optimistic fallback):
            // receipts need verified headers + bodies, not snap state, so this path
            // keeps working through snap-peer outages — see headerAnchor().
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            long headNum = anchor.number();

            int count = (int) Math.min(RECEIPT_LOOKBACK_BLOCKS, headNum + 1);
            long start = headNum - count + 1;
            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(start, count)
                    // Future.get(timeout) — NOT CompletableFuture.orTimeout (API 31, minSdk 29).
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            // Anchor the window: its last header must BE the verified head and every
            // header must hash-link to the next's parentHash.
            if (!anchor.anchors(window)) {
                LogBuffer.i(TAG, "[rpc] eth_getTransactionReceipt: header window failed to anchor");
                return null;
            }

            Bytes32 want = Bytes32.wrap(txHash);
            // Fire the body fetches concurrently rather than 32 sequential round-trips:
            // worst case (tx pending / outside the window) is then ~one round-trip of
            // latency instead of the sum. The window itself is the bandwidth bound.
            List<CompletableFuture<List<BlockBodiesMessage.BlockBody>>> bodyFutures =
                    new ArrayList<>(window.size());
            for (BlockHeadersMessage.VerifiedHeader vh : window) {
                bodyFutures.add(conn.requestBlockBodies(vh.hash()));
            }
            for (int hi = window.size() - 1; hi >= 0; hi--) {
                BlockHeader h = window.get(hi).header();
                Bytes32 blockHash = window.get(hi).hash();
                List<BlockBodiesMessage.BlockBody> bodies;
                try {
                    bodies = bodyFutures.get(hi).get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
                } catch (Exception e) {
                    continue; // body fetch failed/timed out for this block — skip it
                }
                if (bodies.isEmpty()) continue;
                List<Bytes> txs = bodies.get(0).transactions();
                // Verify the body before trusting which txs (and indices) it contains.
                if (!OrderedTrieRoot.verify(txs, h.transactionsRoot)) {
                    LogBuffer.i(TAG, "[rpc] block #" + h.number + " body failed transactionsRoot verify");
                    continue;
                }
                int idx = -1;
                for (int i = 0; i < txs.size(); i++) {
                    if (Hash.keccak256(txs.get(i)).equals(want)) { idx = i; break; }
                }
                if (idx < 0) continue;

                // Found. Fetch + verify the block's receipts against receiptsRoot.
                List<List<Bytes>> rcptBlocks = conn
                        .requestReceipts(blockHash)
                        .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
                if (rcptBlocks.isEmpty()) return null;
                List<Bytes> receipts = rcptBlocks.get(0);
                if (!OrderedTrieRoot.verify(receipts, h.receiptsRoot)) {
                    LogBuffer.i(TAG, "[rpc] block #" + h.number + " receipts failed receiptsRoot verify");
                    return null;
                }
                if (idx >= receipts.size()) return null;
                LogBuffer.i(TAG, "[rpc] eth_getTransactionReceipt verified tx in block #"
                        + h.number + " index " + idx);
                return buildReceiptJson(receipts, idx, h, blockHash, want);
            }
            // Verified head + anchored window, but the tx isn't in it → a VERIFIED
            // "not seen yet": return the JSON-null literal (eth's pending/unknown), NOT
            // Kotlin null (which means "couldn't verify" → router error).
            return "null";
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_getTransactionReceipt failed: " + unwrap(e));
            return null; // couldn't verify → router errors (not a misleading "pending")
        }
    }

    /** The contiguous header window [start..head] is valid iff its last header is the
     *  beacon-verified head (stateRoot match) and each header hash-links to the next. */
    private static boolean windowAnchoredToHead(List<BlockHeadersMessage.VerifiedHeader> window,
                                                byte[] headStateRoot) {
        if (window.isEmpty()) return false;
        BlockHeader last = window.get(window.size() - 1).header();
        if (!java.util.Arrays.equals(last.stateRoot.toArrayUnsafe(), headStateRoot)) return false;
        return windowHashLinked(window);
    }

    /** Like {@link #windowAnchoredToHead} but anchored by the head's block HASH —
     *  used with the beacon optimistic anchor, whose exec blockHash is what the
     *  light client verified. */
    private static boolean windowAnchoredToHash(List<BlockHeadersMessage.VerifiedHeader> window,
                                                byte[] headBlockHash) {
        if (window.isEmpty()) return false;
        if (!java.util.Arrays.equals(
                window.get(window.size() - 1).hash().toArrayUnsafe(), headBlockHash)) return false;
        return windowHashLinked(window);
    }

    private static boolean windowHashLinked(List<BlockHeadersMessage.VerifiedHeader> window) {
        for (int i = 0; i < window.size() - 1; i++) {
            if (!window.get(i).hash().equals(window.get(i + 1).header().parentHash)) return false;
        }
        return true;
    }

    /** A beacon-verified header anchor: block {@code number} plus either the head's
     *  {@code stateRoot} (snap-built head) or its block {@code hash} (beacon optimistic
     *  exec payload) — exactly one is non-null. */
    private record HeaderAnchor(long number, byte[] stateRoot, byte[] blockHash) {
        boolean anchors(List<BlockHeadersMessage.VerifiedHeader> window) {
            return stateRoot != null ? windowAnchoredToHead(window, stateRoot)
                                     : windowAnchoredToHash(window, blockHash);
        }
    }

    /**
     * Resolve a beacon-verified header anchor for block/receipt serving — paths that
     * need verified HEADERS but no snap state. Prefers the snap-built anchored head
     * (freshest, the chain tip); falls back to the beacon optimistic execution payload
     * (light-client-verified blockHash, at worst ~1 epoch stale) when no snap peer is
     * available — so eth_getBlockByNumber / eth_getTransactionReceipt keep working
     * through snap-peer outages (e.g. a cold start before discovery finds snap peers,
     * where MetaMask's block tracker previously died and hung the UI).
     */
    private HeaderAnchor headerAnchor() {
        RLPxConnector c = connector;
        // Only pay the anchored-head wait when a snap peer exists to build from.
        if (c != null && !c.activeSnapHandlers().isEmpty()) {
            EnsCall ctx = anchoredHeadOrWait();
            if (ctx != null && ctx.beaconVerified()) {
                return new HeaderAnchor(ctx.blockNumber(), ctx.blockCtx().stateRoot(), null);
            }
        }
        BeaconSyncState bss = beaconSyncState;
        if (bss == null) return null;
        long n = bss.getOptimisticBlockNumber();
        byte[] h = bss.getOptimisticBlockHash();
        if (n <= 0 || h == null) return null;
        return new HeaderAnchor(n, null, h);
    }

    /** Build the eth_getTransactionReceipt JSON object from VERIFIED receipt bytes.
     *  {@code txHash} is the body's tx hash (already confirmed == the requested hash). */
    private static String buildReceiptJson(List<Bytes> receipts, int idx,
                                           BlockHeader h, Bytes32 blockHash, Bytes32 txHash) {
        Receipt r = Receipt.decode(receipts.get(idx));
        // Single pass over the preceding receipts: gasUsed needs receipt[idx-1]'s
        // cumulative, logIndex needs the running log count — decode each only once.
        long prevCum = 0L;
        int logBase = 0;
        for (int j = 0; j < idx; j++) {
            Receipt prev = Receipt.decode(receipts.get(j));
            logBase += prev.logs().size();
            if (j == idx - 1) prevCum = prev.cumulativeGasUsed();
        }
        long gasUsed = r.cumulativeGasUsed() - prevCum;

        String txHashHex = txHash.toHexString();
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"transactionHash\":\"").append(txHashHex).append("\"");
        sb.append(",\"transactionIndex\":\"").append(hexQuantity(idx)).append("\"");
        sb.append(",\"blockHash\":\"").append(blockHash.toHexString()).append("\"");
        sb.append(",\"blockNumber\":\"").append(hexQuantity(h.number)).append("\"");
        sb.append(",\"cumulativeGasUsed\":\"").append(hexQuantity(r.cumulativeGasUsed())).append("\"");
        sb.append(",\"gasUsed\":\"").append(hexQuantity(gasUsed)).append("\"");
        if (r.hasStatus()) {
            sb.append(",\"status\":\"").append(r.success() ? "0x1" : "0x0").append("\"");
        }
        sb.append(",\"type\":\"").append(hexQuantity(r.type())).append("\"");
        sb.append(",\"logsBloom\":\"").append(r.logsBloom().toHexString()).append("\"");
        sb.append(",\"logs\":[");
        for (int k = 0; k < r.logs().size(); k++) {
            Receipt.Log log = r.logs().get(k);
            if (k > 0) sb.append(",");
            sb.append("{\"address\":\"").append(log.address().toHexString()).append("\"");
            sb.append(",\"topics\":[");
            for (int t = 0; t < log.topics().size(); t++) {
                if (t > 0) sb.append(",");
                sb.append("\"").append(log.topics().get(t).toHexString()).append("\"");
            }
            sb.append("],\"data\":\"").append(log.data().toHexString()).append("\"");
            sb.append(",\"blockNumber\":\"").append(hexQuantity(h.number)).append("\"");
            sb.append(",\"blockHash\":\"").append(blockHash.toHexString()).append("\"");
            sb.append(",\"transactionHash\":\"").append(txHashHex).append("\"");
            sb.append(",\"transactionIndex\":\"").append(hexQuantity(idx)).append("\"");
            sb.append(",\"logIndex\":\"").append(hexQuantity(logBase + k)).append("\"");
            sb.append(",\"removed\":false}");
        }
        sb.append("]}");
        return sb.toString();
    }

    /** Ethereum JSON-RPC QUANTITY: minimal hex, no leading zeros, 0 → "0x0". */
    private static String hexQuantity(long v) {
        return "0x" + Long.toHexString(v);
    }

    /**
     * eth_getBlockByNumber, verified. Serves the block header fields from a
     * beacon-anchored verified header plus the tx hashes from a body checked against
     * transactionsRoot — no snap state needed (so it works even where eth_call can't).
     * Returns the block JSON when verified; the literal "null" for a non-existent
     * (future) block (eth's standard); Kotlin null when it can't verify (not synced)
     * → router errors. fullTransactions=true (full tx objects, needs tx decode + sender
     * recovery) is a follow-up — returns Kotlin null for now.
     */
    private String rpcGetBlockByNumber(String block, boolean fullTx) {
        RLPxConnector conn = connector;
        if (conn == null || fullTx) return null;
        try {
            // Headers-only anchor: snap-built head when available, beacon optimistic
            // exec payload otherwise — block serving must survive snap-peer outages
            // (MetaMask's block tracker polls this and hangs the UI without it).
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            long headNum = anchor.number();

            long target;
            String b = (block == null) ? "latest" : block;
            switch (b) {
                case "latest": case "pending": case "safe": case "finalized":
                    target = headNum; break;
                case "earliest":
                    return null; // genesis not served verified here (rarely needed)
                default:
                    try { target = Long.decode(b); } catch (Exception e) { return null; }
            }
            if (target < 0) return null;                    // invalid (negative) block number
            if (target > headNum) return "null";            // future/unknown block → eth null
            long back = headNum - target;
            if (back >= BLOCK_LOOKBACK_MAX) return null;     // too far to verify cheaply → error

            List<BlockHeadersMessage.VerifiedHeader> window = conn
                    .requestBlockHeadersBatched(target, (int) (back + 1))
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!anchor.anchors(window)) return null;
            BlockHeadersMessage.VerifiedHeader vh = window.get(0); // target is first in [target..head]

            List<BlockBodiesMessage.BlockBody> bodies = conn
                    .requestBlockBodies(vh.hash())
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (bodies.isEmpty()) return null;
            List<Bytes> txs = bodies.get(0).transactions();
            if (!OrderedTrieRoot.verify(txs, vh.header().transactionsRoot)) return null;

            return buildBlockJson(vh, txs);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_getBlockByNumber failed: " + unwrap(e));
            return null;
        }
    }

    /** Build the eth_getBlockByNumber JSON from a VERIFIED header + verified tx list
     *  (transactions as hashes; fullTransactions=true is handled upstream as a follow-up). */
    private static String buildBlockJson(BlockHeadersMessage.VerifiedHeader vh, List<Bytes> txs) {
        BlockHeader h = vh.header();
        StringBuilder sb = new StringBuilder(1024);
        sb.append("{\"number\":\"").append(hexQuantity(h.number)).append("\"");
        sb.append(",\"hash\":\"").append(vh.hash().toHexString()).append("\"");
        sb.append(",\"parentHash\":\"").append(h.parentHash.toHexString()).append("\"");
        sb.append(",\"nonce\":\"").append(h.nonce.toHexString()).append("\"");
        sb.append(",\"sha3Uncles\":\"").append(h.ommersHash.toHexString()).append("\"");
        sb.append(",\"logsBloom\":\"").append(h.logsBloom.toHexString()).append("\"");
        sb.append(",\"transactionsRoot\":\"").append(h.transactionsRoot.toHexString()).append("\"");
        sb.append(",\"stateRoot\":\"").append(h.stateRoot.toHexString()).append("\"");
        sb.append(",\"receiptsRoot\":\"").append(h.receiptsRoot.toHexString()).append("\"");
        sb.append(",\"miner\":\"").append(h.beneficiary.toHexString()).append("\"");
        sb.append(",\"difficulty\":\"0x").append(h.difficulty.toString(16)).append("\"");
        sb.append(",\"extraData\":\"").append(h.extraData.toHexString()).append("\"");
        sb.append(",\"gasLimit\":\"").append(hexQuantity(h.gasLimit)).append("\"");
        sb.append(",\"gasUsed\":\"").append(hexQuantity(h.gasUsed)).append("\"");
        sb.append(",\"timestamp\":\"").append(hexQuantity(h.timestamp)).append("\"");
        sb.append(",\"mixHash\":\"").append(h.mixHashOrPrevRandao.toHexString()).append("\"");
        if (h.baseFeePerGas != null) {
            sb.append(",\"baseFeePerGas\":\"0x").append(h.baseFeePerGas.toString(16)).append("\"");
        }
        if (h.withdrawalsRoot != null) {
            sb.append(",\"withdrawalsRoot\":\"").append(h.withdrawalsRoot.toHexString()).append("\"");
        }
        if (h.blobGasUsed >= 0) {
            sb.append(",\"blobGasUsed\":\"").append(hexQuantity(h.blobGasUsed)).append("\"");
        }
        if (h.excessBlobGas >= 0) {
            sb.append(",\"excessBlobGas\":\"").append(hexQuantity(h.excessBlobGas)).append("\"");
        }
        if (h.parentBeaconBlockRoot != null) {
            sb.append(",\"parentBeaconBlockRoot\":\"").append(h.parentBeaconBlockRoot.toHexString()).append("\"");
        }
        sb.append(",\"transactions\":[");
        for (int i = 0; i < txs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(Hash.keccak256(txs.get(i)).toHexString()).append("\"");
        }
        sb.append("],\"uncles\":[]}");
        return sb.toString();
    }

    // ---- Fee suggestion (verified) ----------------------------------------
    // MetaMask's signing screen blocks on fee data (eth_feeHistory / eth_gasPrice /
    // eth_maxPriorityFeePerGas) — without it the confirm UI sits in skeleton-loading
    // forever. All fee data here is derived from VERIFIED sources only: baseFee /
    // gasUsed / gasLimit from beacon-anchored headers, priority-fee tips from block
    // bodies verified against transactionsRoot (+ receipts verified against
    // receiptsRoot for gas-used percentile weighting).

    /** Max blocks served per eth_feeHistory call (clamped per EIP-1559; MetaMask asks 5-10). */
    private static final int FEE_HISTORY_MAX_BLOCKS = 10;
    /** Blocks scanned for the priority-fee suggestion. */
    private static final int TIP_SUGGEST_BLOCKS = 3;
    /** Floor for the suggested tip: 0.1 gwei — keeps suggestions inclusive-but-sane
     *  when recent blocks are empty or full of zero-tip txs. */
    private static final java.math.BigInteger MIN_SUGGESTED_TIP =
            java.math.BigInteger.valueOf(100_000_000L);
    /** Tip suggestion cache TTL (~one block) — MetaMask polls fees every few seconds,
     *  and each recompute fetches TIP_SUGGEST_BLOCKS bodies. */
    private static final long TIP_CACHE_TTL_MS = 12_000;
    /** Suggested tip + when it was computed, one immutable unit behind a single
     *  volatile so a reader can't pair a fresh tip with a stale timestamp
     *  (same pattern as {@link HeadWithTimestamp}). */
    private record TipWithTimestamp(java.math.BigInteger tip, long atMs) {}
    private volatile TipWithTimestamp cachedSuggestedTip;

    /** Next block's base fee per the EIP-1559 update rule, from the parent header. */
    private static java.math.BigInteger nextBaseFee(BlockHeader h) {
        java.math.BigInteger base = h.baseFeePerGas;
        if (base == null) return java.math.BigInteger.ZERO; // pre-London (not mainnet today)
        long gasTarget = h.gasLimit / 2;
        if (gasTarget <= 0 || h.gasUsed == gasTarget) return base;
        java.math.BigInteger target = java.math.BigInteger.valueOf(gasTarget);
        if (h.gasUsed > gasTarget) {
            java.math.BigInteger delta = base
                    .multiply(java.math.BigInteger.valueOf(h.gasUsed - gasTarget))
                    .divide(target)
                    .divide(java.math.BigInteger.valueOf(8))
                    .max(java.math.BigInteger.ONE);
            return base.add(delta);
        }
        java.math.BigInteger delta = base
                .multiply(java.math.BigInteger.valueOf(gasTarget - h.gasUsed))
                .divide(target)
                .divide(java.math.BigInteger.valueOf(8));
        return base.subtract(delta);
    }

    /** Fetch the beacon-anchored header window [head-count+1 .. head]; null if it
     *  can't be fetched or doesn't anchor. */
    private List<BlockHeadersMessage.VerifiedHeader> anchoredHeaderWindow(
            HeaderAnchor anchor, int count) throws Exception {
        RLPxConnector conn = connector;
        if (conn == null) return null;
        long start = Math.max(0, anchor.number() - count + 1);
        List<BlockHeadersMessage.VerifiedHeader> window = conn
                .requestBlockHeadersBatched(start, (int) (anchor.number() - start + 1))
                .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
        return anchor.anchors(window) ? window : null;
    }

    /** A tx's effective priority fee plus the gas it used (receipt cumulative diff). */
    private record TxTip(java.math.BigInteger tip, long gasUsed) {}

    /** Per-tx (effectiveTip, gasUsed) of a block, from a body verified against
     *  transactionsRoot (+ receipts verified against receiptsRoot when
     *  {@code needGasWeights}). Null when the block can't be verified; empty for
     *  an empty block. */
    private List<TxTip> verifiedBlockTips(BlockHeadersMessage.VerifiedHeader vh,
                                          boolean needGasWeights) throws Exception {
        RLPxConnector conn = connector;
        if (conn == null) return null;
        BlockHeader h = vh.header();
        List<BlockBodiesMessage.BlockBody> bodies = conn
                .requestBlockBodies(vh.hash())
                .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
        if (bodies.isEmpty()) {
            LogBuffer.i(TAG, "[rpc] tips: no body for block #" + h.number);
            return null;
        }
        List<Bytes> txs = bodies.get(0).transactions();
        if (!OrderedTrieRoot.verify(txs, h.transactionsRoot)) {
            LogBuffer.i(TAG, "[rpc] tips: block #" + h.number + " body failed transactionsRoot verify");
            return null;
        }
        if (txs.isEmpty()) return java.util.Collections.emptyList();

        long[] gasUsed = null;
        if (needGasWeights) {
            List<List<Bytes>> rcptBlocks = conn
                    .requestReceipts(vh.hash())
                    .get(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (rcptBlocks.isEmpty()) {
                LogBuffer.i(TAG, "[rpc] tips: no receipts for block #" + h.number);
                return null;
            }
            List<Bytes> receipts = rcptBlocks.get(0);
            if (receipts.size() != txs.size()
                    || !OrderedTrieRoot.verify(receipts, h.receiptsRoot)) {
                LogBuffer.i(TAG, "[rpc] tips: block #" + h.number + " receipts mismatch (got "
                        + receipts.size() + " for " + txs.size() + " txs) or root verify failed");
                return null;
            }
            gasUsed = new long[txs.size()];
            long prevCum = 0;
            for (int i = 0; i < receipts.size(); i++) {
                long cum = Receipt.decode(receipts.get(i)).cumulativeGasUsed();
                gasUsed[i] = cum - prevCum;
                prevCum = cum;
            }
        }

        java.math.BigInteger baseFee =
                h.baseFeePerGas != null ? h.baseFeePerGas : java.math.BigInteger.ZERO;
        List<TxTip> out = new ArrayList<>(txs.size());
        for (int i = 0; i < txs.size(); i++) {
            TxFeeFields f = TxFeeFields.decode(txs.get(i));
            if (f == null) { // verified body with an unparseable tx — bail
                LogBuffer.i(TAG, "[rpc] tips: block #" + h.number + " tx " + i
                        + " undecodable (" + (txs.get(i).isEmpty() ? "empty"
                        : "first byte 0x" + Integer.toHexString(txs.get(i).get(0) & 0xFF)) + ")");
                return null;
            }
            out.add(new TxTip(f.effectiveTip(baseFee), gasUsed != null ? gasUsed[i] : 0));
        }
        return out;
    }

    /** Suggested priority fee: median effective tip over the last
     *  {@link #TIP_SUGGEST_BLOCKS} verified blocks, floored at
     *  {@link #MIN_SUGGESTED_TIP}. Cached for ~one block. Null → can't verify. */
    private java.math.BigInteger rpcMaxPriorityFeePerGas() {
        TipWithTimestamp cached = cachedSuggestedTip;
        if (cached != null
                && android.os.SystemClock.elapsedRealtime() - cached.atMs() < TIP_CACHE_TTL_MS) {
            return cached.tip();
        }
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            List<BlockHeadersMessage.VerifiedHeader> window =
                    anchoredHeaderWindow(anchor, TIP_SUGGEST_BLOCKS);
            if (window == null) return null;
            List<java.math.BigInteger> tips = new ArrayList<>();
            for (BlockHeadersMessage.VerifiedHeader vh : window) {
                List<TxTip> blockTips = verifiedBlockTips(vh, false);
                if (blockTips == null) continue; // one unverifiable block doesn't kill the suggestion
                for (TxTip t : blockTips) tips.add(t.tip());
            }
            java.math.BigInteger tip;
            if (tips.isEmpty()) {
                tip = MIN_SUGGESTED_TIP;
            } else {
                java.util.Collections.sort(tips);
                tip = tips.get(tips.size() / 2).max(MIN_SUGGESTED_TIP);
            }
            cachedSuggestedTip = new TipWithTimestamp(tip, android.os.SystemClock.elapsedRealtime());
            return tip;
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_maxPriorityFeePerGas failed: " + unwrap(e));
            return null;
        }
    }

    /** Legacy-style total gas price: next block's base fee + the suggested tip. */
    private java.math.BigInteger rpcGasPrice() {
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            List<BlockHeadersMessage.VerifiedHeader> window = anchoredHeaderWindow(anchor, 1);
            if (window == null || window.isEmpty()) return null;
            java.math.BigInteger tip = rpcMaxPriorityFeePerGas();
            if (tip == null) return null;
            return nextBaseFee(window.get(window.size() - 1).header()).add(tip);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_gasPrice failed: " + unwrap(e));
            return null;
        }
    }

    /**
     * eth_feeHistory from verified data. baseFeePerGas / gasUsedRatio come from the
     * beacon-anchored header window; reward percentiles (when requested) from bodies
     * verified against transactionsRoot + receipts verified against receiptsRoot,
     * using geth's gas-used-weighted percentile walk. blockCount is clamped to
     * {@link #FEE_HISTORY_MAX_BLOCKS}; the result reflects what was served.
     */
    private String rpcFeeHistory(long blockCount, String newestBlock, double[] percentiles) {
        try {
            HeaderAnchor anchor = headerAnchor();
            if (anchor == null) return null;
            long headNum = anchor.number();

            long newest;
            String nb = (newestBlock == null) ? "latest" : newestBlock;
            switch (nb) {
                case "latest": case "pending": case "safe": case "finalized":
                    newest = headNum; break;
                case "earliest":
                    return null;
                default:
                    try { newest = Long.decode(nb); } catch (Exception e) { return null; }
            }
            if (newest < 0 || newest > headNum) return null;

            int count = (int) Math.min(Math.min(blockCount, FEE_HISTORY_MAX_BLOCKS), newest + 1);
            long oldest = newest - count + 1;
            if (headNum - oldest >= BLOCK_LOOKBACK_MAX) return null; // too far back to verify cheaply

            // One anchored window [oldest..head]; the requested span is its first
            // `count` entries (the window may extend past `newest` up to the head —
            // that's what anchors it, and it gives the ACTUAL next-block baseFee).
            List<BlockHeadersMessage.VerifiedHeader> window =
                    anchoredHeaderWindow(anchor, (int) (headNum - oldest + 1));
            if (window == null || window.size() < count) return null;

            StringBuilder sb = new StringBuilder(256);
            sb.append("{\"oldestBlock\":\"").append(hexQuantity(oldest)).append("\"");

            sb.append(",\"baseFeePerGas\":[");
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(",");
                java.math.BigInteger bf = window.get(i).header().baseFeePerGas;
                sb.append("\"0x").append((bf != null ? bf : java.math.BigInteger.ZERO).toString(16)).append("\"");
            }
            // Entry count+1: the next block after `newest` — its actual baseFee when the
            // window extends past newest, else the EIP-1559 prediction from `newest`.
            java.math.BigInteger nextBf = (count < window.size())
                    ? (window.get(count).header().baseFeePerGas != null
                        ? window.get(count).header().baseFeePerGas : java.math.BigInteger.ZERO)
                    : nextBaseFee(window.get(count - 1).header());
            sb.append(",\"0x").append(nextBf.toString(16)).append("\"]");

            sb.append(",\"gasUsedRatio\":[");
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(",");
                BlockHeader h = window.get(i).header();
                double ratio = h.gasLimit > 0 ? (double) h.gasUsed / (double) h.gasLimit : 0.0;
                sb.append(ratio);
            }
            sb.append("]");

            if (percentiles != null) {
                sb.append(",\"reward\":[");
                for (int i = 0; i < count; i++) {
                    if (i > 0) sb.append(",");
                    List<TxTip> tips = verifiedBlockTips(window.get(i), true);
                    if (tips == null) return null; // strict: no unverified rewards
                    sb.append(rewardJson(tips, percentiles));
                }
                sb.append("]");
            }
            sb.append("}");
            return sb.toString();
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_feeHistory failed: " + unwrap(e));
            return null;
        }
    }

    /** Gas-used-weighted percentile rewards for one block (geth's algorithm): sort txs
     *  by tip, walk percentile thresholds over cumulative gasUsed. Empty block → zeros. */
    private static String rewardJson(List<TxTip> tips, double[] percentiles) {
        StringBuilder sb = new StringBuilder(percentiles.length * 12 + 2);
        sb.append("[");
        if (tips.isEmpty()) {
            for (int p = 0; p < percentiles.length; p++) {
                if (p > 0) sb.append(",");
                sb.append("\"0x0\"");
            }
            return sb.append("]").toString();
        }
        List<TxTip> sorted = new ArrayList<>(tips);
        sorted.sort(java.util.Comparator.comparing(TxTip::tip));
        long totalGas = 0;
        for (TxTip t : sorted) totalGas += t.gasUsed();
        int idx = 0;
        long cumGas = sorted.get(0).gasUsed();
        for (int p = 0; p < percentiles.length; p++) {
            if (p > 0) sb.append(",");
            double threshold = totalGas * percentiles[p] / 100.0;
            while (cumGas < threshold && idx < sorted.size() - 1) {
                idx++;
                cumGas += sorted.get(idx).gasUsed();
            }
            sb.append("\"0x").append(sorted.get(idx).tip().toString(16)).append("\"");
        }
        return sb.append("]").toString();
    }

    /**
     * eth_estimateGas over the shared anchored head: runs the call in the local EVM
     * against snap-verified state with full gas accounting (intrinsic + execution +
     * 15% headroom — see {@code DefaultEvmExecutor.estimateGas}). A reverting tx gets
     * an error, not a number — the wallet must not broadcast it. Contract creation
     * (to=null) isn't served verified yet → null → router errors.
     */
    private java.math.BigInteger rpcEstimateGas(byte[] from, byte[] to, byte[] data,
                                                java.math.BigInteger value) {
        if (to == null || to.length != 20) return null;
        if (from != null && from.length != 20) return null;
        EnsCall h = anchoredHeadOrWait();
        if (h == null) return null;
        try {
            // Fast path: a value transfer with no calldata to a plain account costs
            // exactly 21000 — no EVM execution, no 15% headroom (it's exact). This is
            // MetaMask's send-ETH flow. We still fetch the recipient ONCE to confirm
            // it has no code (a contract receive()/fallback, or a 7702 delegation,
            // would execute and cost more) — but skip building+running the EVM, the
            // bulk of the per-estimate work on ART.
            boolean noData = data == null || data.length == 0;
            if (noData) {
                io.myotis.evm.world.AccountState acct = h.oracle()
                        .fetchAccount(h.blockCtx().stateRoot(), io.myotis.evm.Address.of(to))
                        .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
                byte[] codeHash = acct == null ? null : acct.codeHash();
                if (codeHash != null && java.util.Arrays.equals(codeHash, EMPTY_CODE_HASH)) {
                    return java.math.BigInteger.valueOf(21_000);
                }
                // Has code (contract / 7702 EOA) → fall through to the full EVM estimate.
            }
            io.myotis.evm.UnsignedTransaction tx = new io.myotis.evm.UnsignedTransaction(
                    io.myotis.evm.Address.of(from != null ? from : new byte[20]),
                    io.myotis.evm.Address.of(to),
                    value != null ? value : java.math.BigInteger.ZERO,
                    data != null ? data : new byte[0],
                    null);
            Long gas = h.offchainExecutor().estimateGas(tx, h.blockCtx())
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
            return gas == null ? null : java.math.BigInteger.valueOf(gas);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_estimateGas -> error: " + describeEvmError(e));
            return null;
        }
    }

    /** Render an estimate/call failure, decoding EvmExecutionException revert data —
     *  the estimator packs halt diagnostics ("halt=... state=...") into Reverted bytes,
     *  which the default toString prints as an opaque [B@hash. */
    private static String describeEvmError(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof io.myotis.evm.EvmExecutionException ee
                    && ee.error() instanceof io.myotis.evm.EvmExecutionError.Reverted rev) {
                byte[] d = rev.data();
                boolean printable = d.length > 0;
                for (byte b : d) {
                    if (b < 0x20 || b > 0x7e) { printable = false; break; }
                }
                return "Reverted: " + (printable
                        ? new String(d, java.nio.charset.StandardCharsets.US_ASCII)
                        : Bytes.wrap(d).toHexString());
            }
        }
        return unwrap(e);
    }

    /** Render a storage value as a 32-byte big-endian word (drops BigInteger's
     *  two's-complement sign byte, left-pads short magnitudes). */
    private static byte[] word32(java.math.BigInteger v) {
        byte[] out = new byte[32];
        byte[] mag = v.toByteArray();
        int len = Math.min(mag.length, 32);
        System.arraycopy(mag, mag.length - len, out, 32 - len, len);
        return out;
    }

    /** Build (or reuse within {@link #RPC_HEAD_TTL_MS}) a snap-peer head context
     *  whose state root is anchored back to the beacon-finalized root, so reads +
     *  EVM calls run against cryptographically-verified state. Blocking. */
    /** Full-budget variant for the background warmer. */
    private EnsCall verifiedHeadCallContext() throws Exception {
        return verifiedHeadCallContext(RPC_ACCOUNT_TIMEOUT_SEC * 1000L, TimeUnit.MILLISECONDS);
    }

    private EnsCall verifiedHeadCallContext(long timeout, TimeUnit unit) throws Exception {
        CompletableFuture<EnsCall> future;
        boolean build = false;
        synchronized (rpcCallCtxLock) {
            long now = android.os.SystemClock.elapsedRealtime();
            // Reuse an in-flight build (regardless of age — never start a parallel
            // one) or a completed-OK result still within the TTL.
            if (rpcCallCtx != null
                    && (!rpcCallCtx.isDone()
                        || (!rpcCallCtx.isCompletedExceptionally() && now - rpcCallCtxAtMs < RPC_HEAD_TTL_MS))) {
                future = rpcCallCtx;
            } else {
                future = new CompletableFuture<>();
                rpcCallCtx = future;
                rpcCallCtxAtMs = now;
                build = true;
            }
        }
        // Build on a background thread so the caller only blocks up to `timeout`
        // (honoring verifiedHeadFor's bounded wait even when this call triggers the
        // build). A burst of concurrent reads shares the one builder's future.
        if (build) {
            final CompletableFuture<EnsCall> f = future;
            try {
                headBuildPool.execute(() -> {
                    try {
                        EnsCall ctx = buildAnchoredHead();
                        lastGoodHead = new HeadWithTimestamp(ctx, android.os.SystemClock.elapsedRealtime());
                        f.complete(ctx);
                    } catch (Throwable t) {
                        f.completeExceptionally(t);
                        synchronized (rpcCallCtxLock) {
                            if (rpcCallCtx == f) rpcCallCtx = null;   // let the next call retry
                        }
                    }
                });
            } catch (java.util.concurrent.RejectedExecutionException rex) {  // shutting down
                f.completeExceptionally(rex);
                synchronized (rpcCallCtxLock) { if (rpcCallCtx == f) rpcCallCtx = null; }
            }
        }
        try {
            return future.get(timeout, unit);   // build continues in the background on timeout
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw (cause instanceof Exception) ? (Exception) cause : new Exception(cause);
        }
    }

    /**
     * Pre-warm and keep-warm the shared anchored head: build it as soon as a snap
     * peer is ready (retrying every few seconds), so a wallet's first read hits a
     * ready cache instead of triggering a cold build — shrinking the post-start
     * window where reads fall back to the proxy down to "time until first usable
     * snap peer". Cheap when warm: verifiedHeadCallContext reuses a fresh context.
     */
    /**
     * Keep a working set of snap peers connected ({@link #TARGET_SNAP_PEERS}) so a
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
            if (snapPeers >= TARGET_SNAP_PEERS) return;
            long now = System.currentTimeMillis();
            LogBuffer.i(TAG, "[peers] " + snapPeers + " snap peer(s) < target " + TARGET_SNAP_PEERS
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
                        if (conn.activeSnapHandlers().size() >= TARGET_SNAP_PEERS) break;
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
            if (!pool.isEmpty() && conn.activeSnapHandlers().size() < TARGET_SNAP_PEERS) {
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
            if (conn.activeSnapHandlers().size() < TARGET_SNAP_PEERS
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
     * Feed a snap-serving verdict for {@code peer} into the EL peer cache so good
     * snap peers are remembered across restarts (dialed first) and repeat hangers
     * deprioritized. {@code served=true} on a usable proof, {@code false} on a
     * root-unavailable (empty/invalid proof, timeout, IO). No-op if the cache is
     * absent or the handler's remote address can't be parsed.
     */
    private static void recordSnapQuality(AndroidPeerCache cache,
            com.jaeckel.ethp2p.networking.eth.EthHandler peer, boolean served) {
        if (cache == null || peer == null) return;
        InetSocketAddress addr = remoteAddressOf(peer);
        if (addr == null) return;
        try {
            if (served) cache.recordSnapServed(addr);
            else cache.recordSnapFailure(addr);
        } catch (RuntimeException ignore) {
            // Never let cache bookkeeping disrupt an in-flight RPC.
        }
    }

    /**
     * Parse {@link com.jaeckel.ethp2p.networking.eth.EthHandler#getRemoteAddress()}
     * ("ip:port", or "[v6]:port") into an unresolved {@link InetSocketAddress} whose
     * {@code getHostString()} matches the key {@link AndroidPeerCache} stored at dial
     * time. Returns {@code null} on a missing/malformed address.
     */
    private static InetSocketAddress remoteAddressOf(
            com.jaeckel.ethp2p.networking.eth.EthHandler peer) {
        String ra = peer.getRemoteAddress();
        if (ra == null || ra.isEmpty()) return null;
        int colon = ra.lastIndexOf(':');
        if (colon <= 0 || colon == ra.length() - 1) return null;
        String host = ra.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        try {
            int port = Integer.parseInt(ra.substring(colon + 1));
            return InetSocketAddress.createUnresolved(host, port);
        } catch (NumberFormatException e) {
            return null;
        }
    }

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

    private void startHeadWarmer() {
        if (headWarmer != null) return;
        headWarmer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "rpc-head-warmer");
            t.setDaemon(true);
            return t;
        });
        headWarmer.scheduleWithFixedDelay(() -> {
            if (!RUNNING.get()) return;
            try {
                verifiedHeadCallContext();
            } catch (Exception ignored) {
                // No usable snap peer / anchorable head yet — retry next tick.
            }
        }, 3, 5, TimeUnit.SECONDS);
    }

    /**
     * Build a fully beacon-verified head context, preferring the freshest
     * snap-servable head (PEER_HEAD, anchored to finalized via headerChain) and
     * falling back to the beacon-finalized root (verified directly by the light
     * client, ~12 min stale) when no peer serves a fresh head. Both paths are
     * cryptographically anchored to the beacon chain — so under poor snap
     * conditions reads stay verified (just staler) instead of all proxying.
     */
    private EnsCall buildAnchoredHead() throws Exception {
        try {
            EnsCall ctx = prepareEnsCall(io.myotis.ens.EnsResolutionRoot.PEER_HEAD);
            if (anchorHeadToBeacon(ctx.blockNumber(), ctx.blockCtx().stateRoot())) {
                // anchorHeadToBeacon ran the full headerChain verify from beacon-finalized
                // to this head, so it IS cryptographically anchored now — but prepareEnsCall
                // initialized the PEER_HEAD flag to false. Reflect the verification in the
                // returned context so beaconVerified() is true (eth_getBlockByNumber /
                // eth_getTransactionReceipt gate on it; without this they reject the freshly
                // anchored head and only the finalized fallback ever passed).
                return new EnsCall(ctx.resolver(), ctx.blockCtx(), ctx.blockNumber(),
                        true, ctx.offchainExecutor(), ctx.oracle());
            }
            LogBuffer.i(TAG, "[rpc] fresh head not beacon-anchored (block #"
                    + ctx.blockNumber() + "); falling back to finalized");
        } catch (Exception headEx) {
            LogBuffer.i(TAG, "[rpc] no snap-servable fresh head (" + unwrap(headEx)
                    + "); falling back to finalized");
        }
        // Fallback: the beacon-finalized execution root, verified directly by the
        // light client (no headerChain needed). Throws if no peer retains it.
        return prepareEnsCall(io.myotis.ens.EnsResolutionRoot.FINALIZED);
    }

    /** True iff {@code peerStateRoot} at {@code peerBlock} chains back to the
     *  beacon-finalized execution root (same headerChain method as get-account). */
    private boolean anchorHeadToBeacon(long peerBlock, byte[] peerStateRoot) throws Exception {
        com.jaeckel.ethp2p.consensus.BeaconLightClient blc = beaconLightClient;
        RLPxConnector conn = connector;
        if (blc == null || conn == null) return false;
        com.jaeckel.ethp2p.consensus.types.LightClientHeader fin =
                blc.getStore().getFinalizedHeader();
        if (fin == null) return false;
        com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader exec = fin.execution();
        if (exec.blockNumber() == peerBlock) {
            // Head is exactly the finalized block — roots must match directly.
            return java.util.Arrays.equals(exec.stateRoot(), peerStateRoot);
        }
        return verifyHeaderChainBatched(conn, exec.blockNumber(), peerBlock,
                exec.stateRoot(), peerStateRoot)
                .get(HEADER_CHAIN_TIMEOUT_SEC + 5, TimeUnit.SECONDS);
    }

    private record EnsCall(io.myotis.ens.EnsResolver resolver,
                           io.myotis.evm.BlockContext blockCtx,
                           long blockNumber,
                           boolean beaconVerified,
                           io.myotis.evm.CcipReadEvmExecutor offchainExecutor,
                           io.myotis.evm.world.SnapBackedStateOracle oracle) {}

    /** A snap peer paired with the fresh head it both reported and snap-serves. */
    private record PeerHead(com.jaeckel.ethp2p.networking.eth.EthHandler peer,
                            com.jaeckel.ethp2p.core.types.BlockHeader header) {}

    /** A built anchored head plus when it was built (elapsedRealtime), held as one
     *  immutable unit so the serve-stale check reads both atomically. */
    private record HeadWithTimestamp(EnsCall head, long builtAtMs) {}

    /**
     * Resolve to the first future that completes <em>successfully</em> (non-null),
     * ignoring failures; if every future fails, throw the last failure; if none
     * resolves within {@code timeoutSec}, throw {@link java.util.concurrent.TimeoutException}.
     * Hung futures are simply never awaited again — harmless, and bounded by the
     * overall timeout. Used to run the snap-peer head probes in parallel.
     */
    private static <T> T firstSuccess(java.util.List<CompletableFuture<T>> futures, long timeoutSec)
            throws Exception {
        if (futures.isEmpty()) throw new IllegalStateException("no ready snap peers");
        CompletableFuture<T> result = new CompletableFuture<>();
        java.util.concurrent.atomic.AtomicInteger remaining =
                new java.util.concurrent.atomic.AtomicInteger(futures.size());
        java.util.concurrent.atomic.AtomicReference<Throwable> lastErr =
                new java.util.concurrent.atomic.AtomicReference<>();
        for (CompletableFuture<T> f : futures) {
            f.whenComplete((v, e) -> {
                if (e == null && v != null) {
                    if (result.complete(v)) {
                        // First winner: cancel the rest so losing probes don't keep
                        // burning CPU/battery/data in the background on mobile.
                        for (CompletableFuture<T> other : futures) {
                            if (other != f) other.cancel(true);
                        }
                    }
                } else {
                    if (e != null) lastErr.set(e);
                    if (remaining.decrementAndGet() == 0) {
                        Throwable le = lastErr.get();
                        result.completeExceptionally(le != null ? le
                                : new IllegalStateException("no peer qualified"));
                    }
                }
            });
        }
        try {
            return result.get(timeoutSec, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException ee) {
            Throwable c = ee.getCause() != null ? ee.getCause() : ee;
            throw (c instanceof Exception) ? (Exception) c : new Exception(c);
        }
    }

    /** An {@link #attemptResolve} outcome plus whether it used an ERC-3668 gateway. */
    private record Attempt(EnsResolution resolution, boolean usedOffchain) {}

    /**
     * Build the EVM/ENS stack. The {@code root} selects which state the ENS
     * contracts run against — see {@link io.myotis.ens.EnsResolutionRoot}:
     * FINALIZED (default) anchors resolution to the light client's
     * beacon-verified finalized state (verified mapping, no head probe);
     * PEER_HEAD uses a snap peer's latest head (freshest, but peer-claimed).
     * Mirrors {@code CommandHandler.prepareEnsCall}. Blocking — call off the UI thread.
     */
    private EnsCall prepareEnsCall(io.myotis.ens.EnsResolutionRoot root) throws Exception {
        RLPxConnector conn = connector;
        if (conn == null) throw new IllegalStateException("node not running");
        List<com.jaeckel.ethp2p.networking.eth.EthHandler> snapPeers = conn.activeSnapHandlers();
        if (snapPeers.isEmpty()) {
            throw new IllegalStateException("No active peer with snap/1 support");
        }

        io.myotis.evm.BlockContext blockCtx;
        long blockNumber;
        boolean verified;
        com.jaeckel.ethp2p.networking.eth.EthHandler pinned;

        if (root == io.myotis.ens.EnsResolutionRoot.FINALIZED) {
            // Resolve against the beacon-verified finalized execution header — the
            // resulting name→address mapping is anchored to a beacon-attested root
            // (snap proofs verify against it). ~12 min stale (finality lag). A snap
            // peer must still retain that block's state, which they often DON'T
            // (Geth prunes trie state beyond ~128 blocks and serves snap from a
            // flat layer lagging the head). So we don't blindly pin a peer — we
            // probe each one for the finalized root and pin the first that actually
            // serves it. If none do, we throw and AUTO falls back to the head.
            com.jaeckel.ethp2p.consensus.BeaconLightClient blc = beaconLightClient;
            if (blc == null) throw new IllegalStateException("beacon light client not running");
            com.jaeckel.ethp2p.consensus.types.LightClientHeader fin = blc.getStore().getFinalizedHeader();
            if (fin == null) throw new IllegalStateException("no beacon-verified finalized header yet");
            com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader exec = fin.execution();
            org.apache.tuweni.bytes.Bytes32 finRoot =
                    org.apache.tuweni.bytes.Bytes32.wrap(exec.stateRoot());
            pinned = firstPeerServing(snapPeers, finRoot);
            if (pinned == null) {
                throw new IllegalStateException(
                        "no snap peer retains the beacon-finalized state (block #"
                        + exec.blockNumber() + ")");
            }
            blockCtx = new io.myotis.evm.BlockContext(
                    exec.stateRoot(),
                    exec.blockNumber(),
                    exec.timestamp(),
                    leUint256ToBigInteger(exec.baseFeePerGas()),
                    io.myotis.evm.Address.of(exec.feeRecipient()),
                    exec.prevRandao(),
                    java.math.BigInteger.valueOf(conn.getNetwork().networkId()),
                    exec.gasLimit());
            blockNumber = exec.blockNumber();
            verified = true;
        } else {
            // PEER_HEAD: each peer's bleeding-edge head root is frequently NOT yet
            // snap-servable (the flat state lags the head). Walk every peer: fetch
            // its fresh head, then PROBE that the peer actually serves a snap
            // account at that root before pinning it — the same resilience
            // get-account gets by retrying across peers. The first peer that passes
            // both is pinned for the whole resolution (one consistent root).
            final long minHead = conn.getNetwork().minSensibleHeadBlock();
            // Live staleness floor: a peer whose head is BEHIND the beacon-finalized
            // exec block can never anchor (anchorHeadToBeacon verifies the chain
            // finalized→head, and finality has already passed it) — yet such a peer
            // happily snap-serves its frozen root and can win the probe race below,
            // forcing every build into the finalized fallback while fresh-headed
            // peers sit connected. Observed on-device: two peers frozen at the same
            // head for 5+ min starved number-pinned reads.
            long finalizedFloor = -1;
            com.jaeckel.ethp2p.consensus.BeaconLightClient blcFloor = beaconLightClient;
            if (blcFloor != null) {
                com.jaeckel.ethp2p.consensus.types.LightClientHeader finHdr =
                        blcFloor.getStore().getFinalizedHeader();
                if (finHdr != null) finalizedFloor = finHdr.execution().blockNumber();
            }
            final long headFloor = Math.max(minHead, finalizedFloor);
            // Probe every ready snap peer CONCURRENTLY — fetch its fresh head, then
            // probe that it snap-serves that head root — and award the FIRST to
            // qualify. The old serial walk paid each unresponsive peer's timeout in
            // turn (the dominant build cost, and a frequent proxy-fallback trigger);
            // running the probes in parallel collapses that to ~one round-trip.
            java.util.List<CompletableFuture<PeerHead>> probes = new java.util.ArrayList<>();
            for (com.jaeckel.ethp2p.networking.eth.EthHandler peer : snapPeers) {
                if (!peer.isReady() || peer.isSnapServingFailed()) continue;
                CompletableFuture<com.jaeckel.ethp2p.core.types.BlockHeader> headFut =
                        peer.requestFreshHeadHeaderAsync();
                if (headFut == null) continue;
                probes.add(headFut.thenCompose(fresh -> {
                    if (fresh.number < headFloor) {
                        throw new java.util.concurrent.CompletionException(
                                new IllegalStateException("stale head #" + fresh.number
                                        + " (< floor #" + headFloor + ")"));
                    }
                    // servesRoot, but async: the peer must return a non-empty proof
                    // for the probe account at its head root.
                    return peer.requestAccountByHashAsync(SNAP_PROBE_ACCOUNT_HASH, fresh.stateRoot)
                            .thenApply(probe -> {
                                if (probe.proof() == null || probe.proof().isEmpty()) {
                                    throw new java.util.concurrent.CompletionException(
                                            new IllegalStateException(
                                                    "peer does not snap-serve head root (block #"
                                                            + fresh.number + ")"));
                                }
                                return new PeerHead(peer, fresh);
                            });
                }));
            }
            PeerHead chosen;
            try {
                chosen = firstSuccess(probes, PEER_PROBE_TIMEOUT_SEC);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "No snap peer served a fresh head root (" + unwrap(e) + ")");
            }
            com.jaeckel.ethp2p.networking.eth.EthHandler headPeer = chosen.peer();
            com.jaeckel.ethp2p.core.types.BlockHeader header = chosen.header();
            blockCtx = new io.myotis.evm.BlockContext(
                    header.stateRoot.toArrayUnsafe(),
                    header.number,
                    header.timestamp,
                    header.baseFeePerGas,
                    io.myotis.evm.Address.of(header.beneficiary.toArrayUnsafe()),
                    header.mixHashOrPrevRandao.toArrayUnsafe(),
                    java.math.BigInteger.valueOf(conn.getNetwork().networkId()),
                    header.gasLimit);
            blockNumber = header.number;
            verified = false;
            pinned = headPeer;
        }

        // Snap requests carry the stateRoot explicitly, so ANY connected snap peer
        // that retains blockCtx's trie can serve them — not just the one we probed.
        // The oracle retries across peers (peerSupplier.get() per attempt); rotate the
        // supplier so a peer that times out fails over to others instead of funnelling
        // all retries into one dead peer (every eth_call against that context then hit
        // the 30s timeout while OTHER peers held the same state). The probed peer is
        // tried first (known to serve this root); subsequent attempts round-robin the
        // rest of the ready snap set.
        final com.jaeckel.ethp2p.networking.eth.EthHandler probedPeer = pinned;
        final RLPxConnector oracleConn = conn;
        final java.util.concurrent.atomic.AtomicInteger rotation =
                new java.util.concurrent.atomic.AtomicInteger();
        // Peers that returned an empty proof / no-state for THIS head's stateRoot — they
        // don't retain its trie (a chunk of the pool lags the head). Deny them for this
        // context so the rotation converges on peers that actually serve the root instead
        // of re-handing out empty-proof peers and exhausting every fetch's retries (the
        // cause of heavy-multicall eth_call 30s failures). Per-context; cleared next build.
        final java.util.Set<com.jaeckel.ethp2p.networking.eth.EthHandler> rootDenied =
                java.util.concurrent.ConcurrentHashMap.newKeySet();
        // Persisted EL-cache quality signal: a non-empty proof confirms the peer
        // as snap-serving (dialed first on restart); the same root-unavailable
        // event that deprioritizes it for this head also feeds a failure verdict
        // so repeat hangers are deprioritized across restarts.
        final AndroidPeerCache snapQualityCache = peerCache;
        io.myotis.evm.world.SnapBackedStateOracle oracle =
                new io.myotis.evm.world.SnapBackedStateOracle(
                        () -> {
                            int n = rotation.getAndIncrement();
                            if (n == 0 && probedPeer.isReady() && !probedPeer.isSnapServingFailed()
                                    && !rootDenied.contains(probedPeer)) {
                                final com.jaeckel.ethp2p.networking.eth.EthHandler pp = probedPeer;
                                return new com.jaeckel.ethp2p.android.snap.EthHandlerSnapPeer(
                                        pp,
                                        () -> { rootDenied.add(pp); recordSnapQuality(snapQualityCache, pp, false); },
                                        () -> recordSnapQuality(snapQualityCache, pp, true));
                            }
                            // activeSnapHandlers() already returns only ready, snap-negotiated,
                            // non-failed peers; drop the ones denied for this root.
                            java.util.List<com.jaeckel.ethp2p.networking.eth.EthHandler> ready =
                                    new java.util.ArrayList<>();
                            for (com.jaeckel.ethp2p.networking.eth.EthHandler p : oracleConn.activeSnapHandlers()) {
                                if (!rootDenied.contains(p)) ready.add(p);
                            }
                            if (ready.isEmpty()) return null;
                            final com.jaeckel.ethp2p.networking.eth.EthHandler chosen =
                                    ready.get(Math.floorMod(n, ready.size()));
                            return new com.jaeckel.ethp2p.android.snap.EthHandlerSnapPeer(
                                    chosen,
                                    () -> { rootDenied.add(chosen); recordSnapQuality(snapQualityCache, chosen, false); },
                                    () -> recordSnapQuality(snapQualityCache, chosen, true));
                        },
                        ensBytecodeCache,
                        SNAP_ORACLE_MAX_ATTEMPTS);
        io.myotis.evm.DefaultEvmExecutor base =
                new io.myotis.evm.DefaultEvmExecutor(oracle, ensBytecodeCache, evmPool);
        io.myotis.evm.PrefetchingEvmExecutor prefetching =
                new io.myotis.evm.PrefetchingEvmExecutor(base);
        io.myotis.evm.ccipread.CcipReadHandler ccip =
                new io.myotis.evm.ccipread.CcipReadHandler(
                        new com.jaeckel.ethp2p.android.ens.AndroidCcipGateway(ccipPool));
        io.myotis.evm.CcipReadEvmExecutor executor =
                new io.myotis.evm.CcipReadEvmExecutor(prefetching, ccip);
        io.myotis.ens.EnsResolver resolver =
                io.myotis.ens.EnsResolver.forChainId(executor, conn.getNetwork().networkId());
        return new EnsCall(resolver, blockCtx, blockNumber, verified, executor, oracle);
    }

    /**
     * Probe account used only to confirm a peer can actually serve snap state at a
     * given root before we pin it for a whole ENS resolution. The beacon deposit
     * contract is present in every post-Merge state, so a non-empty proof for it
     * means the peer retains that root's trie.
     */
    private static final org.apache.tuweni.bytes.Bytes32 SNAP_PROBE_ACCOUNT_HASH =
            org.apache.tuweni.crypto.Hash.keccak256(
                    org.apache.tuweni.bytes.Bytes.fromHexString("0x00000000219ab540356cBB839Cbe05303d7705Fa"));

    /** First ready snap peer that returns a non-empty account proof at {@code root},
     *  or null. Probes all peers CONCURRENTLY (same rationale as the PEER_HEAD probe)
     *  and awards the first to serve the root. */
    private com.jaeckel.ethp2p.networking.eth.EthHandler firstPeerServing(
            List<com.jaeckel.ethp2p.networking.eth.EthHandler> peers,
            org.apache.tuweni.bytes.Bytes32 root) {
        java.util.List<CompletableFuture<com.jaeckel.ethp2p.networking.eth.EthHandler>> probes =
                new java.util.ArrayList<>();
        for (com.jaeckel.ethp2p.networking.eth.EthHandler peer : peers) {
            if (!peer.isReady() || peer.isSnapServingFailed()) continue;
            probes.add(peer.requestAccountByHashAsync(SNAP_PROBE_ACCOUNT_HASH, root)
                    .thenApply(probe -> {
                        if (probe.proof() == null || probe.proof().isEmpty()) {
                            throw new java.util.concurrent.CompletionException(
                                    new IllegalStateException("peer does not serve root"));
                        }
                        return peer;
                    }));
        }
        try {
            return firstSuccess(probes, PEER_PROBE_TIMEOUT_SEC);
        } catch (Exception e) {
            return null;
        }
    }

    /** Convert an SSZ uint256 (32-byte little-endian) to a non-negative BigInteger. */
    private static java.math.BigInteger leUint256ToBigInteger(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[i] = le[le.length - 1 - i];
        return new java.math.BigInteger(1, be);
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
            NetworkConfig network = NetworkConfig.byName("mainnet");
            localGenesisTime = network.clGenesisTime();
            Path keyFile = new java.io.File(getFilesDir(), "nodekey.hex").toPath();
            NodeKey nodeKey = NodeKey.loadOrGenerate(keyFile);
            LogBuffer.i(TAG, "Node ID: " + nodeKey.nodeId().toHexString());

            // Reconstructible network state lives in getCacheDir() (not getFilesDir())
            // so the OS / user "Clear cache" wipes peer caches + sync snapshot and
            // resets bootstrapping, while identity (nodekey) and query history in
            // getFilesDir() survive. cacheDir can also be evicted under storage
            // pressure — harmless, we fall back to the embedded checkpoint.
            Path cacheFile = new java.io.File(getCacheDir(), "peers.cache").toPath();
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
            Path clCacheFile = new java.io.File(getCacheDir(), "cl-peers.cache").toPath();
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
            localBlc.setProvenCatchUpServers(clCacheRef.servedPeriods());
            localBlc.setOnCatchUpServed(clCacheRef::recordServed);
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
            localBlc.setSnapshotFile(new java.io.File(getCacheDir(), SYNC_SNAPSHOT_FILE).toPath());
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
            // Verified-read backend: delegate to the node's shared connector +
            // beacon state. Phase B serves chain id + verified head; more methods
            // are added here as they're implemented.
            final RLPxConnector backendConn = conn;
            final BeaconSyncState backendState = beaconState;
            final long backendGenesis = genesisTime;
            io.myotis.jsonrpc.MyotisRpcBackend backend = new io.myotis.jsonrpc.MyotisRpcBackend() {
                @Override public long chainId() { return backendConn.getNetwork().networkId(); }
                @Override public Long headBlockNumber() {
                    long n = backendState.getOptimisticBlockNumber();
                    return n > 0 ? Long.valueOf(n) : null;
                }
                @Override public String syncState() {
                    return backendState.getSyncState(backendGenesis).name();
                }
                @Override public byte[] call(byte[] to, byte[] data, String block) {
                    return rpcCall(to, data, block);
                }
                @Override public java.math.BigInteger getBalance(byte[] address, String block) {
                    io.myotis.evm.world.AccountState a = rpcAccountState(address, block);
                    return a == null ? null : a.balance();
                }
                @Override public Long getTransactionCount(byte[] address, String block) {
                    io.myotis.evm.world.AccountState a = rpcAccountState(address, block);
                    return a == null ? null : Long.valueOf(a.nonce());
                }
                @Override public byte[] getCode(byte[] address, String block) {
                    return rpcCode(address, block);
                }
                @Override public byte[] getStorageAt(byte[] address, byte[] slot, String block) {
                    return rpcStorageAt(address, slot, block);
                }
                @Override public byte[] sendRawTransaction(byte[] rawTx) {
                    return rpcSendRawTransaction(rawTx);
                }
                @Override public String getTransactionReceipt(byte[] txHash) {
                    return rpcGetTransactionReceipt(txHash, "latest");
                }
                @Override public String getTransactionByHash(byte[] txHash) {
                    return rpcGetTransactionByHash(txHash);
                }
                @Override public String getBlockByNumber(String block, boolean fullTx) {
                    return rpcGetBlockByNumber(block, fullTx);
                }
                @Override public java.math.BigInteger gasPrice() {
                    return rpcGasPrice();
                }
                @Override public java.math.BigInteger maxPriorityFeePerGas() {
                    return rpcMaxPriorityFeePerGas();
                }
                @Override public String feeHistory(long blockCount, String newestBlock,
                                                   double[] rewardPercentiles) {
                    return rpcFeeHistory(blockCount, newestBlock, rewardPercentiles);
                }
                @Override public java.math.BigInteger estimateGas(byte[] from, byte[] to,
                                                                  byte[] data, java.math.BigInteger value) {
                    return rpcEstimateGas(from, to, data, value);
                }
            };
            // Bind loopback-only: the wallet (MetaMask) runs on the same device and
            // reaches us via localhost. Binding 0.0.0.0 would expose an unauthenticated,
            // TLS-less RPC — incl. eth_sendRawTransaction relay — to the whole LAN.
            io.myotis.jsonrpc.MyotisRpcServer s =
                    new io.myotis.jsonrpc.MyotisRpcServer(8545, upstream, "127.0.0.1", backend);
            s.start();
            this.rpcServer = s;
            startHeadWarmer();
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
        // Stop the head pre-warmer + JSON-RPC server first so the port frees and no
        // warm-tick builds against torn-down state.
        if (headWarmer != null) {
            headWarmer.shutdownNow();
            headWarmer = null;
        }
        if (peerMaintainer != null) {
            peerMaintainer.shutdownNow();
            peerMaintainer = null;
        }
        if (rpcServer != null) {
            try { rpcServer.stop(); } catch (Throwable ignored) {}
            rpcServer = null;
        }
        // Drop the cached head context + last-good head so a later Start doesn't
        // briefly reuse one pinned to a now-dead peer (fails safe to proxy anyway).
        synchronized (rpcCallCtxLock) { rpcCallCtx = null; }
        lastGoodHead = null;
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
            java.io.File cacheFile = new java.io.File(getCacheDir(), "peers.cache");
            if (cacheFile.exists() && !cacheFile.delete()) {
                LogBuffer.w(TAG, "failed to delete " + cacheFile);
            }
        }
        AndroidCLPeerCache clpc = clPeerCache;
        if (clpc != null) {
            clpc.clear();
        } else {
            java.io.File clCacheFile = new java.io.File(getCacheDir(), "cl-peers.cache");
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
            java.io.File snap = new java.io.File(getCacheDir(), SYNC_SNAPSHOT_FILE);
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
                bs.syncStartPeriod, bs.syncCurrentPeriod, bs.syncTargetPeriod,
                ready);
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
        return new BeaconStats(
                bss.getSyncState(genesis).name(),
                blc.isBootstrapped(),
                peers.size(),
                lc,
                bss.getFinalizedSlot(),
                bss.getExecutionBlockNumber(),
                execHashHex,
                bss.getCatchUpStartPeriod(),
                bss.getCurrentSyncCommitteePeriod(),
                com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec.currentPeriod(genesis));
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
        evmPool.shutdownNow();
        ccipPool.shutdownNow();
        headBuildPool.shutdownNow();
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
