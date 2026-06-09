package com.jaeckel.ethp2p.android;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Binder;
import android.os.IBinder;
import com.jaeckel.ethp2p.android.log.LogBuffer;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService;
import com.jaeckel.ethp2p.consensus.proof.MerklePatriciaVerifier;
import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv5.DiscV5Service;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
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
    // Same bound the JVM daemon uses (CommandHandler.MAX_HEADER_CHAIN_GAP).
    // Caps how many headers we'll fetch to bridge from the beacon-finalized
    // block to the peer's head — i.e. the maximum gap the headerChain
    // verification path will tolerate. In normal operation the gap is small
    // (snap peers track head, BLC finality lags by ~12.8 minutes ≈ 64 blocks),
    // but the bound has to cover catch-up after the phone wakes from doze.
    private static final int MAX_HEADER_CHAIN_GAP = 8192;
    private static final long HEADER_CHAIN_TIMEOUT_SEC = 60;

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

    // Service-lifecycle fields: written on the start/shutdown worker, read from
    // the Netty event loop, the Ktor IO dispatcher (JSON-RPC backend), and the UI
    // thread (snapshot()). volatile so readers never see a stale/null reference.
    private volatile DiscV4Service discV4;
    private volatile DiscV5Service discV5;
    private volatile RLPxConnector connector;
    private io.myotis.jsonrpc.MyotisRpcServer rpcServer;
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

    /** Reuse one anchored head context across a burst of eth_calls (a MetaMask
     *  page load fires hundreds) instead of re-probing peers + re-anchoring each
     *  time; short enough that "latest" stays within a few seconds of the head. */
    private static final long RPC_CALL_TTL_MS = 4_000;
    /** Per-eth_call EVM budget (CCIP gateways can add a round-trip). */
    private static final long RPC_CALL_TIMEOUT_SEC = 30;
    /** Account read budget — includes the headerChain anchoring fetch. */
    private static final long RPC_ACCOUNT_TIMEOUT_SEC = HEADER_CHAIN_TIMEOUT_SEC + 10;

    private final Object rpcCallCtxLock = new Object();
    private CompletableFuture<EnsCall> rpcCallCtx;   // cached beacon-anchored head call context
    private long rpcCallCtxAtMs;

    /** Only fresh-head tags are served verified for now; others → proxy. */
    private static boolean isLatestTag(String block) {
        return block == null || block.isEmpty()
                || block.equals("latest") || block.equals("pending");
    }

    /** eth_call over a beacon-anchored head. Returns raw ABI bytes, or null to proxy. */
    private byte[] rpcCall(byte[] to, byte[] data, String block) {
        if (!isLatestTag(block) || to == null || to.length != 20) return null;
        try {
            EnsCall ctx = verifiedHeadCallContext();
            return ctx.offchainExecutor()
                    .callView(io.myotis.evm.Address.of(to), data == null ? new byte[0] : data,
                            ctx.blockCtx())
                    .get(RPC_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_call not verifiable now: " + unwrap(e));
            return null;
        }
    }

    /** Verified account read (balance/nonce). Null unless beacon-anchored → proxy. */
    private AccountQueryResult rpcAccount(byte[] address, String block) {
        if (!isLatestTag(block) || address == null || address.length != 20) return null;
        try {
            AccountQueryResult r = requestAccount(Bytes.wrap(address).toHexString())
                    .get(RPC_ACCOUNT_TIMEOUT_SEC, TimeUnit.SECONDS);
            // Only serve cryptographically-anchored results; otherwise fall to proxy.
            if (r.failReason() != null || !r.beaconChainVerified()) return null;
            return r;
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] account read not verifiable now: " + unwrap(e));
            return null;
        }
    }

    /** keccak256("") — an account with this codeHash is an EOA (no contract code). */
    private static final byte[] EMPTY_CODE_HASH = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();

    /** eth_sendRawTransaction: gossip the user-signed tx to peers; return its hash
     *  (keccak256 of the raw bytes), or null (→ proxy) if no peer took it. Myotis
     *  never signs or originates a tx — this only relays bytes the user submitted. */
    private byte[] rpcSendRawTransaction(byte[] rawTx) {
        RLPxConnector conn = connector;
        if (conn == null || rawTx == null || rawTx.length == 0) return null;
        try {
            int sent = conn.broadcastTransaction(rawTx);
            if (sent == 0) return null;   // no peer reached → let the proxy relay it
            byte[] txHash = Hash.keccak256(Bytes.wrap(rawTx)).toArrayUnsafe();
            LogBuffer.i(TAG, "[rpc] eth_sendRawTransaction broadcast to " + sent
                    + " peer(s), hash=" + Bytes.wrap(txHash).toHexString());
            return txHash;
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_sendRawTransaction failed: " + unwrap(e));
            return null;
        }
    }

    /** First ready snap-serving peer, or null. */
    private com.jaeckel.ethp2p.networking.eth.EthHandler firstReadySnapPeer() {
        RLPxConnector conn = connector;
        if (conn == null) return null;
        for (com.jaeckel.ethp2p.networking.eth.EthHandler p : conn.activeSnapHandlers()) {
            if (p.isReady() && !p.isSnapServingFailed()) return p;
        }
        return null;
    }

    /** eth_getCode: bytecode verified against the proven codeHash, or null to proxy. */
    private byte[] rpcCode(byte[] address, String block) {
        if (!isLatestTag(block) || address == null || address.length != 20) return null;
        AccountQueryResult r = rpcAccount(address, block);   // codeHashHex is from the proven leaf
        if (r == null) return null;
        if (!r.exists()) return new byte[0];                 // no account → no code
        try {
            byte[] codeHash = Bytes.fromHexString(r.codeHashHex()).toArrayUnsafe();
            if (java.util.Arrays.equals(codeHash, EMPTY_CODE_HASH)) return new byte[0];  // EOA
            com.jaeckel.ethp2p.networking.eth.EthHandler peer = firstReadySnapPeer();
            if (peer == null) return null;
            java.util.List<Bytes> codes =
                    new com.jaeckel.ethp2p.android.snap.EthHandlerSnapPeer(peer)
                            .getByteCodes(java.util.List.of(Bytes32.wrap(codeHash)))
                            .get(30, TimeUnit.SECONDS);
            if (codes.isEmpty()) return null;
            Bytes code = codes.get(0);
            // Content-addressed: the bytecode is verified iff keccak256(code)==codeHash.
            if (!java.util.Arrays.equals(Hash.keccak256(code).toArrayUnsafe(), codeHash)) return null;
            return code.toArrayUnsafe();
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_getCode not verifiable now: " + unwrap(e));
            return null;
        }
    }

    /** eth_getStorageAt: the 32-byte value at {@code slot32}, proven against the
     *  account's verified storageRoot. Returns null (→ proxy) for absent slots,
     *  which a single inclusion proof can't positively prove here. */
    private byte[] rpcStorageAt(byte[] address, byte[] slot32, String block) {
        if (!isLatestTag(block) || address == null || address.length != 20
                || slot32 == null || slot32.length != 32) return null;
        try {
            // Verified account read → PROVEN storageRoot + the beacon-anchored peer
            // state root the storage proof must be fetched against.
            AccountQueryResult r = rpcAccount(address, block);
            if (r == null || !r.exists()
                    || r.storageRootHex() == null || r.peerStateRootHex() == null) return null;
            RLPxConnector conn = connector;
            if (conn == null) return null;
            Bytes32 storageRoot = Bytes32.fromHexString(r.storageRootHex());
            Bytes32 snapStateRoot = Bytes32.fromHexString(r.peerStateRootHex());
            Bytes contractAddress = Bytes.wrap(address);
            Bytes32 storageKeyHash = Hash.keccak256(Bytes.wrap(slot32));
            com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage.DecodeResult storageResult =
                    conn.requestStorage(contractAddress, storageKeyHash, snapStateRoot)
                            .get(RPC_ACCOUNT_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (storageResult.proof().isEmpty()) return null;
            // Plain loop (not Stream.toList — that's API 34, minSdk is 29).
            java.util.List<byte[]> proofBytes =
                    new java.util.ArrayList<>(storageResult.proof().size());
            for (Bytes pb : storageResult.proof()) proofBytes.add(pb.toArrayUnsafe());
            byte[] provenLeaf = MerklePatriciaVerifier.verifyStorageProof(
                    storageRoot.toArrayUnsafe(), slot32, proofBytes);
            if (provenLeaf == null) return null;   // absent or invalid → proxy
            // The trie leaf stores RLP(value); cross-check the peer's slim slotValue
            // against it so a forged slotValue in the slots() list can't slip through.
            com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage.StorageData found =
                    storageResult.slots().stream()
                            .filter(s -> s.slotHash().equals(storageKeyHash)).findFirst().orElse(null);
            byte[] value = (found != null && !found.slotValue().isEmpty())
                    ? found.slotValue().toArrayUnsafe() : new byte[0];
            if (!java.util.Arrays.equals(rlpEncodeShort(value), provenLeaf)) {
                return null;   // slim value inconsistent with the proven leaf
            }
            return leftPad32(value);
        } catch (Exception e) {
            LogBuffer.i(TAG, "[rpc] eth_getStorageAt not verifiable now: " + unwrap(e));
            return null;
        }
    }

    /** RLP-encode a minimal big-endian value ≤ 32 bytes (a storage slot value):
     *  a single byte < 0x80 is itself; otherwise a short-string header (0x80+len)
     *  precedes the bytes. Used to compare the peer's slim slotValue to the
     *  proof-verified trie leaf (which holds RLP(value)). */
    private static byte[] rlpEncodeShort(byte[] v) {
        if (v.length == 1 && (v[0] & 0xFF) < 0x80) return v;
        byte[] out = new byte[v.length + 1];
        out[0] = (byte) (0x80 + v.length);   // v.length ≤ 32 < 56, so single-byte header
        System.arraycopy(v, 0, out, 1, v.length);
        return out;
    }

    /** Right-align {@code v} into a 32-byte big-endian word. */
    private static byte[] leftPad32(byte[] v) {
        if (v.length >= 32) return java.util.Arrays.copyOfRange(v, v.length - 32, v.length);
        byte[] out = new byte[32];
        System.arraycopy(v, 0, out, 32 - v.length, v.length);
        return out;
    }

    /** Build (or reuse within {@link #RPC_CALL_TTL_MS}) a snap-peer head context
     *  whose state root is anchored back to the beacon-finalized root, so the EVM
     *  call runs against cryptographically-verified state. Blocking. */
    private EnsCall verifiedHeadCallContext() throws Exception {
        CompletableFuture<EnsCall> future;
        boolean build = false;
        synchronized (rpcCallCtxLock) {
            long now = android.os.SystemClock.elapsedRealtime();
            if (rpcCallCtx != null && !rpcCallCtx.isCompletedExceptionally()
                    && now - rpcCallCtxAtMs < RPC_CALL_TTL_MS) {
                future = rpcCallCtx;
            } else {
                future = new CompletableFuture<>();
                rpcCallCtx = future;
                rpcCallCtxAtMs = now;
                build = true;
            }
        }
        // Build OUTSIDE the lock so a burst of concurrent eth_calls (a MetaMask
        // page load fires hundreds) shares the one builder's future instead of
        // serializing — or starving — on the monitor during the up-to-60s
        // peer-probe + headerChain anchor.
        if (build) {
            try {
                EnsCall ctx = prepareEnsCall(io.myotis.ens.EnsResolutionRoot.PEER_HEAD);
                if (!anchorHeadToBeacon(ctx.blockNumber(), ctx.blockCtx().stateRoot())) {
                    throw new IllegalStateException(
                            "peer head not beacon-anchored (block #" + ctx.blockNumber() + ")");
                }
                future.complete(ctx);
            } catch (Throwable t) {
                future.completeExceptionally(t);
                synchronized (rpcCallCtxLock) {
                    if (rpcCallCtx == future) rpcCallCtx = null;   // let the next call retry
                }
            }
        }
        try {
            return future.get(RPC_ACCOUNT_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw (cause instanceof Exception) ? (Exception) cause : new Exception(cause);
        }
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
                           io.myotis.evm.CcipReadEvmExecutor offchainExecutor) {}

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
            long minSensibleHead = conn.getNetwork().minSensibleHeadBlock();
            com.jaeckel.ethp2p.networking.eth.EthHandler headPeer = null;
            com.jaeckel.ethp2p.core.types.BlockHeader header = null;
            String lastError = null;
            for (com.jaeckel.ethp2p.networking.eth.EthHandler peer : snapPeers) {
                if (!peer.isReady() || peer.isSnapServingFailed()) continue;
                try {
                    com.jaeckel.ethp2p.core.types.BlockHeader fresh =
                            peer.requestFreshHeadHeaderAsync().get(6, TimeUnit.SECONDS);
                    if (fresh.number < minSensibleHead) {
                        lastError = "stale head #" + fresh.number;
                        continue;
                    }
                    if (!servesRoot(peer, fresh.stateRoot)) {
                        lastError = "peer does not snap-serve head root (block #" + fresh.number + ")";
                        continue;
                    }
                    headPeer = peer;
                    header = fresh;
                    break;
                } catch (Exception e) {
                    lastError = unwrap(e);
                }
            }
            if (headPeer == null || header == null) {
                throw new IllegalStateException("No snap peer served a fresh head root for ENS"
                        + (lastError != null ? " (" + lastError + ")" : ""));
            }
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

        // Pin every SNAP request to the chosen peer (serves blockCtx's stateRoot).
        final com.jaeckel.ethp2p.networking.eth.EthHandler finalPeer = pinned;
        io.myotis.evm.world.SnapBackedStateOracle oracle =
                new io.myotis.evm.world.SnapBackedStateOracle(
                        () -> finalPeer.isReady() && !finalPeer.isSnapServingFailed()
                                ? new com.jaeckel.ethp2p.android.snap.EthHandlerSnapPeer(finalPeer)
                                : null,
                        ensBytecodeCache);
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
        return new EnsCall(resolver, blockCtx, blockNumber, verified, executor);
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

    /** First ready snap peer that returns a non-empty account proof at {@code root}, or null. */
    private com.jaeckel.ethp2p.networking.eth.EthHandler firstPeerServing(
            List<com.jaeckel.ethp2p.networking.eth.EthHandler> peers,
            org.apache.tuweni.bytes.Bytes32 root) {
        for (com.jaeckel.ethp2p.networking.eth.EthHandler peer : peers) {
            if (peer.isReady() && !peer.isSnapServingFailed() && servesRoot(peer, root)) {
                return peer;
            }
        }
        return null;
    }

    /** True if this peer returns a non-empty account proof for the probe account at {@code root}. */
    private boolean servesRoot(com.jaeckel.ethp2p.networking.eth.EthHandler peer,
                               org.apache.tuweni.bytes.Bytes32 root) {
        try {
            com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage.DecodeResult r =
                    peer.requestAccountByHashAsync(SNAP_PROBE_ACCOUNT_HASH, root).get(10, TimeUnit.SECONDS);
            return r.proof() != null && !r.proof().isEmpty();
        } catch (Exception e) {
            return false;
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
            // after a restart instead of waiting for re-discovery.
            cached.sort((a, b) -> Boolean.compare(b.snap(), a.snap()));

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
            // (set in gitignored local.properties); blank → strict (no proxy).
            String upstream = BuildConfig.RPC_UPSTREAM;
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
                    AccountQueryResult r = rpcAccount(address, block);
                    if (r == null) return null;
                    return r.exists() ? new java.math.BigInteger(r.balanceWei()) : java.math.BigInteger.ZERO;
                }
                @Override public Long getTransactionCount(byte[] address, String block) {
                    AccountQueryResult r = rpcAccount(address, block);
                    if (r == null) return null;
                    return r.exists() ? Long.valueOf(r.nonce()) : Long.valueOf(0L);
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
            };
            io.myotis.jsonrpc.MyotisRpcServer s =
                    new io.myotis.jsonrpc.MyotisRpcServer(8545, upstream, "0.0.0.0", backend);
            s.start();
            this.rpcServer = s;
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
        // Stop the JSON-RPC server first so its port is freed promptly.
        if (rpcServer != null) {
            try { rpcServer.stop(); } catch (Throwable ignored) {}
            rpcServer = null;
        }
        // Drop the cached eth_call context so a later Start doesn't briefly reuse
        // a head pinned to a now-dead peer (it would fail safe to proxy anyway).
        synchronized (rpcCallCtxLock) { rpcCallCtx = null; }
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
