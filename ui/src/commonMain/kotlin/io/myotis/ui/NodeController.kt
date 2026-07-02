package io.myotis.ui

import kotlinx.coroutines.flow.Flow

/**
 * The backend operations the shared UI needs, abstracted so each platform supplies its own
 * actual: Android wraps `NodeService`; Desktop drives `node-core` in-process. commonMain
 * (the screens) depends only on this + [Settings] + the models below — never on the
 * Java/JVM backend, so the same UI compiles for Android, Desktop (and iOS later).
 */
interface NodeController {
    /** Whether any network stack is currently running. */
    val running: Boolean

    /** Live per-network snapshots, keyed by network name, for the UI to render. */
    fun snapshots(): Flow<Map<String, NodeSnapshot>>

    fun enableNetwork(name: String)
    fun disableNetwork(name: String)
    fun rebootNetwork(name: String)
    fun shutdown()

    /** Live-update the snap-peer target on all running stacks. */
    fun setTargetSnapPeers(target: Int)

    /**
     * Re-apply the BLS backend to the process-global selector after [Settings.setNativeBlsEnabled]
     * flips the preference (Android: native blst ⇄ pure-Java Milagro). Takes effect immediately —
     * the decompressed-pubkey cache is process-global so the swap is cheap. Desktop currently has
     * no bundled native library, so its actual is a no-op until the macOS blst dylib ships.
     */
    fun applyBlsBackend()

    /**
     * Wipe a network's peer caches — clear the live stack's backoff/blacklist and delete the
     * on-disk EL/CL peer cache files — so discovery starts from a fresh slate. Safe whether or
     * not the network is currently running.
     */
    fun clearCaches(network: String)

    /**
     * Delete a network's persisted sync-committee snapshot so the NEXT start re-bootstraps from
     * the embedded checkpoint and re-runs catch-up (a debugging aid). A running stack keeps its
     * in-memory state; this only affects the next start.
     */
    fun resetSyncState(network: String)

    /**
     * Query an account on [network] and verify the returned proof against the beacon-attested
     * state root (the shared `VerifiedAccountQuery` ladder). Suspends until verification
     * completes. Throws on a bad address or a network that isn't running; verification
     * *failures* surface as [AccountResult.failReason], not exceptions.
     */
    suspend fun requestAccount(network: String, address: String): AccountResult

    /**
     * Resolve an ENS name to an address on [network]. Beacon-verified when resolved against
     * finalized state ([EnsResult.verified]). Throws if the network isn't running / has no ENS;
     * resolution failures surface as [EnsResult.error].
     */
    suspend fun resolveEns(network: String, name: String): EnsResult

    // Logs / Settings ops are added with their screens.
}

/** Verified account-query result. Mirrors `io.myotis.node.VerifiedAccountQuery.Result`. */
data class AccountResult(
    val address: String,
    val exists: Boolean,
    val nonce: Long,                 // -1 when !exists
    val balanceWei: String?,         // decimal string or null
    val storageRootHex: String?,
    val codeHashHex: String?,
    val blockNumber: Long,           // peer-reported block the proof anchors to
    val peerStateRootHex: String?,
    val peerProofValid: Boolean,     // proof verifies against peerStateRoot
    val beaconChainVerified: Boolean,// peerStateRoot ties to a beacon-attested root
    val blsVerified: Boolean,        // the beacon match was BLS-signed
    val matchedBeaconSlot: Long,     // -1 when not matched
    val verifyMethod: String?,       // "stateRootMatch" / "headerChain" / null
    val failReason: String?,         // null when verified
)

/** ENS resolution result. Mirrors `io.myotis.rpc.EnsResolution`. */
data class EnsResult(
    val name: String,
    val addressHex: String?,         // null when unresolved/errored
    val blockNumber: Long,           // -1 when none
    val verified: Boolean,           // true iff beacon-verified finalized state
    val error: String?,              // null on success
)

/** Persisted per-network + shared settings, abstracted from Android SharedPreferences. */
interface Settings {
    fun enabledNetworks(): List<String>
    fun primaryNetwork(): String
    fun allNetworks(): List<String>
    fun isNetworkEnabled(name: String): Boolean
    fun setNetworkEnabled(name: String, enabled: Boolean)
    fun rpcPortFor(network: String): Int
    fun setRpcPort(network: String, port: Int)
    fun snapTarget(): Int
    fun setSnapTarget(v: Int)

    // --- network metadata (so commonMain need not reference the Java NetworkConfig) ---
    /** Human-facing name for the Settings row, e.g. "Gnosis Chain". */
    fun displayName(network: String): String
    /** The network's built-in default JSON-RPC port, shown as the field hint. */
    fun defaultRpcPort(network: String): Int
    /** Whether this network supports ENS resolution (mainnet/Sepolia); Query gates ENS input on it. */
    fun hasEns(network: String): Boolean

    // --- shared node-tuning knobs ---
    fun deepPoolThreshold(): Int
    fun setDeepPool(v: Int)
    /** true = strict 2-minute state freshness (default); false = relaxed/experimental. */
    fun strictStateFreshness(): Boolean
    fun setStrictStateFreshness(v: Boolean)
    /** true = use bundled native blst (default on Android); false = pure-Java Milagro. */
    fun nativeBlsEnabled(): Boolean
    fun setNativeBlsEnabled(v: Boolean)
}

/** Device network connectivity, as an observable stream so the UI can react to changes. */
interface NetworkStatus {
    /** Emits the current connectivity and re-emits on change. Android: ConnectivityManager;
     *  Desktop: a constant `true`. */
    fun online(): Flow<Boolean>
}

/**
 * One network's status, mirroring `NodeService.Snapshot` (the actual maps the Java record
 * into this Kotlin model). Trimmed to what the shared screens render today; extend as more
 * screens are ported.
 */
data class NodeSnapshot(
    val running: Boolean,
    val network: String,
    val beaconState: String,        // STOPPED / SYNCING / CATCHING_UP / SYNCED
    val connectedPeers: Int,
    val readyPeers: Int,
    val snapPeers: Int,             // peers that negotiated snap/1 (capability)
    val snapServingPeers: Int,      // peers actually in the serving pool now (drives readiness)
    val discoveredPeers: Int,
    val executionBlockNumber: Long,
    val finalizedSlot: Long,
    val syncCurrentPeriod: Long,
    val syncTargetPeriod: Long,
    val verifiedHeadAgeMs: Long,
    val uptimeSeconds: Long,
)
