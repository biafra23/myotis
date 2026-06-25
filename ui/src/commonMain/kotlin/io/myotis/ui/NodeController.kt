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
}

/** Whether the device currently has network connectivity (Android: ConnectivityManager). */
interface NetworkStatus {
    val online: Boolean
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
    val snapPeers: Int,
    val discoveredPeers: Int,
    val executionBlockNumber: Long,
    val finalizedSlot: Long,
    val syncCurrentPeriod: Long,
    val syncTargetPeriod: Long,
    val verifiedHeadAgeMs: Long,
    val uptimeSeconds: Long,
)
