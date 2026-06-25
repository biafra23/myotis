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

    // Query + maintenance ops are added with their screens (Query/Logs/Settings).
}

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
