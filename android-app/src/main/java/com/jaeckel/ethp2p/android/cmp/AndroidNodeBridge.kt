package com.jaeckel.ethp2p.android.cmp

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.jaeckel.ethp2p.android.AndroidQueryHistory
import com.jaeckel.ethp2p.android.NodeService
import io.myotis.ui.AccountResult
import io.myotis.ui.EnsResult
import io.myotis.ui.NetworkStatus
import io.myotis.ui.NodeController
import io.myotis.ui.NodeSnapshot
import io.myotis.ui.PeerRow
import io.myotis.ui.QueryHistory
import io.myotis.ui.QueryHistoryEntry
import io.myotis.ui.Settings
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.future.await

/**
 * Android actuals for the shared `:ui` seam: back [NodeController]/[Settings]/[NetworkStatus]
 * with the existing [NodeService] + its SharedPreferences statics, so the same Compose
 * `NodeScreen` renders on Android and Desktop.
 *
 * The controller holds a [serviceProvider] (`() -> NodeService?`) rather than a fixed service so
 * a single controller instance survives the Activity's bind/unbind cycle (onStart binds, onStop
 * unbinds): the shared UI's state (selected tab, in-flight query) is retained across
 * foreground/background instead of resetting on every rebind. Ops degrade gracefully while the
 * service isn't bound — snapshots are empty and mutating ops no-op — except enabling a network,
 * which starts the foreground service via [onStartService].
 */
class AndroidNodeController(
    private val serviceProvider: () -> NodeService?,
    private val appContext: Context,
    private val onStartService: () -> Unit,
) : NodeController {

    override val running: Boolean
        get() = NodeService.isRunning()

    override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flow {
        while (true) {
            emit(serviceProvider()?.snapshots()?.mapValues { (_, s) -> s.toModel() } ?: emptyMap())
            delay(2000)
        }
        // snapshotOf() prunes the backoff map and walks/sorts the live peer list — keep it off the
        // main/UI dispatcher so the 2s poll can't drop frames.
    }.flowOn(Dispatchers.Default)

    override fun enableNetwork(name: String) {
        // Only boot a stack live on an already-RUNNING bound service. Otherwise (service not
        // running, or only the BIND_AUTO_CREATE shell is bound) persist the enabled flag and go
        // through onStartService — which both prompts for POST_NOTIFICATIONS and boots the enabled
        // set. Gating on isRunning (not just svc != null) is what keeps the notification-permission
        // prompt reachable, since the shell is bound whenever the UI is visible.
        val svc = serviceProvider()
        if (svc != null && NodeService.isRunning()) {
            svc.enableNetwork(name)
        } else {
            NodeService.setNetworkEnabled(appContext, name, true)
            onStartService()
        }
    }
    override fun disableNetwork(name: String) { serviceProvider()?.disableNetwork(name) }
    override fun rebootNetwork(name: String) { serviceProvider()?.rebootNetwork(name) }
    override fun shutdown() { serviceProvider()?.shutdown() }
    override fun setTargetSnapPeers(target: Int) { serviceProvider()?.setTargetSnapPeers(target) }
    override fun applyBlsBackend() { NodeService.applyBlsBackend(appContext) }
    override fun clearCaches(network: String) { serviceProvider()?.clearCaches(network) }
    override fun resetSyncState(network: String) { serviceProvider()?.resetSyncState(network) }

    override suspend fun requestAccount(network: String, address: String): AccountResult {
        val svc = serviceProvider() ?: throw IllegalStateException("Node is not running")
        return svc.requestAccount(network, address).await().let { r ->
            AccountResult(
                r.address(), r.exists(), r.nonce(), r.balanceWei(),
                r.storageRootHex(), r.codeHashHex(), r.blockNumber(), r.peerStateRootHex(),
                r.peerProofValid(), r.beaconChainVerified(), r.blsVerified(), r.matchedBeaconSlot(),
                r.verifyMethod(), r.failReason(),
            )
        }
    }

    override suspend fun resolveEns(network: String, name: String): EnsResult {
        val svc = serviceProvider() ?: throw IllegalStateException("Node is not running")
        return svc.resolveEns(network, name).await().let { r ->
            EnsResult(r.name(), r.addressHex(), r.blockNumber(), r.beaconVerified(), r.error())
        }
    }
}

/**
 * Android actual of [NetworkStatus] over ConnectivityManager. Emits the current
 * internet-validated connectivity and re-emits on change (ports the old MainActivity
 * `rememberIsOnline`), unregistering the callback when collection stops.
 */
class AndroidNetworkStatus(private val ctx: Context) : NetworkStatus {
    override fun online(): Flow<Boolean> = callbackFlow {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        fun validated(caps: NetworkCapabilities?): Boolean =
            caps != null &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        fun current(): Boolean = validated(cm.activeNetwork?.let { cm.getNetworkCapabilities(it) })
        trySend(current())
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { trySend(current()) }
            override fun onLost(network: Network) { trySend(current()) }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                trySend(validated(caps))
            }
        }
        cm.registerDefaultNetworkCallback(cb)
        awaitClose { cm.unregisterNetworkCallback(cb) }
    }.distinctUntilChanged()
}

/** Map the Java `NodeService.Snapshot` record into the shared Kotlin model. */
private fun NodeService.Snapshot.toModel(): NodeSnapshot = NodeSnapshot(
    running = running(),
    lifecycle = lifecycle(),
    network = network(),
    beaconState = beaconState(),
    connectedPeers = connectedPeers(),
    readyPeers = readyPeers(),
    snapPeers = snapPeers(),
    snapServingPeers = snapServingPeers(),
    clConnectedPeers = clPeersConnected(),
    clServedPeersLastMin = clPeersServedLastMin(),
    discoveredPeers = discoveredPeers(),
    backedOffPeers = backedOffPeers(),
    blacklistedPeers = blacklistedPeers(),
    discv5Peers = discv5Peers(),
    executionBlockNumber = executionBlockNumber(),
    finalizedSlot = finalizedSlot(),
    syncStartPeriod = syncStartPeriod(),
    syncCurrentPeriod = syncCurrentPeriod(),
    syncTargetPeriod = syncTargetPeriod(),
    verifiedHeadAgeMs = verifiedHeadAgeMs(),
    uptimeSeconds = if (startTimeMs() > 0) (System.currentTimeMillis() - startTimeMs()) / 1000 else 0,
    readyPeerList = readyPeerList().map { PeerRow(it.remoteAddress(), it.snapSupported(), it.clientId()) },
    pauseCount = pauseCount(),
    totalPausedMs = totalPausedMs(),
    lastPauseEpochMs = lastPauseEpochMs(),
    lastResumeEpochMs = lastResumeEpochMs(),
    lastWakeReason = lastWakeReason(),
)

/** Android actual of [Settings] over the NodeService SharedPreferences statics. */
class AndroidSettings(private val ctx: Context) : Settings {
    override fun enabledNetworks(): List<String> = NodeService.enabledNetworks(ctx)
    override fun primaryNetwork(): String = NodeService.primaryNetwork(ctx)
    override fun allNetworks(): List<String> = NodeService.allNetworkNames()
    override fun isNetworkEnabled(name: String): Boolean = NodeService.isNetworkEnabled(ctx, name)
    override fun setNetworkEnabled(name: String, on: Boolean) = NodeService.setNetworkEnabled(ctx, name, on)
    override fun rpcPortFor(network: String): Int = NodeService.rpcPortFor(ctx, network)
    override fun setRpcPort(network: String, port: Int) = NodeService.setRpcPort(ctx, network, port)
    override fun snapTarget(): Int = NodeService.snapTarget(ctx)
    override fun setSnapTarget(v: Int) = NodeService.setSnapTargetPref(ctx, v)

    override fun displayName(network: String): String = NodeService.displayName(network)
    override fun defaultRpcPort(network: String): Int = NodeService.defaultRpcPort(network)
    override fun hasEns(network: String): Boolean = NodeService.hasEns(network)

    override fun deepPoolThreshold(): Int = NodeService.deepPoolThreshold(ctx)
    override fun setDeepPool(v: Int) = NodeService.setDeepPoolThreshold(ctx, v)
    override fun strictStateFreshness(): Boolean = NodeService.strictStateFreshness(ctx)
    override fun setStrictStateFreshness(v: Boolean) = NodeService.setStrictStateFreshness(ctx, v)
    override fun nativeBlsEnabled(): Boolean = NodeService.nativeBlsEnabled(ctx)
    override fun setNativeBlsEnabled(v: Boolean) = NodeService.setNativeBlsEnabled(ctx, v)

    override fun idlePauseMinutes(): Int = NodeService.idlePauseMinutes(ctx)
    override fun setIdlePauseMinutes(v: Int) = NodeService.setIdlePauseMinutes(ctx, v)
    override fun stayAwakeWhileCharging(): Boolean = NodeService.stayAwakeWhileCharging(ctx)
    override fun setStayAwakeWhileCharging(v: Boolean) = NodeService.setStayAwakeWhileCharging(ctx, v)
    override fun supportsIdleSleep(): Boolean = true   // NodeService runs the idle controller
}

/**
 * Android actual of [QueryHistory]. Wraps the existing file-backed [AndroidQueryHistory] on the
 * SAME `filesDir/query-history.tsv` the app already used, so previously stored queries are
 * retained across the switch to the shared UI.
 */
class AndroidQueryHistoryAdapter(ctx: Context) : QueryHistory {
    private val impl = AndroidQueryHistory(File(ctx.filesDir, "query-history.tsv").toPath())
    override fun entries(): List<QueryHistoryEntry> =
        impl.list().map { QueryHistoryEntry(it.input(), it.timestampMs(), it.label()) }
    override fun add(input: String, label: String) = impl.add(input, label)
    override fun clear() = impl.clear()
}
