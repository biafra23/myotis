package com.jaeckel.ethp2p.android.cmp

import android.content.Context
import com.jaeckel.ethp2p.android.NodeService
import com.jaeckel.ethp2p.networking.NetworkConfig
import io.myotis.ui.NodeController
import io.myotis.ui.NodeSnapshot
import io.myotis.ui.Settings
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * Android actuals for the shared `:ui` seam: back [NodeController]/[Settings]
 * with the existing [NodeService] + its SharedPreferences statics, so the same
 * Compose `NodeScreen` renders on Android and Desktop. Additive — wired into MainActivity
 * as the Status/other tabs are ported to `:ui`.
 */
class AndroidNodeController(private val service: NodeService) : NodeController {

    override val running: Boolean
        get() = NodeService.isRunning()

    override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flow {
        while (true) {
            emit(service.snapshots().mapValues { (_, s) -> s.toModel() })
            delay(2000)
        }
    }

    override fun enableNetwork(name: String) { service.enableNetwork(name) }
    override fun disableNetwork(name: String) { service.disableNetwork(name) }
    override fun rebootNetwork(name: String) { service.rebootNetwork(name) }
    override fun shutdown() { service.shutdown() }
    override fun setTargetSnapPeers(target: Int) { service.setTargetSnapPeers(target) }
}

/** Map the Java `NodeService.Snapshot` record into the shared Kotlin model. */
private fun NodeService.Snapshot.toModel(): NodeSnapshot = NodeSnapshot(
    running = running(),
    network = network(),
    beaconState = beaconState(),
    connectedPeers = connectedPeers(),
    readyPeers = readyPeers(),
    snapPeers = snapPeers(),
    discoveredPeers = discoveredPeers(),
    executionBlockNumber = executionBlockNumber(),
    finalizedSlot = finalizedSlot(),
    syncCurrentPeriod = syncCurrentPeriod(),
    syncTargetPeriod = syncTargetPeriod(),
    verifiedHeadAgeMs = verifiedHeadAgeMs(),
    uptimeSeconds = if (startTimeMs() > 0) (System.currentTimeMillis() - startTimeMs()) / 1000 else 0,
)

/** Android actual of [Settings] over the NodeService SharedPreferences statics. */
class AndroidSettings(private val ctx: Context) : Settings {
    override fun enabledNetworks(): List<String> = NodeService.enabledNetworks(ctx)
    override fun primaryNetwork(): String = NodeService.primaryNetwork(ctx)
    override fun allNetworks(): List<String> = NetworkConfig.allNetworks().map { it.name() }
    override fun isNetworkEnabled(name: String): Boolean = NodeService.isNetworkEnabled(ctx, name)
    override fun setNetworkEnabled(name: String, on: Boolean) = NodeService.setNetworkEnabled(ctx, name, on)
    override fun rpcPortFor(network: String): Int = NodeService.rpcPortFor(ctx, network)
    override fun setRpcPort(network: String, port: Int) = NodeService.setRpcPort(ctx, network, port)
    override fun snapTarget(): Int = NodeService.snapTarget(ctx)
    override fun setSnapTarget(v: Int) = NodeService.setSnapTargetPref(ctx, v)
}
