package io.myotis.desktop

import com.jaeckel.ethp2p.app.CLPeerCache
import com.jaeckel.ethp2p.app.ClPeerCacheAdapter
import com.jaeckel.ethp2p.app.PeerCache
import com.jaeckel.ethp2p.app.PeerCacheAdapter
import com.jaeckel.ethp2p.app.rpc.JavaHttpCcipGateway
import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec
import com.jaeckel.ethp2p.core.crypto.NodeKey
import com.jaeckel.ethp2p.networking.NetworkConfig
import io.myotis.node.ChainPorts
import io.myotis.node.ChainStack
import io.myotis.node.NodeRegistry
import io.myotis.ui.NetworkStatus
import io.myotis.ui.NodeController
import io.myotis.ui.NodeSnapshot
import io.myotis.ui.Settings
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.nio.file.Path
import kotlin.io.path.createDirectories

/**
 * The Desktop actual of {@link NodeController}: drives the SAME Java backend (`node-core`
 * `ChainStack`/`NodeRegistry`) the daemon and Android use, in-process — no Android Service,
 * no IPC. Reuses the daemon's file-backed caches + CCIP gateway from `:app`.
 */
class DesktopNodeController(private val dataDir: Path) : NodeController {

    private val registry = NodeRegistry()
    private val startMs = System.currentTimeMillis()

    init {
        dataDir.createDirectories()
    }

    override val running: Boolean
        get() = !registry.isEmpty

    override fun enableNetwork(name: String) {
        if (registry.get(name) != null) return
        val network = NetworkConfig.byName(name)
        val ports = ChainPorts.defaultsFor(network)
        val keyFile = if (name == "mainnet") "nodekey.hex" else "nodekey-$name.hex"
        val nodeKey = NodeKey.loadOrGenerate(dataDir.resolve(keyFile))
        val suffix = if (name == "mainnet") "" else "-$name"
        val peerCache = PeerCache(dataDir.resolve("peers$suffix.cache"))
        val clPeerCache = CLPeerCache(dataDir.resolve("cl-peers$suffix.cache"))
        val stack = ChainStack(
            network, ports, nodeKey,
            PeerCacheAdapter(peerCache), ClPeerCacheAdapter(clPeerCache),
            JavaHttpCcipGateway(),
            dataDir.resolve("sync-state$suffix.snapshot"),
            false,
        )
        stack.configureSnapMaintainer(32, null)  // desktop has system DNS → null provider
        registry.add(stack)
        Thread({ stack.start() }, "desktop-boot-$name").apply { isDaemon = true }.start()
    }

    override fun disableNetwork(name: String) = registry.remove(name)

    override fun rebootNetwork(name: String) {
        disableNetwork(name)
        enableNetwork(name)
    }

    override fun shutdown() = registry.shutdownAll()

    override fun setTargetSnapPeers(target: Int) {
        registry.all().forEach { it.setTargetSnapPeers(target) }
    }

    /** Poll the live stacks every 2s and emit a per-network snapshot map for the UI. */
    override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flow {
        while (true) {
            emit(registry.all().associate { it.network().name() to snapshotOf(it) })
            delay(2000)
        }
    }

    private fun snapshotOf(stack: ChainStack): NodeSnapshot {
        val net = stack.network()
        val conn = stack.connector()
        val bss = stack.beaconSyncState()
        val disc4 = stack.discV4()
        val state = if (bss != null)
            bss.getSyncState(net.clGenesisTime(), net.secondsPerSlot()).name
        else "STARTING"
        return NodeSnapshot(
            running = stack.isRunning,
            network = net.name(),
            beaconState = state,
            connectedPeers = conn?.activePeers?.size ?: 0,
            readyPeers = conn?.activePeers?.size ?: 0,
            snapPeers = conn?.activeSnapHandlers()?.size ?: 0,
            discoveredPeers = disc4?.table()?.size() ?: 0,
            executionBlockNumber = bss?.executionBlockNumber ?: 0L,
            finalizedSlot = bss?.finalizedSlot ?: 0L,
            syncCurrentPeriod = bss?.currentSyncCommitteePeriod ?: 0L,
            syncTargetPeriod = BeaconChainSpec.currentPeriod(net.clGenesisTime(), net.secondsPerSlot()),
            verifiedHeadAgeMs = 0L,
            uptimeSeconds = (System.currentTimeMillis() - startMs) / 1000,
        )
    }
}

/** Minimal in-memory desktop settings (Step 1). File-backed persistence is a follow-up. */
class DesktopSettings : Settings {
    private val enabled = linkedSetOf("mainnet")
    private val ports = HashMap<String, Int>()

    override fun enabledNetworks(): List<String> = enabled.toList()
    override fun primaryNetwork(): String = enabled.firstOrNull() ?: "mainnet"
    override fun allNetworks(): List<String> = NetworkConfig.allNetworks().map { it.name() }
    override fun isNetworkEnabled(name: String): Boolean = name in enabled
    override fun setNetworkEnabled(name: String, on: Boolean) { if (on) enabled.add(name) else enabled.remove(name) }
    override fun rpcPortFor(network: String): Int =
        ports[network] ?: NetworkConfig.byName(network).defaultRpcPort()
    override fun setRpcPort(network: String, port: Int) { ports[network] = port }
    override fun snapTarget(): Int = 32
    override fun setSnapTarget(v: Int) {}
}

/** Desktop is treated as always-online (no Android ConnectivityManager). */
object DesktopNetworkStatus : NetworkStatus {
    override val online: Boolean = true
}
