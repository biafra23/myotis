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
 * The Desktop actual of [NodeController]: drives the SAME Java backend (`node-core`
 * `ChainStack`/`NodeRegistry`) the daemon and Android use, in-process — no Android Service,
 * no IPC. Reuses the daemon's file-backed caches + CCIP gateway from `:app`.
 */
class DesktopNodeController(private val dataDir: Path) : NodeController {

    private val registry = NodeRegistry()
    // nanoTime, not currentTimeMillis: wall-clock / NTP steps must not skew uptime.
    private val startNs = System.nanoTime()
    // Serialize lifecycle ops (enable/disable/reboot/shutdown) — they're triggered from the
    // UI thread but mutate the shared registry; `lock` guards against interleaving.
    private val lock = Any()

    init {
        dataDir.createDirectories()
    }

    // A registered stack may still be booting (or have failed start()); report running only
    // when at least one stack is actually up, not merely present in the registry.
    override val running: Boolean
        get() = registry.all().any { it.isRunning }

    override fun enableNetwork(name: String) {
        // All of this (key load/generate, cache init, stack.start()) does blocking disk I/O
        // and network setup — never run it on the UI thread. Boot on a daemon thread, holding
        // `lock` so concurrent enable/reboot calls can't double-add or race the registry.
        Thread({
            synchronized(lock) {
                if (registry.get(name) != null) return@synchronized
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
                // ChainStack.start() is fault-isolated: it returns false (and closes its own
                // resources) on failure rather than throwing. Either way — false return or a
                // stray throwable — drop the stack from the registry so a later enable can
                // retry; leaving a dead entry would report "running" forever and block retries.
                val ok = try {
                    stack.start()
                } catch (t: Throwable) {
                    registry.remove(name)
                    throw t
                }
                if (!ok) registry.remove(name)
            }
        }, "desktop-boot-$name").apply { isDaemon = true }.start()
    }

    override fun disableNetwork(name: String) {
        synchronized(lock) { registry.remove(name) }
    }

    override fun rebootNetwork(name: String) {
        disableNetwork(name)
        enableNetwork(name)
    }

    override fun shutdown() {
        synchronized(lock) { registry.shutdownAll() }
    }

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
        val active = conn?.activePeers ?: emptyList()
        // "ready" = peers past the eth handshake, matching Android's filtered count (the raw
        // active list also includes peers still negotiating Hello/Status).
        val ready = active.count { "READY" == it.state() }
        val backend = stack.rpcBackend()
        return NodeSnapshot(
            running = stack.isRunning,
            network = net.name(),
            beaconState = state,
            connectedPeers = active.size,
            readyPeers = ready,
            snapPeers = conn?.activeSnapHandlers()?.size ?: 0,
            discoveredPeers = disc4?.table()?.size() ?: 0,
            executionBlockNumber = bss?.executionBlockNumber ?: 0L,
            finalizedSlot = bss?.finalizedSlot ?: 0L,
            syncCurrentPeriod = bss?.currentSyncCommitteePeriod ?: 0L,
            syncTargetPeriod = BeaconChainSpec.currentPeriod(net.clGenesisTime(), net.secondsPerSlot()),
            // Real age of the last verified RPC head, or MAX_VALUE if RPC hasn't built one yet
            // (same sentinel Android's NodeService uses; the UI renders it as "—").
            verifiedHeadAgeMs = backend?.verifiedHeadAgeMs() ?: Long.MAX_VALUE,
            uptimeSeconds = (System.nanoTime() - startNs) / 1_000_000_000L,
        )
    }
}

/**
 * Minimal in-memory desktop settings (Step 1). File-backed persistence is a follow-up.
 * Read/written from both the UI thread and the boot threads, so every access is guarded by
 * `synchronized(this)` over the non-thread-safe backing collections.
 */
class DesktopSettings : Settings {
    private val enabled = linkedSetOf("mainnet")
    private val ports = HashMap<String, Int>()
    private var snap = 32

    override fun enabledNetworks(): List<String> = synchronized(this) { enabled.toList() }
    override fun primaryNetwork(): String = synchronized(this) { enabled.firstOrNull() ?: "mainnet" }
    override fun allNetworks(): List<String> = NetworkConfig.allNetworks().map { it.name() }
    override fun isNetworkEnabled(name: String): Boolean = synchronized(this) { name in enabled }
    override fun setNetworkEnabled(name: String, on: Boolean) = synchronized(this) {
        if (on) enabled.add(name) else enabled.remove(name)
        Unit
    }
    override fun rpcPortFor(network: String): Int = synchronized(this) {
        ports[network] ?: NetworkConfig.byName(network).defaultRpcPort()
    }
    override fun setRpcPort(network: String, port: Int) = synchronized(this) {
        ports[network] = port
        Unit
    }
    override fun snapTarget(): Int = synchronized(this) { snap }
    override fun setSnapTarget(v: Int) = synchronized(this) { snap = v }
}

/** Desktop is treated as always-online (no Android ConnectivityManager). */
object DesktopNetworkStatus : NetworkStatus {
    override val online: Boolean = true
}
