package io.myotis.desktop

import com.jaeckel.ethp2p.app.CLPeerCache
import com.jaeckel.ethp2p.app.ClPeerCacheAdapter
import com.jaeckel.ethp2p.app.PeerCache
import com.jaeckel.ethp2p.app.PeerCacheAdapter
import com.jaeckel.ethp2p.app.rpc.JavaHttpCcipGateway
import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec
import com.jaeckel.ethp2p.core.crypto.NodeKey
import com.jaeckel.ethp2p.networking.NetworkConfig
import io.myotis.ens.EnsResolutionRoot
import io.myotis.node.ChainPorts
import io.myotis.node.ChainStack
import io.myotis.node.NodeRegistry
import io.myotis.node.VerifiedAccountQuery
import io.myotis.ui.AccountResult
import io.myotis.ui.EnsResult
import io.myotis.ui.NetworkStatus
import io.myotis.ui.NodeController
import io.myotis.ui.NodeSnapshot
import io.myotis.ui.PeerRow
import io.myotis.ui.Settings
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.future.await
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.path.createDirectories

/**
 * The Desktop actual of [NodeController]: drives the SAME Java backend (`node-core`
 * `ChainStack`/`NodeRegistry`) the daemon and Android use, in-process — no Android Service,
 * no IPC. Reuses the daemon's file-backed caches + CCIP gateway from `:app`.
 */
class DesktopNodeController(private val dataDir: Path, private val settings: Settings) : NodeController {

    private val registry = NodeRegistry()

    // Runs the blocking HttpGateway port when the CCIP bridge needs a future (interim,
    // like the PortBridges use below — gone once desktop constructs via MyotisEngine).
    private val httpGatewayExecutor = java.util.concurrent.Executors.newCachedThreadPool { r ->
        Thread(r, "desktop-http-gateway").apply { isDaemon = true }
    }
    // nanoTime, not currentTimeMillis: wall-clock / NTP steps must not skew uptime.
    private val startNs = System.nanoTime()
    // Per-network boot locks keyed by CANONICAL name, mirroring Android's NodeService.bootLocks:
    // serialize enable/disable for one network without a global lock, so a slow boot of network
    // A never blocks shutdown or lifecycle ops on B. NodeRegistry is ConcurrentHashMap-backed
    // (each add/get/remove is already thread-safe), so these locks only guard the per-network
    // check-then-build so two boots of the same network can't race.
    private val bootLocks = ConcurrentHashMap<String, Any>()
    // Live per-network cache instances (keyed by canonical name), retained so clearCaches can wipe
    // the authoritative in-memory state — not just the file, which a running stack would rewrite.
    private val peerCaches = ConcurrentHashMap<String, PeerCache>()
    private val clPeerCaches = ConcurrentHashMap<String, CLPeerCache>()
    private fun bootLock(canonical: String): Any = bootLocks.computeIfAbsent(canonical) { Any() }

    init {
        dataDir.createDirectories()
    }

    // A registered stack may still be booting (or have failed start()); report running only
    // when at least one stack is actually up, not merely present in the registry.
    override val running: Boolean
        get() = registry.all().any { it.isRunning }

    override fun enableNetwork(name: String) {
        // Resolve the canonical name up front: NetworkConfig.byName aliases (xdai/gbc → gnosis,
        // case-folds, etc.). Everything below — registry keys, the boot lock, and the key/cache
        // filenames — must use the canonical form, or an alias would double-boot and leak (the
        // registry keys stacks by network().name(), so a raw-alias remove() would miss).
        val network = NetworkConfig.byName(name)
        val canonical = network.name()
        // All of this (key load/generate, cache init, stack.start()) does blocking disk I/O
        // and network setup — never run it on the UI thread. Boot on a daemon thread; the
        // per-network lock (not a global one) keeps two boots of the SAME network from racing
        // while leaving shutdown / other networks free to proceed.
        Thread({
            synchronized(bootLock(canonical)) {
                if (registry.get(canonical) != null) return@synchronized
                // Honor the configured JSON-RPC port from Settings (the Settings tab's port field),
                // falling back to the network default — otherwise editing the port on desktop would
                // be inert. A reboot (disable+enable) after a port change re-reads this.
                val ports = ChainPorts.defaultsFor(network).withRpcPort(settings.rpcPortFor(canonical))
                val keyFile = if (canonical == "mainnet") "nodekey.hex" else "nodekey-$canonical.hex"
                val nodeKey = NodeKey.loadOrGenerate(dataDir.resolve(keyFile))
                val suffix = if (canonical == "mainnet") "" else "-$canonical"
                val peerCache = PeerCache(dataDir.resolve("peers$suffix.cache"))
                val clPeerCache = CLPeerCache(dataDir.resolve("cl-peers$suffix.cache"))
                // Retain the live instances so clearCaches can wipe their in-memory state.
                peerCaches[canonical] = peerCache
                clPeerCaches[canonical] = clPeerCache
                // Interim bridging (removed when desktop constructs via MyotisEngine in the
                // host-rewiring PR): the daemon's cache adapters + HTTP gateway now implement
                // the api port shapes; PortBridges maps them back to what ChainStack takes.
                val stack = ChainStack(
                    network, ports, nodeKey,
                    io.myotis.node.api.PortBridges.toPeerCachePort(PeerCacheAdapter(peerCache)),
                    io.myotis.node.api.PortBridges.toClPeerCachePort(ClPeerCacheAdapter(clPeerCache)),
                    io.myotis.node.api.PortBridges.toCcipGateway(
                        JavaHttpCcipGateway(), httpGatewayExecutor),
                    dataDir.resolve("sync-state$suffix.snapshot"),
                    false,
                )
                // Configured snap-peer target (Settings tab), not a hardcoded 32. system DNS → null.
                stack.configureSnapMaintainer(settings.snapTarget(), null)
                registry.add(stack)
                // ChainStack.start() is fault-isolated: it returns false (and closes its own
                // resources) on failure rather than throwing. Either way — false return or a
                // stray throwable — drop the stack from the registry so a later enable can
                // retry; leaving a dead entry would report "running" forever and block retries.
                val ok = try {
                    stack.start()
                } catch (t: Throwable) {
                    dropStack(canonical)
                    throw t
                }
                if (!ok) dropStack(canonical)
            }
        }, "desktop-boot-$canonical").apply { isDaemon = true }.start()
    }

    /** Drop a network's registry entry and forget its retained cache instances. */
    private fun dropStack(canonical: String) {
        registry.remove(canonical)
        peerCaches.remove(canonical)
        clPeerCaches.remove(canonical)
    }

    override fun disableNetwork(name: String) {
        val canonical = NetworkConfig.byName(name).name()
        synchronized(bootLock(canonical)) { dropStack(canonical) }
    }

    override fun rebootNetwork(name: String) {
        disableNetwork(name)
        enableNetwork(name)
    }

    override fun shutdown() {
        // No global lock: NodeRegistry and ChainStack.shutdown() are each thread-safe, so window
        // close tears every stack down promptly without waiting behind an in-progress boot of an
        // unrelated network.
        registry.shutdownAll()
        httpGatewayExecutor.shutdown()
        // Forget the (now-closed) cache instances so a stray post-shutdown clearCaches takes the
        // stopped-chain purge path rather than clear()ing a closed instance.
        peerCaches.clear()
        clPeerCaches.clear()
    }

    override fun setTargetSnapPeers(target: Int) {
        registry.all().forEach { it.setTargetSnapPeers(target) }
    }

    override fun applyBlsBackend() {
        // No-op on desktop: there's no bundled native blst library yet (the macOS dylib is a
        // follow-up — see the CMP plan), so desktop always runs the pure-Java Milagro backend and
        // the Settings toggle has nothing to swap. Wire this to BlsBackends.set(...) once the
        // native library ships for desktop.
    }

    override fun clearCaches(network: String) {
        val canonical = NetworkConfig.byName(network).name()
        // File deletes are IO — never on the Compose UI thread. Run on a daemon thread (mirrors
        // Android's NodeService.doClearCaches offloading). Serialize with enable/disable via the
        // per-network boot lock so "is the stack live?" and the clear/purge can't race a teardown.
        Thread({
            synchronized(bootLock(canonical)) {
                val suffix = if (canonical == "mainnet") "" else "-$canonical"
                val stack = registry.get(canonical)
                if (stack != null) {
                    // Chain is up: clear the LIVE instances (memory + file) so the running stack
                    // can't rewrite the old peers back, plus the backoff/blacklist.
                    stack.backoff().clear(); stack.blacklistedNodeIds().clear()
                    peerCaches[canonical]?.clear() ?: PeerCache.purge(dataDir.resolve("peers$suffix.cache"))
                    clPeerCaches[canonical]?.clear() ?: CLPeerCache.purge(dataDir.resolve("cl-peers$suffix.cache"))
                } else {
                    // Chain stopped: any retained instance is CLOSED (its diskWriter is shut down, so
                    // clear() would silently drop the file delete on RejectedExecutionException).
                    // Forget the stale references and purge the on-disk files directly.
                    peerCaches.remove(canonical)
                    clPeerCaches.remove(canonical)
                    PeerCache.purge(dataDir.resolve("peers$suffix.cache"))
                    CLPeerCache.purge(dataDir.resolve("cl-peers$suffix.cache"))
                }
            }
        }, "desktop-clear-caches-$canonical").apply { isDaemon = true }.start()
    }

    override fun resetSyncState(network: String) {
        val canonical = NetworkConfig.byName(network).name()
        // Off the UI thread — directory scan + deletes are blocking IO.
        Thread({
            val suffix = if (canonical == "mainnet") "" else "-$canonical"
            // Delete the persisted snapshot and any sibling parts (e.g. the ".roots" accumulator)
            // so the next start re-bootstraps from the embedded checkpoint. A running stack keeps
            // its in-memory state; this only affects the next start.
            java.nio.file.Files.newDirectoryStream(dataDir, "sync-state$suffix.snapshot*").use { s ->
                s.forEach { java.nio.file.Files.deleteIfExists(it) }
            }
        }, "desktop-reset-sync-$canonical").apply { isDaemon = true }.start()
    }

    override suspend fun requestAccount(network: String, address: String): AccountResult {
        // VerifiedAccountQuery handles a null/!running stack itself (failed future → throws).
        val stack = registry.get(NetworkConfig.byName(network).name())
        val r = VerifiedAccountQuery.query(stack, address).await()
        return AccountResult(
            r.address(), r.exists(), r.nonce(), r.balanceWei(),
            r.storageRootHex(), r.codeHashHex(), r.blockNumber(), r.peerStateRootHex(),
            r.peerProofValid(), r.beaconChainVerified(), r.blsVerified(), r.matchedBeaconSlot(),
            r.verifyMethod(), r.failReason(),
        )
    }

    override suspend fun resolveEns(network: String, name: String): EnsResult {
        val stack = registry.get(NetworkConfig.byName(network).name())
            ?: throw IllegalStateException("Node is not running on $network")
        val backend = stack.rpcBackend()
            ?: throw IllegalStateException("RPC backend not started on $network")
        val r = backend.resolveEns(name.trim(), EnsResolutionRoot.AUTO).await()
        return EnsResult(r.name(), r.addressHex(), r.blockNumber(), r.verified(), r.error())
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
        val readyList = active.filter { "READY" == it.state() }
        val backend = stack.rpcBackend()
        return NodeSnapshot(
            running = stack.isRunning,
            network = net.name(),
            beaconState = state,
            connectedPeers = active.size,
            readyPeers = readyList.size,
            snapPeers = conn?.activeSnapHandlers()?.size ?: 0,
            // Desktop's connector exposes only the serving handlers, so serving == negotiated here.
            snapServingPeers = conn?.activeSnapHandlers()?.size ?: 0,
            discoveredPeers = disc4?.table()?.size() ?: 0,
            // Prune expired entries before counting (backoff() leaks expired entries until a peer
            // is re-encountered) — matches Android's NodeService, which uses this same accessor.
            backedOffPeers = stack.pruneAndCountActiveBackoff(),
            blacklistedPeers = stack.blacklistedNodeIds().size,
            discv5Peers = stack.discV5()?.liveNodeCount() ?: 0,
            executionBlockNumber = bss?.executionBlockNumber ?: 0L,
            finalizedSlot = bss?.finalizedSlot ?: 0L,
            syncStartPeriod = bss?.catchUpStartPeriod ?: -1L,
            syncCurrentPeriod = bss?.currentSyncCommitteePeriod ?: 0L,
            syncTargetPeriod = BeaconChainSpec.currentPeriod(net.clGenesisTime(), net.secondsPerSlot()),
            // Real age of the last verified RPC head, or MAX_VALUE if RPC hasn't built one yet
            // (same sentinel Android's NodeService uses; the UI renders it as "—").
            verifiedHeadAgeMs = backend?.verifiedHeadAgeMs() ?: Long.MAX_VALUE,
            uptimeSeconds = (System.nanoTime() - startNs) / 1_000_000_000L,
            // snap-capable peers first (matches Android's ordering).
            readyPeerList = readyList.sortedByDescending { it.snapSupported() }
                .map { PeerRow(it.remoteAddress(), it.snapSupported(), it.clientId()) },
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
    private var deep = 16
    private var strict = true
    // Desktop has no bundled native blst yet (Milagro-only), so the honest default is off; the
    // toggle persists but DesktopNodeController.applyBlsBackend() is a no-op until the dylib ships.
    private var nativeBls = false

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
        // Clamp to the valid TCP range, falling back to the network default on out-of-range input
        // (parity with Android's NodeService.setRpcPort) so we never try to bind an unusable port.
        ports[network] = if (port in 1024..65535) port else NetworkConfig.byName(network).defaultRpcPort()
        Unit
    }
    override fun snapTarget(): Int = synchronized(this) { snap }
    override fun setSnapTarget(v: Int) = synchronized(this) { snap = v }

    override fun displayName(network: String): String = NetworkConfig.byName(network).displayName()
    override fun defaultRpcPort(network: String): Int = NetworkConfig.byName(network).defaultRpcPort()
    override fun hasEns(network: String): Boolean = NetworkConfig.byName(network).hasEns()

    override fun deepPoolThreshold(): Int = synchronized(this) { deep }
    override fun setDeepPool(v: Int) = synchronized(this) { deep = v }
    override fun strictStateFreshness(): Boolean = synchronized(this) { strict }
    override fun setStrictStateFreshness(v: Boolean) = synchronized(this) { strict = v }
    override fun nativeBlsEnabled(): Boolean = synchronized(this) { nativeBls }
    override fun setNativeBlsEnabled(v: Boolean) = synchronized(this) { nativeBls = v }
}

/** Desktop is treated as always-online (no Android ConnectivityManager). */
object DesktopNetworkStatus : NetworkStatus {
    override fun online(): Flow<Boolean> = flowOf(true)
}
