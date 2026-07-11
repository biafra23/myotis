package io.myotis.desktop

import com.jaeckel.ethp2p.app.CLPeerCache
import com.jaeckel.ethp2p.app.ClPeerCacheAdapter
import com.jaeckel.ethp2p.app.FileNodeKeyStore
import com.jaeckel.ethp2p.app.PeerCache
import com.jaeckel.ethp2p.app.PeerCacheAdapter
import com.jaeckel.ethp2p.app.rpc.JavaHttpCcipGateway
import io.myotis.api.ChainHandle
import io.myotis.api.EngineConfig
import io.myotis.api.EnsRoot
import io.myotis.api.MyotisEngine
import io.myotis.api.NetworkInfo
import io.myotis.api.ports.EnginePorts
import io.myotis.engines.Engines
import io.myotis.ui.AccountResult
import io.myotis.ui.EnsResult
import io.myotis.ui.NetworkStatus
import io.myotis.ui.NodeController
import io.myotis.ui.NodeSnapshot
import io.myotis.ui.PeerRow
import io.myotis.ui.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.path.createDirectories

/**
 * The Desktop actual of [NodeController]: drives the SAME engine the daemon and Android
 * use — through the engine API ([MyotisEngine]/[ChainHandle]) only. The composition-root
 * default is the [Engines] selector (Java engine unless `myotis.engine`/the Settings
 * toggle says otherwise); everything else this host touches is `io.myotis.api`. Reuses the daemon's file-backed caches + CCIP
 * gateway from `:app` as its port implementations.
 */
class DesktopNodeController(
    private val dataDir: Path,
    private val settings: Settings,
    private val engine: MyotisEngine = Engines.engine(),
) : NodeController {

    private val log = org.slf4j.LoggerFactory.getLogger(DesktopNodeController::class.java)

    // nanoTime, not currentTimeMillis: wall-clock / NTP steps must not skew uptime.
    private val startNs = System.nanoTime()
    // Per-network boot locks keyed by CANONICAL name, mirroring Android's NodeService.bootLocks:
    // serialize enable/disable for one network without a global lock, so a slow boot of network
    // A never blocks shutdown or lifecycle ops on B. The engine's registry is thread-safe, so
    // these locks only guard the per-network check-then-build so two boots can't race.
    private val bootLocks = ConcurrentHashMap<String, Any>()
    // Live per-network cache instances (keyed by canonical name), retained so clearCaches can wipe
    // the authoritative in-memory state — not just the file, which a running stack would rewrite.
    private val peerCaches = ConcurrentHashMap<String, PeerCache>()
    private val clPeerCaches = ConcurrentHashMap<String, CLPeerCache>()
    private fun bootLock(canonical: String): Any = bootLocks.computeIfAbsent(canonical) { Any() }

    init {
        dataDir.createDirectories()
    }

    override val running: Boolean
        get() = engine.hostedNetworks().any { engine.get(it)?.isRunning == true }

    override fun enableNetwork(name: String) {
        // Settings semantics: persist the enabled flag, then the runtime start. (The shared
        // SettingsTab also persists before calling this — idempotent — but hosts must not
        // rely on that: the interface contract is that enableNetwork persists.)
        settings.setNetworkEnabled(engine.canonicalNetworkName(name), true)
        startNetwork(name)
    }

    override fun startNetwork(name: String) {
        // Runtime-only start (Status page): never touches the persisted enabled flag.
        // Resolve the canonical name up front (xdai/gbc → gnosis, case-folds): the boot lock
        // and the key/cache filenames must use the canonical form, or an alias would
        // double-boot and leak.
        val canonical = engine.canonicalNetworkName(name)
        // All of this (key load/generate, cache init, start()) does blocking disk I/O and
        // network setup — never on the UI thread. Boot on a daemon thread; the per-network
        // lock keeps two boots of the SAME network from racing while leaving shutdown /
        // other networks free to proceed.
        Thread({
            synchronized(bootLock(canonical)) {
                if (engine.get(canonical) != null) return@synchronized
                val suffix = if (canonical == "mainnet") "" else "-$canonical"
                val peerCache = PeerCache(dataDir.resolve("peers$suffix.cache"))
                val clPeerCache = CLPeerCache(dataDir.resolve("cl-peers$suffix.cache"))
                // Retain the live instances so clearCaches can wipe their in-memory state.
                peerCaches[canonical] = peerCache
                clPeerCaches[canonical] = clPeerCache
                // Honor the Settings tab's JSON-RPC port + snap target + freshness toggle;
                // EL/discv5 ports use the engine's per-network defaults (0).
                val config = EngineConfig(
                    canonical, 0, 0, settings.rpcPortFor(canonical),
                    dataDir.resolve("sync-state$suffix.snapshot").toString(),
                    false,
                    settings.snapTarget(),
                    settings.strictStateFreshness(),
                    dataDir.toString(),
                )
                val ports = EnginePorts(
                    FileNodeKeyStore { n ->
                        dataDir.resolve(if (n == "mainnet") "nodekey.hex" else "nodekey-$n.hex")
                    },
                    PeerCacheAdapter(peerCache),
                    ClPeerCacheAdapter(clPeerCache),
                    null,                    // system DNS
                    JavaHttpCcipGateway(),
                    null, null,              // engine default logger/clock
                )
                val handle = engine.create(config, ports)
                // start() is fault-isolated: false (resources closed) on failure rather than a
                // throw. Either way, drop the network so a later enable can retry — leaving a
                // dead entry would report "running" forever and block retries.
                val ok = try {
                    handle.start()
                } catch (t: Throwable) {
                    dropNetwork(canonical)
                    throw t
                }
                if (!ok) dropNetwork(canonical)
            }
        }, "desktop-boot-$canonical").apply { isDaemon = true }.start()
    }

    /** Stop + unregister a network and forget its retained cache instances. */
    private fun dropNetwork(canonical: String) {
        engine.stop(canonical)
        peerCaches.remove(canonical)
        clPeerCaches.remove(canonical)
    }

    override fun disableNetwork(name: String) {
        // Settings semantics: persist the flag off, then the runtime stop.
        settings.setNetworkEnabled(engine.canonicalNetworkName(name), false)
        stopNetwork(name)
    }

    override fun stopNetwork(name: String) {
        // Runtime-only stop (Status page): never touches the persisted enabled flag.
        val canonical = engine.canonicalNetworkName(name)
        synchronized(bootLock(canonical)) { dropNetwork(canonical) }
    }

    override fun rebootNetwork(name: String) {
        // stop+start, NOT disable+enable: a reboot (e.g. RPC-port change) must not
        // rewrite the persisted enabled flags.
        stopNetwork(name)
        startNetwork(name)
    }

    override fun shutdown() {
        // No global lock: the engine's shutdown is thread-safe, so window close tears every
        // network down promptly without waiting behind an in-progress boot of another one.
        engine.shutdownAll()
        // Forget the (now-closed) cache instances so a stray post-shutdown clearCaches takes
        // the stopped-chain purge path rather than clear()ing a closed instance.
        peerCaches.clear()
        clPeerCaches.clear()
    }

    override fun setTargetSnapPeers(target: Int) {
        engine.hostedNetworks().forEach { engine.get(it)?.setTargetSnapPeers(target) }
    }

    override fun applyBlsBackend() {
        // No-op on desktop: there's no bundled native blst library yet (the macOS dylib is a
        // follow-up — see the CMP plan), so desktop always runs the pure-Java Milagro backend
        // and the Settings toggle has nothing to swap.
    }

    override fun applyEngineChoice() {
        // auto (not rust): the Rust engine is catalog-only for now, so a hard `rust` would
        // refuse to boot networks; auto prefers Rust where it can serve and falls back to
        // Java with a log. Applies to networks (re)started afterwards — live ones keep
        // their engine (reboot the network from Settings to switch it).
        Engines.select(if (settings.rustEngineEnabled()) "auto" else "java")
    }

    override fun clearCaches(network: String) {
        val canonical = engine.canonicalNetworkName(network)
        // File deletes are IO — never on the Compose UI thread. Serialize with enable/disable
        // via the per-network boot lock so "is the chain live?" and the clear can't race a
        // teardown.
        Thread({
            synchronized(bootLock(canonical)) {
                val suffix = if (canonical == "mainnet") "" else "-$canonical"
                val handle = engine.get(canonical)
                if (handle != null) {
                    // Chain is up: clear the live dial state (backoff + session blacklist)
                    // through the API, and the LIVE cache instances (memory + file) so the
                    // running stack can't rewrite the old peers back.
                    handle.clearPeerState()
                    peerCaches[canonical]?.clear() ?: PeerCache.purge(dataDir.resolve("peers$suffix.cache"))
                    clPeerCaches[canonical]?.clear() ?: CLPeerCache.purge(dataDir.resolve("cl-peers$suffix.cache"))
                } else {
                    // Chain stopped: any retained instance is CLOSED (clear() would silently drop
                    // the file delete). Forget the stale references and purge the files directly.
                    peerCaches.remove(canonical)
                    clPeerCaches.remove(canonical)
                    PeerCache.purge(dataDir.resolve("peers$suffix.cache"))
                    CLPeerCache.purge(dataDir.resolve("cl-peers$suffix.cache"))
                }
            }
        }, "desktop-clear-caches-$canonical").apply { isDaemon = true }.start()
    }

    override fun resetSyncState(network: String) {
        val canonical = engine.canonicalNetworkName(network)
        // Off the UI thread — directory scan + deletes are blocking IO.
        Thread({
            val suffix = if (canonical == "mainnet") "" else "-$canonical"
            // Delete the persisted snapshot and any sibling parts (e.g. the ".roots"
            // accumulator) so the next start re-bootstraps from the embedded checkpoint.
            java.nio.file.Files.newDirectoryStream(dataDir, "sync-state$suffix.snapshot*").use { s ->
                s.forEach { java.nio.file.Files.deleteIfExists(it) }
            }
        }, "desktop-reset-sync-$canonical").apply { isDaemon = true }.start()
    }

    override suspend fun requestAccount(network: String, address: String): AccountResult {
        val handle = engine.get(engine.canonicalNetworkName(network))
            ?: throw IllegalStateException("Node is not running on $network")
        // Blocking engine call (snap fetch + verification ladder) — worker thread.
        val r = withContext(Dispatchers.IO) { handle.requestAccount(address) }
        return AccountResult(
            r.address(), r.exists(), r.nonce(), r.balanceWei(),
            r.storageRootHex(), r.codeHashHex(), r.blockNumber(), r.peerStateRootHex(),
            r.peerProofValid(), r.beaconChainVerified(), r.blsVerified(), r.matchedBeaconSlot(),
            r.verifyMethod(), r.failReason(),
        )
    }

    override suspend fun resolveEns(network: String, name: String): EnsResult {
        val handle = engine.get(engine.canonicalNetworkName(network))
            ?: throw IllegalStateException("Node is not running on $network")
        val ens = handle.ens()
            ?: throw IllegalStateException("ENS is not available on $network")
        val r = withContext(Dispatchers.IO) { ens.resolveAddress(name.trim(), EnsRoot.AUTO) }
        return EnsResult(r.name(), r.addressHex(), r.blockNumber(), r.verified(), r.error())
    }

    /** Poll the hosted networks every 2s and emit a per-network snapshot map for the UI.
     *  flowOn(Default): status() walks/sorts peer lists and prunes the backoff map — keep
     *  that off the Compose UI thread (parity with Android's bridge, which does the same). */
    override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flow {
        while (true) {
            emit(engine.hostedNetworks().mapNotNull { name ->
                engine.get(name)?.let { name to snapshotOf(it) }
            }.toMap())
            delay(2000)
        }
    }.flowOn(Dispatchers.Default)

    init {
        // Rust log pump on a dedicated daemon thread — NOT inside snapshots():
        // draining must not stop when the UI stops collecting the flow (window
        // closed while the node runs) or the ring silently overflows and drops
        // exactly the incident lines this seam exists to capture. Severity is
        // preserved (tracing fmt puts the level first). Process-lifetime, like
        // the controller itself.
        Thread({
            while (true) {
                try {
                    val batch = Engines.drainRustLogs(500)
                    if (batch.isNotEmpty()) {
                        batch.split('\n').forEach {
                            val t = it.trim()
                            when {
                                t.startsWith("ERROR") -> log.error("[rust] {}", it)
                                t.startsWith("WARN") -> log.warn("[rust] {}", it)
                                else -> log.info("[rust] {}", it)
                            }
                        }
                    }
                } catch (e: InterruptedException) {
                    return@Thread // don't swallow an interrupt raised mid-drain
                } catch (ignored: Throwable) {
                    // Observability must never take the host down.
                }
                try {
                    Thread.sleep(5_000)
                } catch (e: InterruptedException) {
                    return@Thread
                }
            }
        }, "myotis-rust-logs").apply { isDaemon = true }.start()
    }

    private fun snapshotOf(handle: ChainHandle): NodeSnapshot {
        val s = handle.status()
        // Live counts parsed from the cache FILES (the cross-engine truth; the
        // Rust engine writes them directly). Memoized on (mtime, size).
        val suffix = if (s.network() == "mainnet") "" else "-${s.network()}"
        val clCache = CacheFileStats.cl(dataDir.resolve("cl-peers$suffix.cache"))
        val elCache = CacheFileStats.el(dataDir.resolve("peers$suffix.cache"))
        // CL peer counts live on the beacon-status surface (parity with Android's
        // NodeService.snapshotOf, which reads both).
        val bs = handle.beaconStatus()
        return NodeSnapshot(
            running = s.running(),
            lifecycle = s.lifecycle().name,
            network = s.network(),
            beaconState = s.beaconState().name,
            connectedPeers = s.connectedPeers(),
            readyPeers = s.readyPeers(),
            snapPeers = s.snapPeers(),
            snapServingPeers = s.snapServingPeers(),
            clConnectedPeers = bs.connectedPeers(),
            clServedPeersLastMin = bs.servedPeersLastMinute(),
            clCachedPeers = clCache.total,
            clCachedProven = clCache.proven,
            clCachedNolc = clCache.nolc,
            elCachedPeers = elCache.total,
            elCachedSnapOk = elCache.snapOk,
            elCachedSnapBad = elCache.snapBad,
            discoveredPeers = s.discoveredPeers(),
            backedOffPeers = s.backedOffPeers(),
            blacklistedPeers = s.blacklistedPeers(),
            discv5Peers = s.discv5TableSize(),
            executionBlockNumber = s.executionBlockNumber(),
            finalizedSlot = s.finalizedSlot(),
            syncStartPeriod = s.syncStartPeriod(),
            syncCurrentPeriod = s.syncCurrentPeriod(),
            syncTargetPeriod = s.syncTargetPeriod(),
            verifiedHeadAgeMs = s.verifiedHeadAgeMs(),
            uptimeSeconds = (System.nanoTime() - startNs) / 1_000_000_000L,
            readyPeerList = s.readyPeerList().map { PeerRow(it.remoteAddress(), it.snapSupported(), it.clientId()) },
            pauseCount = s.pauseCount(),
            totalPausedMs = s.totalPausedMs(),
            lastPauseEpochMs = s.lastPauseEpochMs(),
            lastResumeEpochMs = s.lastResumeEpochMs(),
            lastWakeReason = s.lastWakeReason(),
        )
    }
}

/**
 * Minimal in-memory desktop settings (Step 1). File-backed persistence is a follow-up.
 * Network metadata comes from the engine's [NetworkInfo] catalog — no engine-internal
 * config types. Read/written from both the UI thread and the boot threads, so every
 * access is guarded by `synchronized(this)` over the non-thread-safe backing collections.
 */
class DesktopSettings(
    private val networks: List<NetworkInfo> = Engines.engine().availableNetworks(),
) : Settings {
    private val enabled = linkedSetOf("mainnet")
    private val ports = HashMap<String, Int>()
    private var snap = 32
    private var deep = 16
    private var strict = true
    // Desktop has no bundled native blst yet (Milagro-only), so the honest default is off; the
    // toggle persists but DesktopNodeController.applyBlsBackend() is a no-op until the dylib ships.
    private var nativeBls = false
    // The Rust engine is experimental (catalog-only today) — off by default everywhere.
    private var rustEngine = false

    private fun info(network: String): NetworkInfo? = networks.firstOrNull { it.name() == network }

    override fun enabledNetworks(): List<String> = synchronized(this) { enabled.toList() }
    override fun primaryNetwork(): String = synchronized(this) { enabled.firstOrNull() ?: "mainnet" }
    override fun allNetworks(): List<String> = networks.map { it.name() }
    override fun isNetworkEnabled(name: String): Boolean = synchronized(this) { name in enabled }
    override fun setNetworkEnabled(name: String, on: Boolean) = synchronized(this) {
        if (on) enabled.add(name) else enabled.remove(name)
        Unit
    }
    override fun rpcPortFor(network: String): Int = synchronized(this) {
        ports[network] ?: defaultRpcPort(network)
    }
    override fun setRpcPort(network: String, port: Int) = synchronized(this) {
        // Clamp to the valid TCP range, falling back to the network default on out-of-range
        // input (parity with Android's NodeService.setRpcPort).
        ports[network] = if (port in 1024..65535) port else defaultRpcPort(network)
        Unit
    }
    override fun snapTarget(): Int = synchronized(this) { snap }
    override fun setSnapTarget(v: Int) = synchronized(this) { snap = v }

    override fun displayName(network: String): String = info(network)?.displayName() ?: network
    override fun defaultRpcPort(network: String): Int = info(network)?.defaultRpcPort() ?: 8545
    override fun hasEns(network: String): Boolean = info(network)?.hasEns() ?: false

    override fun deepPoolThreshold(): Int = synchronized(this) { deep }
    override fun setDeepPool(v: Int) = synchronized(this) { deep = v }
    override fun strictStateFreshness(): Boolean = synchronized(this) { strict }
    override fun setStrictStateFreshness(v: Boolean) = synchronized(this) { strict = v }
    override fun nativeBlsEnabled(): Boolean = synchronized(this) { nativeBls }
    override fun setNativeBlsEnabled(v: Boolean) = synchronized(this) { nativeBls = v }
    override fun rustEngineEnabled(): Boolean = synchronized(this) { rustEngine }
    override fun setRustEngineEnabled(v: Boolean) = synchronized(this) { rustEngine = v }
}

/** Desktop is treated as always-online (no Android ConnectivityManager). */
object DesktopNetworkStatus : NetworkStatus {
    override fun online(): Flow<Boolean> = flowOf(true)
}
