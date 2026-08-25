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
import io.myotis.ui.LogIndexWatch
import io.myotis.engines.SelectorEngine
import io.myotis.engines.Tor
import io.myotis.txhistory.TxHistoryEvent
import io.myotis.txhistory.TxHistoryService
import io.myotis.txhistory.TxSummary
import io.myotis.txhistory.headline
import io.myotis.txhistory.uiKind
import io.myotis.ui.AccountResult
import io.myotis.ui.CacheFileStats
import io.myotis.ui.EnsResult
import io.myotis.ui.NetworkStatus
import io.myotis.ui.NodeController
import io.myotis.ui.NodeSnapshot
import io.myotis.ui.PeerRow
import io.myotis.ui.Settings
import io.myotis.ui.TxRowUi
import io.myotis.ui.TxScanEvent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.path.createDirectories

/**
 * The Desktop actual of [NodeController]: drives the SAME engine the daemon and Android
 * use — through the engine API ([MyotisEngine]/[ChainHandle]) only. The composition-root
 * default is the [Engines] selector (`auto`: the Rust engine where it can serve, Java
 * fallback — unless `myotis.engine`/the Settings toggle says otherwise); everything else
 * this host touches is `io.myotis.api`. Reuses the daemon's file-backed caches + CCIP
 * gateway from `:app` as its port implementations.
 */
class DesktopNodeController(
    private val dataDir: Path,
    private val settings: Settings,
    private val engine: MyotisEngine = Engines.engine(),
) : NodeController {

    private val log = org.slf4j.LoggerFactory.getLogger(DesktopNodeController::class.java)

    // Per-network boot stamp driving the UI uptime: stamped when a boot BEGINS (any engine,
    // Java or Rust) — uptime counts from the start request (Status button / app-launch
    // auto-start), not from when the blocking start() finished — and cleared on drop
    // (every failure path runs dropNetwork), so the counter restarts from zero on every
    // network/engine (re)boot; it is NOT the controller's (app's) lifetime.
    // nanoTime, not currentTimeMillis: wall-clock / NTP steps must not skew uptime.
    private val startNsByNetwork = ConcurrentHashMap<String, Long>()
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
    // Pairs the boot path's read-settings-then-apply of the served-block window with the
    // Save fan-out, so a Save can never be overwritten by a concurrently booting network.
    private val servedWindowApplyLock = Any()

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
                // Anchor uptime to the start REQUEST: create()+start() below block through
                // key load, DNS resolution, and socket binds — the counter must already be
                // running while that happens (it becomes visible once create() registers
                // the handle). Stamped immediately before the try so the invariant is
                // structural, not dependent on earlier lines staying non-throwing: every
                // failure path from here on runs dropNetwork, which clears it.
                startNsByNetwork[canonical] = System.nanoTime()
                // create() is all-or-nothing (nothing registered on failure), so on a throw
                // dropNetwork only forgets the cache instances retained above — leaving them
                // would hand clearCaches a live-looking instance for a network that never
                // booted. engine.stop() on an unregistered network is a no-op.
                val handle = try {
                    engine.create(config, ports)
                } catch (t: Throwable) {
                    dropNetwork(canonical)
                    throw t
                }
                // start() is fault-isolated: false (resources closed) on failure rather than a
                // throw. Either way, drop the network so a later enable can retry — leaving a
                // dead entry would report "running" forever and block retries. The served-window
                // apply shares the try: a throw there would otherwise leave a registered-but-
                // never-started network behind, uptime stamp included.
                val ok = try {
                    // Apply the Settings served-block window before start() (so the very first
                    // eth/69 Status advertises the configured size), reading the setting INSIDE
                    // servedWindowApplyLock: the Save fan-out takes the same lock, and create()
                    // above already made this handle visible to hostedNetworks() — so either the
                    // fan-out reaches this handle, or our read observes its already-persisted
                    // value. Without the pairing a Save landing between our read and apply
                    // would be overwritten, leaving the live window one Save behind settings.
                    synchronized(servedWindowApplyLock) {
                        handle.setServedBlockWindow(settings.servedBlockWindow())
                        // Weak-subjectivity bound override rides the same pre-start
                        // apply + lock: the cold-start gate must judge with it.
                        handle.setWsBoundPeriods(settings.wsBoundPeriods().toLong())
                    }
                    handle.start()
                } catch (t: Throwable) {
                    dropNetwork(canonical)
                    throw t
                }
                if (!ok) dropNetwork(canonical)
                else {
                    // Boot-time apply of the log-index preset — AFTER start:
                    // the engine only accepts the config on a running handle
                    // (its reader owns the index). Re-pushed on every
                    // (re)start, which cures restart dormancy: the persisted
                    // index reloads when the fingerprint matches.
                    pushLogIndexConfig(canonical, handle)
                }
            }
        }, "desktop-boot-$canonical").apply { isDaemon = true }.start()
    }

    /** Stop + unregister a network and forget its retained cache instances. */
    private fun dropNetwork(canonical: String) {
        engine.stop(canonical)
        peerCaches.remove(canonical)
        clPeerCaches.remove(canonical)
        startNsByNetwork.remove(canonical) // next start re-anchors uptime
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
        startNsByNetwork.clear() // symmetry with dropNetwork: no stamp outlives its stack
    }

    override fun setTargetSnapPeers(target: Int) {
        engine.hostedNetworks().forEach { engine.get(it)?.setTargetSnapPeers(target) }
    }

    override fun setServedBlockWindow(blocks: Int) {
        // Same lock as the boot-path read+apply: see the comment there. (The SettingsTab
        // persists via settings.setServedBlockWindow BEFORE calling this.)
        synchronized(servedWindowApplyLock) {
            engine.hostedNetworks().forEach { engine.get(it)?.setServedBlockWindow(blocks) }
        }
    }

    override fun setWsBoundPeriods(periods: Int) {
        // Same lock discipline as the served-window fan-out (the boot path applies
        // this knob pre-start under the same lock). A STALE_ANCHOR park re-evaluates
        // against the new bound within a second.
        synchronized(servedWindowApplyLock) {
            engine.hostedNetworks().forEach { engine.get(it)?.setWsBoundPeriods(periods.toLong()) }
        }
    }

    override fun acceptStaleAnchor(network: String) {
        engine.get(network)?.acceptStaleAnchor()
    }

    override fun applyBlsBackend() {
        // No-op on desktop: there's no bundled native blst library yet (the macOS dylib is a
        // follow-up — see the CMP plan), so desktop always runs the pure-Java Milagro backend
        // and the Settings toggle has nothing to swap.
    }

    override fun applyEngineChoice() {
        // auto (not rust) as the default: auto prefers Rust where it can serve and falls
        // back to Java with a log, so a host without the native library still boots.
        // Applies to networks (re)started afterwards — live ones keep their engine
        // (reboot the network from Settings to switch it).
        Engines.select(if (settings.preferJavaEngine()) "java" else "auto")
    }

    override fun applyLogIndex(network: String) {
        // Off the UI thread: the engine-side install may reload a persisted
        // index from disk (fingerprint-matched), which can be large.
        Thread({
            engine.get(network)?.let { pushLogIndexConfig(network, it) }
        }, "log-index-apply-$network").apply { isDaemon = true }.start()
    }

    private fun pushLogIndexConfig(network: String, handle: ChainHandle) {
        val enabled = settings.logIndexEnabled(network)
        val maxSpeed = settings.logIndexMaxSpeed(network)
        // Nothing to say (no watched contracts, never configured) -> never push;
        // the engine keeps eth_getLogs in its honest not-configured state. A
        // CONFIGURED network always pushes — a disable must reach the engine or
        // its boot-time activate-from-disk re-enables an imported index.
        val json = LogIndexWatch.configJson(
            settings.logIndexWatchJson(network), enabled, maxSpeed,
            configured = settings.logIndexConfigured(network),
        ) ?: return
        val ok = handle.setLogIndexConfig(json)
        if (enabled && !ok) {
            log.warn("[desktop] log index config rejected for {} (Java engine, or engine gate down)", network)
        }
    }

    /** Raw log-index status JSON, fetched ONCE per snapshot (both the status
     *  line and the Index tab derive from it), or null when unavailable.
     *  Deliberately NOT gated on the Settings flag: an imported or dropped-in
     *  snapshot activates engine-side without the flag ever being touched,
     *  and the Java engine's stable disabled default keeps this cheap. */
    private fun logIndexRawFor(network: String): String? =
        runCatching { engine.get(network)?.logIndexStatusJson() }.getOrNull()

    override val canImportLogIndex: Boolean get() = true

    override fun importLogIndexSnapshots(network: String, onResult: (String) -> Unit): Boolean {
        val canonical = engine.canonicalNetworkName(network)
        // AWT file dialog wants the EDT; the import itself (engine-side merge
        // of possibly-GB snapshots) then moves to a worker thread.
        java.awt.EventQueue.invokeLater {
            val dialog = java.awt.FileDialog(null as java.awt.Frame?, "Import log-index snapshots", java.awt.FileDialog.LOAD)
            dialog.isMultipleMode = true
            dialog.isVisible = true
            val files = dialog.files?.toList().orEmpty()
            if (files.isEmpty()) {
                onResult("Import cancelled.")
                return@invokeLater
            }
            Thread({
                val handle = engine.get(canonical)
                if (handle == null) {
                    onResult("$canonical is not running — start it first.")
                    return@Thread
                }
                val pathsJson = files.joinToString(",", "[", "]") {
                    "\"${it.absolutePath.replace("\\", "\\\\").replace("\"", "\\\"")}\""
                }
                val result = runCatching { handle.importLogIndexFiles(pathsJson) }
                    .getOrElse { "{\"error\":\"${it.message}\"}" }
                if (result.startsWith("{\"ok\":true")) {
                    // Importing is the opt-in: persist the flag so the next
                    // start's config push keeps the index enabled.
                    settings.setLogIndexEnabled(canonical, true)
                    onResult("Imported ${files.size} snapshot${if (files.size == 1) "" else "s"} — catch-up started.")
                } else {
                    val err = Regex("\"error\":\"((?:[^\"\\\\]|\\\\.)*)\"").find(result)
                        ?.groupValues?.get(1) ?: result
                    onResult("Import failed: $err")
                }
            }, "log-index-import-$canonical").apply { isDaemon = true }.start()
        }
        return true
    }

    // Answered from the loaded engine build: only a -PtorEngine dylib links Arti,
    // and RustMyotisEngine.isAvailable() is already resolved by the time the UI
    // renders (Main.kt loads the lib before composition). Cached — the answer
    // cannot change within a process, and the row reads it on every recomposition.
    override val supportsTor: Boolean by lazy { runCatching { Tor.supported() }.getOrDefault(false) }

    override fun applyTorMode() {
        // Push the persisted Tor preference to the process-global Rust-engine flag
        // (docs/privacy-and-tor.md). Tor is Rust-engine-only and experimental: Tor.select
        // returns whether the loaded engine build actually supports it, which we log so a
        // silently-unsupported build is visible. Unlike the engine choice, the Tor flag is
        // LIVE — ElReader checks it per read, so a flip takes effect on the next read of an
        // already-running Rust-engine network (no restart needed).
        val on = settings.torEnabled()
        val supported = Tor.select(on)
        if (on && !supported) {
            log.warn("[desktop] Tor routing requested but this engine build has no Tor support "
                    + "(needs the Rust engine dylib built with --features tor)")
        }
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

    // ------------------------------------------------------------------------------
    // TrueBlocks transaction history (Query tab add-on) — a documented exemption from
    // the "hosts consume only io.myotis.api" rule, same category as the daemon's
    // get-transactions stream: the scan needs the raw RLPxConnector, reached through
    // the CONCRETE Java engine's debug accessor. Java-engine + mainnet only; a
    // Rust-hosted mainnet simply reports unsupported and the UI hides the section.
    // ------------------------------------------------------------------------------

    override fun supportsTransactionHistory(network: String): Boolean {
        if (engine.canonicalNetworkName(network) != "mainnet") return false
        val selector = engine as? SelectorEngine ?: return false
        return runCatching { selector.javaDelegate().debugStack("mainnet") != null }
            .getOrDefault(false)
    }

    override fun transactionHistory(network: String, address: String): Flow<TxScanEvent> {
        val canonical = engine.canonicalNetworkName(network)
        check(canonical == "mainnet") { "Transaction history is mainnet-only" }
        val selector = engine as? SelectorEngine
            ?: throw IllegalStateException("Transaction history requires the engine selector")
        val stack = selector.javaDelegate().debugStack("mainnet")
            ?: throw IllegalStateException("Transaction history requires the Java engine (mainnet not Java-hosted or not running)")
        // Gate on SYNCED (non-blocking check) so the manifest eth_call degrades to
        // the cached/hardcoded CID instead of parking on the readiness wait.
        fun syncedReads() = engine.get("mainnet")?.reads()
            ?.takeIf { it.syncState() == io.myotis.api.SyncState.SYNCED }
        val service = TxHistoryService(
            stack.connector(),
            ::syncedReads,
            dataDir.resolve("trueblocks"),
            publisherResolver = {
                // The index publisher's current wallet via VERIFIED ENS (TrueBlocks
                // re-points the name on wallet rotation). Null → built-in default.
                runCatching {
                    if (syncedReads() == null) null
                    else engine.get("mainnet")?.ens()?.resolveAddress(
                        io.myotis.txhistory.ManifestCidResolver.PUBLISHER_ENS_NAME,
                        io.myotis.api.EnsRoot.AUTO,
                    )?.addressHex()
                }.getOrNull()
            },
        )
        return service.scan(address).map { it.toUi() }
    }

    private fun TxHistoryEvent.toUi(): TxScanEvent = when (this) {
        is TxHistoryEvent.Started -> TxScanEvent.Started(
            manifestCid, cidSource, totalChunks, latestIndexedBlock, headBlock)
        is TxHistoryEvent.Progress -> TxScanEvent.Progress(
            chunksScanned, totalChunks, currentRange, hits, bytesDownloaded)
        is TxHistoryEvent.Hit -> TxScanEvent.Hit(blockNumber, txIndex)
        is TxHistoryEvent.Tx -> TxScanEvent.Tx(summary.toRow())
        is TxHistoryEvent.TxFailed -> TxScanEvent.Failed(blockNumber, txIndex, error)
        is TxHistoryEvent.Done -> TxScanEvent.Done(total = txCount)
    }

    private fun TxSummary.toRow(): TxRowUi = TxRowUi(
        blockNumber = blockNumber,
        txIndex = txIndex,
        hash = hash,
        from = from,
        to = to,
        kind = uiKind(),
        headline = headline(), // shared with the Android mapper (:tx-history TxSummaryDisplay)
    )

    /** Poll the hosted networks every 2s and emit a per-network snapshot map for the UI.
     *  flowOn(Default): status() walks/sorts peer lists and prunes the backoff map — keep
     *  that off the Compose UI thread (parity with Android's bridge, which does the same). */
    override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flow {
        while (true) {
            emit(engine.hostedNetworks().mapNotNull { name ->
                engine.get(name)?.let { name to snapshotOf(name, it) }
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

    private fun snapshotOf(network: String, handle: ChainHandle): NodeSnapshot {
        val s = handle.status()
        // Live counts parsed from the cache FILES (the cross-engine truth; the
        // Rust engine writes them directly). Memoized on (mtime, size).
        val suffix = if (s.network() == "mainnet") "" else "-${s.network()}"
        val clCache = CacheFileStats.cl(dataDir.resolve("cl-peers$suffix.cache").toString())
        val elCache = CacheFileStats.el(dataDir.resolve("peers$suffix.cache").toString())
        // CL peer counts live on the beacon-status surface (parity with Android's
        // NodeService.snapshotOf, which reads both).
        val bs = handle.beaconStatus()
        val logIndexRaw = logIndexRawFor(s.network())
        return NodeSnapshot(
            running = s.running(),
            lifecycle = s.lifecycle().name,
            network = s.network(),
            engine = Engines.engineKindFor(s.network()),
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
            // hostedNetworks() keys are canonical (create() canonicalizes), matching the
            // boot path's startNsByNetwork key — no re-canonicalization needed here.
            uptimeSeconds = startNsByNetwork[network]
                ?.let { (System.nanoTime() - it) / 1_000_000_000L } ?: 0L,
            peerHeaderRequests = s.peerHeaderRequests(),
            peerHeaderRequestsServed = s.peerHeaderRequestsServed(),
            peerBodyRequests = s.peerBodyRequests(),
            peerBodyRequestsServed = s.peerBodyRequestsServed(),
            readyPeerList = s.readyPeerList().map { PeerRow(it.remoteAddress(), it.snapSupported(), it.clientId()) },
            pauseCount = s.pauseCount(),
            totalPausedMs = s.totalPausedMs(),
            lastPauseEpochMs = s.lastPauseEpochMs(),
            lastResumeEpochMs = s.lastResumeEpochMs(),
            lastWakeReason = s.lastWakeReason(),
            lcHunting = s.lcHunting(),
            elHunting = s.elHunting(),
            rpcPort = s.rpcPort(),
            rpcServing = s.rpcServing(),
            tor = torModeFor(Engines.engineKindFor(s.network())),
            logIndex = logIndexRaw?.let(io.myotis.ui.LogIndexStatus::format),
            logIndexJson = logIndexRaw,
            wsBoundPeriods = s.wsBoundPeriods(),
        )
    }

    /**
     * Tor routing state for the Status row (docs/privacy-and-tor.md), or null when it
     * doesn't apply: Tor is a Rust-engine-only capability, and a Rust build without
     * `--features tor` reports no support (status bit0 clear). Otherwise: "off" (supported
     * but disabled), "on" (enabled, circuit still bootstrapping), "active" (circuit ready).
     */
    private fun torModeFor(engineKind: String?): String? {
        if (engineKind != "rust") return null
        val st = Tor.status()
        if (st and 1 == 0) return null
        return when {
            st and 2 == 0 -> "off"
            st and 4 != 0 -> "active"
            else -> "on"
        }
    }
}

/**
 * Desktop settings, file-backed so every toggle survives an app restart (Android parity —
 * there SharedPreferences does this for free). [file] is a java.util.Properties file under
 * the app data dir (`~/.myotis/settings.properties`); null keeps the store in-memory
 * (tests, syncSmoke). Loaded once at construction; every setter rewrites the file.
 * Unknown keys and unparsable values fall back to the defaults, so a hand-edited or
 * older-version file can't break boot.
 *
 * Network metadata comes from the engine's [NetworkInfo] catalog — no engine-internal
 * config types. Read/written from both the UI thread and the boot threads, so every
 * access is guarded by `synchronized(this)` over the non-thread-safe backing collections.
 */
class DesktopSettings(
    private val networks: List<NetworkInfo> = Engines.engine().availableNetworks(),
    private val file: Path? = null,
) : Settings {
    private val enabled = linkedSetOf("mainnet")
    private val ports = HashMap<String, Int>()
    private var snap = 32
    private var servedWindow = 32
    // Weak-subjectivity bound override (periods); 0 = each network's default.
    private var wsBound = 0
    private var deep = 16
    private var strict = true
    // Desktop has no bundled native blst yet (Milagro-only), so the honest default is off; the
    // toggle persists but DesktopNodeController.applyBlsBackend() is a no-op until the dylib ships.
    private var nativeBls = false
    // Default off = the selector's `auto` mode (Rust engine where it can serve, Java
    // fallback). On = force the Java engine — the opt-out, now that Rust is primary.
    private var preferJava = false
    // Tor verified-read routing (docs/privacy-and-tor.md) — experimental, Rust-engine-only,
    // off by default. Persists independently; applyTorMode() pushes it to the Rust engine.
    private var torRouting = false
    // Per-network opt-in for the eth_getLogs watch-list index (Rust engine only).
    private val logIndexOn = HashMap<String, Boolean>()
    // Per-network backfill pacing (true = max download speed); see Settings.logIndexMaxSpeed.
    private val logIndexMax = HashMap<String, Boolean>()
    // Per-network watched contracts, as LogIndexWatch's JSON array (Settings.logIndexWatchJson).
    private val logIndexWatch = HashMap<String, String>()

    /** Serializes file writes, separate from the state lock (`this`) so settings
     *  readers never wait on disk I/O. */
    private val ioLock = Any()
    private var stateSeq = 0L   // guarded by `this`
    private var writtenSeq = 0L // guarded by [ioLock]

    init {
        load()
    }

    private fun info(network: String): NetworkInfo? = networks.firstOrNull { it.name() == network }

    override fun enabledNetworks(): List<String> = synchronized(this) { enabled.toList() }
    override fun primaryNetwork(): String = synchronized(this) { enabled.firstOrNull() ?: "mainnet" }
    override fun allNetworks(): List<String> = networks.map { it.name() }
    override fun isNetworkEnabled(name: String): Boolean = synchronized(this) { name in enabled }
    override fun setNetworkEnabled(name: String, on: Boolean) = mutate {
        if (on) enabled.add(name) else enabled.remove(name)
    }
    override fun rpcPortFor(network: String): Int = synchronized(this) {
        ports[network] ?: defaultRpcPort(network)
    }
    override fun setRpcPort(network: String, port: Int) = mutate {
        // Clamp to the valid TCP range, falling back to the network default on out-of-range
        // input (parity with Android's NodeService.setRpcPort).
        ports[network] = if (port in 1024..65535) port else defaultRpcPort(network)
    }
    override fun snapTarget(): Int = synchronized(this) { snap }
    // Clamp like Android's NodeService (1..128) so the live value and the reloaded
    // value can't differ (load() applies the same clamp).
    override fun setSnapTarget(v: Int) = mutate { snap = v.coerceIn(1, 128) }
    override fun servedBlockWindow(): Int = synchronized(this) { servedWindow }
    // Clamp like ChainStack.setServedBlockWindow (1..4096) so live and reloaded values agree.
    override fun setServedBlockWindow(v: Int) = mutate { servedWindow = v.coerceIn(1, 4096) }
    override fun wsBoundPeriods(): Int = synchronized(this) { wsBound }
    // 0 = per-network default; cap keeps a typo from storing an absurd bound.
    override fun setWsBoundPeriods(v: Int) = mutate { wsBound = v.coerceIn(0, 9999) }
    override fun logIndexEnabled(network: String): Boolean =
        synchronized(this) { logIndexOn[network] ?: false }
    override fun setLogIndexEnabled(network: String, on: Boolean) = mutate { logIndexOn[network] = on }
    override fun logIndexMaxSpeed(network: String): Boolean =
        synchronized(this) { logIndexMax[network] ?: false }
    override fun setLogIndexMaxSpeed(network: String, on: Boolean) = mutate { logIndexMax[network] = on }
    override fun logIndexConfigured(network: String): Boolean =
        synchronized(this) { logIndexOn.containsKey(network) }
    override fun logIndexWatchJson(network: String): String =
        synchronized(this) { logIndexWatch[network] ?: "[]" }
    override fun setLogIndexWatchJson(network: String, json: String) =
        mutate { logIndexWatch[network] = json }

    override fun displayName(network: String): String = info(network)?.displayName() ?: network
    override fun defaultRpcPort(network: String): Int = info(network)?.defaultRpcPort() ?: 8545
    override fun hasEns(network: String): Boolean = info(network)?.hasEns() ?: false

    override fun deepPoolThreshold(): Int = synchronized(this) { deep }
    override fun setDeepPool(v: Int) = mutate { deep = v.coerceIn(1, 128) }
    override fun strictStateFreshness(): Boolean = synchronized(this) { strict }
    override fun setStrictStateFreshness(v: Boolean) = mutate { strict = v }
    override fun nativeBlsEnabled(): Boolean = synchronized(this) { nativeBls }
    override fun setNativeBlsEnabled(v: Boolean) = mutate { nativeBls = v }
    override fun preferJavaEngine(): Boolean = synchronized(this) { preferJava }
    override fun setPreferJavaEngine(v: Boolean) = mutate { preferJava = v }
    override fun torEnabled(): Boolean = synchronized(this) { torRouting }
    override fun setTorEnabled(v: Boolean) = mutate { torRouting = v }

    /** Best-effort load; a missing or unreadable file just keeps the defaults. */
    private fun load() {
        val f = file ?: return
        if (!Files.exists(f)) return
        val p = java.util.Properties()
        if (runCatching { Files.newInputStream(f).use(p::load) }.isFailure) return
        p.getProperty(K_ENABLED)?.let { csv ->
            // Key present = the user's explicit set (possibly empty). Unknown names are
            // dropped so a stale/hand-edited entry can't feed startNetwork() a bad name.
            enabled.clear()
            csv.split(',').map(String::trim).filter { it.isNotEmpty() && info(it) != null }
                .forEach(enabled::add)
        }
        networks.forEach { n ->
            p.getProperty("$K_RPC_PORT_PREFIX${n.name()}")?.toIntOrNull()
                ?.takeIf { it in 1024..65535 }
                ?.let { ports[n.name()] = it }
        }
        p.getProperty(K_SNAP)?.toIntOrNull()?.let { snap = it.coerceIn(1, 128) }
        p.getProperty(K_SERVED_WINDOW)?.toIntOrNull()?.let { servedWindow = it.coerceIn(1, 4096) }
        p.getProperty(K_WS_BOUND)?.toIntOrNull()?.let { wsBound = it.coerceIn(0, 9999) }
        p.getProperty(K_DEEP)?.toIntOrNull()?.let { deep = it.coerceIn(1, 128) }
        p.getProperty(K_STRICT)?.toBooleanStrictOrNull()?.let { strict = it }
        p.getProperty(K_NATIVE_BLS)?.toBooleanStrictOrNull()?.let { nativeBls = it }
        p.getProperty(K_PREFER_JAVA)?.toBooleanStrictOrNull()?.let { preferJava = it }
        p.getProperty(K_TOR)?.toBooleanStrictOrNull()?.let { torRouting = it }
        p.stringPropertyNames().filter { it.startsWith(K_LOG_INDEX_SPEED_PREFIX) }.forEach { k ->
            p.getProperty(k)?.toBooleanStrictOrNull()
                ?.let { logIndexMax[k.removePrefix(K_LOG_INDEX_SPEED_PREFIX)] = it }
        }
        p.stringPropertyNames().filter { it.startsWith(K_LOG_INDEX_WATCH_PREFIX) }.forEach { k ->
            // Round-trip through the parser so a hand-edited value degrades to the
            // entries that do parse rather than reaching the engine raw.
            p.getProperty(k)?.let {
                logIndexWatch[k.removePrefix(K_LOG_INDEX_WATCH_PREFIX)] =
                    LogIndexWatch.serialize(LogIndexWatch.parse(it))
            }
        }
        p.stringPropertyNames()
            .filter {
                it.startsWith(K_LOG_INDEX_PREFIX) &&
                    !it.startsWith(K_LOG_INDEX_SPEED_PREFIX) &&
                    !it.startsWith(K_LOG_INDEX_WATCH_PREFIX)
            }
            .forEach { k ->
            p.getProperty(k)?.toBooleanStrictOrNull()
                ?.let { logIndexOn[k.removePrefix(K_LOG_INDEX_PREFIX)] = it }
        }
        // MIGRATION: a user who had the retired built-in Kohaku preset toggle on
        // has the enabled flag persisted but NO watch entries — the preset lived
        // in code. Seed the watch list from the legacy preset so the next config
        // push does not silently drop their subscriptions (in-memory here; the
        // next mutate() persists it).
        logIndexOn.filterValues { it }.keys.forEach { net ->
            if (net !in logIndexWatch) {
                LogIndexWatch.legacyKohakuWatchJson(net)?.let { logIndexWatch[net] = it }
            }
        }
    }

    /**
     * Apply [change] under the state lock, snapshot the state, then write the snapshot
     * to disk OUTSIDE that lock — settings readers (UI thread included) never wait on
     * disk I/O. The write stays synchronous on the calling thread (it's a ~200-byte
     * file written only when the user flips a Settings control, and a synchronous
     * write keeps restart-persistence deterministically testable); [ioLock] serializes
     * concurrent writers and the sequence number drops a stale snapshot that lost the
     * race to a newer one.
     */
    private fun mutate(change: () -> Unit) {
        val f = file
        if (f == null) {
            synchronized(this) { change() }
            return
        }
        val p: java.util.Properties
        val seq: Long
        synchronized(this) {
            change()
            p = snapshot()
            seq = ++stateSeq
        }
        persist(f, p, seq)
    }

    /** Snapshot the state as Properties; must be called under the state lock. */
    private fun snapshot(): java.util.Properties {
        val p = java.util.Properties()
        p.setProperty(K_ENABLED, enabled.joinToString(","))
        ports.forEach { (net, port) -> p.setProperty("$K_RPC_PORT_PREFIX$net", port.toString()) }
        p.setProperty(K_SNAP, snap.toString())
        p.setProperty(K_SERVED_WINDOW, servedWindow.toString())
        p.setProperty(K_WS_BOUND, wsBound.toString())
        p.setProperty(K_DEEP, deep.toString())
        p.setProperty(K_STRICT, strict.toString())
        p.setProperty(K_NATIVE_BLS, nativeBls.toString())
        p.setProperty(K_PREFER_JAVA, preferJava.toString())
        p.setProperty(K_TOR, torRouting.toString())
        logIndexOn.forEach { (net, on) -> p.setProperty("$K_LOG_INDEX_PREFIX$net", on.toString()) }
        logIndexMax.forEach { (net, on) -> p.setProperty("$K_LOG_INDEX_SPEED_PREFIX$net", on.toString()) }
        logIndexWatch.forEach { (net, json) -> p.setProperty("$K_LOG_INDEX_WATCH_PREFIX$net", json) }
        return p
    }

    /** Best-effort rewrite. Writes temp + atomic move so a crash mid-write can't leave
     *  a truncated file; failures are logged (a silently unwritable settings file would
     *  look exactly like the bug this class fixes). */
    private fun persist(f: Path, p: java.util.Properties, seq: Long) {
        synchronized(ioLock) {
            if (seq <= writtenSeq) return // a newer snapshot already landed
            writtenSeq = seq
            runCatching {
                f.parent?.let(Files::createDirectories)
                val tmp = f.resolveSibling("${f.fileName}.tmp")
                Files.newOutputStream(tmp).use { p.store(it, "Myotis desktop settings") }
                try {
                    Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
                } catch (_: AtomicMoveNotSupportedException) {
                    Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING)
                }
            }.onFailure {
                log.warn("settings not persisted to {}: {}", f, it.toString())
            }
        }
    }

    private companion object {
        val log: org.slf4j.Logger = org.slf4j.LoggerFactory.getLogger(DesktopSettings::class.java)
        const val K_ENABLED = "networks.enabled"
        const val K_RPC_PORT_PREFIX = "rpcPort."
        const val K_SNAP = "snapTarget"
        const val K_SERVED_WINDOW = "servedBlockWindow"
        const val K_WS_BOUND = "wsBoundPeriods"
        const val K_DEEP = "deepPool"
        const val K_STRICT = "strictStateFreshness"
        const val K_NATIVE_BLS = "nativeBls"
        // Replaces the pre-auto-default "rustEngine" key; that key is simply ignored
        // now (its true meant "auto", which is the default — nothing to migrate).
        const val K_PREFER_JAVA = "engine.preferJava"
        const val K_TOR = "torRouting"
        const val K_LOG_INDEX_PREFIX = "logIndex."
        // Distinct prefixes nested under logIndex.* so the enable-loader's
        // startsWith filter must exclude them (see load()).
        const val K_LOG_INDEX_SPEED_PREFIX = "logIndex.maxSpeed."
        const val K_LOG_INDEX_WATCH_PREFIX = "logIndex.watch."
    }
}

/** Desktop is treated as always-online (no Android ConnectivityManager). */
object DesktopNetworkStatus : NetworkStatus {
    override fun online(): Flow<Boolean> = flowOf(true)
}
