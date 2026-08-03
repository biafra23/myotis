package io.myotis.ios

import io.myotis.jsonrpc.MyotisRpcServer
import io.myotis.ui.AccountResult
import io.myotis.ui.CacheFileStats
import io.myotis.ui.EnsResult
import io.myotis.ui.NodeController
import io.myotis.ui.NodeSnapshot
import io.myotis.ui.Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
// On Kotlin/Native, Dispatchers.IO is an extension property — this import is load-bearing.
import kotlinx.coroutines.IO
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import platform.Foundation.NSFileManager
import platform.Foundation.NSLock
import platform.posix.AF_INET
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_REUSEADDR
import platform.posix.bind
import platform.posix.close
import platform.posix.setsockopt
import platform.posix.sockaddr
import platform.posix.sockaddr_in
import platform.posix.socket
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * The iOS actual of [NodeController]: drives the Rust engine in-process over
 * [RustEngine] (the C-ABI seam) — the same lifecycle + JSON contracts
 * `RustMyotisEngine`/`RustChainHandle` speak over JNI, re-mapped here straight
 * into the UI models. There is no JVM engine on this host.
 *
 * Threading: every engine call is blocking (verified reads up to ~90 s), so all
 * of them run on [Dispatchers.IO]; the handle map is guarded by [stateLock]
 * (reads from the UI thread) with a [bootMutex] serializing lifecycle
 * transitions per invocation, mirroring the desktop host's boot locks.
 */
class IosNodeController(
    private val dataDir: String,
    private val settings: Settings,
    private val logs: IosLogSource,
) : NodeController {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    // Lifecycle ops are fire-and-forget from the UI; a single-lane dispatcher
    // executes them in SUBMISSION order, so a quick disable→enable (or the
    // reverse) can never invert into enable-then-disable the way independent
    // Dispatchers.IO launches could. bootMutex still guards the check-then-act
    // inside each op against any future caller outside the lane.
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private val lifecycleLane = Dispatchers.IO.limitedParallelism(1)
    private val bootMutex = Mutex()

    private val stateLock = NSLock()
    private val handles = mutableMapOf<String, Long>()
    private val startMarks = mutableMapOf<String, TimeMark>()
    // Per-network JSON-RPC listeners (loopback, strict). Foreground-only by iOS
    // app-lifecycle nature; IosBackgroundKeepalive stretches that by the ~30 s
    // background-task grace so an in-flight wallet call can finish.
    private val rpcServers = mutableMapOf<String, MyotisRpcServer>()
    // Listener outcome per network for the Status "RPC" row: port to serving.
    private val rpcStates = mutableMapOf<String, Pair<Int, Boolean>>()
    // Per-network head-advance tracking behind verifiedHeadAgeMs — the same
    // "age since the optimistic head last advanced" scheme RustChainHandle uses.
    private val headAges = mutableMapOf<String, HeadAge>()

    private class HeadAge(var lastBlock: Long, var lastAdvance: TimeMark)

    private inline fun <T> locked(block: () -> T): T {
        stateLock.lock()
        try {
            return block()
        } finally {
            stateLock.unlock()
        }
    }

    init {
        RustEngine.requireAbi()
        val created = NSFileManager.defaultManager.createDirectoryAtPath(
            dataDir, withIntermediateDirectories = true, attributes = null, error = null,
        )
        if (!created) {
            // The engine still runs (it treats dataDir as best-effort), but sync
            // snapshots and peer caches won't persist — say so instead of letting
            // every restart look like a mysterious cold boot.
            logs.append("ERROR failed to create data directory at $dataDir — sync state will not persist")
        }
        // Rust log pump — the only log producer on this host, so it feeds the
        // Logs tab directly. Process-lifetime, decoupled from UI collection
        // (parity with the desktop `myotis-rust-logs` thread).
        scope.launch(Dispatchers.IO) {
            while (true) {
                runCatching {
                    val batch = RustEngine.drainLogs(500)
                    if (batch.isNotEmpty()) batch.split('\n').forEach(logs::append)
                }
                delay(2000)
            }
        }
    }

    override val running: Boolean
        get() = locked { handles.isNotEmpty() }

    override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flow {
        while (true) {
            val live = locked { handles.toMap() }
            emit(live.mapValues { (name, handle) -> snapshotOf(name, handle) })
            delay(2000)
        }
    }.flowOn(Dispatchers.IO)

    override fun enableNetwork(name: String) {
        settings.setNetworkEnabled(canonical(name), true)
        startNetwork(name)
    }

    override fun disableNetwork(name: String) {
        settings.setNetworkEnabled(canonical(name), false)
        stopNetwork(name)
    }

    override fun startNetwork(name: String) {
        val net = canonical(name)
        scope.launch(lifecycleLane) { bootMutex.withLock { boot(net) } }
    }

    override fun stopNetwork(name: String) {
        val net = canonical(name)
        scope.launch(lifecycleLane) { bootMutex.withLock { drop(net) } }
    }

    override fun rebootNetwork(name: String) {
        val net = canonical(name)
        scope.launch(lifecycleLane) {
            bootMutex.withLock {
                drop(net)
                boot(net)
            }
        }
    }

    override fun shutdown() {
        scope.launch(lifecycleLane) {
            bootMutex.withLock {
                locked { handles.keys.toList() }.forEach(::drop)
            }
        }
    }

    override fun applyLogIndex(network: String) {
        val net = canonical(network)
        // On the lifecycle lane like every other mutating op: the engine-side
        // install may reload a persisted index from disk.
        scope.launch(lifecycleLane) {
            locked { handles[net] }?.let { pushLogIndexConfig(net, it) }
        }
    }

    private fun pushLogIndexConfig(net: String, handle: Long) {
        val json = io.myotis.ui.KohakuPreset.configJson(net, settings.logIndexEnabled(net)) ?: return
        if (!RustEngine.setLogIndexConfig(handle, json) && settings.logIndexEnabled(net)) {
            logs.append("WARN log index config rejected for $net")
        }
    }


    /** Blocking create+start; caller holds [bootMutex] and runs on IO. */
    private fun boot(net: String) {
        if (locked { net in handles }) return
        val handle = RustEngine.create(net, dataDir)
        if (handle < 1) {
            logs.append("ERROR failed to create the $net stack (sentinel $handle)")
            return
        }
        if (!RustEngine.start(handle)) {
            RustEngine.stop(handle)
            logs.append("ERROR failed to start the $net stack")
            return
        }
        locked {
            handles[net] = handle
            startMarks[net] = TimeSource.Monotonic.markNow()
        }
        // Boot-time apply of the log-index preset — AFTER start (the engine
        // only accepts config on a running handle). Cures restart dormancy;
        // boot() already runs on the lifecycle lane under bootMutex.
        pushLogIndexConfig(net, handle)
        startRpc(net)
    }

    /** Start the network's loopback JSON-RPC listener (JNI hosts' startRpc twin).
     *  Best-effort: a bind failure logs and the node keeps running without RPC —
     *  Ktor CIO surfaces bind errors asynchronously, so failures land in the log
     *  pump rather than here. Caller holds [bootMutex]. */
    private fun startRpc(net: String) {
        // Everything guarded: an uncaught throw here would escape into the
        // lifecycleLane coroutine and terminate the Kotlin/Native process —
        // the listener is best-effort, the node must keep running without it.
        // The port is resolved BEFORE the guard so onFailure can't throw again.
        val port = runCatching { settings.rpcPortFor(net) }.getOrDefault(0)
        if (port <= 0) return
        runCatching {
            val chainId = engineJson.decodeFromString<List<IosNetworkInfo>>(RustEngine.availableNetworksJson())
                .firstOrNull { it.name == net }?.chainId ?: return
            val server = MyotisRpcServer(
                port = port,
                upstreamUrl = null,          // strict: never serve unverified data
                host = "127.0.0.1",          // loopback only — unauthenticated endpoint
                backend = IosRpcBackend(chainId) { locked { handles[net] } },
                statusReads = IosRpcStatusSource(
                    handleProvider = { locked { handles[net] } },
                    startMarkProvider = { locked { startMarks[net] } },
                ),
            )
            // Deterministic up-front bind probe (JVM hosts' ServerSocket probe
            // twin): Ktor CIO surfaces bind failures ASYNCHRONOUSLY inside its
            // own coroutine scope, where they're uncaught — on Kotlin/Native
            // that terminates the whole process. Seen live: two simulators
            // share the Mac's loopback, the second app's listener killed it.
            if (!loopbackPortFree(port)) {
                logs.append("WARN [$net] JSON-RPC port $port unavailable; continuing without RPC")
                locked { rpcStates[net] = port to false }
                return
            }
            server.start()
            locked {
                rpcServers[net] = server
                rpcStates[net] = port to true
            }
        }.onFailure {
            logs.append("ERROR failed to start the $net JSON-RPC listener: ${it.message}")
            locked { rpcStates[net] = port to false }
        }
    }

    /** Probe-bind 127.0.0.1:[port] and release it (SO_REUSEADDR, JVM-probe parity). */
    private fun loopbackPortFree(port: Int): Boolean = memScoped {
        val fd = socket(AF_INET, SOCK_STREAM, 0)
        // Fail CLOSED when the probe can't even get a socket (fd exhaustion —
        // Ktor's own bind would fail the same way, asynchronously and fatally).
        // Skipping the listener is the safe degradation; RPC is best-effort.
        if (fd < 0) return false
        try {
            val one = alloc<IntVar>()
            one.value = 1
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, one.ptr, sizeOf<IntVar>().convert())
            val addr = alloc<sockaddr_in>().apply {
                sin_family = AF_INET.convert()
                sin_port = ((port and 0xff) shl 8 or (port ushr 8 and 0xff)).convert() // htons
                sin_addr.s_addr = 0x0100007fu // 127.0.0.1, little-endian byte order
                sin_len = sizeOf<sockaddr_in>().convert()
            }
            bind(fd, addr.ptr.reinterpret<sockaddr>(), sizeOf<sockaddr_in>().convert()) == 0
        } finally {
            close(fd)
        }
    }

    /** Blocking stop; caller holds [bootMutex] and runs on IO. */
    private fun drop(net: String) {
        locked { rpcStates.remove(net); rpcServers.remove(net) }?.let { runCatching { it.stop() } }
        val handle = locked { handles.remove(net).also { startMarks.remove(net); headAges.remove(net) } }
        if (handle != null) RustEngine.stop(handle)
    }

    // Live tuning knobs the Rust engine doesn't expose over its FFI yet — the
    // JNI RustChainHandle no-ops these too, so the iOS host matches it.
    override fun setTargetSnapPeers(target: Int) {}
    override fun setServedBlockWindow(blocks: Int) {}

    // blst is compiled into the engine and the Rust engine is the only engine
    // on iOS — both toggles are inert (see IosSettings).
    override fun applyBlsBackend() {}
    override fun applyEngineChoice() {}

    override fun clearCaches(network: String) {
        val net = canonical(network)
        // The Rust engine owns its peer-cache files under dataDir (same names as
        // the JVM hosts). On the lifecycle lane + bootMutex, like desktop's
        // per-network boot lock, so the delete can't interleave with a
        // teardown/boot that would rewrite the files mid-purge.
        scope.launch(lifecycleLane) {
            bootMutex.withLock {
                val suffix = if (net == "mainnet") "" else "-$net"
                listOf("peers$suffix.cache", "cl-peers$suffix.cache").forEach {
                    NSFileManager.defaultManager.removeItemAtPath("$dataDir/$it", error = null)
                }
            }
        }
    }

    override fun resetSyncState(network: String) {
        val net = canonical(network)
        // Same lane + lock as clearCaches: the snapshot files are written on
        // stop/pause, so the delete must not race a concurrent teardown.
        scope.launch(lifecycleLane) {
            bootMutex.withLock {
                val suffix = if (net == "mainnet") "" else "-$net"
                // The snapshot and any sibling parts (e.g. the ".roots" accumulator).
                val fm = NSFileManager.defaultManager
                val names = fm.contentsOfDirectoryAtPath(dataDir, error = null)
                    ?.filterIsInstance<String>().orEmpty()
                names.filter { it.startsWith("sync-state$suffix.snapshot") }
                    .forEach { fm.removeItemAtPath("$dataDir/$it", error = null) }
            }
        }
    }

    override suspend fun requestAccount(network: String, address: String): AccountResult {
        val handle = handleOrThrow(network)
        val json = withContext(Dispatchers.IO) { RustEngine.requestAccountJson(handle, address) }
        val o = parseOrThrow(json, "account query")
        return AccountResult(
            address = o.engineString("address") ?: address,
            exists = o.engineBoolean("exists"),
            nonce = o.engineLong("nonce", -1L),
            balanceWei = o.engineString("balanceWei"),
            storageRootHex = o.engineString("storageRootHex"),
            codeHashHex = o.engineString("codeHashHex"),
            blockNumber = o.engineLong("blockNumber", 0L),
            peerStateRootHex = o.engineString("peerStateRootHex"),
            peerProofValid = o.engineBoolean("peerProofValid"),
            beaconChainVerified = o.engineBoolean("beaconChainVerified"),
            blsVerified = o.engineBoolean("blsVerified"),
            matchedBeaconSlot = o.engineLong("matchedBeaconSlot", -1L),
            verifyMethod = o.engineString("verifyMethod"),
            failReason = o.engineString("failReason"),
        )
    }

    override suspend fun resolveEns(network: String, name: String): EnsResult {
        val handle = handleOrThrow(network)
        if (!settings.hasEns(canonical(network))) {
            throw IllegalStateException("ENS is not available on $network")
        }
        // The generic record dispatch (method=addr, root=auto) — the same envelope
        // RustEnsApi drives, which carries the `verified` flag the UI shows.
        val params = JsonObject(
            mapOf(
                "method" to JsonPrimitive("addr"),
                "name" to JsonPrimitive(name.trim()),
                "root" to JsonPrimitive("auto"),
            )
        ).toString()
        val json = withContext(Dispatchers.IO) { RustEngine.ensRecordJson(handle, params) }
        val o = parseOrThrow(json, "ENS resolution")
        val blockNumber = o.engineLong("blockNumber", -1L)
        val verified = o.engineBoolean("verified")
        return when (o.engineString("status")) {
            // status ok MUST carry the address — a missing addressHex is shape
            // drift, and mapping it to (address null, error null) would render
            // as the authoritative "no record" answer. Fail closed instead,
            // like RustEnsApi's Parsed.requireString does over JNI.
            "ok" -> o.engineString("addressHex")
                ?.let { EnsResult(name, it, blockNumber, verified, null) }
                ?: EnsResult(name, null, blockNumber, verified, "malformed resolver reply (ok without addressHex)")
            // Successfully determined absent — the API's "no record" convention.
            "noRecord" -> EnsResult(name, null, blockNumber, verified, null)
            "offchain" -> EnsResult(
                name, null, blockNumber, verified,
                "$name resolves off-chain (CCIP-Read), which this app doesn't support yet",
            )
            else -> EnsResult(name, null, blockNumber, verified, "unexpected resolver reply")
        }
    }

    private fun canonical(name: String): String = RustEngine.canonicalNetworkName(name) ?: name

    private fun handleOrThrow(network: String): Long {
        // Canonicalize BEFORE taking stateLock: canonical() crosses the FFI, and
        // the lock is read on the UI thread (running, snapshots) — keep its
        // critical section down to the map lookup.
        val net = canonical(network)
        return locked { handles[net] }
            ?: throw IllegalStateException("Node is not running on $network")
    }

    /** Malformed JSON or an `{"error": ...}` envelope → throw (the Query tab renders it). */
    private fun parseOrThrow(json: String, what: String): JsonObject {
        val o = runCatching { engineJson.parseToJsonElement(json).jsonObject }
            .getOrElse { throw IllegalStateException("malformed $what reply from the engine") }
        // ANY non-null error value is an error — not just a string one. The JNI
        // twin (RustChainHandle.parseResultOrThrow) tolerates a structured value
        // rather than misreading the envelope as a default-valued result.
        o["error"]?.takeIf { it !is JsonNull }?.let {
            throw IllegalStateException((it as? JsonPrimitive)?.content ?: it.toString())
        }
        return o
    }

    /** Map one handle's status JSON into the UI snapshot (RustChainHandle.status() twin). */
    private fun snapshotOf(network: String, handle: Long): NodeSnapshot {
        val o = runCatching { engineJson.parseToJsonElement(RustEngine.statusJson(handle)).jsonObject }
            .getOrElse { JsonObject(emptyMap()) }
        // ONE locked read for both maps — a drop() interleaving between two
        // separate reads could pair a stale state with a missing server and
        // render a clean stop as a red "port unavailable" for one poll.
        val (rpcState, rpcServer) = locked { rpcStates[network] to rpcServers[network] }
        // Live counts from the cache FILES (mtime-memoized, shared parser in
        // :ui) — the cross-engine truth the engine writes under dataDir.
        val suffix = if (network == "mainnet") "" else "-$network"
        val clCache = CacheFileStats.cl("$dataDir/cl-peers$suffix.cache")
        val elCache = CacheFileStats.el("$dataDir/peers$suffix.cache")
        val running = o.engineBoolean("running")
        val paused = o.engineBoolean("paused")
        val beaconState = o.engineString("beaconState") ?: "STARTING"
        val snapPeers = o.engineInt("snapPeers")
        val currentPeriod = o.engineLong("currentPeriod", 0L)
        // Older-native fallback: a missing targetPeriod parses as 0 — keep the
        // target >= current invariant.
        val targetPeriod = maxOf(o.engineLong("targetPeriod", 0L), currentPeriod)
        val optimisticBlock = o.engineLong("optimisticBlockNumber", 0L)
        val finalizedBlock = o.engineLong("finalizedBlockNumber", 0L)

        // verifiedHeadAgeMs: age since the optimistic head last ADVANCED, reported
        // only while a verified read can actually be served; otherwise the
        // Long.MAX_VALUE "no verified head yet" sentinel, with the advance clock
        // pinned to now so the age starts fresh once serveable.
        val serveable = beaconState == "SYNCED" && optimisticBlock > 0 && snapPeers > 0
        val verifiedHeadAgeMs = locked {
            val age = headAges.getOrPut(network) {
                HeadAge(optimisticBlock, TimeSource.Monotonic.markNow())
            }
            if (!serveable) {
                age.lastBlock = optimisticBlock
                age.lastAdvance = TimeSource.Monotonic.markNow()
                Long.MAX_VALUE
            } else {
                if (optimisticBlock != age.lastBlock) {
                    age.lastBlock = optimisticBlock
                    age.lastAdvance = TimeSource.Monotonic.markNow()
                }
                age.lastAdvance.elapsedNow().inWholeMilliseconds.coerceAtLeast(0L)
            }
        }

        val logIndexRaw = if (settings.logIndexEnabled(network)) RustEngine.logIndexStatusJson(handle) else null
        return NodeSnapshot(
            running = running,
            lifecycle = if (running) "RUNNING" else if (paused) "PAUSED" else "STOPPED",
            network = network,
            engine = "rust",
            beaconState = beaconState,
            connectedPeers = o.engineInt("peerCount"),        // CL libp2p peers
            readyPeers = snapPeers,                      // EL pool holds only snap-ready
            snapPeers = snapPeers,
            snapServingPeers = snapPeers,                // approximation, as over JNI
            clConnectedPeers = o.engineInt("peerCount"),
            clServedPeersLastMin = o.engineInt("servedPeersLastMinute"),
            clCachedPeers = clCache.total,
            clCachedProven = clCache.proven,
            clCachedNolc = clCache.nolc,
            elCachedPeers = elCache.total,
            elCachedSnapOk = elCache.snapOk,
            elCachedSnapBad = elCache.snapBad,
            discoveredPeers = o.engineInt("discoveredPeers"),
            backedOffPeers = o.engineInt("backedOffPeers"),
            blacklistedPeers = o.engineInt("blacklistedPeers"),
            discv5Peers = o.engineInt("discv5TableSize"),
            executionBlockNumber = finalizedBlock,       // == finalized payload's block
            finalizedSlot = o.engineLong("finalizedSlot", 0L),
            syncStartPeriod = o.engineLong("syncStartPeriod", -1L),
            syncCurrentPeriod = currentPeriod,
            syncTargetPeriod = targetPeriod,
            verifiedHeadAgeMs = verifiedHeadAgeMs,
            uptimeSeconds = locked { startMarks[network] }
                ?.elapsedNow()?.inWholeSeconds ?: 0L,
            peerHeaderRequests = o.engineLong("peerHeaderRequests", 0L),
            peerHeaderRequestsServed = o.engineLong("peerHeaderRequestsServed", 0L),
            peerBodyRequests = o.engineLong("peerBodyRequests", 0L),
            peerBodyRequestsServed = o.engineLong("peerBodyRequestsServed", 0L),
            readyPeerList = emptyList(),                 // not exposed over the FFI yet
            pauseCount = 0, totalPausedMs = 0L,          // idle-sleep isn't wired on iOS yet
            lastPauseEpochMs = 0L, lastResumeEpochMs = 0L, lastWakeReason = null,
            rpcPort = rpcState?.first ?: 0,
            // A started listener can still die asynchronously (contained by the
            // server's supervisor) — consult the live server, not just the
            // recorded start outcome.
            rpcServing = (rpcState?.second ?: false) && (rpcServer?.isServing() ?: false),
            lcHunting = o.engineBoolean("lcHunting"),
            logIndex = logIndexRaw?.let(io.myotis.ui.LogIndexStatus::format),
            logIndexJson = logIndexRaw,
            elHunting = o.engineBoolean("elHunting"),
        )
    }
}

