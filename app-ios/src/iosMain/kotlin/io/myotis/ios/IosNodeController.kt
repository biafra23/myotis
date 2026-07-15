package io.myotis.ios

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
import platform.Foundation.NSFileManager
import platform.Foundation.NSLock
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
    }

    /** Blocking stop; caller holds [bootMutex] and runs on IO. */
    private fun drop(net: String) {
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
            address = o.string("address") ?: address,
            exists = o.boolean("exists"),
            nonce = o.long("nonce", -1L),
            balanceWei = o.string("balanceWei"),
            storageRootHex = o.string("storageRootHex"),
            codeHashHex = o.string("codeHashHex"),
            blockNumber = o.long("blockNumber", 0L),
            peerStateRootHex = o.string("peerStateRootHex"),
            peerProofValid = o.boolean("peerProofValid"),
            beaconChainVerified = o.boolean("beaconChainVerified"),
            blsVerified = o.boolean("blsVerified"),
            matchedBeaconSlot = o.long("matchedBeaconSlot", -1L),
            verifyMethod = o.string("verifyMethod"),
            failReason = o.string("failReason"),
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
        val blockNumber = o.long("blockNumber", -1L)
        val verified = o.boolean("verified")
        return when (o.string("status")) {
            // status ok MUST carry the address — a missing addressHex is shape
            // drift, and mapping it to (address null, error null) would render
            // as the authoritative "no record" answer. Fail closed instead,
            // like RustEnsApi's Parsed.requireString does over JNI.
            "ok" -> o.string("addressHex")
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
        // Live counts from the cache FILES (mtime-memoized, shared parser in
        // :ui) — the cross-engine truth the engine writes under dataDir.
        val suffix = if (network == "mainnet") "" else "-$network"
        val clCache = CacheFileStats.cl("$dataDir/cl-peers$suffix.cache")
        val elCache = CacheFileStats.el("$dataDir/peers$suffix.cache")
        val running = o.boolean("running")
        val paused = o.boolean("paused")
        val beaconState = o.string("beaconState") ?: "STARTING"
        val snapPeers = o.int("snapPeers")
        val currentPeriod = o.long("currentPeriod", 0L)
        // Older-native fallback: a missing targetPeriod parses as 0 — keep the
        // target >= current invariant.
        val targetPeriod = maxOf(o.long("targetPeriod", 0L), currentPeriod)
        val optimisticBlock = o.long("optimisticBlockNumber", 0L)
        val finalizedBlock = o.long("finalizedBlockNumber", 0L)

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

        return NodeSnapshot(
            running = running,
            lifecycle = if (running) "RUNNING" else if (paused) "PAUSED" else "STOPPED",
            network = network,
            engine = "rust",
            beaconState = beaconState,
            connectedPeers = o.int("peerCount"),        // CL libp2p peers
            readyPeers = snapPeers,                      // EL pool holds only snap-ready
            snapPeers = snapPeers,
            snapServingPeers = snapPeers,                // approximation, as over JNI
            clConnectedPeers = o.int("peerCount"),
            clServedPeersLastMin = o.int("servedPeersLastMinute"),
            clCachedPeers = clCache.total,
            clCachedProven = clCache.proven,
            clCachedNolc = clCache.nolc,
            elCachedPeers = elCache.total,
            elCachedSnapOk = elCache.snapOk,
            elCachedSnapBad = elCache.snapBad,
            discoveredPeers = o.int("discoveredPeers"),
            backedOffPeers = o.int("backedOffPeers"),
            blacklistedPeers = o.int("blacklistedPeers"),
            discv5Peers = o.int("discv5TableSize"),
            executionBlockNumber = finalizedBlock,       // == finalized payload's block
            finalizedSlot = o.long("finalizedSlot", 0L),
            syncStartPeriod = o.long("syncStartPeriod", -1L),
            syncCurrentPeriod = currentPeriod,
            syncTargetPeriod = targetPeriod,
            verifiedHeadAgeMs = verifiedHeadAgeMs,
            uptimeSeconds = locked { startMarks[network] }
                ?.elapsedNow()?.inWholeSeconds ?: 0L,
            peerHeaderRequests = o.long("peerHeaderRequests", 0L),
            peerHeaderRequestsServed = o.long("peerHeaderRequestsServed", 0L),
            peerBodyRequests = o.long("peerBodyRequests", 0L),
            peerBodyRequestsServed = o.long("peerBodyRequestsServed", 0L),
            readyPeerList = emptyList(),                 // not exposed over the FFI yet
            pauseCount = 0, totalPausedMs = 0L,          // idle-sleep isn't wired on iOS yet
            lastPauseEpochMs = 0L, lastResumeEpochMs = 0L, lastWakeReason = null,
            lcHunting = o.boolean("lcHunting"),
            elHunting = o.boolean("elHunting"),
        )
    }
}

// Small null-safe JSON accessors over kotlinx JsonObject (minimal-json getString/
// getLong/getBoolean twins: absent or JSON-null reads as the default).
private fun JsonObject.string(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content

private fun JsonObject.boolean(key: String): Boolean =
    (this[key] as? JsonPrimitive)?.booleanOrNull ?: false

private fun JsonObject.long(key: String, default: Long): Long =
    (this[key] as? JsonPrimitive)?.longOrNull ?: default

private fun JsonObject.int(key: String): Int =
    (this[key] as? JsonPrimitive)?.intOrNull ?: 0
