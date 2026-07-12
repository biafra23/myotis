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

    /**
     * Settings semantics: persist the network's enabled flag AND bring its stack up.
     * The enabled flag is what boots on the next app/service start.
     */
    fun enableNetwork(name: String)

    /** Settings semantics: persist the enabled flag off AND tear the stack down. */
    fun disableNetwork(name: String)

    /**
     * Runtime-only start: bring the stack up WITHOUT touching the persisted enabled
     * flag. The Status page's Start button — starting a stopped chain there must not
     * flip its Settings switch. Callers ensure the network is ENABLED (a disabled
     * chain routes through [enableNetwork] instead): hosts may boot only the enabled
     * set (Android's cold service does) or refuse disabled chains outright.
     */
    fun startNetwork(name: String)

    /**
     * Runtime-only stop: tear the stack down WITHOUT touching the persisted enabled
     * flag. The Status page's Stop button — the chain stays enabled and comes back
     * on the next app/service start.
     */
    fun stopNetwork(name: String)

    fun rebootNetwork(name: String)
    fun shutdown()

    /** Live-update the snap-peer target on all running stacks. */
    fun setTargetSnapPeers(target: Int)

    /** Live-update the eth/69 served-block window on all running stacks. */
    fun setServedBlockWindow(blocks: Int)

    /**
     * Re-apply the BLS backend to the process-global selector after [Settings.setNativeBlsEnabled]
     * flips the preference (Android: native blst ⇄ pure-Java Milagro). Takes effect immediately —
     * the decompressed-pubkey cache is process-global so the swap is cheap. Desktop currently has
     * no bundled native library, so its actual is a no-op until the macOS blst dylib ships.
     */
    fun applyBlsBackend()

    /**
     * Re-apply the engine choice (Java ⇄ Rust) to the process-global selector after
     * [Settings.setRustEngineEnabled] flips the preference. Unlike the BLS toggle this is
     * NOT live: networks keep the engine that created them — the new choice applies when a
     * network is (re)started. The Rust engine is experimental (catalog-only today), so the
     * enabled state maps to the selector's `auto` mode, which falls back to Java per
     * network until the Rust engine can host it.
     */
    fun applyEngineChoice()

    /**
     * Wipe a network's peer caches — clear the live stack's backoff/blacklist and delete the
     * on-disk EL/CL peer cache files — so discovery starts from a fresh slate. Safe whether or
     * not the network is currently running.
     */
    fun clearCaches(network: String)

    /**
     * Delete a network's persisted sync-committee snapshot so the NEXT start re-bootstraps from
     * the embedded checkpoint and re-runs catch-up (a debugging aid). A running stack keeps its
     * in-memory state; this only affects the next start.
     */
    fun resetSyncState(network: String)

    /**
     * Query an account on [network] and verify the returned proof against the beacon-attested
     * state root (the shared `VerifiedAccountQuery` ladder). Suspends until verification
     * completes. Throws on a bad address or a network that isn't running; verification
     * *failures* surface as [AccountResult.failReason], not exceptions.
     */
    suspend fun requestAccount(network: String, address: String): AccountResult

    /**
     * Resolve an ENS name to an address on [network]. Beacon-verified when resolved against
     * finalized state ([EnsResult.verified]). Throws if the network isn't running / has no ENS;
     * resolution failures surface as [EnsResult.error].
     */
    suspend fun resolveEns(network: String, name: String): EnsResult

    // Logs / Settings ops are added with their screens.
}

/** Verified account-query result. Mirrors `io.myotis.node.VerifiedAccountQuery.Result`. */
data class AccountResult(
    val address: String,
    val exists: Boolean,
    val nonce: Long,                 // -1 when !exists
    val balanceWei: String?,         // decimal string or null
    val storageRootHex: String?,
    val codeHashHex: String?,
    val blockNumber: Long,           // peer-reported block the proof anchors to
    val peerStateRootHex: String?,
    val peerProofValid: Boolean,     // proof verifies against peerStateRoot
    val beaconChainVerified: Boolean,// peerStateRoot ties to a beacon-attested root
    val blsVerified: Boolean,        // the beacon match was BLS-signed
    val matchedBeaconSlot: Long,     // -1 when not matched
    val verifyMethod: String?,       // "stateRootMatch" / "headerChain" / null
    val failReason: String?,         // null when verified
)

/** ENS resolution result. Mirrors `io.myotis.rpc.EnsResolution`. */
data class EnsResult(
    val name: String,
    val addressHex: String?,         // null when unresolved/errored
    val blockNumber: Long,           // -1 when none
    val verified: Boolean,           // true iff beacon-verified finalized state
    val error: String?,              // null on success
)

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
    /** eth/69 served-block window: how many recent headers the node retains and
     *  advertises as servable to peers (EIP-7642 Status range). */
    fun servedBlockWindow(): Int
    fun setServedBlockWindow(v: Int)

    // --- network metadata (so commonMain need not reference the Java NetworkConfig) ---
    /** Human-facing name for the Settings row, e.g. "Gnosis Chain". */
    fun displayName(network: String): String
    /** The network's built-in default JSON-RPC port, shown as the field hint. */
    fun defaultRpcPort(network: String): Int
    /** Whether this network supports ENS resolution (mainnet/Sepolia); Query gates ENS input on it. */
    fun hasEns(network: String): Boolean

    // --- shared node-tuning knobs ---
    fun deepPoolThreshold(): Int
    fun setDeepPool(v: Int)
    /** true = strict 2-minute state freshness (default); false = relaxed/experimental. */
    fun strictStateFreshness(): Boolean
    fun setStrictStateFreshness(v: Boolean)
    /** true = use bundled native blst (default on Android); false = pure-Java Milagro. */
    fun nativeBlsEnabled(): Boolean
    fun setNativeBlsEnabled(v: Boolean)
    /** true = prefer the (experimental) Rust engine for newly started networks; default false. */
    fun rustEngineEnabled(): Boolean
    fun setRustEngineEnabled(v: Boolean)

    /**
     * Minutes of no RPC/UI activity before a running stack is paused into idle sleep
     * (networking off, RPC listening, first request wakes it). 0 disables auto-pause.
     * Defaults keep hosts without an idle controller (desktop) compiling: auto-pause off.
     */
    fun idlePauseMinutes(): Int = 0
    fun setIdlePauseMinutes(v: Int) {}

    /**
     * When true (default), the idle controller does NOT auto-pause while the device is
     * charging — plugged in, battery isn't a concern, so the node stays awake and synced.
     * Emergency memory-pressure pauses ignore this. Default true keeps desktop compiling.
     */
    fun stayAwakeWhileCharging(): Boolean = true
    fun setStayAwakeWhileCharging(v: Boolean) {}

    /**
     * Whether this host actually has an idle-sleep controller (Android). The idle-sleep
     * Settings row is shown only when true — desktop has no controller, so surfacing a
     * battery-saving toggle there would imply a feature that can't take effect. Default false.
     */
    fun supportsIdleSleep(): Boolean = false
}

/** Device network connectivity, as an observable stream so the UI can react to changes. */
interface NetworkStatus {
    /** Emits the current connectivity and re-emits on change. Android: ConnectivityManager;
     *  Desktop: a constant `true`. */
    fun online(): Flow<Boolean>
}

/**
 * One network's status, mirroring `NodeService.Snapshot` (the actual maps the Java record
 * into this Kotlin model). Trimmed to what the shared screens render today; extend as more
 * screens are ported.
 */
data class NodeSnapshot(
    val running: Boolean,
    val lifecycle: String,          // RUNNING / PAUSED / STOPPED — PAUSED = idle sleep
                                    // (networking off, RPC listening, wakes on request)
    val network: String,
    val engine: String? = null,     // "java" | "rust" — which engine hosts this network
                                    // (null = host didn't say); Status shows it as a
                                    // one-letter suffix on the network chip
    val beaconState: String,        // STOPPED / SYNCING / CATCHING_UP / SYNCED
    val connectedPeers: Int,
    val readyPeers: Int,
    val snapPeers: Int,             // peers that negotiated snap/1 (capability)
    val snapServingPeers: Int,      // peers actually in the serving pool now (drives readiness)
    val clConnectedPeers: Int,      // connected CL libp2p peers (usually 0 — connections are short-lived)
    val clServedPeersLastMin: Int,  // distinct peers that served a light-client response in the last 60s
    val clCachedPeers: Int,         // CL peers in cl-peers[-net].cache (live file count)
    val clCachedProven: Int,        // …of which proven LC servers (served range/bootstrap or lc token)
    val clCachedNolc: Int,          // …of which known non-LC (skipped when dialing for updates)
    val elCachedPeers: Int,         // EL peers in peers[-net].cache (live file count)
    val elCachedSnapOk: Int,        // …of which snap-serving confirmed
    val elCachedSnapBad: Int,       // …of which snap-serving denied
    val discoveredPeers: Int,
    val backedOffPeers: Int,        // peers in dial backoff right now
    val blacklistedPeers: Int,      // peers permanently blacklisted this session
    val discv5Peers: Int,           // live nodes in the discv5 (CL) routing table
    val executionBlockNumber: Long,
    val finalizedSlot: Long,
    val syncStartPeriod: Long,      // sync-committee catch-up start period (-1 if unknown)
    val syncCurrentPeriod: Long,
    val syncTargetPeriod: Long,
    val verifiedHeadAgeMs: Long,
    val uptimeSeconds: Long,
    // Inbound-serve counters: peers asking US for data (eth GetBlockHeaders /
    // GetBlockBodies), and how often we answered non-empty. Bodies-served is 0
    // today (a light client holds none; they get a prompt empty reply).
    val peerHeaderRequests: Long,
    val peerHeaderRequestsServed: Long,
    val peerBodyRequests: Long,
    val peerBodyRequestsServed: Long,
    val readyPeerList: List<PeerRow>,  // per-peer detail for the READY peers
    // Idle-sleep metrics (pseudo-sleep observability). See WakeReason.
    val pauseCount: Int,               // times the stack idle-slept since start
    val totalPausedMs: Long,           // cumulative time paused
    val lastPauseEpochMs: Long,        // wall-clock ms of the last pause; 0 if never
    val lastResumeEpochMs: Long,       // wall-clock ms of the last DEMAND wake; 0 if none
    val lastWakeReason: String?,       // reason of the last demand wake; null if none
)

/** One connected READY peer, for the Status peer list. */
data class PeerRow(
    val remoteAddress: String,
    val snapSupported: Boolean,
    val clientId: String?,          // null until the peer sends Hello
)
