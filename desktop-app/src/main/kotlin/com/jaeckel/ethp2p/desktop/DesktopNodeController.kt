package com.jaeckel.ethp2p.desktop

import com.jaeckel.ethp2p.app.AppPaths
import com.jaeckel.ethp2p.app.DaemonRuntime
import com.jaeckel.ethp2p.networking.NetworkConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory

/** Coarse lifecycle of the embedded daemon, surfaced to the UI. */
enum class NodeStatus { STOPPED, STARTING, RUNNING, STOPPING, ERROR }

/** Immutable snapshot the Compose UI renders. Polled from the live node every few seconds. */
data class NodeUiState(
    val status: NodeStatus = NodeStatus.STOPPED,
    val network: String = "mainnet",
    val beaconState: String = "—",
    val peerCount: Int = 0,
    val snapPeerCount: Int = 0,
    val finalizedSlot: Long = 0,
    val executionBlock: Long = 0,
    val error: String? = null,
)

/**
 * Drives the in-process {@link DaemonRuntime} on behalf of the desktop UI: start/stop on
 * background threads, a 2s poll loop that snapshots live node state into an observable
 * {@link StateFlow}, and a helper to run IPC commands (account/storage/ENS) off the UI thread.
 *
 * <p>This is the desktop analogue of Android's {@code NodeService} — except it embeds the real
 * {@code :app} daemon rather than re-porting it, so the GUI, the CLI, and CI all exercise one
 * node implementation.
 */
class DesktopNodeController(private val scope: CoroutineScope) {

    private val log = LoggerFactory.getLogger(DesktopNodeController::class.java)

    private val _state = MutableStateFlow(NodeUiState())
    val state: StateFlow<NodeUiState> = _state.asStateFlow()

    @Volatile
    private var runtime: DaemonRuntime? = null

    @Volatile
    private var clGenesisTime: Long = 0L

    private var pollJob: Job? = null

    fun start(networkName: String, gossipsub: Boolean = false) {
        val current = _state.value.status
        if (current == NodeStatus.RUNNING || current == NodeStatus.STARTING) return
        _state.value = NodeUiState(status = NodeStatus.STARTING, network = networkName)
        scope.launch(Dispatchers.IO) {
            var rt: DaemonRuntime? = null
            try {
                val network = NetworkConfig.byName(networkName)
                clGenesisTime = network.clGenesisTime()
                val config = AppPaths.daemonConfig(network, DEFAULT_PORT, gossipsub)
                rt = DaemonRuntime(config)
                rt.start()
                runtime = rt
                _state.value = _state.value.copy(status = NodeStatus.RUNNING)
                log.info("Embedded daemon started on {}", networkName)
                startPolling()
            } catch (e: Throwable) {
                log.error("Failed to start embedded daemon", e)
                // DaemonRuntime.start() already self-cleans on failure; close() again here is
                // an idempotent no-op, and covers the case where rt was created but start()
                // threw before its own guard engaged.
                try {
                    rt?.close()
                } catch (ignored: Throwable) {
                }
                runtime = null
                _state.value = _state.value.copy(
                    status = NodeStatus.ERROR,
                    error = e.message ?: e.toString(),
                )
            }
        }
    }

    fun stop() {
        val rt = runtime ?: return
        val net = _state.value.network
        _state.value = _state.value.copy(status = NodeStatus.STOPPING)
        scope.launch(Dispatchers.IO) {
            try {
                pollJob?.cancel()
                pollJob = null
                rt.close()
            } catch (e: Throwable) {
                log.warn("Error during shutdown", e)
            } finally {
                runtime = null
                _state.value = NodeUiState(status = NodeStatus.STOPPED, network = net)
            }
        }
    }

    /**
     * Synchronously close the embedded node on the calling thread. Used on window-close /
     * JVM shutdown so the daemon's Netty + Ktor threads are torn down before the process exits
     * (the runtime no longer registers its own JVM shutdown hook — the embedder owns lifecycle).
     */
    fun shutdownBlocking() {
        pollJob?.cancel()
        pollJob = null
        val rt = runtime
        runtime = null
        if (rt != null) {
            try {
                rt.close()
            } catch (e: Throwable) {
                log.warn("Error during blocking shutdown", e)
            }
        }
    }

    /** Run a JSON-Lines IPC command against the live node, off the UI thread. */
    suspend fun command(json: String): String = withContext(Dispatchers.IO) {
        val rt = runtime ?: return@withContext """{"error":"node not running"}"""
        try {
            rt.commandHandler().handle(json)
        } catch (e: Throwable) {
            """{"error":"${jsonEscape(e.message ?: e.toString())}"}"""
        }
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = scope.launch(Dispatchers.Default) {
            while (isActive) {
                refresh()
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private fun refresh() {
        val rt = runtime ?: return
        try {
            val sync = rt.beaconSyncState()
            val connector = rt.connector()
            val peers = connector?.activePeers ?: emptyList()
            val snapPeers = peers.count { it.snapSupported() }
            val beaconState = sync?.getSyncState(clGenesisTime)?.name ?: "—"
            _state.value = _state.value.copy(
                beaconState = beaconState,
                peerCount = peers.size,
                snapPeerCount = snapPeers,
                finalizedSlot = sync?.finalizedSlot ?: 0,
                executionBlock = sync?.executionBlockNumber ?: 0,
            )
        } catch (e: Throwable) {
            log.debug("refresh failed: {}", e.toString())
        }
    }

    companion object {
        private const val DEFAULT_PORT = 30303
        private const val POLL_INTERVAL_MS = 2000L

        fun jsonEscape(s: String): String =
            s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")
    }
}
