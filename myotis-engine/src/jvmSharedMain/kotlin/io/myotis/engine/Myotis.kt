package io.myotis.engine

import io.myotis.api.ChainHandle
import io.myotis.api.EngineException
import io.myotis.api.MyotisEngine
import io.myotis.api.ports.DnsServers
import io.myotis.engine.ports.DefaultEnginePorts
import io.myotis.engines.rust.RustMyotisEngine
import io.myotis.logindex.LogIndexDownloads
import io.myotis.logindex.LogIndexPresets
import java.nio.file.Path

/**
 * The engine library's entry point: the Rust engine behind the `io.myotis.api`
 * contract, for a host that runs it IN-PROCESS — every verified read through
 * [io.myotis.api.ChainHandle.reads], nothing listening on a port. The Myotis
 * apps keep their loopback JSON-RPC listener through the `:myotis-engines`
 * selector; a wallet built on this library needs none.
 *
 * A host supplies its platform through [io.myotis.api.ports.EnginePorts] on
 * `create()` (the node-key store, the peer caches, DNS, the CCIP gateway) — its
 * own, or the library's file-backed defaults from [defaultPorts] — and drives the
 * handle it gets back; the engine persists its own sync state under the data dir
 * it is given.
 */
object Myotis {

    /** True when `libmyotis_engine` loaded and passed the ABI handshake on this host. */
    @JvmStatic
    fun isAvailable(): Boolean = RustMyotisEngine.isAvailable()

    /**
     * A new engine instance. One per process is the intended shape: an engine
     * hosts every network the host creates on it, and two instances know nothing
     * of each other's networks.
     *
     * @throws EngineException when the native library is not available here
     */
    @JvmStatic
    fun newEngine(): MyotisEngine = RustMyotisEngine()

    /**
     * The library's default ports for one network ([io.myotis.engine.ports]): the
     * node key under [keyDir], the EL and CL peer caches under [cacheDir] (the
     * per-network file names of [io.myotis.engine.ports.NetworkFiles], the Myotis
     * apps' own), the CCIP-Read gateway over `HttpURLConnection`, and [dnsServers]
     * — the host's DNS servers for EIP-1459 resolution, which a mobile host must
     * supply (null on a host whose system resolver the engine can use).
     * [DefaultEnginePorts.ports] is what [engine]'s `create()` takes; [network] is
     * canonicalized through [engine] first, so an alias names the same files as the
     * engine. One instance per `create()`.
     *
     * The Rust engine this library ships reads the DNS servers and the gateway from
     * these ports and keeps its peer caches and sync snapshot itself under the
     * [io.myotis.api.EngineConfig]'s `dataDir`, in the same file names — pass one
     * directory as both that `dataDir` and [cacheDir] and
     * [DefaultEnginePorts.peerCacheFile] / [DefaultEnginePorts.syncSnapshot] name the
     * files it writes; its node identity is ephemeral per run (the key file under
     * [keyDir] serves the Java engine only). See [DefaultEnginePorts] for which engine
     * reads which port.
     */
    @JvmStatic
    @JvmOverloads
    fun defaultPorts(
        engine: MyotisEngine,
        keyDir: Path,
        cacheDir: Path,
        network: String,
        dnsServers: DnsServers? = null,
    ): DefaultEnginePorts =
        DefaultEnginePorts.forNetwork(keyDir, cacheDir, engine.canonicalNetworkName(network), dnsServers)

    /**
     * Drain up to [max] buffered engine tracing lines (oldest first,
     * newline-joined; empty when idle or unavailable) into the host's own log
     * pipeline. Never throws.
     */
    @JvmStatic
    fun drainLogs(max: Int): String = RustMyotisEngine.drainLogs(max)

    /**
     * Tor routing of account reads and of the wallet's own transaction broadcast
     * (docs/how-it-works/privacy-and-tor.md): the engine's process-wide toggle, re-exported for
     * library consumers so the Rust module stays an implementation detail. Only a
     * library built with the Tor feature (`-PtorEngine`) can turn it on;
     * [supported] says whether this one was.
     */
    object Tor {
        /** Whether this build of the engine links Tor (Arti) at all. */
        fun supported(): Boolean = io.myotis.engines.rust.Tor.supported()

        /** The host's choice: route through Tor when the engine supports it. */
        fun enabled(): Boolean = io.myotis.engines.rust.Tor.enabled()

        /** Whether reads are going through Tor right now (enabled AND the circuit is up). */
        fun active(): Boolean = io.myotis.engines.rust.Tor.active()

        /** The engine's Tor status code, as the status screens render it. */
        fun status(): Int = io.myotis.engines.rust.Tor.status()

        /**
         * Where Tor keeps its state and cache (set before [select]ing it on). False
         * when the engine refused the directories (or is not available).
         */
        fun configureStorage(stateDir: String, cacheDir: String): Boolean =
            io.myotis.engines.rust.Tor.configureStorage(stateDir, cacheDir)

        /**
         * Switch Tor routing on or off, process-wide. False when the engine could not
         * apply it (unsupported build, library not available); on stays a no-op then.
         */
        fun select(on: Boolean): Boolean = io.myotis.engines.rust.Tor.select(on)
    }

    /**
     * The log index's PREDEFINED CONTRACTS — RAILGUN, Swarm, Privacy Pools and
     * Tornado Cash ([LogIndexPresets]) — and the trigger that downloads and
     * verifies their history on a running handle: the same catalog and estimates
     * the Myotis apps' Index tab shows (docs/how-it-works/log-index-presets.md).
     *
     * ```kotlin
     * val est = Myotis.LogIndex.estimate(handle, listOf("railgun-mainnet"))
     * // show est.downloadBytes / est.storageBytes (LogIndexDownloads.formatBytes) and,
     * // when est.cheaperTogether, that adding them together saves est.savedBytes
     * Myotis.LogIndex.download(handle, listOf("railgun-mainnet"))  // unmetered only
     * engine.setNetworkMetering(NetworkMetering.METERED)           // the host's word
     * ```
     *
     * "Unmetered only" is the default and the ENGINE enforces it: while the host
     * reports a metered network (`MyotisEngine.setNetworkMetering`) the backfill
     * walk waits — head-follow keeps running — and `logIndexStatusJson` carries
     * `"meteredHold":true`. A host that never reports metering is never held.
     */
    object LogIndex {
        /** The presets offered on [handle]'s network (empty for one without any). */
        @JvmStatic
        fun presets(handle: ChainHandle): List<LogIndexPresets.Preset> =
            LogIndexPresets.forNetwork(handle.networkName())

        /**
         * The download and disk estimate for [presetIds] on [handle]'s network, at
         * its current verified head (the presets' census head while it has none).
         *
         * @throws IllegalArgumentException for an unknown id or one of another network
         */
        @JvmStatic
        fun estimate(handle: ChainHandle, presetIds: List<String>): LogIndexDownloads.Estimate =
            LogIndexDownloads.estimate(resolve(handle, presetIds), headOf(handle))

        /**
         * Start downloading and verifying [presetIds]: one config push
         * (`ChainHandle.setLogIndexConfig`) that adds their contracts to the
         * handle's index. Additive — what the index already watches stays. A push
         * also carries the index's runtime bits; each one left null keeps what the
         * engine's status reports now, or its default for an index with none:
         * [allowMetered] false (unmetered only), [maxSpeed] false, [backfillPaused]
         * false. Returns the engine's answer: false = refused, nothing changed.
         *
         * @throws IllegalArgumentException for an unknown id or one of another network
         */
        @JvmStatic
        @JvmOverloads
        fun download(
            handle: ChainHandle,
            presetIds: List<String>,
            allowMetered: Boolean? = null,
            maxSpeed: Boolean? = null,
            backfillPaused: Boolean? = null,
        ): Boolean {
            val presets = resolve(handle, presetIds)
            val status = runCatching { handle.logIndexStatusJson() }.getOrNull().orEmpty()
            fun current(key: String) = status.contains("\"$key\":true")
            return handle.setLogIndexConfig(
                LogIndexDownloads.configJson(
                    presets,
                    maxSpeed = maxSpeed ?: current("maxSpeed"),
                    allowMetered = allowMetered ?: current("allowMetered"),
                    backfillPaused = backfillPaused ?: current("backfillPaused"),
                ),
            )
        }

        private fun resolve(handle: ChainHandle, ids: List<String>): List<LogIndexPresets.Preset> {
            val network = handle.networkName()
            return ids.map { id ->
                val p = requireNotNull(LogIndexPresets.byId(id)) { "unknown log-index preset: $id" }
                require(p.network == network) { "preset $id is for ${p.network}, the handle is $network" }
                p
            }
        }

        private fun headOf(handle: ChainHandle): Long? =
            runCatching { handle.status().executionBlockNumber() }.getOrNull()?.takeIf { it > 0 }
    }
}
