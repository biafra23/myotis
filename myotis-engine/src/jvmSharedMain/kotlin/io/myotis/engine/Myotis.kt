package io.myotis.engine

import io.myotis.api.EngineException
import io.myotis.api.MyotisEngine
import io.myotis.engines.rust.RustMyotisEngine

/**
 * The engine library's entry point: the Rust engine behind the `io.myotis.api`
 * contract, for a host that runs it IN-PROCESS — every verified read through
 * [io.myotis.api.ChainHandle.reads], nothing listening on a port. The Myotis
 * apps keep their loopback JSON-RPC listener through the `:myotis-engines`
 * selector; a wallet built on this library needs none.
 *
 * A host supplies its platform through [io.myotis.api.ports.EnginePorts] on
 * `create()` (the node-key store, the peer caches, DNS, the CCIP gateway) and
 * drives the handle it gets back; the engine persists its own sync state under
 * the data dir it is given.
 */
object Myotis {

    /** True when `libmyotis_engine` loaded and passed the ABI handshake on this host. */
    fun isAvailable(): Boolean = RustMyotisEngine.isAvailable()

    /**
     * A new engine instance. One per process is the intended shape: an engine
     * hosts every network the host creates on it, and two instances know nothing
     * of each other's networks.
     *
     * @throws EngineException when the native library is not available here
     */
    fun newEngine(): MyotisEngine = RustMyotisEngine()

    /**
     * Drain up to [max] buffered engine tracing lines (oldest first,
     * newline-joined; empty when idle or unavailable) into the host's own log
     * pipeline. Never throws.
     */
    fun drainLogs(max: Int): String = RustMyotisEngine.drainLogs(max)

    /**
     * Tor routing of account reads and of the wallet's own transaction broadcast
     * (docs/privacy-and-tor.md): the engine's process-wide toggle, re-exported for
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
}
