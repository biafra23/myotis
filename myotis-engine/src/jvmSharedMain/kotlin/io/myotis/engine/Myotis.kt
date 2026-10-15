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
}
