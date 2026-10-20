package io.myotis.ios

import io.myotis.engine.ios.RustEngine
import platform.Network.nw_path_get_status
import platform.Network.nw_path_is_constrained
import platform.Network.nw_path_is_expensive
import platform.Network.nw_path_monitor_create
import platform.Network.nw_path_monitor_set_queue
import platform.Network.nw_path_monitor_set_update_handler
import platform.Network.nw_path_monitor_start
import platform.Network.nw_path_monitor_t
import platform.Network.nw_path_status_satisfied
import platform.darwin.dispatch_queue_create
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Tells the engine whether the device's network is metered, so its data-usage figures
 * (docs/data-usage.md) can say how much went over mobile data. iOS's own words for it:
 * a path is "expensive" on cellular or a personal hotspot and "constrained" in Low Data
 * Mode — either counts as metered; no usable path is unknown. The engine reports it back
 * on the Status screen's "Connection" row. Process-lifetime, like the engine.
 */
@OptIn(ExperimentalAtomicApi::class)
internal object IosNetworkMetering {

    private val monitor = AtomicReference<nw_path_monitor_t?>(null)

    /** Start watching (idempotent). Every path update — and the first, at once — is pushed. */
    fun start(onError: (String) -> Unit) {
        val m = nw_path_monitor_create()
        if (!monitor.compareAndSet(null, m)) return
        nw_path_monitor_set_update_handler(m) { path ->
            val code = when {
                nw_path_get_status(path) != nw_path_status_satisfied -> 0     // UNKNOWN
                nw_path_is_expensive(path) || nw_path_is_constrained(path) -> 2 // METERED
                else -> 1                                                        // UNMETERED
            }
            runCatching { RustEngine.setNetworkMetering(code) }
                .onFailure { onError("network metering push failed: $it") }
        }
        nw_path_monitor_set_queue(m, dispatch_queue_create("io.myotis.network-path", null))
        nw_path_monitor_start(m)
    }
}
