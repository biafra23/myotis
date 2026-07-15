package io.myotis.jsonrpc

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
// On Kotlin/Native, Dispatchers.IO is an extension property — this import is load-bearing.
import kotlinx.coroutines.IO
import kotlin.concurrent.Volatile

internal actual val rpcIoDispatcher: CoroutineDispatcher = Dispatchers.IO

/**
 * iOS log routing: there is no slf4j here, so hosts point [sink] at their log
 * pipeline (the app wires it into the Logs-tab ring). Structured (level char,
 * dotted logger name, message) so the host can tag lines properly — the Logs
 * tab's filter matches tags, and RPC access lines filter as "access"/"rpc".
 * Defaults to println so the server is never silently mute. DEBUG (full
 * request/response bodies) is deliberately unavailable on iOS — the
 * capture/debug tooling is JVM-side.
 */
object IosRpcLog {
    @Volatile
    var sink: (level: Char, logger: String, message: String) -> Unit =
        { level, logger, message -> println("$level $logger: $message") }
}

internal actual fun rpcLogInfo(logger: String, message: String) {
    IosRpcLog.sink('I', logger, message)
}

internal actual fun rpcLogDebugEnabled(logger: String): Boolean = false

internal actual fun rpcLogDebug(logger: String, message: String) {
    // unreachable while rpcLogDebugEnabled is false; keep as a sink call for safety
    IosRpcLog.sink('D', logger, message)
}

internal actual fun appendRpcCapture(request: String, response: String) {
    // JVM-only debug feature; no capture file on iOS.
}
