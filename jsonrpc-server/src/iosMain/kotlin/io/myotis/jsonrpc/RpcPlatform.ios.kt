package io.myotis.jsonrpc

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
// On Kotlin/Native, Dispatchers.IO is an extension property — this import is load-bearing.
import kotlinx.coroutines.IO
import kotlin.concurrent.Volatile

internal actual val rpcIoDispatcher: CoroutineDispatcher = Dispatchers.IO

/**
 * iOS log routing: there is no slf4j here, so hosts point [sink] at their log
 * pipeline (the app wires it into the Logs-tab ring). Defaults to println so
 * the server is never silently mute. DEBUG (full request/response bodies) is
 * deliberately unavailable on iOS — the capture/debug tooling is JVM-side.
 */
object IosRpcLog {
    @Volatile
    var sink: (String) -> Unit = ::println
}

internal actual fun rpcLogInfo(logger: String, message: String) {
    IosRpcLog.sink("INFO $logger: $message")
}

internal actual fun rpcLogDebugEnabled(logger: String): Boolean = false

internal actual fun rpcLogDebug(logger: String, message: String) {
    // unreachable while rpcLogDebugEnabled is false; keep as a sink call for safety
    IosRpcLog.sink("DEBUG $logger: $message")
}

internal actual fun appendRpcCapture(request: String, response: String) {
    // JVM-only debug feature; no capture file on iOS.
}
