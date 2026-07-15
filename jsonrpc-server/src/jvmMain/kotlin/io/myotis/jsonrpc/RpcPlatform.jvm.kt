package io.myotis.jsonrpc

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import java.io.File

internal actual val rpcIoDispatcher: CoroutineDispatcher = Dispatchers.IO

internal actual fun rpcLogInfo(logger: String, message: String) {
    LoggerFactory.getLogger(logger).info(message)
}

internal actual fun rpcLogDebugEnabled(logger: String): Boolean =
    LoggerFactory.getLogger(logger).isDebugEnabled

internal actual fun rpcLogDebug(logger: String, message: String) {
    LoggerFactory.getLogger(logger).debug(message)
}

/**
 * Optional request/response capture for debugging + replay. Off unless the
 * system property `myotis.rpc.capture` names a file: then every exchange is
 * appended as one JSON line `{"t":<ms>,"req":<body>,"resp":<body>}`. Lets us
 * record a real client session (e.g. a MetaMask send) once and replay it at
 * the daemon on a loop while hardening the backend — no browser needed.
 * Synchronized append; best-effort (capture failures never affect serving).
 */
private val captureFile: File? =
    System.getProperty("myotis.rpc.capture")?.takeIf { it.isNotBlank() }?.let { File(it) }

private val captureLock = Any()

internal actual fun appendRpcCapture(request: String, response: String) {
    val f = captureFile ?: return
    try {
        val line = buildString {
            append("{\"t\":").append(System.currentTimeMillis())
            append(",\"req\":").append(request.trim())
            append(",\"resp\":").append(response.trim())
            append("}\n")
        }
        synchronized(captureLock) { f.appendText(line) }
    } catch (_: Exception) { /* capture is best-effort */ }
}
