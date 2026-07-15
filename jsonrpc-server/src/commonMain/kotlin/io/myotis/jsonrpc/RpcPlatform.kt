package io.myotis.jsonrpc

import kotlinx.coroutines.CoroutineDispatcher

// The platform seams behind the router/server. Deliberately tiny: a blocking-IO
// dispatcher (Dispatchers.IO exists on both JVM and native, but is not visible
// from COMMON code), logging (slf4j on the JVM so host log config and the
// RpcAccessLogTest ListAppender keep working; a pluggable sink on iOS that hosts
// point at their Logs-tab ring), and the JVM-only capture-file debug feature.

/** Dispatcher for the BLOCKING backend/status reads (JNI or C-ABI crossings). */
internal expect val rpcIoDispatcher: CoroutineDispatcher

/** INFO-level line under [logger] (a dotted logger name, e.g. MethodLogger.ACCESS_LOGGER). */
internal expect fun rpcLogInfo(logger: String, message: String)

/** Whether DEBUG is enabled for [logger] — gates building the full-body access line. */
internal expect fun rpcLogDebugEnabled(logger: String): Boolean

/** DEBUG-level line under [logger]. */
internal expect fun rpcLogDebug(logger: String, message: String)

/**
 * Append one request/response exchange to the debug capture file, if the
 * platform has one configured (JVM: the `myotis.rpc.capture` system property;
 * iOS: never). Best-effort and blocking — callers dispatch appropriately.
 */
internal expect fun appendRpcCapture(request: String, response: String)
