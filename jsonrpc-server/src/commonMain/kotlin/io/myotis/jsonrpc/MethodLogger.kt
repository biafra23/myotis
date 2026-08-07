package io.myotis.jsonrpc

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.concurrent.Volatile

/**
 * Per-request access log + an in-memory coverage map. Emits one concise line per
 * call the server answers — the "which methods did the wallet call, and how did we
 * serve each" record — and feeds the {@code myotis_rpcCoverage} introspection map.
 *
 * `path` is one of VERIFIED (served by Myotis, cryptographically verified),
 * PROXY (relayed upstream — unverified), ERROR, or LOCAL (answered here, e.g.
 * the coverage introspection method).
 *
 * The access line goes out under the dedicated logger [ACCESS_LOGGER] at a UNIFORM
 * INFO level for every outcome (the outcome is in the text). That's deliberate: it
 * keeps the whole access stream on one level so raising the Logs-tab / logback level
 * never silently drops successful calls (the old code logged success at INFO but
 * errors at WARN, so quieting the log hid exactly the calls you wanted to see).
 * Full request/response bodies are logged separately at DEBUG by [MyotisRpcServer]
 * under the same logger name.
 *
 * Multiplatform note: counters were ConcurrentHashMap+AtomicLong on the JVM;
 * commonMain has neither, so the map is copy-on-write behind a [Mutex] (record
 * is only ever called from the router's suspend paths) with a [Volatile]
 * snapshot for the lock-free readers ([coverage]/[logSummary]).
 */
class MethodLogger {

    companion object {
        /** Dedicated logger name for the RPC access log (concise INFO + full-body DEBUG).
         *  Namespaced under io.myotis.jsonrpc so every host's log config / Logs-tab filter
         *  can target it; filter the Logs tab on "rpc" (the [rpc] message prefix) to isolate it. */
        const val ACCESS_LOGGER = "io.myotis.jsonrpc.access"
    }

    private data class Stat(
        val count: Long = 0,
        val verified: Long = 0,
        val proxied: Long = 0,
        val error: Long = 0,
        val local: Long = 0,
        val simulated: Long = 0,
    )

    /** Buckets that mean "answered" — anything else counts as an error. */
    private val ANSWERED = setOf("VERIFIED", "SIMULATED", "PROXY", "LOCAL")

    private val mutex = Mutex()

    @Volatile
    private var byMethod: Map<String, Stat> = emptyMap()

    /**
     * Record one answered request: bump the coverage map and emit the access line.
     *
     * @param method the JSON-RPC method (or a placeholder like {@code <parse-error>} for
     *   a request that couldn't be parsed to a method)
     * @param id     the request id, stringified (e.g. {@code 42}, {@code "abc"}, {@code null})
     * @param path   the coverage bucket: VERIFIED / SIMULATED / PROXY / LOCAL / ERROR.
     *   SIMULATED is a call answered over verified state but under CALLER-SUPPLIED
     *   overrides — the state underneath was proven, the answer is not a chain
     *   fact, and lumping it in with VERIFIED would overstate what this node
     *   proved.
     * @param latencyMs handling latency in millis (0 when not meaningfully measurable)
     * @param code   the JSON-RPC error code for ERROR outcomes (e.g. -32000), else null
     */
    suspend fun record(method: String, id: String, path: String, latencyMs: Long, code: Int? = null) {
        mutex.withLock {
            val s = byMethod[method] ?: Stat()
            byMethod = byMethod + (method to s.copy(
                count = s.count + 1,
                verified = s.verified + if (path == "VERIFIED") 1 else 0,
                simulated = s.simulated + if (path == "SIMULATED") 1 else 0,
                proxied = s.proxied + if (path == "PROXY") 1 else 0,
                local = s.local + if (path == "LOCAL") 1 else 0,
                error = s.error + if (path !in ANSWERED) 1 else 0,
            ))
        }
        val outcome = if (code != null) "$path($code)" else path
        rpcLogInfo(ACCESS_LOGGER, "[rpc] method=$method id=$id outcome=$outcome latencyMs=$latencyMs")
    }

    /** Coverage map as a JSON object: method -> {count, verified, proxied, error, local}. */
    fun coverage(): JsonObject = buildJsonObject {
        byMethod.entries.sortedBy { it.key }.forEach { (method, s) ->
            put(method, buildJsonObject {
                put("count", s.count)
                put("verified", s.verified)
                put("simulated", s.simulated)
                put("proxied", s.proxied)
                put("error", s.error)
                put("local", s.local)
            })
        }
    }

    /** Dump the coverage summary to the log (call on shutdown). */
    fun logSummary() {
        rpcLogInfo(ACCESS_LOGGER, "[rpc] coverage summary: ${coverage()}")
    }
}
