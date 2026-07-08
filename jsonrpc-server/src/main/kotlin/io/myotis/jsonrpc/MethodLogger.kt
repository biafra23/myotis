package io.myotis.jsonrpc

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

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
 */
class MethodLogger {

    private val log = LoggerFactory.getLogger(ACCESS_LOGGER)

    companion object {
        /** Dedicated logger name for the RPC access log (concise INFO + full-body DEBUG).
         *  Namespaced under io.myotis.jsonrpc so every host's log config / Logs-tab filter
         *  can target it; filter the Logs tab on "rpc" (the [rpc] message prefix) to isolate it. */
        const val ACCESS_LOGGER = "io.myotis.jsonrpc.access"
    }

    private class Stat {
        val count = AtomicLong()
        val verified = AtomicLong()
        val proxied = AtomicLong()
        val error = AtomicLong()
        val local = AtomicLong()
    }

    private val byMethod = ConcurrentHashMap<String, Stat>()

    /**
     * Record one answered request: bump the coverage map and emit the access line.
     *
     * @param method the JSON-RPC method (or a placeholder like {@code <parse-error>} for
     *   a request that couldn't be parsed to a method)
     * @param id     the request id, stringified (e.g. {@code 42}, {@code "abc"}, {@code null})
     * @param path   the coverage bucket: VERIFIED / PROXY / LOCAL / ERROR
     * @param latencyMs handling latency in millis (0 when not meaningfully measurable)
     * @param code   the JSON-RPC error code for ERROR outcomes (e.g. -32000), else null
     */
    fun record(method: String, id: String, path: String, latencyMs: Long, code: Int? = null) {
        val s = byMethod.computeIfAbsent(method) { Stat() }
        s.count.incrementAndGet()
        when (path) {
            "VERIFIED" -> s.verified.incrementAndGet()
            "PROXY" -> s.proxied.incrementAndGet()
            "LOCAL" -> s.local.incrementAndGet()
            else -> s.error.incrementAndGet()
        }
        val outcome = if (code != null) "$path($code)" else path
        log.info("[rpc] method={} id={} outcome={} latencyMs={}", method, id, outcome, latencyMs)
    }

    /** Coverage map as a JSON object: method -> {count, verified, proxied, error, local}. */
    fun coverage(): JsonObject = buildJsonObject {
        byMethod.toSortedMap().forEach { (method, s) ->
            put(method, buildJsonObject {
                put("count", s.count.get())
                put("verified", s.verified.get())
                put("proxied", s.proxied.get())
                put("error", s.error.get())
                put("local", s.local.get())
            })
        }
    }

    /** Dump the coverage summary to the log (call on shutdown). */
    fun logSummary() {
        log.info("[rpc] coverage summary: {}", coverage().toString())
    }
}
