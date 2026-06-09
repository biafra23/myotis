package io.myotis.jsonrpc

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Per-request structured logging + an in-memory coverage map. The point of
 * Phase A: after a MetaMask session, this is the exact "which methods did the
 * wallet call, and how did we serve each" answer that drives Phases B–D.
 *
 * `path` is one of VERIFIED (served by Myotis, cryptographically verified),
 * PROXY (relayed upstream — unverified), ERROR, or LOCAL (answered here, e.g.
 * the coverage introspection method).
 */
class MethodLogger {

    private val log = LoggerFactory.getLogger("RpcCoverage")

    private class Stat {
        val count = AtomicLong()
        val verified = AtomicLong()
        val proxied = AtomicLong()
        val error = AtomicLong()
        val local = AtomicLong()
    }

    private val byMethod = ConcurrentHashMap<String, Stat>()

    fun record(method: String, path: String, latencyMs: Long) {
        val s = byMethod.computeIfAbsent(method) { Stat() }
        s.count.incrementAndGet()
        when (path) {
            "VERIFIED" -> s.verified.incrementAndGet()
            "PROXY" -> s.proxied.incrementAndGet()
            "LOCAL" -> s.local.incrementAndGet()
            else -> s.error.incrementAndGet()
        }
        // PROXY (relayed upstream, unverified) and ERROR are the noteworthy
        // outcomes — log them at WARN so they stand out; VERIFIED/LOCAL stay INFO.
        when (path) {
            "VERIFIED", "LOCAL" -> log.info("[rpc] method={} path={} latencyMs={}", method, path, latencyMs)
            else -> log.warn("[rpc] method={} path={} latencyMs={}", method, path, latencyMs)
        }
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
