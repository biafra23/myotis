package io.myotis.jsonrpc

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.concurrent.Volatile
import kotlin.time.TimeSource

/**
 * Per-request access log + an in-memory coverage map. Emits one concise line per
 * call the server answers — the "which methods did the wallet call, and how did we
 * serve each" record — and feeds the {@code myotis_rpcCoverage} introspection map.
 *
 * `path` is one of VERIFIED (served by Myotis, cryptographically verified),
 * SIMULATED (served over verified state but under CALLER-SUPPLIED overrides —
 * proven state, but the answer is the caller's hypothesis, not a chain fact),
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
 * It also runs every request under a slow-call watchdog ([watch]): a request still
 * unanswered after [SLOW_CALL_WARN_MS] is logged at WARN under [SLOW_LOGGER] while it
 * is stuck, with the phase it is in, and again when it ends.
 *
 * Multiplatform note: counters were ConcurrentHashMap+AtomicLong on the JVM;
 * commonMain has neither, so the map is copy-on-write behind a [Mutex] (record
 * is only ever called from the router's suspend paths) with a [Volatile]
 * snapshot for the lock-free readers ([coverage]/[logSummary]).
 */
class MethodLogger(
    /** How long a request may stay unanswered before [watch] logs it; tests shorten it. */
    private val slowCallWarnMs: Long = SLOW_CALL_WARN_MS,
) {

    companion object {
        /** Dedicated logger name for the RPC access log (concise INFO + full-body DEBUG).
         *  Namespaced under io.myotis.jsonrpc so every host's log config / Logs-tab filter
         *  can target it; filter the Logs tab on "rpc" (the [rpc] message prefix) to isolate it. */
        const val ACCESS_LOGGER = "io.myotis.jsonrpc.access"

        /** Dedicated logger for the slow-call watchdog ([watch]) — deliberately NOT
         *  [ACCESS_LOGGER], whose stream stays uniformly INFO. Its lines are WARN, so a
         *  log quieted to WARN still shows every stall. */
        const val SLOW_LOGGER = "io.myotis.jsonrpc.slow"

        /** Default slow-call threshold: an order of magnitude above a healthy verified
         *  read, and far enough under the ~10 s timeout browser wallets abort at that a
         *  stall is on record long before the wallet gives up. */
        const val SLOW_CALL_WARN_MS = 1_000L
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

    /** Coverage map as a JSON object:
     *  method -> {count, verified, simulated, proxied, error, local}. */
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

    /**
     * Run one request's dispatch under the slow-call watchdog (#312). A request still
     * unanswered after [slowCallWarnMs] is logged at WARN under [SLOW_LOGGER] while it
     * is stuck — method, id, batch position and the [CallPhase] it is in — and every
     * request that took that long is logged again when it ends, with its total time.
     * The access line records only completions, so a stall used to surface only once
     * it was over: the 2-minute freeze this was added for looked like a burst of
     * completions at one instant.
     */
    internal suspend fun <T> watch(
        method: String,
        id: String,
        batchPos: String?,
        phase: CallPhase,
        block: suspend () -> T,
    ): T = coroutineScope {
        val t0 = TimeSource.Monotonic.markNow()
        val what = "method=$method id=$id" + (batchPos?.let { " batch=$it" } ?: "")
        val watchdog = launch {
            delay(slowCallWarnMs)
            warnSlow("[rpc] slow call: $what still unanswered after " +
                "${t0.elapsedNow().inWholeMilliseconds}ms (phase=${phase.name})")
        }
        var ending = "finished"
        try {
            block()
        } catch (e: Throwable) {
            ending = if (e is CancellationException) "abandoned (request cancelled)"
                else "failed (${e::class.simpleName})"
            throw e
        } finally {
            watchdog.cancel()
            val ms = t0.elapsedNow().inWholeMilliseconds
            if (ms >= slowCallWarnMs) {
                warnSlow("[rpc] slow call: $what $ending after ${ms}ms (phase=${phase.name})")
            }
        }
    }

    /** A slow-call line that can never fail the request it describes: the watchdog is a
     *  child of the request's scope, so a throwing log sink (iOS hosts supply their own)
     *  would otherwise cancel the request — diagnostics must never change outcomes (the
     *  rule WakeGate's holdReason follows too). */
    private fun warnSlow(message: String) {
        try {
            rpcLogWarn(SLOW_LOGGER, message)
        } catch (_: Exception) {
            // a broken log sink is not the request's problem
        }
    }
}

/**
 * Where one request is right now — `dispatch`, `status`, `lifecycle`, `backend` or
 * `proxy` — for the slow-call watchdog ([MethodLogger.watch]). Written by the
 * dispatching coroutine, read by the watchdog's. What a backend does INSIDE its phase
 * (e.g. a wake-gate hold) is the backend's to log.
 */
internal class CallPhase {
    @Volatile
    var name: String = "dispatch"
}
