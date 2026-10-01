package io.myotis.jsonrpc

import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.put
import kotlin.time.TimeSource

/**
 * Routes a JSON-RPC request body. Phase A: every method is relayed to the
 * upstream (raw passthrough) and logged, except a local introspection method
 * (`myotis_rpcCoverage`). Verified Myotis handlers replace proxy entries
 * method-by-method in later phases (see the plan).
 *
 * Handles both a single request object and a batch array. For a batch we proxy
 * the whole body verbatim (Phase A is all-proxy anyway) and log each element's
 * method; a single local method is answered here.
 */
class RpcRouter(
    private val proxy: UpstreamProxy?,
    private val logger: MethodLogger,
    private val backend: RpcBackend? = null,
    private val statusReads: RpcStatusSource? = null,
    private val lifecycle: RpcLifecycle? = null,
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    internal companion object {
        private val HEX_DIGITS = "0123456789abcdef".toCharArray()

        /** Methods we have a verified implementation for. Used in strict mode to tell
         *  "supported but can't answer right now" (-32000, retryable) from "we don't
         *  serve this verified at all" (-32601). Keep in sync with tryVerified's cases. */
        private val VERIFIED_METHODS = setOf(
            "eth_chainId", "net_version", "eth_blockNumber", "eth_call", "eth_getBalance",
            "eth_getTransactionCount", "eth_getCode", "eth_getStorageAt",
            "eth_sendRawTransaction", "eth_getTransactionReceipt", "eth_getBlockByNumber",
            "eth_gasPrice", "eth_maxPriorityFeePerGas", "eth_feeHistory", "eth_estimateGas",
            "eth_getTransactionByHash", "eth_getBlockByHash", "eth_getBlockReceipts", "eth_getLogs",
            "web3_clientVersion", "eth_syncing",
            "eth_accounts", "net_listening", "net_peerCount", "web3_sha3",
            "eth_getBlockTransactionCountByNumber", "eth_getBlockTransactionCountByHash",
            "eth_getTransactionByBlockNumberAndIndex", "eth_getTransactionByBlockHashAndIndex",
            "eth_getUncleCountByBlockNumber", "eth_getUncleCountByBlockHash",
            "eth_getUncleByBlockNumberAndIndex", "eth_getUncleByBlockHashAndIndex",
        )

        /** The most requests one batch may carry — geth's default
         *  `BatchRequestLimit`. Elements are served one after another, so an
         *  unbounded batch would hold the server for as long as its sender
         *  likes (#366). */
        internal const val MAX_BATCH_REQUESTS = 1000

        /** The most reward percentiles one `eth_feeHistory` may ask for — geth's
         *  limit. */
        private const val MAX_FEE_HISTORY_PERCENTILES = 100

        /** The most blocks one `eth_feeHistory` may ask for — the spec's (and
         *  geth's) ceiling. A larger count is clamped, as geth clamps it: the
         *  answer's `oldestBlock` says how many blocks were served, and the
         *  spec lets a node serve fewer than asked. Each engine clamps further
         *  to what it can verify cheaply. */
        private const val MAX_FEE_HISTORY_BLOCKS = 1024L
    }

    /**
     * Handle one HTTP body: a request object or a batch array. Returns the
     * response body, or the EMPTY string when nothing may be answered — a
     * notification (a request without an `id`), or a batch made only of them
     * (JSON-RPC 2.0 §4.1, §6) — which the server sends as an empty body.
     */
    suspend fun handle(body: String): String {
        val t0 = TimeSource.Monotonic.markNow()
        val root = try {
            json.parseToJsonElement(body)
        } catch (e: Exception) {
            // Log the parse failure too — otherwise a malformed request the server DID
            // respond to (with -32700) would be invisible in the access log.
            logger.record("<parse-error>", "null", "ERROR", elapsedMs(t0), -32700)
            return errorEnvelope(JsonNull, -32700, "Parse error")
        }
        return when (root) {
            is JsonObject -> handleOne(root, body) ?: ""
            is JsonArray -> {
                // JSON-RPC 2.0 batch: each request gets its own response/error object so
                // a wallet (MetaMask batches heavily) can match them by id — not a single
                // error envelope. Elements are handled independently.
                if (root.isEmpty()) {
                    logger.record("<empty-batch>", "null", "ERROR", elapsedMs(t0), -32600)
                    return errorEnvelope(JsonNull, -32600, "Invalid Request")
                }
                if (root.size > MAX_BATCH_REQUESTS) {
                    // geth's answer to an oversized batch: one error, refusing the
                    // whole of it, carrying the first request's id — the protocol
                    // has no way to address an error to a batch as such.
                    logger.record("<batch-too-large>", "null", "ERROR", elapsedMs(t0), -32600)
                    val firstId = root.firstNotNullOfOrNull { el ->
                        (el as? JsonObject)?.get("id")?.takeIf { validId(it) }
                    } ?: JsonNull
                    return "[" + errorEnvelope(
                        firstId,
                        -32600,
                        "batch too large: ${root.size} requests (at most $MAX_BATCH_REQUESTS)",
                    ) + "]"
                }
                val responses = root.mapIndexedNotNull { i, el ->
                    if (el is JsonObject) {
                        // null = a notification, which is served but never answered.
                        handleOne(el, null, "${i + 1}/${root.size}")
                    } else {
                        logger.record("<invalid>", "null", "ERROR", 0, -32600)
                        errorEnvelope(JsonNull, -32600, "Invalid Request")
                    }
                }
                // A batch of notifications has nothing to answer, and an empty
                // array is not an answer either (JSON-RPC 2.0 §6).
                if (responses.isEmpty()) "" else "[" + responses.joinToString(",") + "]"
            }
            else -> {
                logger.record("<invalid>", "null", "ERROR", elapsedMs(t0), -32600)
                errorEnvelope(JsonNull, -32600, "Invalid Request")
            }
        }
    }

    private fun elapsedMs(t0: TimeSource.Monotonic.ValueTimeMark): Long =
        t0.elapsedNow().inWholeMilliseconds

    /** The request id rendered for the access log ({@code 42} / {@code "abc"} / {@code null}),
     *  bounded so a pathological id can't produce a giant log line. */
    private fun idString(id: JsonElement): String {
        val s = id.toString()
        return if (s.length > 64) s.substring(0, 64) + "…" else s
    }

    private val ADDRESS_HEX = Regex("^0[xX][0-9a-fA-F]{40}$")

    /** Fields geth's state override defines; anything else is malformed. */
    private val OVERRIDE_FIELDS = setOf("code", "balance", "nonce", "state", "stateDiff")

    /** True when the request carries a NON-EMPTY override object PAST THE BLOCK
     *  TAG — `stateOverride` at index 2 or `blockOverrides` at index 3 of
     *  `eth_call` / `eth_estimateGas`. geth's signature is
     *  `(args, blockNrOrHash, stateOverride, blockOverrides)`, and this node
     *  applies neither: `blockOverrides` rewrites number/time/baseFee/prevRandao/
     *  coinbase, changing the answer exactly the way a state override does, so
     *  checking only index 2 would leave the same silent-wrong-answer hole open
     *  for time-warp simulations (vesting cliffs, deadlines, TWAP windows).
     *
     *  An EMPTY object is not an override — nothing would change — so it is
     *  served normally; clients that always send the parameter must not break. */
    private fun hasUnsupportedOverride(root: JsonObject): Boolean =
        stateOverrideParam(root) is OverrideParam.Malformed ||
        // DERIVED, not re-implemented: this decides whether to REFUSE while
        // stateOverrideJson decides whether to APPLY and how to LABEL. If the
        // two ever disagreed, the node would answer a question the caller
        // didn't ask — the exact class of bug CLAUDE.md's apply-or-refuse rule
        // exists to prevent — so there is one source of truth.
        stateOverrideJson(root) != null || blockOverridePresent(root)

    /** What `params[2]` (the state override) is, as far as this node is
     *  concerned. Three outcomes, because collapsing them is how a caller ends
     *  up with an answer to a question they didn't ask:
     *   - [Absent]: no parameter, JSON null, or a map that changes nothing —
     *     serve normally.
     *   - [Valid]: an override to apply (or refuse, if the backend can't).
     *   - [Malformed]: structurally wrong. REFUSED, never treated as absent:
     *     serving it would run the call against unmodified state and report
     *     VERIFIED. Refusing here also keeps the error PERMANENT (-32602) — the
     *     engine's own parser would reject it too, but that failure crosses the
     *     backend boundary as a bare null and would be reported as retryable. */
    private sealed interface OverrideParam {
        object Absent : OverrideParam
        data class Valid(val json: String) : OverrideParam
        data class Malformed(val why: String) : OverrideParam
    }

    private fun stateOverrideParam(root: JsonObject): OverrideParam {
        val raw = root.params()?.getOrNull(2) ?: return OverrideParam.Absent
        if (raw is JsonNull) return OverrideParam.Absent
        val ov = raw as? JsonObject
            ?: return OverrideParam.Malformed("state override must be an object keyed by address")
        var changesExecution = false
        for ((addr, entry) in ov) {
            if (!ADDRESS_HEX.matches(addr)) {
                return OverrideParam.Malformed("state override key '$addr' is not a 20-byte address")
            }
            // An explicit null is "no override for this account" — geth reads it
            // the same way (null unmarshals to a zero-valued override).
            if (entry is JsonNull) continue
            val fields = entry as? JsonObject
                ?: return OverrideParam.Malformed("state override for '$addr' must be an object")
            for (k in fields.keys) {
                if (k !in OVERRIDE_FIELDS) {
                    return OverrideParam.Malformed("unsupported state override field '$k'")
                }
            }
            if (fields.isNotEmpty()) changesExecution = true
        }
        if (!changesExecution) return OverrideParam.Absent
        return OverrideParam.Valid(json.encodeToString(JsonObject.serializer(), ov))
    }

    /** [stateOverrideParam]'s JSON when it is one to apply, else null. */
    private fun stateOverrideJson(root: JsonObject): String? =
        (stateOverrideParam(root) as? OverrideParam.Valid)?.json

    /** `blockOverrides` (params[3]) — NOT applied by this node, so its presence
     *  forces the refusal path even when the state override could be served. */
    private fun blockOverridePresent(root: JsonObject): Boolean =
        (root.params()?.getOrNull(3) as? JsonObject)?.isNotEmpty() == true

    /** True when the request is a contract-creation `eth_call`: `to` absent or
     *  explicitly null. A present-but-malformed `to` is NOT creation — running
     *  init code the caller never asked to run would be worse than refusing. */
    private fun isContractCreation(root: JsonObject): Boolean {
        val callObj = root.params()?.getOrNull(0) as? JsonObject ?: return false
        val to = callObj["to"]
        return to == null || to is JsonNull
    }

    /** What an `eth_estimateGas` request asks of this node (#509): a
     *  transaction to [Serve], or why it can never be served here ([Refuse],
     *  answered -32602). ONE derivation for the handler (which serves or
     *  declines) and the strict branch (which names the reason), so the two can
     *  never disagree about which question is being answered. */
    private sealed interface EstimateTx {
        class Serve(val tx: RpcTransactionArgs, val selector: Selector) : EstimateTx {
            val block: String get() = selector.value
        }
        class Refuse(val why: String) : EstimateTx
    }

    private fun estimateTx(root: JsonObject): EstimateTx {
        val callObj = root.params()?.getOrNull(0) as? JsonObject
            ?: return EstimateTx.Refuse("eth_estimateGas expects a transaction object as its first parameter")
        val tx = when (val parsed = RpcTransactionArgs.parse(callObj)) {
            is RpcTransactionArgs.Parsed.Invalid ->
                return EstimateTx.Refuse("invalid transaction object: ${parsed.why}")
            is RpcTransactionArgs.Parsed.Valid -> parsed.tx
        }
        val block = when (val selector = txBlock(root.params()?.getOrNull(1), "eth_estimateGas")) {
            is SelectorParse.Refuse -> return EstimateTx.Refuse(selector.why)
            is SelectorParse.Ok -> selector.selector
        }
        unservableTx(tx, "eth_estimateGas", "an estimate without it would be for a different transaction")
            ?.let { return EstimateTx.Refuse(it) }
        val be = backend ?: return EstimateTx.Serve(tx, block)
        if (tx.to == null && !be.supportsContractCreation()) {
            return EstimateTx.Refuse(
                "eth_estimateGas without a 'to' (contract creation) is not supported by this node's engine",
            )
        }
        return EstimateTx.Serve(tx, block)
    }

    /** What an `eth_call` request asks of this node (#509), as [EstimateTx] for
     *  `eth_estimateGas`: the transaction object to [CallTx.Serve] — through the
     *  engine's transaction-object call when it carries anything beyond
     *  from/to/data/value, the plain call otherwise — or why it can never be
     *  served here ([CallTx.Refuse], answered -32602). ONE derivation for the
     *  handler and the strict branch. */
    private sealed interface CallTx {
        class Serve(val tx: RpcTransactionArgs, val selector: Selector) : CallTx {
            val block: String get() = selector.value
        }
        class Refuse(val why: String) : CallTx
    }

    private fun callTx(root: JsonObject): CallTx {
        val callObj = root.params()?.getOrNull(0) as? JsonObject
            ?: return CallTx.Refuse("eth_call expects a transaction object as its first parameter")
        val tx = when (val parsed = RpcTransactionArgs.parse(callObj)) {
            is RpcTransactionArgs.Parsed.Invalid -> return CallTx.Refuse("invalid transaction object: ${parsed.why}")
            is RpcTransactionArgs.Parsed.Valid -> parsed.tx
        }
        // Every selector form — tag, number, EIP-1898's object — is applied or
        // refused exactly as for eth_estimateGas ([txBlock], #366).
        val block = when (val selector = txBlock(root.params()?.getOrNull(1), "eth_call")) {
            is SelectorParse.Refuse -> return CallTx.Refuse(selector.why)
            is SelectorParse.Ok -> selector.selector
        }
        unservableTx(tx, "eth_call", "the call would run without it")?.let { return CallTx.Refuse(it) }
        return CallTx.Serve(tx, block)
    }

    /** What this node's engine cannot apply of [tx] for [method] — a `chainId`
     *  for another chain, a list the engine does not apply — as the -32602
     *  reason, or null. [without] says what answering anyway would mean. ONE
     *  copy for eth_call and eth_estimateGas, so neither can drop what the
     *  other refuses. */
    private fun unservableTx(tx: RpcTransactionArgs, method: String, without: String): String? {
        val be = backend ?: return null
        tx.chainId?.let { requested ->
            if (requested != be.chainId().toString()) {
                return "invalid transaction object: chainId $requested does not match this node's chain (${be.chainId()})"
            }
        }
        if ((tx.hasAuthorizationList || tx.hasAccessList) && !be.supportsTransactionLists()) {
            val field = if (tx.hasAuthorizationList) "an authorizationList (EIP-7702)" else "an accessList"
            return "$method with $field is not supported by this node's engine (the field was rejected, not " +
                "ignored — $without)"
        }
        return null
    }

    /** [method]'s block selector (`params[1]`), applied or refused — never
     *  silently read as the head: [parseSelector]'s reading of a
     *  `BlockNumberOrHash`, less a block hash (bare or `{"blockHash": …}`),
     *  which names historical state this node does not hold. eth_call and
     *  eth_estimateGas read every selector through it, so a refusal here is
     *  the same in the handler and in the strict branch. */
    private fun txBlock(param: JsonElement?, method: String): SelectorParse {
        val parsed = parseSelector(param, 1, Takes.NUMBER_OR_HASH)
        return if (parsed is SelectorParse.Ok && parsed.selector.hash) {
            SelectorParse.Refuse("$method at a block hash is not supported (this node holds no historical state)")
        } else {
            parsed
        }
    }

    /** The methods that take override parameters. `eth_call` and
     *  `eth_estimateGas` state overrides are APPLIED when the backend supports
     *  them; `blockOverrides` are refused. */
    private fun takesOverrides(method: String?): Boolean =
        method == "eth_call" || method == "eth_estimateGas"

    /**
     * Handle one request object, returning its complete JSON-RPC response envelope.
     * [wholeBody] is the original request text used for the single-request proxy path;
     * null for a batch element (re-serialized and proxied individually). [batchPos]
     * ("2/5") places a batch element in the slow-call watchdog's WARN; null for a
     * single request.
     */
    private suspend fun handleOne(root: JsonObject, wholeBody: String?, batchPos: String? = null): String? {
        // The request envelope (JSON-RPC 2.0 §4), checked before anything is
        // served: `jsonrpc` exactly "2.0", `method` a string, `id` — when
        // present — a string, a number or null. A request failing any of these
        // is answered -32600 with a null id when its own is unusable; reading
        // `method` with a cast instead of `jsonPrimitive` keeps a non-string one
        // (`"method": {}`) from throwing out of the router mid-response (#366).
        val rawId = root["id"]
        val idOk = rawId == null || validId(rawId)
        val id = if (idOk) rawId ?: JsonNull else JsonNull
        val method = (root["method"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
        val version = (root["jsonrpc"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
        val malformed = when {
            version != "2.0" -> "'jsonrpc' must be \"2.0\""
            method == null -> "'method' must be a string"
            !idOk -> "'id' must be a string, a number or null"
            else -> null
        }
        if (malformed != null || method == null) {
            logger.record(method ?: "<invalid>", idString(id), "ERROR", 0, -32600)
            return errorEnvelope(id, -32600, "Invalid Request: ${malformed ?: "'method' must be a string"}")
        }
        val idStr = idString(id)
        val phase = CallPhase()
        val response = logger.watch(method, idStr, batchPos, phase) {
            try {
                dispatchOne(root, wholeBody, method, id, idStr, phase)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e   // never swallow coroutine cancellation (client disconnect / shutdown)
            } catch (e: Exception) {
                // Nothing a handler throws may escape as a half-written HTTP
                // response: the server streams heartbeat bytes before the
                // answer, so an exception there truncates the body the client
                // is already reading, and takes every batch sibling with it.
                logger.record(method, idStr, "ERROR", 0, -32603)
                val detail = e.message?.takeIf { it.isNotBlank() } ?: (e::class.simpleName ?: "Exception")
                errorEnvelope(id, -32603, "Internal error: $detail")
            }
        }
        // A notification (no `id` member — JSON null is an id) is served but
        // never answered (JSON-RPC 2.0 §4.1).
        return if (rawId == null) null else response
    }

    /** Whether [id] may identify a request: a string, a number or null
     *  (JSON-RPC 2.0 §4) — not a boolean, object or array. */
    private fun validId(id: JsonElement): Boolean = when (id) {
        is JsonNull -> true
        is JsonPrimitive -> id.isString || id.content.toDoubleOrNull() != null
        else -> false
    }

    /** [handleOne]'s body: route one request, keeping [phase] current for the watchdog. */
    private suspend fun dispatchOne(
        root: JsonObject,
        wholeBody: String?,
        method: String,
        id: JsonElement,
        idStr: String,
        phase: CallPhase,
    ): String {
        if (method == "myotis_rpcCoverage") {
            logger.record(method, idStr, "LOCAL", 0)
            return resultEnvelope(id, logger.coverage())
        }
        // Local node-status introspection — the JSON-RPC counterpart of the daemon's
        // status / beacon-status IPC commands. Like myotis_rpcCoverage these bypass the
        // verified backend, so a myotis-aware client can poll sync progress even when the
        // node isn't synced / has no peers. -32601 when the host didn't wire a source.
        if (method == "myotis_status" || method == "myotis_beaconStatus") {
            val sr = statusReads
            if (sr == null) {
                logger.record(method, idStr, "ERROR", 0, -32601)
                return errorEnvelope(id, -32601, "method '$method' is not supported by this node")
            }
            phase.name = "status"
            // Isolate the read like the IPC command does (CommandHandler wraps dispatch in
            // try/catch): a throw becomes a JSON-RPC error envelope, never a raw Ktor 500.
            return try {
                // The reads can cross a JNI boundary into the native engine (the Rust host's
                // nativeStatusJson), so run them on the IO dispatcher rather than blocking the
                // Ktor CIO event loop — same as the verified handlers below. For the Java engine
                // these are cheap in-memory reads, so this is a no-op there.
                val result = withContext(rpcIoDispatcher) {
                    val uptime = sr.uptimeSeconds()   // read once so both fields/branches agree
                    if (method == "myotis_status") sr.statusJson(uptime)
                    else sr.beaconStatusJson(uptime)
                }
                logger.record(method, idStr, "LOCAL", 0)
                resultEnvelope(id, result)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e   // never swallow coroutine cancellation (client disconnect / shutdown)
            } catch (e: Exception) {
                logger.record(method, idStr, "ERROR", 0, -32603)
                val detail = e.message?.takeIf { it.isNotBlank() } ?: (e::class.simpleName ?: "Exception")
                errorEnvelope(id, -32603, "status read failed: $detail")
            }
        }
        // Local lifecycle control — the JSON-RPC counterpart of the daemon's pause /
        // resume IPC commands. Like the status methods these bypass the verified
        // backend: a Myotis-aware wallet pauses the node when its UI backgrounds and
        // wakes it (then polls myotis_status / myotis_beaconStatus until ready) before
        // its next burst of queries. -32601 when the host didn't wire a control seam.
        if (method == "myotis_pause" || method == "myotis_wakeup") {
            val lc = lifecycle
            if (lc == null) {
                logger.record(method, idStr, "ERROR", 0, -32601)
                return errorEnvelope(id, -32601, "method '$method' is not supported by this node")
            }
            // Isolate the transition like the status reads / IPC command do: a throw
            // becomes a JSON-RPC error envelope, never a raw Ktor 500.
            phase.name = "lifecycle"
            val tLc = TimeSource.Monotonic.markNow()
            return try {
                // pause()/wakeUp() tear down / rebuild networking (seconds) and can
                // cross a JNI boundary into the native engine — run them on the IO
                // dispatcher rather than blocking the Ktor CIO event loop, same as
                // the status handler and the verified handlers below.
                val r = withContext(rpcIoDispatcher) {
                    if (method == "myotis_pause") lc.pause() else lc.wakeUp()
                }
                // Unlike the status reads (hardcoded 0), record the REAL elapsed time:
                // a pause/wakeup takes seconds, and the access log is where that shows.
                logger.record(method, idStr, "LOCAL", elapsedMs(tLc))
                resultEnvelope(id, buildJsonObject {
                    put("ok", r.ok)
                    put("lifecycle", r.lifecycle)
                })
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e   // never swallow coroutine cancellation (client disconnect / shutdown)
            } catch (e: Exception) {
                logger.record(method, idStr, "ERROR", 0, -32603)
                val detail = e.message?.takeIf { it.isNotBlank() } ?: (e::class.simpleName ?: "Exception")
                errorEnvelope(id, -32603, "lifecycle op failed: $detail")
            }
        }
        phase.name = "backend"
        val t0 = TimeSource.Monotonic.markNow()
        val verified = try {
            tryVerified(method, id, root)
        } catch (e: EngineReadUnavailable) {
            // A backend read that failed WITH a reason: the same -32000 class
            // as the generic decline below, but carrying the engine's actual
            // diagnosis — e.g. "all 8 snap peer(s) failed to serve a
            // verifiable block: 8x peer returned 0 headers" (the 2026-09-02
            // stale-pool incident, whose generic "no peer / not synced" text
            // sent everyone chasing sync state while the node WAS synced).
            //
            // Deliberately no dev-proxy fallback here (unlike a bare-null
            // decline): the engine ENGAGED verified serving and produced a
            // diagnosis; forwarding to a proxy would mask exactly the failure
            // this path exists to surface.
            logger.record(method, idStr, "ERROR", elapsedMs(t0), -32000)
            // A STALE_ANCHOR park must keep its curated, actionable message on
            // this path too: the Rust engine reports the park through shared
            // read plumbing ("beacon not synced" via anchored_head), which now
            // arrives as an envelope — without this probe the operator
            // guidance would fire only for methods whose failures still cross
            // as bare nulls (PR review finding).
            staleAnchorMessage(method)?.let { return errorEnvelope(id, -32000, it) }
            return errorEnvelope(id, -32000,
                "method '$method' cannot be served verified right now: ${e.reason}")
        } catch (e: EngineRefused) {
            // The engine's PERMANENT refusal (e.g. an EVM fork this build cannot
            // price): -32602 with its reason, like the router's own override /
            // contract-creation refusals — no retry changes it, and -32000 is
            // documented as retryable. No dev-proxy fallback, for the same reason
            // as above: the engine engaged and decided.
            logger.record(method, idStr, "ERROR", elapsedMs(t0), -32602)
            return errorEnvelope(id, -32602, "method '$method' refused: ${e.reason}")
        } catch (e: InvalidParams) {
            // The REQUEST can never be served as asked (#366): malformed, out of
            // spec, or asking for something this node does not hold. Permanent,
            // so -32602 with the reason — -32000 is documented as retryable, and
            // a conforming client would retry it forever. A dev proxy still gets
            // its chance, as for the router's other refusals: unlike the engine
            // refusals above, nothing was asked of the engine.
            if (proxy == null) {
                logger.record(method, idStr, "ERROR", elapsedMs(t0), -32602)
                return errorEnvelope(id, -32602, e.why)
            }
            null
        }
        if (verified != null) {
            // Label the answer for what it IS. A served override ran over
            // verified state but under the CALLER'S hypothesis, so it is not a
            // chain fact; counting it as VERIFIED would overstate what this node
            // proved in the coverage map. Only a request that carried an
            // applicable override can have been served with one — a refusal
            // returns null above.
            val label =
                if (takesOverrides(method) && stateOverrideJson(root) != null) "SIMULATED"
                else "VERIFIED"
            // NB a code-3 REVERT response counts here too, deliberately: the
            // revert is a verified (or simulated) ANSWER, not a failure to
            // answer — coverage tracks "could we serve this", not "did the
            // contract say yes".
            logger.record(method, idStr, label, elapsedMs(t0))
            return verified
        }
        val m = method
        if (proxy == null) {
            // Strict (permissionless) mode: no verified answer, no proxy → error. We
            // refuse to serve unverified data. The MethodLogger still records every
            // rejected method, so myotis_rpcCoverage keeps mapping what the wallet needs.
            // -32601 = we don't implement it verified (wallet can stop asking); -32000 =
            // implemented but can't answer right now — no peer / not synced (retryable).
            // An override-bearing call is PERMANENTLY unanswerable on this build,
            // so it must not use -32000 — that code is documented (here, and in
            // the README integrators read) as retryable, and a client backing off
            // and retrying would spin forever instead of taking the fallback this
            // refusal exists to unlock. -32602 says what is true: the params are
            // structurally valid but unsupported, and no retry will change that.
            // -32602 (permanent) ONLY when the override genuinely cannot be
            // applied here: an unsupported KIND (blockOverrides, estimateGas), or
            // a backend that cannot apply overrides at all. A capable backend
            // that returned null did so for an ordinary reason — not synced, no
            // peer, out-of-window block — and those are
            // transient, so they must fall through to the retryable -32000
            // below. (A contract REVERT is neither: it is a verified answer,
            // served as code 3 by the eth_call handler and never reaching
            // here.) Getting this wrong tells a wallet to stop asking and pin
            // its public-node fallback for the session, which is the behaviour
            // #314 exists to remove.
            // NOTE the outer guard: only a request that actually CARRIES an
            // override can be refused for one. Without it every ordinary
            // eth_estimateGas failure (a revert, not synced) would come back
            // permanent — a pre-existing test caught exactly that.
            // A MALFORMED override is permanently invalid regardless of backend
            // capability, and its reason is worth returning: the engine's parser
            // would reject it too, but that crosses the boundary as a bare null
            // and would be reported retryable.
            (stateOverrideParam(root) as? OverrideParam.Malformed)?.let { bad ->
                if (takesOverrides(m)) {
                    logger.record(m, idStr, "ERROR", elapsedMs(t0), -32602)
                    return errorEnvelope(id, -32602, "invalid state override: ${bad.why}")
                }
            }
            // An eth_estimateGas transaction object this node cannot serve as
            // asked (#509): contradictory, for another chain, or carrying a field
            // this engine does not apply. Permanent, like the refusals around it.
            if (m == "eth_estimateGas") {
                (estimateTx(root) as? EstimateTx.Refuse)?.let { refusal ->
                    logger.record(m, idStr, "ERROR", elapsedMs(t0), -32602)
                    return errorEnvelope(id, -32602, refusal.why)
                }
            }
            if (m == "eth_call") {
                (callTx(root) as? CallTx.Refuse)?.let { refusal ->
                    logger.record(m, idStr, "ERROR", elapsedMs(t0), -32602)
                    return errorEnvelope(id, -32602, refusal.why)
                }
            }
            // Contract creation this build cannot serve is permanent, not retryable.
            if (m == "eth_call" && isContractCreation(root) &&
                backend?.supportsContractCreation() != true
            ) {
                logger.record(m, idStr, "ERROR", elapsedMs(t0), -32602)
                return errorEnvelope(
                    id,
                    -32602,
                    "method 'eth_call' without a 'to' (contract creation) is not supported by " +
                        "this node's engine",
                )
            }
            val overrideUnsupported = takesOverrides(m) && hasUnsupportedOverride(root) && (
                blockOverridePresent(root) ||            // never applied
                    backend?.supportsStateOverrides() != true   // this backend cannot
                )
            if (overrideUnsupported) {
                logger.record(m, idStr, "ERROR", elapsedMs(t0), -32602)
                return errorEnvelope(
                    id,
                    -32602,
                    "method '$m' with state/block overrides is not supported by this node " +
                        "(the override was rejected, not ignored — a result computed without " +
                        "it would answer a different question than you asked)",
                )
            }
            val code = if (m in VERIFIED_METHODS) -32000 else -32601
            logger.record(m, idStr, "ERROR", elapsedMs(t0), code)
            return if (m in VERIFIED_METHODS) {
                // A STALE_ANCHOR park deserves its own message: unlike ordinary
                // not-synced it will NOT progress on its own — a human must raise
                // the weak-subjectivity bound or accept the risk — and the generic
                // "no peer / not synced" text would send an operator chasing peers.
                // The code stays -32000 (retryable): the state CAN change without
                // the caller acting, once the user decides. Same off-event-loop
                // discipline as eth_syncing for the (non-blocking, but
                // FFI-crossing) syncState probe.
                staleAnchorMessage(m)?.let { return errorEnvelope(id, -32000, it) }
                errorEnvelope(id, -32000, "method '$m' cannot be served verified right now (no peer / not synced)")
            } else {
                errorEnvelope(id, -32601, "method '$m' is not supported by this permissionless node")
            }
        }
        // Dev-only proxy fallback (never used in production / strict mode).
        phase.name = "proxy"
        val pt0 = TimeSource.Monotonic.markNow()
        val forwardBody = wholeBody ?: json.encodeToString(JsonObject.serializer(), root)
        return try {
            val response = proxy.forward(forwardBody)
            logger.record(m, idStr, "PROXY", elapsedMs(pt0))
            response
        } catch (e: Exception) {
            // Upstream down/timeout: JSON-RPC error, not a raw HTTP 500, so the wallet copes.
            logger.record(m, idStr, "ERROR", elapsedMs(pt0), -32603)
            errorEnvelope(id, -32603, "upstream proxy error: ${e.message}")
        }
    }

    /**
     * Verified handlers (Phase B). Returns a JSON-RPC response string, or null to
     * fall through to the proxy — either because the method isn't served verified
     * yet, or because the node can't answer it verified right now (not synced, no
     * peer, head not beacon-anchored, or an unsupported block tag / malformed
     * params we'd rather let the upstream handle than reject).
     *
     * The state-reading handlers (eth_call / eth_getBalance / …) are BLOCKING, so
     * they run on the IO dispatcher to keep the Ktor worker thread free.
     */
    /** Thrown inside [tryVerified] when a backend JSON read carried an engine
     *  {"error": ...} envelope; caught at the dispatch site in [handleOne] and
     *  surfaced as -32000 WITH the engine's reason instead of the generic
     *  no-peer/not-synced text. */
    private class EngineReadUnavailable(val reason: String) : RuntimeException(reason)

    /** Thrown inside [tryVerified] when the engine REFUSED an eth_call /
     *  eth_estimateGas for good ([RpcCallResult.Kind.REFUSED] — e.g. the Java
     *  engine past an EVM fork its Besu cannot price); caught at the dispatch
     *  site in [handleOne] and surfaced as the PERMANENT -32602 with the
     *  engine's reason, never the retryable -32000 a client would spin on. */
    private class EngineRefused(val reason: String) : RuntimeException(reason)

    /** Thrown inside [tryVerified] when the REQUEST can never be served as
     *  asked — a malformed or out-of-spec param, or one asking for something
     *  this node does not hold (#366). Caught at the dispatch site: -32602 with
     *  [why] in strict mode, the dev proxy otherwise. Raised where the param is
     *  read, so the refusal and the serve can never disagree about it. */
    private class InvalidParams(val why: String) : RuntimeException(why)

    private fun invalid(why: String): Nothing = throw InvalidParams(why)

    /** params[[i]], or refused as missing. */
    private fun JsonArray?.required(i: Int, what: String): JsonElement =
        this?.getOrNull(i)?.takeUnless { it is JsonNull } ?: invalid("missing argument $i: $what")

    /** params[[i]] as a 20-byte address. */
    private fun JsonArray?.addressAt(i: Int): ByteArray =
        required(i, "address").asHexBytes()?.takeIf { it.size == 20 }
            ?: invalid("invalid argument $i: expected a 20-byte address (0x + 40 hex digits)")

    /** params[[i]] as a 32-byte hash; [what] names it ("transaction hash"). */
    private fun JsonArray?.hashAt(i: Int, what: String): ByteArray =
        required(i, what).asHexBytes()?.takeIf { it.size == 32 }
            ?: invalid("invalid argument $i: expected a 32-byte $what (0x + 64 hex digits)")

    /** params[[i]] as hex data. */
    private fun JsonArray?.dataAt(i: Int, what: String): ByteArray =
        required(i, what).asHexBytes() ?: invalid("invalid argument $i: expected $what as 0x-prefixed hex")

    /** The `fullTransactions` flag at params[[i]]: absent or null is false; any
     *  other non-boolean is refused, never coerced into a different shape. */
    private fun JsonArray?.flagAt(i: Int): Boolean {
        val el = this?.getOrNull(i)
        if (el == null || el is JsonNull) return false
        return (el as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull
            ?: invalid("invalid argument $i: expected a boolean")
    }

    /** params[[i]] as a list index (a hex QUANTITY). */
    private fun JsonArray?.indexAt(i: Int): Int =
        required(i, "index").asQuantityIndex()
            ?: invalid("invalid argument $i: expected an index as a 0x-prefixed hex quantity")

    /** Which block selectors a method takes — geth's split: a `BlockNumber`
     *  (a tag or a number) or a `BlockNumberOrHash`, which adds a 32-byte
     *  block hash and EIP-1898's object form. */
    private enum class Takes { NUMBER, NUMBER_OR_HASH }

    /** A block selector as read: [value] is what the engine is handed — a tag,
     *  a 0x-number or a 0x-hash; [number] is set for a number, [hash] for a
     *  hash. */
    private class Selector(val value: String, val number: Long?, val hash: Boolean)

    /** A selector, or why it is refused — for the transaction methods, whose
     *  strict branch re-derives the refusal ([txBlock]), and for
     *  [selectorAt], which raises it. */
    private sealed interface SelectorParse {
        class Ok(val selector: Selector) : SelectorParse
        class Refuse(val why: String) : SelectorParse
    }

    /**
     * The ONE reading of a block selector, shared by every method that takes
     * one (#366): applied or refused, never silently read as the head.
     *  - absent or null: `latest`;
     *  - a tag: `latest`, `pending` and `finalized` (the last only on an engine
     *    that applies it — [RpcBackend.supportsFinalizedTag]); `safe` and
     *    `earliest` are refused, as nothing here serves the safe head or
     *    genesis;
     *  - a number: 0x-hex only. Bare digits are refused rather than guessed —
     *    the engines read them differently (the Java engine as decimal, the
     *    Rust block reads as hex);
     *  - where the method [takes] a `BlockNumberOrHash`: a 32-byte hash, bare or
     *    as `{"blockHash": …}`, and `{"blockNumber": …}` for a number. Any other
     *    object — or one where only a number is taken — is refused.
     * Pure: it reads only the param and the backend's static capabilities.
     */
    private fun parseSelector(param: JsonElement?, argIndex: Int, takes: Takes): SelectorParse {
        fun refuse(why: String) = SelectorParse.Refuse("invalid argument $argIndex: $why")
        // A bare string may name a hash where the method takes one; EIP-1898's
        // `blockNumber` field never does — 64 hex digits there are a number out
        // of range, not a hash to look the block up by.
        var hashAllowed = takes == Takes.NUMBER_OR_HASH
        val raw: String = when (param) {
            null, is JsonNull -> "latest"
            is JsonPrimitive -> param.takeIf { it.isString }?.contentOrNull?.trim()
                ?: return refuse("expected a block tag or a 0x-prefixed hex block number as a JSON string")
            is JsonObject -> {
                if (takes != Takes.NUMBER_OR_HASH) {
                    return refuse("expected a block tag or number; this method takes no EIP-1898 block object")
                }
                val byHash = param["blockHash"]?.takeUnless { it is JsonNull }
                val byNumber = param["blockNumber"]?.takeUnless { it is JsonNull }
                // `requireCanonical` is type-checked but needs nothing applied:
                // both engines resolve a hash only among the canonical blocks
                // they verified, so a non-canonical hash is unknown either way
                // (eth's null), as the flag asks.
                param["requireCanonical"]?.takeUnless { it is JsonNull }?.let {
                    if ((it as? JsonPrimitive)?.takeUnless { p -> p.isString }?.booleanOrNull == null) {
                        return refuse("'requireCanonical' must be a boolean")
                    }
                }
                when {
                    byHash != null && byNumber != null ->
                        return refuse("a block object takes 'blockHash' or 'blockNumber', not both")
                    byHash != null -> {
                        val h = (byHash as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.trim()
                        if (h == null || h.length != 66 || !isHex(h)) {
                            return refuse("'blockHash' must be a 32-byte hash (0x + 64 hex digits)")
                        }
                        return SelectorParse.Ok(Selector(h.lowercase(), number = null, hash = true))
                    }
                    byNumber != null -> {
                        hashAllowed = false
                        (byNumber as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.trim()
                            ?: return refuse("'blockNumber' must be a block tag or a 0x-prefixed hex number")
                    }
                    else -> return refuse("a block object needs 'blockHash' or 'blockNumber'")
                }
            }
            else -> return refuse("expected a block tag or a 0x-prefixed hex block number")
        }
        val s = raw.ifEmpty { "latest" }
        when (s) {
            "latest", "pending" -> return SelectorParse.Ok(Selector(s, number = null, hash = false))
            "finalized" -> return if (backend?.supportsFinalizedTag() == true) {
                SelectorParse.Ok(Selector(s, number = null, hash = false))
            } else {
                refuse("the 'finalized' tag is not served by this node's engine (it would be answered from " +
                    "the head, a different block); ask for 'latest' or a block number")
            }
            "safe" -> return refuse("the 'safe' tag is not served: this node tracks the verified head and the " +
                "beacon-finalized block, not the safe (justified) head; ask for 'latest' or 'finalized'")
            "earliest" -> return refuse("the 'earliest' tag (genesis) is not served: this node holds recent " +
                "blocks and state only")
        }
        if (!(s.startsWith("0x") || s.startsWith("0X")) || s.length <= 2 || !isHex(s)) {
            val shown = if (s.length > 70) s.take(70) + "…" else s
            return refuse("invalid block selector '$shown': expected latest, pending, finalized or a " +
                "0x-prefixed hex block number" + if (takes == Takes.NUMBER_OR_HASH) " or block hash" else "")
        }
        if (s.length == 66 && hashAllowed) {
            return SelectorParse.Ok(Selector(s.lowercase(), number = null, hash = true))
        }
        if (s.length == 66 && takes == Takes.NUMBER) {
            return refuse("a block hash is not a block number; this method takes a number or a tag")
        }
        val digits = s.substring(2).trimStart('0')
        // Leading zeros are tolerated (the value is unambiguous); past 63 bits
        // no block exists to name.
        val n = if (digits.isEmpty()) 0L else digits.takeIf { it.length <= 16 }?.toLongOrNull(16)
            ?: return refuse("block number $s is out of range")
        if (n == 0L) {
            return refuse("block 0 (genesis) is not served: this node holds recent blocks and state only")
        }
        return SelectorParse.Ok(Selector("0x" + n.toString(16), number = n, hash = false))
    }

    /** [parseSelector] for a handler in [tryVerified]: a refusal is raised. */
    private fun JsonArray?.selectorAt(i: Int, takes: Takes): Selector =
        when (val parsed = parseSelector(this?.getOrNull(i), i, takes)) {
            is SelectorParse.Ok -> parsed.selector
            is SelectorParse.Refuse -> invalid(parsed.why)
        }

    /** A state read's selector (eth_getBalance, eth_getCode, …): a
     *  `BlockNumberOrHash`, but a hash names a historical state this node does
     *  not hold — refused, never answered from the head. */
    private fun JsonArray?.stateSelectorAt(i: Int, method: String): Selector {
        val sel = selectorAt(i, Takes.NUMBER_OR_HASH)
        if (sel.hash) invalid("$method at a block hash is not supported (this node holds no historical state)")
        return sel
    }

    /**
     * Refuse a state read pinned to a block number BEHIND the window this node
     * serves state for ([RpcBlockWindow]) — permanent: the head only moves on,
     * and no engine holds older state. A pin AHEAD of the window is left to the
     * engine, which answers it retryably (the head may yet reach it), as is any
     * pin while no verified head is known. Inside the window the engine serves
     * head state — the documented near-head trade-off (#382).
     */
    private suspend fun refuseBehindWindow(sel: Selector, b: RpcBackend, method: String) {
        val n = sel.number ?: return
        val head = withContext(rpcIoDispatcher) { b.headBlockNumber() } ?: return
        if (n < head - RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE) {
            invalid("$method at block $n is not supported: it is more than " +
                "${RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE} blocks behind the verified head ($head), and this " +
                "node holds no historical state")
        }
    }

    /** `eth_feeHistory`'s block count at params[[i]]: what geth takes — a hex or
     *  decimal string, or a JSON number — at least 1, clamped to
     *  [MAX_FEE_HISTORY_BLOCKS] (see there). */
    private fun JsonArray?.feeHistoryBlockCountAt(i: Int): Long {
        val prim = required(i, "block count") as? JsonPrimitive
        val decimal = prim?.takeIf { it.isString || it.booleanOrNull == null }
            ?.let { RpcQuantities.parseWeiQuantity(it.content.trim()) }
            ?: invalid("invalid argument $i: expected the block count as a quantity")
        if (decimal == "0") invalid("invalid argument $i: the block count must be at least 1")
        // Past MAX_FEE_HISTORY_BLOCKS the exact value no longer matters: any
        // count that does not fit a Long is far beyond it.
        return minOf(decimal.toLongOrNull() ?: Long.MAX_VALUE, MAX_FEE_HISTORY_BLOCKS)
    }

    /** `eth_feeHistory`'s reward percentiles at params[[i]]: absent, null or an
     *  empty list ask for no reward column — as geth reads an empty one, so no
     *  `reward` field is answered for it; otherwise JSON numbers in [0, 100],
     *  non-decreasing, at most [MAX_FEE_HISTORY_PERCENTILES]. */
    private fun JsonArray?.rewardPercentilesAt(i: Int): DoubleArray? {
        val el = this?.getOrNull(i)
        if (el == null || el is JsonNull) return null
        val arr = el as? JsonArray ?: invalid("invalid argument $i: expected the reward percentiles as an array")
        if (arr.isEmpty()) return null
        if (arr.size > MAX_FEE_HISTORY_PERCENTILES) {
            invalid("invalid argument $i: at most $MAX_FEE_HISTORY_PERCENTILES reward percentiles, got ${arr.size}")
        }
        val vals = DoubleArray(arr.size)
        for (k in arr.indices) {
            val d = (arr[k] as? JsonPrimitive)?.takeUnless { it.isString }?.doubleOrNull
                ?: invalid("invalid argument $i: reward percentiles must be JSON numbers")
            if (d.isNaN() || d < 0.0 || d > 100.0) {
                invalid("invalid argument $i: reward percentile $d is outside [0, 100]")
            }
            if (k > 0 && vals[k - 1] > d) {
                invalid("invalid argument $i: reward percentiles must be non-decreasing")
            }
            vals[k] = d
        }
        return vals
    }

    /** Whether an engine `{"error": …}` envelope carries the PERMANENT code —
     *  the `{"error","code":-32602}` shape engines answer a request with when
     *  no retry can change the outcome. */
    private fun JsonObject?.permanentCode(): Boolean =
        (this?.get("code") as? JsonPrimitive)?.takeUnless { it.isString }?.contentOrNull == "-32602"

    private fun isHex(s: String): Boolean =
        (s.startsWith("0x") || s.startsWith("0X")) &&
            s.drop(2).all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    /** Unwrap an engine error envelope from a JSON-string read result: a
     *  single-key `{"error": ...}` object throws [EngineReadUnavailable] (so
     *  the call sites stay one-liners); every normal result — block object,
     *  receipt array, the literal "null" — passes through untouched. Engines
     *  return the envelope instead of a bare null exactly when the failure has
     *  a reason a wallet/operator needs (mirrors the eth_getLogs contract,
     *  which pioneered the shape for index-coverage errors). */
    private fun String.orEngineThrow(): String {
        // Fast path: both engines emit the envelope verbatim as {"error":...}
        // and nothing else starts that way (a block object starts with its own
        // first field), so a multi-MB full-transactions block is never parsed
        // twice just to prove it isn't an error.
        if (!startsWith("{\"error\"")) return this
        val parsed = try { json.parseToJsonElement(this) } catch (_: Exception) { return this }
        val obj = parsed as? JsonObject ?: return this
        // The envelope is `{"error"}`, or `{"error","code"}` when the engine
        // marks the refusal permanent; anything else is a result. Checking the
        // size alone served the coded form to the wallet AS A RESULT (#366).
        if (obj.size != 1 && !(obj.size == 2 && obj.containsKey("code"))) return this
        val err = obj["error"] ?: return this
        val msg = (err as? JsonPrimitive)?.contentOrNull ?: err.toString()
        if (obj.permanentCode()) throw EngineRefused(msg)
        throw EngineReadUnavailable(msg)
    }

    /** The curated STALE_ANCHOR refusal for [method], or null when the node
     *  isn't parked. Shared by the bare-null decline path and the
     *  [EngineReadUnavailable] path — the park must keep its actionable
     *  message ("raise the bound or accept the risk") no matter which shape
     *  the failure crossed the backend boundary in: unlike ordinary
     *  not-synced it will NOT progress without a human deciding. Same
     *  off-event-loop discipline as eth_syncing for the FFI-crossing probe. */
    private suspend fun staleAnchorMessage(method: String): String? {
        val be = backend ?: return null
        val parked = withContext(rpcIoDispatcher) { be.syncState() == RpcSyncState.STALE_ANCHOR }
        if (!parked) return null
        return "method '$method' refused: the node's trust anchor is past the " +
            "weak-subjectivity bound and syncing is paused awaiting user " +
            "consent — raise the bound or accept the risk (Settings / " +
            "accept-stale-anchor; details via myotis_beaconStatus)"
    }

    private suspend fun tryVerified(method: String, id: JsonElement, root: JsonObject): String? {
        val b = backend ?: return null
        return when (method) {
            // Chain id is config-derived — always answerable, no sync needed.
            "eth_chainId" -> resultEnvelope(id, JsonPrimitive(hexQuantity(b.chainId())))
            "net_version" -> resultEnvelope(id, JsonPrimitive(b.chainId().toString()))
            // Client identity string — no chain data, no verification. rotki's node
            // connectivity check calls this first and rejects the node if it errors,
            // so a static identifier (not a proxy/-32601) is what lets rotki connect.
            "web3_clientVersion" -> resultEnvelope(id, JsonPrimitive("Myotis/verified-light-client"))
            // Sync status straight from the beacon light client: `false` once
            // SYNCED (the spec's "not syncing"), else a syncing object. Both
            // arms answer PROMPTLY from the non-blocking syncState() — no
            // headBlockNumber here, whose wake-and-hold (up to the 90s wake
            // cap) would hang exactly the probe a wallet uses to decide
            // whether the node is alive. The verified surface has no
            // block-download notion (checkpoint bootstrap + sync-committee
            // catch-up) and serves no reads before SYNCED, so zero bounds are
            // the honest report; the object's truthy-ness is what clients act
            // on (and progress-computing ones read 0%, never a false 100%).
            "eth_syncing" -> {
                // syncState() is non-blocking by contract, but on the Rust engine it
                // still crosses an FFI — keep it off the server's event loop like
                // every other backend read.
                val synced = withContext(rpcIoDispatcher) {
                    b.syncState() == RpcSyncState.SYNCED
                }
                if (synced) {
                    resultEnvelope(id, JsonPrimitive(false))
                } else {
                    resultEnvelope(id, buildJsonObject {
                        put("startingBlock", hexQuantity(0L))
                        put("currentBlock", hexQuantity(0L))
                        put("highestBlock", hexQuantity(0L))
                    })
                }
            }
            // Verified beacon head; null (not synced) -> proxy. BLOCKING like every read
            // below (a paused or warming stack holds it in the wake gate), so it runs on
            // the IO dispatcher too — which also leaves the slow-call watchdog free to
            // report it while it is held.
            "eth_blockNumber" -> withContext(rpcIoDispatcher) { b.headBlockNumber() }
                ?.let { resultEnvelope(id, JsonPrimitive(hexQuantity(it))) }

            "eth_call" -> {
                // An override the ENGINE can apply is served (and labelled
                // SIMULATED below); one it cannot is `null` here — the file's
                // existing "can't serve this verified" signal — so a dev proxy
                // still gets its chance, and strict mode answers -32602.
                // Never answer an override-bearing call from unmodified state:
                // that is a well-formed result to a different question.
                // blockOverrides are never applied, so their presence refuses on
                // its own — regardless of whether a state override accompanies
                // them (checking only the pair would serve a blockOverrides-only
                // request against an unmodified block context: a well-formed
                // answer to a different question, the very defect this closes).
                if (blockOverridePresent(root)) return null
                if (stateOverrideParam(root) is OverrideParam.Malformed) return null
                val overrideJson = stateOverrideJson(root)
                // The whole transaction object (#509): every field is applied or
                // the request is refused, and a refusal is `null` here so a dev
                // proxy still gets its chance and strict mode names it ([callTx],
                // the one source of truth for both).
                val serve = callTx(root) as? CallTx.Serve ?: return null
                val tx = serve.tx
                // `to` absent or null is CONTRACT CREATION — the calldata is init
                // code and its return data is the answer (the deployless Deploy
                // form).
                val to = tx.to
                // Ask BEFORE dispatching. On an engine that can't serve creation
                // (the Java engine is still the default) the call would wake a
                // paused stack, wait for a verified head, and refuse anyway —
                // an expensive refusal where there used to be a free one, and
                // reported as retryable though it is permanent for that build.
                if (to == null && backend?.supportsContractCreation() != true) return null
                // A pin behind the state window is permanent whatever the engine
                // (#366); judged here, against the head as of dispatch, so the
                // strict branch's re-derivation ([callTx]) stays a pure function
                // of the request.
                refuseBehindWindow(serve.selector, b, "eth_call")
                // The caller (msg.sender): absent/null is anonymous (the backend uses
                // the zero-address default). Threading it is what lets a wallet's
                // confirm-screen simulation of a sender-gated call (ERC-20
                // transfer/approve, …) run as the real `from` instead of reverting
                // "transfer from the zero address". The calldata is `input`, else
                // `data` (the parser refused a differing pair), and the value is
                // decimal wei — the FFI-neutral boundary.
                val outcome = withContext(rpcIoDispatcher) {
                    if (tx.hasExtendedFields) {
                        // Gas, fees or lists: only the transaction-object call
                        // applies them.
                        b.callTx(tx, serve.block, overrideJson)
                    } else {
                        // Nothing beyond from/to/data/value: the plain call, as always.
                        b.callDetailed(tx.from, to, tx.data, tx.valueWei, serve.block, overrideJson)
                    }
                }
                when (outcome.kind) {
                    RpcCallResult.Kind.OK ->
                        resultEnvelope(id, JsonPrimitive(hexData(outcome.data ?: ByteArray(0))))
                    // A revert is a VERIFIED chain answer (the contract said no),
                    // not a failure to answer: return the standard shape wallets
                    // parse — geth's code 3 with the raw revert payload attached.
                    // Falling through to -32000 here made clients treat a normal
                    // negative answer (e.g. an ERC-165 probe on a plain ERC-20)
                    // as a node outage — MetaMask's token-standard detection then
                    // aborts and its confirmation screen never renders.
                    RpcCallResult.Kind.REVERTED ->
                        revertEnvelope(id, outcome.data ?: ByteArray(0))
                    // No verified answer right now — fall through to the strict
                    // retryable -32000 (or the dev proxy), exactly as before.
                    RpcCallResult.Kind.UNAVAILABLE -> return null
                    // Never answerable on this build: permanent -32602 (handleOne).
                    RpcCallResult.Kind.REFUSED -> throw EngineRefused(outcome.detail ?: "refused")
                    // An answer (#509): the call cannot succeed within the caller's
                    // gas, fee cap or funds. Served exactly as geth serves it —
                    // -32000 with geth's message — never as return data.
                    RpcCallResult.Kind.INFEASIBLE -> errorEnvelope(id, -32000, outcome.detail ?: "out of gas")
                }
            }
            // The state reads: every param applied or refused (#366) — a malformed
            // one is -32602, never the retryable "cannot be served right now" — and
            // a block pinned behind the state window refused before the engine is
            // asked ([refuseBehindWindow]).
            "eth_getBalance" -> {
                val p = root.params()
                val addr = p.addressAt(0)
                val sel = p.stateSelectorAt(1, "eth_getBalance").also { refuseBehindWindow(it, b, "eth_getBalance") }
                val bal = withContext(rpcIoDispatcher) { b.getBalance(addr, sel.value) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantityDecimal(bal)))
            }
            "eth_getTransactionCount" -> {
                val p = root.params()
                val addr = p.addressAt(0)
                val sel = p.stateSelectorAt(1, "eth_getTransactionCount")
                    .also { refuseBehindWindow(it, b, "eth_getTransactionCount") }
                val nonce = withContext(rpcIoDispatcher) { b.getTransactionCount(addr, sel.value) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantity(nonce)))
            }
            "eth_getCode" -> {
                val p = root.params()
                val addr = p.addressAt(0)
                val sel = p.stateSelectorAt(1, "eth_getCode").also { refuseBehindWindow(it, b, "eth_getCode") }
                val code = withContext(rpcIoDispatcher) { b.getCode(addr, sel.value) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(code)))
            }
            "eth_getStorageAt" -> {
                val p = root.params()
                val addr = p.addressAt(0)
                val slot = p.required(1, "storage slot").asWord32()
                    ?: invalid("invalid argument 1: expected a storage slot (a hex quantity or 32-byte word)")
                val sel = p.stateSelectorAt(2, "eth_getStorageAt").also { refuseBehindWindow(it, b, "eth_getStorageAt") }
                val v = withContext(rpcIoDispatcher) { b.getStorageAt(addr, slot, sel.value) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(v)))
            }
            "eth_sendRawTransaction" -> {
                val raw = root.params().dataAt(0, "the signed transaction")
                if (raw.isEmpty()) invalid("invalid argument 0: the signed transaction is empty")
                val hash = withContext(rpcIoDispatcher) { b.sendRawTransaction(raw) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(hash)))
            }
            "eth_getTransactionReceipt" -> {
                val txHash = root.params().hashAt(0, "transaction hash")
                // Backend contract: a receipt JSON object when found+verified; the literal
                // "null" for a VERIFIED "not seen yet" (synced, not in the recent chain →
                // eth's standard pending/unknown, a valid result); or Kotlin-null when it
                // CAN'T verify (not synced / no peer), which falls through to the strict
                // error — so we never tell the wallet "pending on a healthy chain" when we
                // actually couldn't check.
                val receiptJson = withContext(rpcIoDispatcher) { b.getTransactionReceipt(txHash) }?.orEngineThrow() ?: return null
                resultEnvelope(id, json.parseToJsonElement(receiptJson)) // "null" → JsonNull result
            }
            "eth_getTransactionByHash" -> {
                val txHash = root.params().hashAt(0, "transaction hash")
                // Object string when found (mined or pending-from-our-cache); "null" for a
                // verified-unknown tx; Kotlin null (can't verify) → strict error.
                val txJson = withContext(rpcIoDispatcher) { b.getTransactionByHash(txHash) }?.orEngineThrow() ?: return null
                resultEnvelope(id, json.parseToJsonElement(txJson))
            }
            "eth_getBlockByNumber" -> {
                val p = root.params()
                val sel = p.selectorAt(0, Takes.NUMBER)
                // Default false only when the flag is ABSENT; a present-but-non-boolean
                // value (number, "yes", object) is refused rather than silently coerced
                // to false and answered in the wrong shape.
                val fullTx = p.flagAt(1)
                // Object string when found; "null" for a future/unknown block; Kotlin null
                // (can't verify) → fall through to the strict error.
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(sel.value, fullTx) }?.orEngineThrow() ?: return null
                resultEnvelope(id, json.parseToJsonElement(blockJson))
            }
            "eth_getBlockByHash" -> {
                val p = root.params()
                // VerifiedReads takes the block hash as EXACTLY 32 bytes; anything else
                // names nothing verifiable and is refused.
                val blockHash = p.hashAt(0, "block hash")
                val fullTx = p.flagAt(1)
                // Object string when found; "null" for an unknown/non-canonical hash; Kotlin
                // null (can't verify) → strict error.
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, fullTx) }?.orEngineThrow() ?: return null
                resultEnvelope(id, json.parseToJsonElement(blockJson))
            }
            // ---- compat batch: answers derived from reads already served above ----
            // The node holds no keys and signs nothing: the accounts list is
            // exactly empty — a verified-grade constant, not a stub.
            "eth_accounts" -> resultEnvelope(id, JsonArray(emptyList()))
            // Dialer-only on TCP, but the discovery UDP listener is live whenever
            // the node runs — "actively listening for network connections" in the
            // sense health probes mean it. Config-derived like eth_chainId.
            "net_listening" -> resultEnvelope(id, JsonPrimitive(true))
            "net_peerCount" -> {
                // Served from the same status snapshot myotis_status exposes; no
                // status source wired, a throwing read (it can cross an FFI, like
                // the myotis_status handler guards for), or a snapshot without the
                // field → strict error, never a fabricated zero.
                val sr = statusReads ?: return null
                val peers = withContext(rpcIoDispatcher) {
                    try {
                        (sr.statusJson(sr.uptimeSeconds())["connectedPeers"] as? JsonPrimitive)
                            ?.contentOrNull?.toLongOrNull()
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        throw e // never swallow cancellation (the myotis_status rule)
                    } catch (e: Exception) {
                        null
                    }
                } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantity(peers)))
            }
            // Pure local compute (keccak-256 of the DATA param) — no chain state.
            "web3_sha3" -> {
                val data = root.params().dataAt(0, "the data to hash")
                resultEnvelope(id, JsonPrimitive(hexData(Keccak256.digest(data))))
            }
            // Counts/lookups below reuse the verified block serve and read the
            // answer out of its JSON — the tri-state (object | "null" | Kotlin
            // null) carries through unchanged.
            "eth_getBlockTransactionCountByNumber" -> {
                val block = root.params().selectorAt(0, Takes.NUMBER).value
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, false) }?.orEngineThrow() ?: return null
                blockArraySizeResult(id, blockJson, "transactions")
            }
            "eth_getBlockTransactionCountByHash" -> {
                val blockHash = root.params().hashAt(0, "block hash")
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, false) }?.orEngineThrow() ?: return null
                blockArraySizeResult(id, blockJson, "transactions")
            }
            "eth_getTransactionByBlockNumberAndIndex" -> {
                val p = root.params()
                val block = p.selectorAt(0, Takes.NUMBER).value
                val index = p.indexAt(1)
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, true) }?.orEngineThrow() ?: return null
                txAtIndexResult(id, blockJson, index)
            }
            "eth_getTransactionByBlockHashAndIndex" -> {
                val p = root.params()
                val blockHash = p.hashAt(0, "block hash")
                val index = p.indexAt(1)
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, true) }?.orEngineThrow() ?: return null
                txAtIndexResult(id, blockJson, index)
            }
            "eth_getUncleCountByBlockNumber" -> {
                val block = root.params().selectorAt(0, Takes.NUMBER).value
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, false) }?.orEngineThrow() ?: return null
                blockArraySizeResult(id, blockJson, "uncles")
            }
            "eth_getUncleCountByBlockHash" -> {
                val blockHash = root.params().hashAt(0, "block hash")
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, false) }?.orEngineThrow() ?: return null
                blockArraySizeResult(id, blockJson, "uncles")
            }
            "eth_getUncleByBlockNumberAndIndex" -> {
                val p = root.params()
                val block = p.selectorAt(0, Takes.NUMBER).value
                val index = p.indexAt(1)
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, false) }?.orEngineThrow() ?: return null
                uncleAtIndexResult(id, blockJson, index)
            }
            "eth_getUncleByBlockHashAndIndex" -> {
                val p = root.params()
                val blockHash = p.hashAt(0, "block hash")
                val index = p.indexAt(1)
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, false) }?.orEngineThrow() ?: return null
                uncleAtIndexResult(id, blockJson, index)
            }
            "eth_getBlockReceipts" -> {
                // One selector — geth's BlockNumberOrHash: a tag, a 0x-number, a
                // 0x-32-byte hash, or EIP-1898's object (absent → "latest" per spec).
                // Read by [parseSelector] like every other selector, so the same
                // request can never resolve to different blocks depending on which
                // engine is behind the router.
                val selector = root.params().selectorAt(0, Takes.NUMBER_OR_HASH).value
                // Array string when served; "null" for a verified unknown/future
                // block; Kotlin null (can't verify) → strict error.
                val receiptsJson =
                    withContext(rpcIoDispatcher) { b.getBlockReceipts(selector) }?.orEngineThrow() ?: return null
                resultEnvelope(id, json.parseToJsonElement(receiptsJson))
            }
            "eth_getLogs" -> {
                // One filter-object param. The engine owns filter semantics
                // (tags, address forms, positional topics) AND the coverage
                // honesty rule — a range the index hasn't covered comes back
                // as {"error": ...}, which we surface verbatim at -32000 so
                // wallets see WHY (e.g. how far the backfill has come)
                // instead of a bare cannot-serve.
                // A missing/non-object param is PERMANENTLY malformed — answer
                // -32602 instead of the retryable -32000 a null would produce
                // (wallets would retry a request that can never succeed).
                val filter = root.params()?.getOrNull(0) as? JsonObject
                    ?: return errorEnvelope(id, -32602, "eth_getLogs expects one filter object param")
                val resultJson = withContext(rpcIoDispatcher) { b.getLogs(filter.toString()) } ?: return null
                val parsed = json.parseToJsonElement(resultJson)
                val envelope = parsed as? JsonObject
                val errorMessage = envelope?.get("error")
                    ?.let { (it as? JsonPrimitive)?.contentOrNull ?: it.toString() }
                if (errorMessage != null) {
                    // The engine marks a refusal no retry can change with -32602
                    // (its documented `{"error","code":-32602}` envelope); anything
                    // else stays the retryable -32000.
                    errorEnvelope(id, if (envelope.permanentCode()) -32602 else -32000, errorMessage)
                } else {
                    resultEnvelope(id, parsed)
                }
            }
            "eth_gasPrice" -> {
                val price = withContext(rpcIoDispatcher) { b.gasPrice() } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantityDecimal(price)))
            }
            "eth_maxPriorityFeePerGas" -> {
                val tip = withContext(rpcIoDispatcher) { b.maxPriorityFeePerGas() } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantityDecimal(tip)))
            }
            "eth_feeHistory" -> {
                val p = root.params()
                val blockCount = p.feeHistoryBlockCountAt(0)
                // Required, as geth has it: a node that picked a block for the
                // caller would answer a question nobody asked (#366).
                if (p?.getOrNull(1).let { it == null || it is JsonNull }) {
                    invalid("missing argument 1: the newest block (a tag or a 0x-prefixed hex number)")
                }
                val newest = p.selectorAt(1, Takes.NUMBER).value
                val pctArr = p.rewardPercentilesAt(2)
                val historyJson = withContext(rpcIoDispatcher) { b.feeHistory(blockCount, newest, pctArr) }
                    ?.orEngineThrow() ?: return null
                resultEnvelope(id, json.parseToJsonElement(historyJson))
            }
            "eth_estimateGas" -> {
                val p = root.params()
                // The full transaction object (#509): every field is applied or
                // the request is refused. A refusal is `null` here — the file's
                // "can't serve this verified" signal — so a dev proxy still gets
                // its chance and strict mode answers -32602 with the reason
                // ([estimateTx], the one source of truth for both). Overrides
                // decline exactly as for eth_call: blockOverrides are never
                // applied, and a state override only by a backend that can.
                if (blockOverridePresent(root)) return null
                if (stateOverrideParam(root) is OverrideParam.Malformed) return null
                val overrideJson = stateOverrideJson(root)
                if (overrideJson != null && !b.supportsStateOverrides()) return null
                val serve = estimateTx(root) as? EstimateTx.Serve ?: return null
                refuseBehindWindow(serve.selector, b, "eth_estimateGas")
                val outcome = withContext(rpcIoDispatcher) { b.estimateGasTx(serve.tx, serve.block, overrideJson) }
                when (outcome.kind) {
                    RpcCallResult.Kind.OK ->
                        resultEnvelope(id, JsonPrimitive(hexQuantity(outcome.gas ?: return null)))
                    // The estimated transaction REVERTS: a verified answer, not a
                    // failure to answer — geth's shape for estimateGas too. -32000
                    // here made wallets show "node not synced" for a doomed tx.
                    RpcCallResult.Kind.REVERTED ->
                        revertEnvelope(id, outcome.data ?: ByteArray(0))
                    RpcCallResult.Kind.UNAVAILABLE -> return null
                    RpcCallResult.Kind.REFUSED -> throw EngineRefused(outcome.detail ?: "refused")
                    // Also an answer: the transaction does not fit the caller's gas
                    // or funds. Served exactly as geth serves it — -32000 with
                    // geth's message, which wallets match on — never as a number.
                    RpcCallResult.Kind.INFEASIBLE ->
                        errorEnvelope(id, -32000, outcome.detail ?: "gas required exceeds allowance")
                }
            }
            else -> null
        }
    }

    /** This request's `params` array, or null if absent / not an array. */
    private fun JsonObject.params(): JsonArray? = (this["params"] as? JsonArray)

    /** Decode a storage position (QUANTITY or 32-byte DATA) to a left-padded
     *  32-byte big-endian key; null if not a hex string or wider than 32 bytes. */
    private fun JsonElement.asWord32(): ByteArray? {
        val s = (this as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: return null
        var h = if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2) else s
        if (h.isEmpty()) return null                // "0x" is not a valid slot
        if (h.length % 2 != 0) h = "0$h"            // tolerate odd-length QUANTITY (e.g. "0x0")
        if (h.length > 64) return null
        return try {
            val raw = ByteArray(h.length / 2) {
                ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte()
            }
            ByteArray(32).also { raw.copyInto(it, 32 - raw.size) }
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    /** Parse a JSON-RPC QUANTITY index param (0x-hex string) as a non-negative
     *  Int; null only for MALFORMED input (non-string, no 0x, non-hex). A
     *  well-formed value too large for any real tx/uncle list (or with
     *  leading zeros pushing past Int) clamps to Int.MAX_VALUE — "past the
     *  end", which the callers answer with eth's null result, not an error. */
    private fun JsonElement.asQuantityIndex(): Int? {
        val s = (this as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: return null
        if (!(s.startsWith("0x") || s.startsWith("0X")) || s.length <= 2 || s.length > 66) return null
        val h = s.substring(2)
        if (!h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        val minimal = h.trimStart('0').ifEmpty { "0" }
        if (minimal.length > 8) return Int.MAX_VALUE // can't address any real list
        val v = minimal.toLong(16)
        return if (v <= Int.MAX_VALUE) v.toInt() else Int.MAX_VALUE
    }

    /** eth_getBlockTransactionCountBy* / eth_getUncleCountBy*: the size of the
     *  served block's [key] array as a QUANTITY. "null" (unknown block) passes
     *  through as a null result; a block object WITHOUT the array is shape
     *  drift → Kotlin null → strict error, never a fabricated zero. */
    private fun blockArraySizeResult(id: JsonElement, blockJson: String, key: String): String? {
        val el = json.parseToJsonElement(blockJson)
        if (el is JsonNull) return resultEnvelope(id, JsonNull)
        val arr = (el as? JsonObject)?.get(key) as? JsonArray ?: return null
        return resultEnvelope(id, JsonPrimitive(hexQuantity(arr.size.toLong())))
    }

    /** eth_getTransactionByBlock*AndIndex: `transactions[index]` of a fullTx
     *  block serve. Unknown block or an index past the end → eth's null. */
    private fun txAtIndexResult(id: JsonElement, blockJson: String, index: Int): String? {
        val el = json.parseToJsonElement(blockJson)
        if (el is JsonNull) return resultEnvelope(id, JsonNull)
        val txs = (el as? JsonObject)?.get("transactions") as? JsonArray ?: return null
        val tx = txs.getOrNull(index) ?: return resultEnvelope(id, JsonNull)
        return resultEnvelope(id, tx)
    }

    /** eth_getUncleByBlock*AndIndex: the verified window is post-merge, so a
     *  served block's uncle list is empty and any index is past the end →
     *  eth's null. A NON-empty list (unreachable today — pre-merge blocks
     *  aren't served) would be found-but-unrenderable (the block JSON carries
     *  only uncle hashes, not the uncle header this method returns) → Kotlin
     *  null → strict error, never null-as-if-absent. */
    private fun uncleAtIndexResult(id: JsonElement, blockJson: String, index: Int): String? {
        val el = json.parseToJsonElement(blockJson)
        if (el is JsonNull) return resultEnvelope(id, JsonNull)
        val uncles = (el as? JsonObject)?.get("uncles") as? JsonArray ?: return null
        return if (index < uncles.size) null else resultEnvelope(id, JsonNull)
    }

    /** Decode a `0x…` hex JSON string to bytes; null if not a hex string. */
    private fun JsonElement.asHexBytes(): ByteArray? {
        val s = (this as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: return null
        val h = if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2) else s
        if (h.length % 2 != 0) return null
        return try {
            ByteArray(h.length / 2) { ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte() }
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    /** Ethereum JSON-RPC QUANTITY encoding: minimal hex, no leading zeros, 0 -> "0x0". */
    private fun hexQuantity(v: Long): String = RpcQuantities.hexQuantity(v)

    /** QUANTITY encode a decimal wei string (the FFI-neutral form the backend returns for
     *  balances/fees). */
    private fun hexQuantityDecimal(decimal: String): String = RpcQuantities.hexQuantityDecimal(decimal)

    /** Ethereum JSON-RPC DATA encoding: 0x-prefixed, every byte rendered (leading
     *  zeros kept). Allocation-free — eth_getCode returns up to ~24KB of bytecode,
     *  so a String-per-byte encoder would churn the GC hard on Android. */
    private fun hexData(b: ByteArray): String {
        val out = CharArray(b.size * 2 + 2)
        out[0] = '0'; out[1] = 'x'
        for (i in b.indices) {
            val v = b[i].toInt() and 0xff
            out[i * 2 + 2] = HEX_DIGITS[v ushr 4]
            out[i * 2 + 3] = HEX_DIGITS[v and 0x0f]
        }
        return out.concatToString()
    }

    private fun resultEnvelope(id: JsonElement, result: JsonElement): String =
        json.encodeToString(JsonObject.serializer(), buildJsonObject {
            put("jsonrpc", JsonPrimitive("2.0"))
            put("id", id)
            put("result", result)
        })

    private fun errorEnvelope(id: JsonElement, code: Int, message: String): String =
        json.encodeToString(JsonObject.serializer(), buildJsonObject {
            put("jsonrpc", JsonPrimitive("2.0"))
            put("id", id)
            put("error", buildJsonObject {
                put("code", JsonPrimitive(code))
                put("message", JsonPrimitive(message))
            })
        })

    /**
     * The standard execution-reverted error (geth's shape, what ethers/viem/
     * MetaMask parse): code 3, `data` = the raw revert payload, and the message
     * suffixed with the decoded `Error(string)` reason when one is present.
     */
    private fun revertEnvelope(id: JsonElement, revertData: ByteArray): String =
        json.encodeToString(JsonObject.serializer(), buildJsonObject {
            put("jsonrpc", JsonPrimitive("2.0"))
            put("id", id)
            put("error", buildJsonObject {
                put("code", JsonPrimitive(3))
                val reason = decodeRevertReason(revertData)
                put("message", JsonPrimitive(
                    if (reason != null) "execution reverted: $reason" else "execution reverted"))
                put("data", JsonPrimitive(hexData(revertData)))
            })
        })

    /**
     * Best-effort human reason from a revert payload: the Solidity
     * `Error(string)` shape (selector 0x08c379a0 + ABI-encoded string) and
     * `Panic(uint256)` (0x4e487b71). Anything else — custom errors, empty data —
     * decodes to null and the message stays the bare "execution reverted"; the
     * raw payload is always in `data` for the client to decode itself.
     */
    private fun decodeRevertReason(d: ByteArray): String? {
        // A full 32-byte ABI word as a Long — null unless the high 24 bytes are
        // zero, so an invalid-ABI payload (which canonical decoders reject)
        // never decodes to a plausible reason here that disagrees with the
        // wallet's own decode of `data`.
        fun word(b: ByteArray, wordStart: Int): Long? {
            for (i in wordStart until wordStart + 24) if (b[i] != 0.toByte()) return null
            var v = 0L
            for (i in wordStart + 24 until wordStart + 32) v = (v shl 8) or (b[i].toLong() and 0xff)
            return v
        }
        if (d.size >= 4 + 32 && d[0] == 0x4e.toByte() && d[1] == 0x48.toByte() &&
            d[2] == 0x7b.toByte() && d[3] == 0x71.toByte()
        ) {
            val code = word(d, 4) ?: return null
            return "panic 0x" + code.toULong().toString(16)
        }
        if (d.size < 4 + 64) return null
        if (d[0] != 0x08.toByte() || d[1] != 0xc3.toByte() ||
            d[2] != 0x79.toByte() || d[3] != 0xa0.toByte()
        ) {
            return null
        }
        // 4-byte selector ‖ offset(32) ‖ len(32) ‖ bytes. Bounds are attacker-
        // controlled: validate every step and give up (null) on anything odd.
        val off = word(d, 4) ?: return null
        if (off < 0 || off > d.size.toLong()) return null
        val lenPos = 4 + off.toInt()
        if (lenPos + 32 > d.size) return null
        val len = word(d, lenPos) ?: return null
        if (len < 0 || len > 1024 || lenPos + 32 + len > d.size) return null
        val bytes = d.copyOfRange(lenPos + 32, lenPos + 32 + len.toInt())
        val s = bytes.decodeToString()
        // The reason is attacker-authored display text: keep it printable ASCII so
        // it can neither forge log lines (\n) nor visually spoof UIs (RTL override,
        // line separators). The raw bytes are always in `data` for exact decoding.
        return s.map { if (it.code in 32..126) it else ' ' }.joinToString("")
    }
}
