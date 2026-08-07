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
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
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
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private companion object {
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
    }

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
            is JsonObject -> handleOne(root, body)
            is JsonArray -> {
                // JSON-RPC 2.0 batch: each request gets its own response/error object so
                // a wallet (MetaMask batches heavily) can match them by id — not a single
                // error envelope. Elements are handled independently.
                if (root.isEmpty()) {
                    logger.record("<empty-batch>", "null", "ERROR", elapsedMs(t0), -32600)
                    return errorEnvelope(JsonNull, -32600, "Invalid Request")
                }
                val responses = root.map { el ->
                    (el as? JsonObject)?.let { handleOne(it, null) }
                        ?: run {
                            logger.record("<invalid>", "null", "ERROR", 0, -32600)
                            errorEnvelope(JsonNull, -32600, "Invalid Request")
                        }
                }
                "[" + responses.joinToString(",") + "]"
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

    /** The methods that take override parameters. `eth_call` state overrides
     *  are APPLIED when the backend supports them; `blockOverrides` and every
     *  `eth_estimateGas` override are refused. */
    private fun takesOverrides(method: String?): Boolean =
        method == "eth_call" || method == "eth_estimateGas"

    /**
     * Handle one request object, returning its complete JSON-RPC response envelope.
     * [wholeBody] is the original request text used for the single-request proxy path;
     * null for a batch element (re-serialized and proxied individually).
     */
    private suspend fun handleOne(root: JsonObject, wholeBody: String?): String {
        val method = root["method"]?.jsonPrimitive?.contentOrNull
        val id = root["id"] ?: JsonNull
        val idStr = idString(id)
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
        val t0 = TimeSource.Monotonic.markNow()
        val verified = tryVerified(method, id, root)
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
            logger.record(method!!, idStr, label, elapsedMs(t0))
            return verified
        }
        val m = method ?: "request"
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
            // peer, out-of-window block, a plain revert — and those are
            // transient, so they must fall through to the retryable -32000
            // below. Getting this wrong tells a wallet to stop asking and pin
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
            val overrideUnsupported = takesOverrides(m) && hasUnsupportedOverride(root) && (
                blockOverridePresent(root) ||            // never applied
                    m == "eth_estimateGas" ||            // executor path not wired
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
                errorEnvelope(id, -32000, "method '$m' cannot be served verified right now (no peer / not synced)")
            } else {
                errorEnvelope(id, -32601, "method '$m' is not supported by this permissionless node")
            }
        }
        // Dev-only proxy fallback (never used in production / strict mode).
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
    private suspend fun tryVerified(method: String?, id: JsonElement, root: JsonObject): String? {
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
            // Verified beacon head; null (not synced) -> proxy.
            "eth_blockNumber" -> b.headBlockNumber()?.let { resultEnvelope(id, JsonPrimitive(hexQuantity(it))) }

            "eth_call" -> {
                val p = root.params()
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
                val callObj = p?.getOrNull(0) as? JsonObject ?: return null
                val to = callObj["to"]?.asHexBytes() ?: return null   // contract creation (to=null) -> proxy
                // The caller (msg.sender). Absent/null -> anonymous (backend uses the
                // zero-address default); present-but-malformed -> proxy. Threading this
                // is what lets a wallet's confirm-screen simulation of a sender-gated
                // call (ERC-20 transfer/approve, …) run as the real `from` instead of
                // reverting "transfer from the zero address".
                val from = (callObj["from"]?.takeUnless { it is JsonNull })?.let { it.asHexBytes() ?: return null }
                // Absent/null calldata -> empty; present-but-malformed -> proxy
                // (don't silently run the call with empty calldata).
                val dataElement = (callObj["data"] ?: callObj["input"])?.takeUnless { it is JsonNull }
                val data = if (dataElement != null) (dataElement.asHexBytes() ?: return null) else ByteArray(0)
                // Optional call value (wei) — QUANTITY, unsigned <=256-bit; malformed /
                // negative / out-of-range -> proxy (a negative would throw in Wei.of).
                val valueElement = callObj["value"]?.takeUnless { it is JsonNull }
                val value = if (valueElement != null) {
                    val s = (valueElement as? JsonPrimitive)?.contentOrNull ?: return null
                    parseWeiQuantity(s) ?: return null
                } else null
                val block = p.blockTag(1)
                // VerifiedReads takes wei as a decimal string (FFI-neutral boundary).
                val out = withContext(rpcIoDispatcher) {
                    if (overrideJson != null) {
                        b.callWithOverrides(from, to, data, value, block, overrideJson)
                    } else {
                        b.call(from, to, data, value, block)
                    }
                } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(out)))
            }
            "eth_getBalance" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val block = p.blockTag(1)
                val bal = withContext(rpcIoDispatcher) { b.getBalance(addr, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantityDecimal(bal)))
            }
            "eth_getTransactionCount" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val block = p.blockTag(1)
                val nonce = withContext(rpcIoDispatcher) { b.getTransactionCount(addr, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantity(nonce)))
            }
            "eth_getCode" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val block = p.blockTag(1)
                val code = withContext(rpcIoDispatcher) { b.getCode(addr, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(code)))
            }
            "eth_getStorageAt" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val slot = (p?.getOrNull(1))?.asWord32() ?: return null
                val block = p.blockTag(2)
                val v = withContext(rpcIoDispatcher) { b.getStorageAt(addr, slot, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(v)))
            }
            "eth_sendRawTransaction" -> {
                val raw = (root.params()?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val hash = withContext(rpcIoDispatcher) { b.sendRawTransaction(raw) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(hash)))
            }
            "eth_getTransactionReceipt" -> {
                val txHash = (root.params()?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                // Backend contract: a receipt JSON object when found+verified; the literal
                // "null" for a VERIFIED "not seen yet" (synced, not in the recent chain →
                // eth's standard pending/unknown, a valid result); or Kotlin-null when it
                // CAN'T verify (not synced / no peer), which falls through to the strict
                // error — so we never tell the wallet "pending on a healthy chain" when we
                // actually couldn't check.
                val receiptJson = withContext(rpcIoDispatcher) { b.getTransactionReceipt(txHash) } ?: return null
                resultEnvelope(id, json.parseToJsonElement(receiptJson)) // "null" → JsonNull result
            }
            "eth_getTransactionByHash" -> {
                val txHash = (root.params()?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                // Object string when found (mined or pending-from-our-cache); "null" for a
                // verified-unknown tx; Kotlin null (can't verify) → strict error.
                val txJson = withContext(rpcIoDispatcher) { b.getTransactionByHash(txHash) } ?: return null
                resultEnvelope(id, json.parseToJsonElement(txJson))
            }
            "eth_getBlockByNumber" -> {
                val p = root.params()
                val block = p.blockTag(0)                          // tag or 0x hex number
                // Default false only when the flag is ABSENT; a present-but-non-boolean
                // value (number, "yes", object) falls through rather than being silently
                // coerced to false and returning the wrong shape.
                val fullParam = p?.getOrNull(1)
                val fullTx: Boolean = when {
                    fullParam == null || fullParam is JsonNull -> false
                    else -> (fullParam as? JsonPrimitive)?.booleanOrNull ?: return null
                }
                // Object string when found; "null" for a future/unknown block; Kotlin null
                // (can't verify) → fall through to the strict error.
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, fullTx) } ?: return null
                resultEnvelope(id, json.parseToJsonElement(blockJson))
            }
            "eth_getBlockByHash" -> {
                val p = root.params()
                // VerifiedReads takes the block hash as EXACTLY 32 bytes; a malformed or
                // wrong-length param falls through (proxy in dev, strict error otherwise).
                val blockHash = (p?.getOrNull(0))?.asHexBytes()?.takeIf { it.size == 32 } ?: return null
                val fullParam = p?.getOrNull(1)
                val fullTx: Boolean = when {
                    fullParam == null || fullParam is JsonNull -> false
                    else -> (fullParam as? JsonPrimitive)?.booleanOrNull ?: return null
                }
                // Object string when found; "null" for an unknown/non-canonical hash; Kotlin
                // null (can't verify) → strict error.
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, fullTx) } ?: return null
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
                val data = (root.params()?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(Keccak256.digest(data))))
            }
            // Counts/lookups below reuse the verified block serve and read the
            // answer out of its JSON — the tri-state (object | "null" | Kotlin
            // null) carries through unchanged.
            "eth_getBlockTransactionCountByNumber" -> {
                val block = root.params().specShapedBlockTag(0) ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, false) } ?: return null
                blockArraySizeResult(id, blockJson, "transactions")
            }
            "eth_getBlockTransactionCountByHash" -> {
                val blockHash = (root.params()?.getOrNull(0))?.asHexBytes()?.takeIf { it.size == 32 } ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, false) } ?: return null
                blockArraySizeResult(id, blockJson, "transactions")
            }
            "eth_getTransactionByBlockNumberAndIndex" -> {
                val p = root.params()
                val block = p.specShapedBlockTag(0) ?: return null
                val index = p?.getOrNull(1)?.asQuantityIndex() ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, true) } ?: return null
                txAtIndexResult(id, blockJson, index)
            }
            "eth_getTransactionByBlockHashAndIndex" -> {
                val p = root.params()
                val blockHash = (p?.getOrNull(0))?.asHexBytes()?.takeIf { it.size == 32 } ?: return null
                val index = p?.getOrNull(1)?.asQuantityIndex() ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, true) } ?: return null
                txAtIndexResult(id, blockJson, index)
            }
            "eth_getUncleCountByBlockNumber" -> {
                val block = root.params().specShapedBlockTag(0) ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, false) } ?: return null
                blockArraySizeResult(id, blockJson, "uncles")
            }
            "eth_getUncleCountByBlockHash" -> {
                val blockHash = (root.params()?.getOrNull(0))?.asHexBytes()?.takeIf { it.size == 32 } ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, false) } ?: return null
                blockArraySizeResult(id, blockJson, "uncles")
            }
            "eth_getUncleByBlockNumberAndIndex" -> {
                val p = root.params()
                val block = p.specShapedBlockTag(0) ?: return null
                val index = p?.getOrNull(1)?.asQuantityIndex() ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByNumber(block, false) } ?: return null
                uncleAtIndexResult(id, blockJson, index)
            }
            "eth_getUncleByBlockHashAndIndex" -> {
                val p = root.params()
                val blockHash = (p?.getOrNull(0))?.asHexBytes()?.takeIf { it.size == 32 } ?: return null
                val index = p?.getOrNull(1)?.asQuantityIndex() ?: return null
                val blockJson = withContext(rpcIoDispatcher) { b.getBlockByHash(blockHash, false) } ?: return null
                uncleAtIndexResult(id, blockJson, index)
            }
            "eth_getBlockReceipts" -> {
                val p = root.params()
                // One selector param: tag | 0x-hex number | 0x-32-byte hash (absent →
                // "latest" per spec). Validated HERE, strictly, because the two
                // engines' bare-numeric conventions differ (Java Long.decode reads
                // decimal, the Rust selector parser hex): only spec-shaped selectors
                // pass, so the same request can never resolve to different blocks
                // depending on which engine is behind the router. A JSON-number param
                // is rejected like the sibling hex helpers reject non-strings.
                val selParam = p?.getOrNull(0)
                // Trimmed like both backends trim it, so the gate here never rejects
                // a selector the engines would have served identically.
                val selector: String = when {
                    selParam == null || selParam is JsonNull -> "latest"
                    else -> (selParam as? JsonPrimitive)
                        ?.takeIf { it.isString }?.contentOrNull?.trim()?.ifEmpty { "latest" }
                        ?: return null
                }
                if (!specShapedSelector(selector)) return null
                // Array string when served; "null" for a verified unknown/future
                // block; Kotlin null (can't verify) → strict error.
                val receiptsJson =
                    withContext(rpcIoDispatcher) { b.getBlockReceipts(selector) } ?: return null
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
                val errorMessage = (parsed as? JsonObject)?.get("error")
                    ?.let { (it as? JsonPrimitive)?.contentOrNull ?: it.toString() }
                if (errorMessage != null) {
                    errorEnvelope(id, -32000, errorMessage)
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
                // blockCount is a QUANTITY (hex) per spec, but some clients send a JSON
                // number — accept both.
                val countPrim = p?.getOrNull(0) as? JsonPrimitive ?: return null
                val blockCount = countPrim.contentOrNull?.let { s ->
                    if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2).toLongOrNull(16)
                    else s.toLongOrNull()
                } ?: return null
                if (blockCount <= 0) return null
                val newest = p.blockTag(1)
                // Percentiles must be monotonically non-decreasing in [0,100]; a request
                // without them gets baseFee/gasUsedRatio only (no reward array).
                val pctArr: DoubleArray? = when (val pe = p.getOrNull(2)) {
                    null, is JsonNull -> null
                    is JsonArray -> {
                        val vals = DoubleArray(pe.size)
                        for (i in pe.indices) {
                            val d = (pe[i] as? JsonPrimitive)?.doubleOrNull ?: return null
                            if (d < 0.0 || d > 100.0) return null
                            if (i > 0 && vals[i - 1] > d) return null
                            vals[i] = d
                        }
                        vals
                    }
                    else -> return null
                }
                val historyJson = withContext(rpcIoDispatcher) { b.feeHistory(blockCount, newest, pctArr) }
                    ?: return null
                resultEnvelope(id, json.parseToJsonElement(historyJson))
            }
            "eth_estimateGas" -> {
                val p = root.params()
                if (hasUnsupportedOverride(root)) return null   // estimateGas: not wired yet
                val callObj = p?.getOrNull(0) as? JsonObject ?: return null
                val from = (callObj["from"]?.takeUnless { it is JsonNull })?.let { it.asHexBytes() ?: return null }
                // to=null is contract creation — supported (estimates the deploy).
                val to = (callObj["to"]?.takeUnless { it is JsonNull })?.let { it.asHexBytes() ?: return null }
                val dataElement = (callObj["data"] ?: callObj["input"])?.takeUnless { it is JsonNull }
                val data = if (dataElement != null) (dataElement.asHexBytes() ?: return null) else null
                val valueElement = callObj["value"]?.takeUnless { it is JsonNull }
                val value = if (valueElement != null) {
                    val s = (valueElement as? JsonPrimitive)?.contentOrNull ?: return null
                    parseWeiQuantity(s) ?: return null
                } else null
                val gas = withContext(rpcIoDispatcher) { b.estimateGas(from, to, data, value) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantity(gas)))
            }
            else -> null
        }
    }

    /** This request's `params` array, or null if absent / not an array. */
    private fun JsonObject.params(): JsonArray? = (this["params"] as? JsonArray)

    /** The block tag at [index] (e.g. "latest"), defaulting to "latest" when absent. */
    private fun JsonArray?.blockTag(index: Int): String =
        (this?.getOrNull(index) as? JsonPrimitive)?.contentOrNull ?: "latest"

    /** Spec-shaped block selector gate: a tag, or 0x-hex ASCII (≤ 66 chars —
     *  covers numbers and 32-byte hashes). Applied to every selector-taking
     *  method ADDED since the engines split, because their bare-numeric
     *  conventions differ (the Java engine reads bare as decimal — and octal
     *  under a leading zero — the Rust parser as hex): only spec shapes pass,
     *  so the same request can never resolve to different blocks depending on
     *  which engine is behind the router. Trimmed like both backends trim. */
    private fun specShapedSelector(s: String): Boolean =
        s in setOf("latest", "pending", "safe", "finalized", "earliest")
            || (s.length > 2 && s.length <= 66
                && (s.startsWith("0x") || s.startsWith("0X"))
                && s.drop(2).all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })

    /** [blockTag] + [specShapedSelector] for the compat batch's by-number
     *  methods: the trimmed spec-shaped selector, or null (→ proxy/strict). */
    private fun JsonArray?.specShapedBlockTag(index: Int): String? =
        blockTag(index).trim().ifEmpty { "latest" }.takeIf { specShapedSelector(it) }

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

    /** Parse a JSON-RPC QUANTITY (hex `0x…` or decimal) as a wei value, enforcing EVM
     *  semantics: unsigned and <= 256 bits. Returns the normalized DECIMAL string (the
     *  backend seam's wei form), or null for malformed / negative / out-of-range input.
     *  Shared by eth_call and eth_estimateGas so both apply identical value validation. */
    private fun parseWeiQuantity(s: String): String? = RpcQuantities.parseWeiQuantity(s)

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

    private fun JsonObject.method(): String? = this["method"]?.jsonPrimitive?.contentOrNull

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
}
