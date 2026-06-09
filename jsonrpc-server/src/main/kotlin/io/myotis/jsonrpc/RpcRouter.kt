package io.myotis.jsonrpc

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

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
    private val backend: MyotisRpcBackend? = null,
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private companion object {
        private val HEX_DIGITS = "0123456789abcdef".toCharArray()
    }

    suspend fun handle(body: String): String {
        val root = try {
            json.parseToJsonElement(body)
        } catch (e: Exception) {
            return errorEnvelope(JsonNull, -32700, "Parse error")
        }

        // Single request: try local + verified handlers before proxying.
        if (root is JsonObject) {
            val method = root["method"]?.jsonPrimitive?.contentOrNull
            val id = root["id"] ?: JsonNull
            if (method == "myotis_rpcCoverage") {
                logger.record(method, "LOCAL", 0)
                return resultEnvelope(id, logger.coverage())
            }
            val t0 = System.nanoTime()
            val verified = tryVerified(method, id, root)
            if (verified != null) {
                logger.record(method!!, "VERIFIED", (System.nanoTime() - t0) / 1_000_000)
                return verified
            }
        }

        val methods: List<String> = when (root) {
            is JsonArray -> root.mapNotNull { (it as? JsonObject)?.method() }
            is JsonObject -> listOfNotNull(root.method())
            else -> return errorEnvelope(JsonNull, -32600, "Invalid Request")
        }

        if (proxy == null) {
            // Strict mode: nothing to verify yet, no upstream → report unavailable.
            methods.forEach { logger.record(it, "ERROR", 0) }
            val id = (root as? JsonObject)?.get("id") ?: JsonNull
            return errorEnvelope(id, -32000, "no upstream configured (strict mode)")
        }

        val t0 = System.nanoTime()
        val response = try {
            proxy.forward(body)
        } catch (e: Exception) {
            // Upstream down/timeout: return a JSON-RPC error, not a raw HTTP 500,
            // so the wallet can handle it.
            methods.forEach { logger.record(it, "ERROR", (System.nanoTime() - t0) / 1_000_000) }
            val id = (root as? JsonObject)?.get("id") ?: JsonNull
            return errorEnvelope(id, -32603, "upstream proxy error: ${e.message}")
        }
        val latencyMs = (System.nanoTime() - t0) / 1_000_000
        methods.forEach { logger.record(it, "PROXY", latencyMs) }
        return response
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
            // Verified beacon head; null (not synced) -> proxy.
            "eth_blockNumber" -> b.headBlockNumber()?.let { resultEnvelope(id, JsonPrimitive(hexQuantity(it))) }

            "eth_call" -> {
                val p = root.params()
                val callObj = p?.getOrNull(0) as? JsonObject ?: return null
                val to = callObj["to"]?.asHexBytes() ?: return null   // contract creation (to=null) -> proxy
                // Absent/null calldata -> empty; present-but-malformed -> proxy
                // (don't silently run the call with empty calldata).
                val dataElement = (callObj["data"] ?: callObj["input"])?.takeUnless { it is JsonNull }
                val data = if (dataElement != null) (dataElement.asHexBytes() ?: return null) else ByteArray(0)
                val block = p.blockTag(1)
                val out = withContext(Dispatchers.IO) { b.call(to, data, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(out)))
            }
            "eth_getBalance" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val block = p.blockTag(1)
                val bal = withContext(Dispatchers.IO) { b.getBalance(addr, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantity(bal)))
            }
            "eth_getTransactionCount" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val block = p.blockTag(1)
                val nonce = withContext(Dispatchers.IO) { b.getTransactionCount(addr, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexQuantity(nonce)))
            }
            "eth_getCode" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val block = p.blockTag(1)
                val code = withContext(Dispatchers.IO) { b.getCode(addr, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(code)))
            }
            "eth_getStorageAt" -> {
                val p = root.params()
                val addr = (p?.getOrNull(0) as? JsonPrimitive)?.asHexBytes() ?: return null
                val slot = (p?.getOrNull(1))?.asWord32() ?: return null
                val block = p.blockTag(2)
                val v = withContext(Dispatchers.IO) { b.getStorageAt(addr, slot, block) } ?: return null
                resultEnvelope(id, JsonPrimitive(hexData(v)))
            }
            else -> null
        }
    }

    /** This request's `params` array, or null if absent / not an array. */
    private fun JsonObject.params(): JsonArray? = (this["params"] as? JsonArray)

    /** The block tag at [index] (e.g. "latest"), defaulting to "latest" when absent. */
    private fun JsonArray?.blockTag(index: Int): String =
        (this?.getOrNull(index) as? JsonPrimitive)?.contentOrNull ?: "latest"

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
    private fun hexQuantity(v: Long): String = "0x" + java.lang.Long.toHexString(v)
    private fun hexQuantity(v: java.math.BigInteger): String = "0x" + v.toString(16)

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
        return String(out)
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
