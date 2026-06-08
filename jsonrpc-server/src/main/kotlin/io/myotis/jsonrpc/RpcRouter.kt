package io.myotis.jsonrpc

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
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
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    suspend fun handle(body: String): String {
        val root = try {
            json.parseToJsonElement(body)
        } catch (e: Exception) {
            return errorEnvelope(JsonNull, -32700, "Parse error")
        }

        // Single request: may be a local method.
        if (root is JsonObject) {
            val method = root["method"]?.jsonPrimitive?.contentOrNull
            val id = root["id"] ?: JsonNull
            if (method == "myotis_rpcCoverage") {
                logger.record(method, "LOCAL", 0)
                return resultEnvelope(id, logger.coverage())
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
        val response = proxy.forward(body)
        val latencyMs = (System.nanoTime() - t0) / 1_000_000
        methods.forEach { logger.record(it, "PROXY", latencyMs) }
        return response
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
