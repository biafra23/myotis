package io.myotis.jsonrpc

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull

/**
 * The JSON-RPC transaction object of an `eth_estimateGas` (geth's
 * `TransactionArgs`) as the router validated it (#509) — the pure-Kotlin
 * mirror of `io.myotis.api.TransactionArgs` (the jvmMain adapter maps 1:1).
 *
 * Every field changes the answer, so an engine applies each one or the router
 * refuses the request (-32602) — never answers with a field dropped. The
 * failure this exists for: a type-4 estimate whose `authorizationList` was
 * ignored ran the call against an EOA with no code, answered ~59k for a
 * transaction needing several hundred thousand, and the wallet's transaction
 * ran out of gas on chain.
 *
 * Two views of one object: [json] is the CANONICAL full object (lowercase hex,
 * minimal quantities, `input` for the calldata) for an engine that applies
 * every field — the Rust engine parses it, over UniFFI or the C ABI; the typed
 * fields are what an engine can apply without a JSON parser (the Java engine).
 * [chainId] and [type] are checked here and by the Rust engine.
 */
class RpcTransactionArgs private constructor(
    val from: ByteArray?,
    /** Null = contract creation (`to` absent or null). */
    val to: ByteArray?,
    val data: ByteArray,
    /** Decimal wei, or null (zero). */
    val valueWei: String?,
    /** The caller's gas limit, or null. Above 2^63−1 it reads as [Long.MAX_VALUE]:
     *  every engine's own ceiling is far lower, so both mean "no cap". */
    val gas: Long?,
    val gasPriceWei: String?,
    val maxFeePerGasWei: String?,
    val maxPriorityFeePerGasWei: String?,
    /** The transaction nonce, or null. Only an EIP-7702 authorization or a
     *  contract creation can observe it (see [hasExtendedFields]). */
    val nonce: Long?,
    /** The request's `chainId` in decimal, or null. */
    val chainId: String?,
    /** The explicit `type`, or null. */
    val type: Int?,
    /** A NON-EMPTY `accessList` is present (an empty one changes nothing). */
    val hasAccessList: Boolean,
    /** An `authorizationList` is present (never empty: that is refused). */
    val hasAuthorizationList: Boolean,
    val json: String,
) {
    /** Whether anything beyond from/to/data/value is present that an engine
     *  could APPLY: `gas`, a fee field, either list — or a `nonce` on a
     *  contract creation, whose address it decides. */
    val hasExtendedFields: Boolean
        get() = gas != null || gasPriceWei != null || maxFeePerGasWei != null ||
            maxPriorityFeePerGasWei != null || hasAccessList || hasAuthorizationList ||
            (to == null && nonce != null)

    /** Either a request to serve, or why it can never be served. */
    sealed interface Parsed {
        class Valid(val tx: RpcTransactionArgs) : Parsed
        class Invalid(val why: String) : Parsed
    }

    companion object {
        private val TYPE_LEGACY = 0
        private val TYPE_ACCESS_LIST = 1
        private val TYPE_DYNAMIC_FEE = 2
        private val TYPE_BLOB = 3
        private val TYPE_SET_CODE = 4

        /** 2^64 − 1 and 2^128 − 1 as minimal hex, for width checks on the
         *  normalized decimal the quantity parser returns. */
        private const val U64_HEX_DIGITS = 16
        private const val U128_HEX_DIGITS = 32

        private val BLOB_FIELDS =
            listOf("blobVersionedHashes", "maxFeePerBlobGas", "blobs", "commitments", "proofs", "sidecar")

        private class Refused(val why: String) : RuntimeException(why)

        /**
         * Parse and validate a call object. Shape rules match the Rust engine's
         * `parse_tx_request` and the cross-field rules `TxRequest::validate`, so
         * a request refused on one engine is refused on the other — and refused
         * HERE first, before any engine is woken. JSON null reads as absent;
         * unknown keys are ignored, as geth ignores them.
         */
        fun parse(obj: JsonObject): Parsed = try {
            Parsed.Valid(parseOrThrow(obj))
        } catch (e: Refused) {
            Parsed.Invalid(e.why)
        }

        private fun parseOrThrow(obj: JsonObject): RpcTransactionArgs {
            fun field(k: String): JsonElement? = obj[k]?.takeUnless { it is JsonNull }
            fun refuse(why: String): Nothing = throw Refused(why)

            for (blob in BLOB_FIELDS) {
                val v = field(blob) ?: continue
                if (v !is JsonArray || v.isNotEmpty()) {
                    refuse("blob transactions (type 0x3) are not supported by this node ('$blob')")
                }
            }
            val from = field("from")?.let { address(it) ?: refuse("'from' is not a 20-byte hex address") }
            val to = field("to")?.let { address(it) ?: refuse("'to' is not a 20-byte hex address") }
            val input = field("input")?.let { hexBytes(it) ?: refuse("'input' is not hex data") }
            val dataField = field("data")?.let { hexBytes(it) ?: refuse("'data' is not hex data") }
            if (input != null && dataField != null && !input.contentEquals(dataField)) {
                refuse("both 'data' and 'input' are set and not equal; use 'input'")
            }
            val data = input ?: dataField ?: ByteArray(0)

            fun quantity(k: String): String? = field(k)?.let {
                val s = (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.contentOrNull
                    ?: refuse("'$k' is not a quantity")
                RpcQuantities.parseWeiQuantity(s) ?: refuse("'$k' is not a quantity")
            }
            fun narrow(k: String, decimal: String?, hexDigits: Int): String? = decimal?.also {
                if (RpcQuantities.decimalToHex(it).length > hexDigits) refuse("'$k' exceeds ${hexDigits * 4} bits")
            }
            val value = quantity("value")
            val gas = narrow("gas", quantity("gas"), U64_HEX_DIGITS)
            val gasPrice = narrow("gasPrice", quantity("gasPrice"), U128_HEX_DIGITS)
            val maxFee = narrow("maxFeePerGas", quantity("maxFeePerGas"), U128_HEX_DIGITS)
            val maxPriority = narrow("maxPriorityFeePerGas", quantity("maxPriorityFeePerGas"), U128_HEX_DIGITS)
            val nonce = narrow("nonce", quantity("nonce"), U64_HEX_DIGITS)
            val chainId = quantity("chainId")
            val type = quantity("type")?.let {
                it.toIntOrNull()?.takeIf { t -> t <= 0xff } ?: refuse("unsupported transaction type $it")
            }
            if (gasPrice != null && (maxFee != null || maxPriority != null)) {
                refuse("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
            }
            if (nonce != null && RpcQuantities.decimalToHex(nonce) == "f".repeat(16)) {
                refuse("nonce 0xffffffffffffffff is not a valid transaction nonce (EIP-2681)")
            }

            val accessList = field("accessList")?.let { accessList(it) }
            val authorizations = field("authorizationList")?.let { authorizationList(it) }
            val hasAccessList = accessList != null && accessList.isNotEmpty()

            // The type the transaction IS: the explicit one, else derived in
            // revm's (and geth's) order.
            val effectiveType = type ?: when {
                authorizations != null -> TYPE_SET_CODE
                maxFee != null || maxPriority != null -> TYPE_DYNAMIC_FEE
                hasAccessList -> TYPE_ACCESS_LIST
                else -> TYPE_LEGACY
            }
            when (effectiveType) {
                TYPE_LEGACY, TYPE_ACCESS_LIST, TYPE_DYNAMIC_FEE, TYPE_SET_CODE -> Unit
                TYPE_BLOB -> refuse("blob transactions (type 0x3) are not supported by this node")
                else -> refuse("unsupported transaction type 0x${effectiveType.toString(16)}")
            }
            if ((maxFee != null || maxPriority != null) && effectiveType < TYPE_DYNAMIC_FEE) {
                refuse("maxFeePerGas/maxPriorityFeePerGas require transaction type 0x2 or later " +
                    "(the request names type 0x${effectiveType.toString(16)})")
            }
            // A missing maxFeePerGas is zero — as every engine reads it — so a
            // lone non-zero tip is already above its cap.
            if (maxPriority != null && compareDecimal(maxPriority, maxFee ?: "0") > 0) {
                refuse("maxPriorityFeePerGas ($maxPriority) is greater than maxFeePerGas (${maxFee ?: "0"})")
            }
            if (effectiveType == TYPE_LEGACY && hasAccessList) {
                refuse("accessList requires transaction type 0x1 or later (the request names type 0x0)")
            }
            when {
                authorizations == null && effectiveType == TYPE_SET_CODE ->
                    refuse("transaction type 0x4 requires an authorizationList")
                authorizations != null && effectiveType != TYPE_SET_CODE ->
                    refuse("authorizationList requires transaction type 0x4 (the request names " +
                        "type 0x${effectiveType.toString(16)})")
                authorizations != null && authorizations.isEmpty() ->
                    refuse("authorizationList must not be empty (EIP-7702)")
            }
            if (effectiveType == TYPE_SET_CODE && to == null) {
                refuse("an EIP-7702 transaction cannot create a contract: authorizationList needs a 'to'")
            }

            val canonical = buildJsonObject {
                from?.let { put("from", JsonPrimitive(hex(it))) }
                to?.let { put("to", JsonPrimitive(hex(it))) }
                put("input", JsonPrimitive(hex(data)))
                value?.let { put("value", JsonPrimitive(quantityHex(it))) }
                gas?.let { put("gas", JsonPrimitive(quantityHex(it))) }
                gasPrice?.let { put("gasPrice", JsonPrimitive(quantityHex(it))) }
                maxFee?.let { put("maxFeePerGas", JsonPrimitive(quantityHex(it))) }
                maxPriority?.let { put("maxPriorityFeePerGas", JsonPrimitive(quantityHex(it))) }
                nonce?.let { put("nonce", JsonPrimitive(quantityHex(it))) }
                chainId?.let { put("chainId", JsonPrimitive(quantityHex(it))) }
                type?.let { put("type", JsonPrimitive("0x" + it.toString(16))) }
                accessList?.let { put("accessList", it) }
                authorizations?.let { put("authorizationList", it) }
            }
            return RpcTransactionArgs(
                from = from,
                to = to,
                data = data,
                valueWei = value,
                gas = gas?.let { g -> g.toLongOrNull() ?: Long.MAX_VALUE },
                gasPriceWei = gasPrice,
                maxFeePerGasWei = maxFee,
                maxPriorityFeePerGasWei = maxPriority,
                nonce = nonce?.toLong(),
                chainId = chainId,
                type = type,
                hasAccessList = hasAccessList,
                hasAuthorizationList = authorizations != null,
                json = canonical.toString(),
            )
        }

        /** `[{address, storageKeys}]`, normalized. */
        private fun accessList(v: JsonElement): JsonArray {
            val items = v as? JsonArray ?: throw Refused("'accessList' must be an array")
            return buildJsonArray {
                for (item in items) {
                    val entry = item as? JsonObject ?: throw Refused("'accessList' entries must be objects")
                    val address = entry["address"]?.let { address(it) }
                        ?: throw Refused("'accessList' entry without a 20-byte 'address'")
                    val keys = entry["storageKeys"]?.takeUnless { it is JsonNull }?.let {
                        (it as? JsonArray ?: throw Refused("'storageKeys' must be an array")).map { k ->
                            hexBytes(k)?.takeIf { b -> b.size == 32 }
                                ?: throw Refused("'storageKeys' entries must be 32-byte hex")
                        }
                    } ?: emptyList()
                    add(buildJsonObject {
                        put("address", JsonPrimitive(hex(address)))
                        put("storageKeys", buildJsonArray { keys.forEach { add(JsonPrimitive(hex(it))) } })
                    })
                }
            }
        }

        /** `[{chainId, address, nonce, yParity (or v), r, s}]`, normalized to
         *  `yParity`. Only the SHAPE is checked: an invalid signature, a foreign
         *  chain id or a stale nonce makes a tuple invalid, which EIP-7702
         *  resolves by skipping it during execution — the engine's job, not a
         *  reason to refuse the transaction. */
        private fun authorizationList(v: JsonElement): JsonArray {
            val items = v as? JsonArray ?: throw Refused("'authorizationList' must be an array")
            return buildJsonArray {
                for (item in items) {
                    val auth = item as? JsonObject ?: throw Refused("'authorizationList' entries must be objects")
                    fun q(k: String, required: Boolean = true): String? {
                        val e = auth[k]?.takeUnless { it is JsonNull }
                            ?: if (required) throw Refused("authorization without '$k'") else return null
                        val s = (e as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
                            ?: throw Refused("authorization '$k' is not a quantity")
                        return RpcQuantities.parseWeiQuantity(s) ?: throw Refused("authorization '$k' is not a quantity")
                    }
                    val address = auth["address"]?.let { address(it) }
                        ?: throw Refused("authorization without a 20-byte 'address'")
                    val nonce = q("nonce")!!
                    if (RpcQuantities.decimalToHex(nonce).length > U64_HEX_DIGITS) {
                        throw Refused("authorization 'nonce' exceeds 64 bits")
                    }
                    // A legacy v of 27/28 is parity 0/1. Left as 27, recovery would
                    // fail and the tuple be SKIPPED — an estimate without the
                    // delegation the signed transaction carries, #509's own failure.
                    fun parity(p: String?) = when (p) { "27" -> "0"; "28" -> "1"; else -> p }
                    val yParity = parity(q("yParity", required = false))
                    val v = parity(q("v", required = false))
                    if (yParity != null && v != null && yParity != v) {
                        throw Refused("authorization 'yParity' and 'v' disagree")
                    }
                    val parity = yParity ?: v ?: throw Refused("authorization without 'yParity'")
                    if (RpcQuantities.decimalToHex(parity).length > 2) {
                        throw Refused("authorization 'yParity' exceeds 8 bits")
                    }
                    add(buildJsonObject {
                        put("chainId", JsonPrimitive(quantityHex(q("chainId")!!)))
                        put("address", JsonPrimitive(hex(address)))
                        put("nonce", JsonPrimitive(quantityHex(nonce)))
                        put("yParity", JsonPrimitive(quantityHex(parity)))
                        put("r", JsonPrimitive(quantityHex(q("r")!!)))
                        put("s", JsonPrimitive(quantityHex(q("s")!!)))
                    })
                }
            }
        }

        private fun address(e: JsonElement): ByteArray? = hexBytes(e)?.takeIf { it.size == 20 }

        private fun hexBytes(e: JsonElement): ByteArray? {
            val s = (e as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: return null
            val h = if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2) else s
            if (h.length % 2 != 0) return null
            return try {
                ByteArray(h.length / 2) { ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte() }
            } catch (e: IllegalArgumentException) {
                null
            }
        }

        private fun hex(b: ByteArray): String =
            "0x" + b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

        /** A normalized decimal as a minimal 0x-hex QUANTITY. */
        private fun quantityHex(decimal: String): String = "0x" + RpcQuantities.decimalToHex(decimal)

        /** Compare two normalized (no leading zeros) unsigned decimals. */
        private fun compareDecimal(a: String, b: String): Int =
            if (a.length != b.length) a.length.compareTo(b.length) else a.compareTo(b)
    }
}
