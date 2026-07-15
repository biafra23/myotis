package io.myotis.ios

import io.myotis.jsonrpc.RpcBackend
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

/**
 * The iOS [RpcBackend]: `RustVerifiedReads`' twin over the C ABI, serving the
 * JSON-RPC listener from the same golden-pinned native JSON the JNI adapter
 * parses. Same conventions throughout: every method returns null rather than
 * throwing ("cannot answer verified right now"), block-number pins are only
 * served inside the [BLOCK_NUM_LAG_TOLERANCE]..[BLOCK_NUM_TOLERANCE] window
 * around the anchored head, verified-absent accounts read as balance "0" /
 * nonce 0, and plain transfers to verified-codeless EOAs take the 21000
 * fast-path without running the EVM.
 *
 * [handleProvider] resolves the network's engine handle at call time (null =
 * not running → every method answers null).
 */
class IosRpcBackend(
    private val chainId: Long,
    private val handleProvider: () -> Long?,
) : RpcBackend {

    override fun chainId(): Long = chainId

    override fun headBlockNumber(): Long? {
        val handle = handleProvider() ?: return null
        val o = statusOrNull(handle) ?: return null
        val head = o.long("optimisticBlockNumber")
        return if (head > 0) head else null
    }

    override fun getBalance(address: ByteArray, block: String): String? {
        if (!isServableBlock(block)) return null
        val r = queryAccount(address) ?: return null
        if (!r.verified) return null
        // Verified-absent account → balance "0": the proof of exclusion IS the
        // verified answer (same convention as RustVerifiedReads).
        return if (r.exists) r.balanceWei else "0"
    }

    override fun getTransactionCount(address: ByteArray, block: String): Long? {
        if (!isServableBlock(block)) return null
        val r = queryAccount(address) ?: return null
        if (!r.verified) return null
        return if (r.exists) r.nonce else 0L
    }

    override fun getCode(address: ByteArray, block: String): ByteArray? {
        if (!isServableBlock(block)) return null
        if (address.size != 20) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.getCodeJson(handle, hex(address))) ?: return null
        if (o.string("verifyMethod") == null) return null // unverified → can't answer
        return hexToBytes(o.string("codeHex")) // 0x / empty → empty bytecode (verified EOA)
    }

    override fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? {
        if (!isServableBlock(block)) return null
        if (address.size != 20 || slot32.size != 32) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.getStorageAtJson(handle, hex(address), hex(slot32))) ?: return null
        if (o.string("verifyMethod") == null) return null
        // Left-pad to the full 32-byte word (a zero/unset slot → 32 zero bytes).
        val raw = hexToBytes(o.string("valueHex")) ?: return null
        return ByteArray(32).also { raw.copyInto(it, 32 - raw.size) }
    }

    override fun call(from: ByteArray?, to: ByteArray, data: ByteArray, valueWei: String?, block: String): ByteArray? {
        if (!isServableBlock(block)) return null
        if (to.size != 20) return null
        if (from != null && from.size != 20) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.ethCallJson(
            handle,
            from?.let(::hex) ?: "",  // empty = anonymous zero sender
            hex(to),
            if (data.isEmpty()) "" else hex(data),
            valueWei ?: "",
            block,
        )) ?: return null
        // Only "ok" carries a result; a revert or unavailable outcome is "no
        // answer" → null (a reverting eth_call is a JSON-RPC null, not -32000).
        if (o.string("status") != "ok") return null
        return hexToBytes(o.string("resultHex"))
    }

    override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): Long? {
        // Contract creation (to=null) isn't handled verified.
        if (to == null || to.size != 20) return null
        if (from != null && from.size != 20) return null
        if (data == null || data.isEmpty()) {
            // Plain transfer: 21000 iff the recipient is a verified codeless EOA;
            // a recipient WITH code falls through to the EVM (receive/fallback).
            val code = getCode(to, "latest") ?: return null
            if (code.isEmpty()) return 21_000L
        }
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.estimateGasJson(
            handle,
            from?.let(::hex) ?: "",
            hex(to),
            data?.let { if (it.isEmpty()) "" else hex(it) } ?: "",
            valueWei ?: "",
        )) ?: return null
        if (o.string("status") != "ok") return null
        return (o["gas"] as? JsonPrimitive)?.longOrNull
    }

    override fun sendRawTransaction(rawTx: ByteArray): ByteArray? {
        if (rawTx.isEmpty()) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.sendRawTransactionJson(handle, hex(rawTx))) ?: return null
        return hexToBytes(o.string("txHash"))
    }

    override fun getTransactionReceipt(txHash: ByteArray): String? {
        if (txHash.size != 32) return null
        val handle = handleProvider() ?: return null
        return triStateJson(RustEngine.getTransactionReceiptJson(handle, hex(txHash)))
    }

    override fun getTransactionByHash(txHash: ByteArray): String? {
        if (txHash.size != 32) return null
        val handle = handleProvider() ?: return null
        return triStateJson(RustEngine.getTransactionByHashJson(handle, hex(txHash)))
    }

    override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? {
        if (fullTransactions) return null // full tx objects aren't served verified
        val handle = handleProvider() ?: return null
        val tag = block.ifBlank { "latest" }
        return triStateJson(RustEngine.getBlockByNumberJson(handle, tag))
    }

    override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? {
        if (fullTransactions) return null
        if (blockHash32.size != 32) return null
        val handle = handleProvider() ?: return null
        return triStateJson(RustEngine.getBlockByHashJson(handle, hex(blockHash32)))
    }

    override fun gasPrice(): String? {
        val handle = handleProvider() ?: return null
        return resultOrNull(RustEngine.feeEstimateJson(handle))?.string("gasPriceWei")
    }

    override fun maxPriorityFeePerGas(): String? {
        val handle = handleProvider() ?: return null
        return resultOrNull(RustEngine.feeEstimateJson(handle))?.string("maxPriorityFeePerGasWei")
    }

    override fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? =
        null // not served verified (parity with RustVerifiedReads)

    // ---- shared plumbing ----

    private class Account(val exists: Boolean, val nonce: Long, val balanceWei: String?, val verified: Boolean)

    private fun queryAccount(address: ByteArray): Account? {
        if (address.size != 20) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.requestAccountJson(handle, hex(address))) ?: return null
        return Account(
            exists = (o["exists"] as? JsonPrimitive)?.content == "true",
            nonce = o.long("nonce", -1L),
            balanceWei = o.string("balanceWei"),
            verified = o.string("verifyMethod") != null, // a verdict was produced
        )
    }

    /** Number-pinned selectors are served only near the anchored head (JNI parity). */
    private fun isServableBlock(block: String): Boolean {
        val b = block.trim()
        if (b.isEmpty()) return true
        when (b.lowercase()) {
            "latest", "pending", "safe", "finalized" -> return true
            "earliest" -> return false
        }
        val n = if (b.startsWith("0x") || b.startsWith("0X")) {
            b.substring(2).toLongOrNull(16)
        } else {
            b.toLongOrNull()
        } ?: return false
        if (n < 0) return false
        val head = headBlockNumber() ?: return false // not synced enough to validate the pin
        return n >= head - BLOCK_NUM_LAG_TOLERANCE && n <= head + BLOCK_NUM_TOLERANCE
    }

    /** Parse an engine reply; null on blank / malformed / an `{"error"}` envelope. */
    private fun resultOrNull(json: String): JsonObject? {
        val o = runCatching { engineJson.parseToJsonElement(json).jsonObject }.getOrNull() ?: return null
        if (o["error"]?.takeIf { it !is JsonNull } != null) return null
        return o
    }

    /** Tri-state JSON passthrough: object string | literal "null" | null (can't verify). */
    private fun triStateJson(json: String): String? {
        val t = json.trim()
        if (t.isEmpty()) return null
        if (t == "null") return t
        return if (resultOrNull(t) != null) t else null
    }

    private fun statusOrNull(handle: Long): JsonObject? =
        runCatching { engineJson.parseToJsonElement(RustEngine.statusJson(handle)).jsonObject }.getOrNull()

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content

    private fun JsonObject.long(key: String, default: Long = 0L): Long =
        (this[key] as? JsonPrimitive)?.longOrNull ?: default

    private fun hex(bytes: ByteArray): String = buildString(bytes.size * 2 + 2) {
        append("0x")
        for (b in bytes) {
            val v = b.toInt() and 0xff
            append(HEX_DIGITS[v ushr 4])
            append(HEX_DIGITS[v and 0x0f])
        }
    }

    /** 0x-hex → bytes; empty/absent → empty array; malformed → null. */
    private fun hexToBytes(s: String?): ByteArray? {
        if (s == null) return ByteArray(0)
        val h = if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2) else s
        if (h.isEmpty()) return ByteArray(0)
        val padded = if (h.length % 2 != 0) "0$h" else h
        return runCatching {
            ByteArray(padded.length / 2) {
                ((padded[it * 2].digitToInt(16) shl 4) or padded[it * 2 + 1].digitToInt(16)).toByte()
            }
        }.getOrNull()
    }

    private companion object {
        val HEX_DIGITS = "0123456789abcdef".toCharArray()

        /** How far ABOVE the anchored head a number-pin is still served. */
        const val BLOCK_NUM_TOLERANCE = 16L

        /** How far BELOW the anchored head a number-pin is still served from head state. */
        const val BLOCK_NUM_LAG_TOLERANCE = 64L
    }
}
