package io.myotis.ios

import io.myotis.jsonrpc.RpcBackend
import io.myotis.jsonrpc.RpcBlockWindow
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
        val head = o.engineLong("optimisticBlockNumber")
        return if (head > 0) head else null
    }

    override fun syncState(): io.myotis.jsonrpc.RpcSyncState {
        // Answers from the status snapshot, never holds the caller (the seam's
        // non-blocking contract). Not running / unreadable status → SYNCING —
        // "not synced yet", never a crash (RustVerifiedReads' fallback, mirrored).
        val handle = handleProvider() ?: return io.myotis.jsonrpc.RpcSyncState.SYNCING
        return when (statusOrNull(handle)?.engineString("beaconState")) {
            "SYNCED" -> io.myotis.jsonrpc.RpcSyncState.SYNCED
            "CATCHING_UP" -> io.myotis.jsonrpc.RpcSyncState.CATCHING_UP
            else -> io.myotis.jsonrpc.RpcSyncState.SYNCING // STARTING / SYNCING / unreadable
        }
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
        val mined = if (r.exists) r.nonce else 0L
        // ONLY the pending tag consults the sent-tx overlay (RustVerifiedReads
        // twin): max(mined, our broadcast nonce + 1) while unmined+unexpired.
        if (block == "pending") {
            val handle = handleProvider() ?: return mined
            val overlaid = RustEngine.pendingNonceOverlay(handle, hex(address), mined)
            return if (overlaid >= 0) overlaid else mined
        }
        return mined
    }

    override fun getCode(address: ByteArray, block: String): ByteArray? {
        if (!isServableBlock(block)) return null
        if (address.size != 20) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.getCodeJson(handle, hex(address))) ?: return null
        if (o.engineString("verifyMethod") == null) return null // unverified → can't answer
        return hexToBytes(o.engineString("codeHex")) // 0x / empty → empty bytecode (verified EOA)
    }

    override fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? {
        if (!isServableBlock(block)) return null
        if (address.size != 20 || slot32.size != 32) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.getStorageAtJson(handle, hex(address), hex(slot32))) ?: return null
        if (o.engineString("verifyMethod") == null) return null
        // Left-pad to the full 32-byte word (a zero/unset slot → 32 zero bytes).
        // A value WIDER than a word is engine shape drift — fail closed rather
        // than crash copyInto with a negative offset (JNI leftPad32 parity).
        val raw = hexToBytes(o.engineString("valueHex")) ?: return null
        if (raw.size > 32) return null
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
        if (o.engineString("status") != "ok") return null
        return hexToBytes(o.engineString("resultHex"))
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
        if (o.engineString("status") != "ok") return null
        return (o["gas"] as? JsonPrimitive)?.longOrNull
    }

    override fun sendRawTransaction(rawTx: ByteArray): ByteArray? {
        if (rawTx.isEmpty()) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.sendRawTransactionJson(handle, hex(rawTx))) ?: return null
        // Fail CLOSED on a missing/short hash (JNI parity: txHashFromJson throws,
        // the adapter maps it to null → strict -32000). A success "0x" here would
        // tell the wallet a send succeeded with a bogus hash.
        val hash = o.engineString("txHash")?.let(::hexToBytes) ?: return null
        return hash.takeIf { it.size == 32 }
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

    override fun getBlockReceipts(blockSelector: String): String? {
        val handle = handleProvider() ?: return null
        val sel = blockSelector.ifBlank { "latest" }
        // Same tri-state as the other JSON reads, but the found form is an
        // ARRAY (the block's whole receipt list) — hence the array-aware check.
        return triStateArrayJson(RustEngine.getBlockReceiptsJson(handle, sel))
    }

    override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? {
        val handle = handleProvider() ?: return null
        val tag = block.ifBlank { "latest" }
        return triStateJson(RustEngine.getBlockByNumberJson(handle, tag, fullTransactions))
    }

    override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? {
        if (blockHash32.size != 32) return null
        val handle = handleProvider() ?: return null
        return triStateJson(RustEngine.getBlockByHashJson(handle, hex(blockHash32), fullTransactions))
    }

    override fun gasPrice(): String? {
        val handle = handleProvider() ?: return null
        return resultOrNull(RustEngine.feeEstimateJson(handle))?.engineString("gasPriceWei")
    }

    override fun maxPriorityFeePerGas(): String? {
        val handle = handleProvider() ?: return null
        return resultOrNull(RustEngine.feeEstimateJson(handle))?.engineString("maxPriorityFeePerGasWei")
    }

    override fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? {
        if (blockCount < 1) return null
        val handle = handleProvider() ?: return null
        // Percentiles cross as a JSON number array (compound values cross as
        // JSON, like every other native); null → empty → no reward matrix.
        val percentilesJson = rewardPercentiles
            ?.joinToString(", ", prefix = "[", postfix = "]") ?: ""
        val tag = newestBlock.ifBlank { "latest" }
        // The feeHistory JSON object, or an error envelope (→ null → strict
        // -32000). No "null" literal case for this method (JNI parity).
        val json = RustEngine.feeHistoryJson(handle, blockCount, tag, percentilesJson)
        return if (resultOrNull(json) != null) json.trim() else null
    }

    // ---- shared plumbing ----

    private class Account(val exists: Boolean, val nonce: Long, val balanceWei: String?, val verified: Boolean)

    private fun queryAccount(address: ByteArray): Account? {
        if (address.size != 20) return null
        val handle = handleProvider() ?: return null
        val o = resultOrNull(RustEngine.requestAccountJson(handle, hex(address))) ?: return null
        return Account(
            exists = o.engineBoolean("exists"),
            nonce = o.engineLong("nonce", -1L),
            balanceWei = o.engineString("balanceWei"),
            verified = o.engineString("verifyMethod") != null, // a verdict was produced
        )
    }

    /** Number-pinned selectors are served only near the anchored head — the
     *  policy lives once in [RpcBlockWindow], shared with the JVM adapter. */
    private fun isServableBlock(block: String): Boolean =
        RpcBlockWindow.blockInWindow(block, ::headBlockNumber)

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

    /** [triStateJson]'s array twin (eth_getBlockReceipts): array string |
     *  literal "null" | null. An `{"error"}` envelope (an object) → null. */
    private fun triStateArrayJson(json: String): String? {
        val t = json.trim()
        if (t.isEmpty()) return null
        if (t == "null") return t
        val e = runCatching { engineJson.parseToJsonElement(t) }.getOrNull() ?: return null
        return if (e is kotlinx.serialization.json.JsonArray) t else null
    }

    private fun statusOrNull(handle: Long): JsonObject? =
        runCatching { engineJson.parseToJsonElement(RustEngine.statusJson(handle)).jsonObject }.getOrNull()

    private fun hex(bytes: ByteArray): String = buildString(bytes.size * 2 + 2) {
        append("0x")
        for (b in bytes) {
            val v = b.toInt() and 0xff
            append(HEX_DIGITS[v ushr 4])
            append(HEX_DIGITS[v and 0x0f])
        }
    }

    /** 0x-hex → bytes; empty/absent → empty array; malformed INCLUDING odd
     *  length → null. These are engine-emitted DATA fields (codeHex, resultHex,
     *  txHash): padding an odd-length value would byte-shift verified data, so
     *  fail closed exactly like the JNI twin's HexFormat.parseHex. */
    private fun hexToBytes(s: String?): ByteArray? {
        if (s == null) return ByteArray(0)
        val h = if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2) else s
        if (h.isEmpty()) return ByteArray(0)
        if (h.length % 2 != 0) return null
        return runCatching {
            ByteArray(h.length / 2) {
                ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte()
            }
        }.getOrNull()
    }

    private companion object {
        val HEX_DIGITS = "0123456789abcdef".toCharArray()
    }
}
