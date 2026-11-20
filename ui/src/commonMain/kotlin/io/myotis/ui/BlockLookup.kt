package io.myotis.ui

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject

/*
 * The Query tab's block lookup by height: a debugging aid that shows how readily the
 * node gets an arbitrary block (header + body) from its EL peers, and whether it could
 * tie that block to the beacon chain. The fetch and the verdict are reported apart, so
 * a block the peers served but the node could not verify (too deep, pre-Merge) reads
 * as "fetched, unverified" and not as a failure to fetch.
 *
 * Hosts fill it from one of two engine paths ([BlockLookupResult.path]):
 *  - [BLOCK_PATH_VERIFIED_FETCH]: the engine API's ChainHandle.getBlockVerified, which
 *    fetches the block at any height and runs the header-chain walk on it (the Java
 *    engine; the daemon's `get-block`).
 *  - [BLOCK_PATH_RPC_READ]: the verified eth_getBlockByNumber read, for an engine
 *    without the first (the Rust engine). It answers only for blocks it can verify —
 *    those near the head — so a deeper block comes back as an error, not "fetched,
 *    unverified".
 * No JVM API, so iOS compiles it too.
 */

/** [BlockLookupResult.path]: ChainHandle.getBlockVerified (fetch at any height, then verify). */
const val BLOCK_PATH_VERIFIED_FETCH = "getBlockVerified"

/** [BlockLookupResult.path]: the verified eth_getBlockByNumber read (near-head blocks only). */
const val BLOCK_PATH_RPC_READ = "eth_getBlockByNumber"

/**
 * One block lookup. [error] non-null = the fetch itself failed (every other field but
 * [number] and [path] is then empty). Otherwise the block came back, and [verified]
 * says whether it was tied to the beacon chain ([failReason] why not).
 */
data class BlockLookupResult(
    val number: Long,
    val hashHex: String?,
    val parentHashHex: String?,
    val stateRootHex: String?,
    val transactionsRootHex: String?,
    val receiptsRootHex: String?,
    val timestamp: Long,             // unix seconds; -1 when none
    val gasUsed: Long,               // -1 when none
    val gasLimit: Long,              // -1 when none
    val baseFeePerGasWei: String?,   // decimal; null pre-London or when none
    val transactionCount: Int,       // -1 when none
    val uncleCount: Int,             // -1 when none
    val withdrawalCount: Int,        // -1 when none (also pre-Shanghai on the RPC path)
    val verified: Boolean,
    val blsVerified: Boolean,
    val matchedBeaconSlot: Long,     // -1 when not matched
    val verifyMethod: String?,
    val failReason: String?,         // null when verified (or when the fetch failed)
    val error: String?,              // null when the block was fetched
    val path: String,                // BLOCK_PATH_VERIFIED_FETCH / BLOCK_PATH_RPC_READ
) {
    companion object {
        /** A failed fetch of block [number] over [path]. */
        fun failed(number: Long, path: String, error: String): BlockLookupResult = BlockLookupResult(
            number, null, null, null, null, null, -1, -1, -1, null, -1, -1, -1,
            verified = false, blsVerified = false, matchedBeaconSlot = -1,
            verifyMethod = null, failReason = null, error = error, path = path,
        )
    }
}

private val blockJson = Json { ignoreUnknownKeys = true }

/**
 * A verified `eth_getBlockByNumber` answer (the VerifiedReads tri-state: a block
 * object, the literal `"null"`, a `{"error": …}` envelope, or null) as a lookup of
 * block [number]. Every block object this read returns is verified — the engine serves
 * nothing else — hence `verified = true` without a method of its own.
 */
fun blockLookupFromRpcJson(number: Long, json: String?): BlockLookupResult {
    val path = BLOCK_PATH_RPC_READ
    if (json == null) {
        return BlockLookupResult.failed(
            number, path,
            "no verified answer right now (no peer served a verifiable block, or the head is not anchored)",
        )
    }
    val t = json.trim()
    if (t == "null") {
        return BlockLookupResult.failed(
            number, path,
            "the engine holds no verifiable block $number (above the verified head, or below the " +
                "window this engine verifies; the Java engine fetches any height)",
        )
    }
    val o = runCatching { blockJson.parseToJsonElement(t).jsonObject }.getOrNull()
        ?: return BlockLookupResult.failed(number, path, "malformed block reply from the engine")
    o["error"]?.takeIf { it !is JsonNull }?.let { e ->
        val msg = (e as? JsonPrimitive)?.contentOrNull ?: e.toString()
        return BlockLookupResult.failed(number, path, msg)
    }
    fun str(key: String): String? = (o[key] as? JsonPrimitive)?.contentOrNull
    fun qty(key: String): Long = str(key)?.let(::hexQuantityToLong) ?: -1L
    fun count(key: String): Int = (o[key] as? JsonArray)?.size ?: -1
    // Fail closed on shape drift: a block object without a parseable number or a hash is
    // no block this card may show under a green pill — and without the number, the
    // requested-height check (forHeight) would have nothing to compare.
    val replyNumber = qty("number")
    if (replyNumber < 0 || str("hash").isNullOrEmpty()) {
        return BlockLookupResult.failed(number, path, "malformed block reply from the engine")
    }
    return BlockLookupResult(
        number = replyNumber,
        hashHex = str("hash"),
        parentHashHex = str("parentHash"),
        stateRootHex = str("stateRoot"),
        transactionsRootHex = str("transactionsRoot"),
        receiptsRootHex = str("receiptsRoot"),
        timestamp = qty("timestamp"),
        gasUsed = qty("gasUsed"),
        gasLimit = qty("gasLimit"),
        baseFeePerGasWei = str("baseFeePerGas")?.let { h -> hexQuantityToLong(h)?.toString() ?: h },
        transactionCount = count("transactions"),
        uncleCount = count("uncles"),
        withdrawalCount = count("withdrawals"),
        verified = true,
        blsVerified = false,
        matchedBeaconSlot = -1,
        verifyMethod = null,
        failReason = null,
        error = null,
        path = path,
    )
}

/**
 * Whether an engine exception from `ChainHandle.getBlockVerified` is the Rust engine's
 * refusal of that Java-engine operator query (RustChainHandle's NOT_AVAILABLE message)
 * — the one refusal a host answers with the [BLOCK_PATH_RPC_READ] fallback. Every other
 * engine exception (the node is not running, a paused stack that did not wake) is the
 * lookup's real error and must reach the user as such.
 */
fun isOperatorQueryRefusal(message: String?): Boolean =
    message?.startsWith("not available on the Rust engine") == true

/**
 * This lookup as the answer for block [requested]: a block that came back under another
 * number is a failed fetch, never a result shown under the wrong height (neither path
 * pins the served header's number to the one asked for on its own).
 */
fun BlockLookupResult.forHeight(requested: Long): BlockLookupResult =
    if (error == null && number != requested) {
        BlockLookupResult.failed(requested, path, "asked for block $requested, got block $number back")
    } else {
        this
    }

/** "0x1a" → 26; null for anything that is not a 0x-hex quantity fitting a non-negative Long. */
internal fun hexQuantityToLong(hex: String): Long? {
    val s = hex.trim()
    if (!s.startsWith("0x") && !s.startsWith("0X")) return null
    val digits = s.substring(2)
    if (digits.isEmpty() || digits.length > 16) return null
    return digits.toULongOrNull(16)?.takeIf { it <= Long.MAX_VALUE.toULong() }?.toLong()
}

/**
 * The Query input as a block height: plain decimal digits, optionally grouped in
 * thousands with ONE kind of separator — `,`, `_` or a space ("22,841,000") — and an
 * optional leading `#`. Null for anything else, a mis-grouped number ("21,0000,00")
 * included: an address is 0x-hex and an ENS name has a dot, so neither is ever read
 * as a height.
 */
internal fun parseBlockHeight(input: String): Long? {
    var s = input.trim()
    if (s.startsWith("#")) s = s.substring(1).trim()
    if (s.isEmpty()) return null
    val separators = s.filter { it == ',' || it == '_' || it == ' ' }.toSet()
    if (separators.size > 1) return null
    val groups = separators.singleOrNull()?.let { s.split(it) } ?: listOf(s)
    if (groups.any { g -> g.isEmpty() || !g.all { it in '0'..'9' } }) return null
    if (groups.size > 1 && (groups.first().length > 3 || groups.drop(1).any { it.length != 3 })) return null
    val digits = groups.joinToString("")
    if (digits.length > 18) return null
    return digits.toLongOrNull()
}
