package io.myotis.ui

import kotlin.jvm.JvmStatic

/**
 * One ERC-20 token the Query tab reads a balance of. [symbol] is what the row shows: a
 * popular token's ticker, or the name the user gave a [custom] one. [decimals] scales the
 * raw `balanceOf` amount for display; a wrong value shows a balance off by powers of ten,
 * which is why a custom token's value is checked against the contract's own `decimals()`
 * when its balance is read ([readTokenBalance]).
 */
data class Token(
    /** EIP-55 checksummed `0x…` contract address. */
    val address: String,
    val symbol: String,
    val decimals: Int,
    /** Added by the user ([CustomTokens]) rather than built in ([PopularTokens]). */
    val custom: Boolean = false,
) {
    /** Identity for lists and maps: the address, case-folded. */
    val key: String get() = address.lowercase()
}

/**
 * The built-in tokens whose balances the Query tab shows for every looked-up address, per
 * network. Addresses are pinned here, not discovered — a token is only ever identified by
 * its contract, never by the symbol a contract claims. Each entry's symbol and decimals were
 * checked against the contract's own `symbol()`/`decimals()` when it was listed, and
 * TokensTest pins every address's EIP-55 checksum, so a typo cannot slip into the list.
 * Kept short on purpose: every row is one verified `eth_call` per lookup.
 */
object PopularTokens {

    private val MAINNET = listOf(
        Token("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT", 6),
        Token("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC", 6),
        Token("0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI", 18),
        Token("0xdC035D45d973E3EC169d2276DDab16f1e407384F", "USDS", 18),
        Token("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH", 18),
        Token("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "WBTC", 8),
        Token("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "stETH", 18),
        Token("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", "wstETH", 18),
        Token("0x514910771AF9Ca656af840dff83E8264EcF986CA", "LINK", 18),
        Token("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "UNI", 18),
        Token("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", "AAVE", 18),
        Token("0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72", "ENS", 18),
        Token("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", "SHIB", 18),
        Token("0x6982508145454Ce325dDbE47a25d4ec3d2311933", "PEPE", 18),
    )

    private val GNOSIS = listOf(
        Token("0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d", "WXDAI", 18),
        Token("0xaf204776c7245bF4147c2612BF6e5972Ee483701", "sDAI", 18),
        // Two USDCs: the Omnibridge "USD//C on xDai" and Circle's bridged standard.
        Token("0xDDAfbb505ad214D7b80b1f830fcCc89B60fb7A83", "USDC", 6),
        Token("0x2a22f9c3b484c3629090FeED35F17Ff8F88f76F0", "USDC.e", 6),
        Token("0x4ECaBa5870353805a9F068101A40E0f32ed605C6", "USDT", 6),
        // Monerium's current EURe contract (v2); the v1 address is its legacy front.
        Token("0x420CA0f9B9b604cE0fd9C18EF134C705e5Fa3430", "EURe", 18),
        Token("0x6A023CCd1ff6F2045C3309768eAd9E68F978f6e1", "WETH", 18),
        Token("0x8e5bBbb09Ed1ebdE8674Cda39A0c169401db4252", "WBTC", 8),
        Token("0x9C58BAcC331c9aa871AFD802DB6379a98e80CEdb", "GNO", 18),
        Token("0x177127622c4A00F3d409B75571e12cB3c8973d3c", "COW", 18),
    )

    private val SEPOLIA = listOf(
        Token("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14", "WETH", 18),
        Token("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", "USDC", 6),
        Token("0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4", "EURC", 6),
        Token("0x779877A7B0D9E8603169DdbD7836e478b4624789", "LINK", 18),
    )

    /** The built-in tokens of [network]; empty for a network this table does not list. */
    @JvmStatic
    fun forNetwork(network: String): List<Token> = when (network) {
        "mainnet" -> MAINNET
        "gnosis" -> GNOSIS
        "sepolia" -> SEPOLIA
        else -> emptyList()
    }
}

/**
 * The user's own tokens, per network: the JSON array [Settings.customTokensJson] holds,
 * `[{"address":"0x…","name":"…","decimals":18},…]`, and the checks a new entry passes
 * before it is stored ([validate]).
 */
object CustomTokens {

    /** Longest name the form accepts: a ticker or a short label, not a description. */
    const val MAX_NAME_LENGTH = 24

    /** ERC-20's `decimals()` is a uint8. */
    const val MAX_DECIMALS = 255

    /**
     * Parse the stored array. Tolerant like the other settings stores: a malformed or
     * hand-edited value yields the entries that do parse (worst case none), never an
     * exception. An entry with a bad address, decimals or name is dropped, and of two
     * entries for one contract the first is kept.
     */
    @JvmStatic
    fun parse(json: String): List<Token> {
        val seen = HashSet<String>()
        return FlatJson.objects(json).mapNotNull { o ->
            val address = (o["address"] as? String)?.let(::normalizeAddress) ?: return@mapNotNull null
            val name = (o["name"] as? String)?.let(::cleanName)?.takeIf { it.isNotEmpty() }
                ?: return@mapNotNull null
            val decimals = (o["decimals"] as? Long)?.takeIf { it in 0..MAX_DECIMALS.toLong() }?.toInt()
                ?: return@mapNotNull null
            if (!seen.add(address.lowercase())) return@mapNotNull null
            Token(address, name, decimals, custom = true)
        }
    }

    /** Serialize for [Settings.setCustomTokensJson]. */
    @JvmStatic
    fun serialize(tokens: List<Token>): String =
        tokens.joinToString(",", "[", "]") {
            """{"address":"${it.address}","name":${FlatJson.quote(it.symbol)},"decimals":${it.decimals}}"""
        }

    /** Round-trip a stored value through [parse] — what a host does on load. */
    @JvmStatic
    fun normalize(json: String): String = serialize(parse(json))

    /** The outcome of [validate]: the token to store, or why the form's input is refused. */
    sealed class Check {
        data class Ok(val token: Token) : Check()
        data class Invalid(val reason: String) : Check()
    }

    /**
     * Check the add-token form's input against the tokens [network] already lists ([listed]:
     * built-in and custom). The address must be a 20-byte hex address; a mixed-case one must
     * carry a valid EIP-55 checksum, which catches most typos (an all-lower or all-upper one
     * carries none and is accepted as typed). The stored address is checksummed.
     */
    @JvmStatic
    fun validate(address: String, name: String, decimals: String, listed: List<Token>): Check {
        val a = address.trim()
        if (!isHexAddress(a)) return Check.Invalid("Enter the token's contract address: 0x followed by 40 hex digits.")
        if (!Eip55.isValid(a)) {
            return Check.Invalid("That address fails its checksum (EIP-55) — check it for a typo.")
        }
        if (a.drop(2).all { it == '0' }) return Check.Invalid("The zero address is not a token contract.")
        listed.firstOrNull { it.key == a.lowercase() }?.let {
            return Check.Invalid("This contract is already listed as ${it.symbol}.")
        }
        val n = cleanName(name)
        if (n.isEmpty()) return Check.Invalid("Enter a name for the token, e.g. its symbol.")
        if (n.length > MAX_NAME_LENGTH) return Check.Invalid("Keep the name to $MAX_NAME_LENGTH characters.")
        val d = decimals.trim().toIntOrNull()
            ?: return Check.Invalid("Decimals must be a whole number, e.g. 18 (USDC uses 6).")
        if (d !in 0..MAX_DECIMALS) return Check.Invalid("Decimals must be between 0 and $MAX_DECIMALS.")
        return Check.Ok(Token(Eip55.checksum(a), n, d, custom = true))
    }

    private fun normalizeAddress(s: String): String? {
        val a = s.trim()
        return if (isHexAddress(a) && Eip55.isValid(a)) Eip55.checksum(a) else null
    }

    /** A name as stored and shown: control characters removed, whitespace collapsed. */
    internal fun cleanName(s: String): String =
        s.filterNot { it.isISOControl() }.trim().replace(Regex("\\s+"), " ")
}

/** `0x` + 40 hex digits, in any case. */
internal fun isHexAddress(s: String): Boolean =
    s.length == 42 && (s.startsWith("0x") || s.startsWith("0X")) &&
        s.drop(2).all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

/**
 * [s] as a `0x`-prefixed address — the Query tab accepts one typed without the prefix,
 * and the Rust engine echoes the input as typed — or null when it is no address.
 */
internal fun asHexAddress(s: String): String? {
    val t = s.trim()
    val body = if (t.startsWith("0x") || t.startsWith("0X")) t.substring(2) else t
    return "0x$body".takeIf(::isHexAddress)
}

/**
 * The ERC-20 calls the Query tab makes, ABI-encoded by hand (four selectors, no ABI library):
 * calldata builders and decoders for the replies.
 */
object Erc20 {
    private const val BALANCE_OF = "70a08231"   // balanceOf(address)
    private const val DECIMALS = "313ce567"     // decimals()
    private const val SYMBOL = "95d89b41"       // symbol()
    private const val ERROR_STRING = "08c379a0" // Error(string), Solidity's revert reason

    /** Calldata for `balanceOf(holder)`. */
    @JvmStatic
    fun balanceOfCall(holder: String): String {
        require(isHexAddress(holder)) { "not an address: $holder" }
        return "0x$BALANCE_OF" + "0".repeat(24) + holder.drop(2).lowercase()
    }

    const val DECIMALS_CALL = "0x$DECIMALS"
    const val SYMBOL_CALL = "0x$SYMBOL"

    /**
     * The first 32-byte word of [data] as an unsigned decimal string, or null when [data]
     * holds less than one word (an address without code answers an `eth_call` with nothing).
     */
    @JvmStatic
    fun decodeUint256(data: ByteArray): String? =
        if (data.size < 32) null else unsignedDecimal(data.copyOfRange(0, 32))

    /** A `decimals()` reply: a uint8, or null when the word holds anything larger. */
    @JvmStatic
    fun decodeDecimals(data: ByteArray): Int? {
        if (data.size < 32) return null
        if ((0 until 31).any { data[it] != 0.toByte() }) return null
        return data[31].toInt() and 0xff
    }

    /**
     * A `symbol()`/`name()` reply as text: the ABI `string` most tokens return, or the
     * `bytes32` some early ones do (MKR, for one), zero padding stripped. Control
     * characters are dropped — this is a contract's claim, rendered as plain text. Null when
     * the reply is neither shape.
     */
    @JvmStatic
    fun decodeText(data: ByteArray): String? {
        val raw = abiString(data, 0)
            ?: if (data.size == 32) data.copyOfRange(0, data.indexOfLast { it != 0.toByte() } + 1) else null
        return raw?.decodeToString()?.filterNot { it.isISOControl() }?.trim()
    }

    /** Solidity's `Error(string)` revert reason, or null for any other revert payload. */
    @JvmStatic
    fun revertReason(data: ByteArray): String? {
        if (data.size < 4 || toHex(data.copyOfRange(0, 4)) != ERROR_STRING) return null
        return abiString(data, 4)?.decodeToString()?.filterNot { it.isISOControl() }?.trim()
    }

    /** The dynamic `string` whose head word sits at [base], or null when [data] is not one. */
    private fun abiString(data: ByteArray, base: Int): ByteArray? {
        if (data.size < base + 64) return null
        val offset = smallWord(data, base) ?: return null
        val at = base + offset
        if (offset < 32 || at + 32 > data.size) return null
        val len = smallWord(data, at) ?: return null
        if (at + 32 + len > data.size) return null
        return data.copyOfRange(at + 32, at + 32 + len)
    }

    /** The word at [at] when it fits comfortably in an Int (offsets, lengths), else null. */
    private fun smallWord(data: ByteArray, at: Int): Int? {
        if ((at until at + 28).any { data[it] != 0.toByte() }) return null
        var v = 0L
        for (i in at + 28 until at + 32) v = (v shl 8) or (data[i].toLong() and 0xff)
        return if (v <= Int.MAX_VALUE / 2) v.toInt() else null
    }
}

/** Big-endian unsigned bytes → decimal string, without BigInteger (commonMain has none). */
internal fun unsignedDecimal(bytes: ByteArray): String {
    // Little-endian limbs of base 1e9.
    val limbs = ArrayList<Long>().apply { add(0L) }
    for (b in bytes) {
        var carry = (b.toLong() and 0xff)
        for (i in limbs.indices) {
            val v = limbs[i] * 256 + carry
            limbs[i] = v % 1_000_000_000L
            carry = v / 1_000_000_000L
        }
        while (carry > 0) {
            limbs.add(carry % 1_000_000_000L)
            carry /= 1_000_000_000L
        }
    }
    val sb = StringBuilder(limbs.last().toString())
    for (i in limbs.size - 2 downTo 0) sb.append(limbs[i].toString().padStart(9, '0'))
    return sb.toString()
}

/**
 * A raw token amount ([rawDecimal], base units) in whole tokens: [decimals] places,
 * truncated toward zero to at most [maxFraction] of them with trailing zeros trimmed, the
 * integer part grouped in thousands. A non-zero amount too small to show reads
 * "< 0.000001" rather than a zero it is not. Non-numeric input passes through unchanged.
 */
fun formatTokenAmount(rawDecimal: String, decimals: Int, maxFraction: Int = 6): String {
    require(decimals >= 0 && maxFraction >= 1) { "decimals=$decimals maxFraction=$maxFraction" }
    if (rawDecimal.isEmpty() || !rawDecimal.all { it in '0'..'9' }) return rawDecimal
    val digits = rawDecimal.trimStart('0')
    if (digits.isEmpty()) return "0"
    val padded = digits.padStart(decimals + 1, '0')
    val intPart = padded.dropLast(decimals).trimStart('0').ifEmpty { "0" }
    val frac = padded.takeLast(decimals).take(maxFraction).trimEnd('0')
    if (intPart == "0" && frac.isEmpty()) return "< 0." + "0".repeat(maxFraction - 1) + "1"
    val grouped = intPart.reversed().chunked(3).joinToString(",").reversed()
    return if (frac.isEmpty()) grouped else "$grouped.$frac"
}

/** One token's balance as the Query tab read it. */
data class TokenBalance(
    val token: Token,
    /** `balanceOf` in base units (decimal), or null when it could not be read ([error]). */
    val raw: String?,
    /** Why there is no [raw] amount; null when there is one. */
    val error: String? = null,
    /**
     * What the contract's own `decimals()` answered, read for custom tokens only (a built-in
     * token's decimals are pinned); null when not read or the contract has no such method.
     * Differing from [Token.decimals] means the shown amount is scaled wrong.
     */
    val chainDecimals: Int? = null,
) {
    val decimalsMismatch: Boolean get() = chainDecimals != null && chainDecimals != token.decimals
}

/**
 * Read [holder]'s balance of [token] on [network] with a verified `eth_call` to
 * `balanceOf` — and, for a custom token, `decimals()` to check the user's value, unless
 * [knownChainDecimals] already holds the contract's answer from an earlier read. Never
 * throws except for cancellation: every failure lands in [TokenBalance.error], worded for
 * the row. An empty reply is NOT a zero balance: an address without contract code answers
 * any call with nothing, and reading that as 0 would be a wrong answer that looks right.
 */
suspend fun readTokenBalance(
    controller: NodeController,
    network: String,
    holder: String,
    token: Token,
    knownChainDecimals: Int? = null,
): TokenBalance {
    val balance = when (val r = ethCallOrError(controller, network, token.address, Erc20.balanceOfCall(holder))) {
        is CallRead.Data -> Erc20.decodeUint256(r.bytes)?.let { TokenBalance(token, it) }
            ?: TokenBalance(
                token, null,
                if (r.bytes.isEmpty()) "no reply — no token contract at this address on this network?"
                else "malformed balanceOf reply (${r.bytes.size} bytes)",
            )
        is CallRead.Failed -> TokenBalance(token, null, r.reason)
    }
    if (!token.custom || balance.raw == null) return balance
    if (knownChainDecimals != null) return balance.copy(chainDecimals = knownChainDecimals)
    val chainDecimals = (ethCallOrError(controller, network, token.address, Erc20.DECIMALS_CALL) as? CallRead.Data)
        ?.let { Erc20.decodeDecimals(it.bytes) }
    return balance.copy(chainDecimals = chainDecimals)
}

/**
 * What a token contract says about itself — `symbol()` and `decimals()` — to fill the
 * add-token form. Either may be null (both are optional in ERC-20); [error] is set when
 * neither could be read.
 */
data class TokenMetadata(val symbol: String?, val decimals: Int?, val error: String?)

/** Read [token]'s `symbol()` and `decimals()` with verified `eth_call`s. */
suspend fun readTokenMetadata(controller: NodeController, network: String, token: String): TokenMetadata {
    val sym = ethCallOrError(controller, network, token, Erc20.SYMBOL_CALL)
    val dec = ethCallOrError(controller, network, token, Erc20.DECIMALS_CALL)
    val symbol = (sym as? CallRead.Data)?.let { Erc20.decodeText(it.bytes) }?.takeIf { it.isNotEmpty() }
    val decimals = (dec as? CallRead.Data)?.let { Erc20.decodeDecimals(it.bytes) }
    val error = when {
        symbol != null || decimals != null -> null
        dec is CallRead.Failed -> dec.reason
        sym is CallRead.Failed -> sym.reason
        else -> "the contract answered neither symbol() nor decimals() — not an ERC-20 token?"
    }
    return TokenMetadata(symbol, decimals, error)
}

private sealed class CallRead {
    class Data(val bytes: ByteArray) : CallRead()
    class Failed(val reason: String) : CallRead()
}

private suspend fun ethCallOrError(controller: NodeController, network: String, to: String, data: String): CallRead {
    val r = try {
        controller.ethCall(network, to, data)
    } catch (c: kotlin.coroutines.cancellation.CancellationException) {
        throw c
    } catch (t: Throwable) {
        return CallRead.Failed(t.message ?: t.toString())
    }
    return when (r.status) {
        EthCallStatus.OK -> hexToBytes(r.dataHex ?: "0x")?.let { CallRead.Data(it) }
            ?: CallRead.Failed("malformed reply from the engine")
        EthCallStatus.REVERTED -> CallRead.Failed(
            "the contract reverted" +
                (r.dataHex?.let(::hexToBytes)?.let(Erc20::revertReason)?.let { ": $it" } ?: ""),
        )
        EthCallStatus.UNAVAILABLE -> CallRead.Failed(
            "no verified answer right now" + (r.detail?.let { " ($it)" } ?: "") + " — try Refresh",
        )
        EthCallStatus.REFUSED -> CallRead.Failed("refused by the engine" + (r.detail?.let { ": $it" } ?: ""))
        EthCallStatus.INFEASIBLE -> CallRead.Failed(r.detail ?: "the call cannot run")
    }
}

internal fun hexToBytes(hex: String): ByteArray? {
    val h = if (hex.startsWith("0x") || hex.startsWith("0X")) hex.substring(2) else hex
    if (h.length % 2 != 0) return null
    val out = ByteArray(h.length / 2)
    for (i in out.indices) {
        val hi = h[2 * i].digitToIntOrNull(16) ?: return null
        val lo = h[2 * i + 1].digitToIntOrNull(16) ?: return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

internal fun toHex(bytes: ByteArray): String {
    val digits = "0123456789abcdef"
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xff
        sb.append(digits[v ushr 4]).append(digits[v and 0xf])
    }
    return sb.toString()
}

/** EIP-55 mixed-case address checksums. */
object Eip55 {

    /** [address] (`0x` + 40 hex, any case) in its checksummed form. */
    @JvmStatic
    fun checksum(address: String): String {
        val lower = address.drop(2).lowercase()
        val hash = Keccak256.digest(lower.encodeToByteArray())
        val sb = StringBuilder("0x")
        lower.forEachIndexed { i, c ->
            val nibble = (hash[i / 2].toInt() ushr (if (i % 2 == 0) 4 else 0)) and 0xf
            sb.append(if (c in 'a'..'f' && nibble >= 8) c.uppercaseChar() else c)
        }
        return sb.toString()
    }

    /**
     * Whether [address]'s case is consistent with EIP-55: all-lower and all-upper carry no
     * checksum and pass; a mixed-case address must match its checksum exactly.
     */
    @JvmStatic
    fun isValid(address: String): Boolean {
        val body = address.drop(2)
        if (body == body.lowercase() || body == body.uppercase()) return true
        return checksum(address).drop(2) == body
    }
}

/** Keccak-256 (Ethereum's pre-standard padding, not SHA3-256), pure Kotlin for commonMain. */
internal object Keccak256 {
    private const val RATE = 136

    private val RC: LongArray = arrayOf(
        "0000000000000001", "0000000000008082", "800000000000808a", "8000000080008000",
        "000000000000808b", "0000000080000001", "8000000080008081", "8000000000008009",
        "000000000000008a", "0000000000000088", "0000000080008009", "000000008000000a",
        "000000008000808b", "800000000000008b", "8000000000008089", "8000000000008003",
        "8000000000008002", "8000000000000080", "000000000000800a", "800000008000000a",
        "8000000080008081", "8000000000008080", "0000000080000001", "8000000080008008",
    ).map { it.toULong(16).toLong() }.toLongArray()

    // Rotation offsets, indexed x + 5y.
    private val ROT = intArrayOf(
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    )

    fun digest(input: ByteArray): ByteArray {
        val state = LongArray(25)
        val padded = ByteArray((input.size / RATE + 1) * RATE)
        input.copyInto(padded)
        padded[input.size] = 0x01
        padded[padded.size - 1] = (padded[padded.size - 1].toInt() or 0x80).toByte()
        for (block in 0 until padded.size / RATE) {
            for (lane in 0 until RATE / 8) {
                var v = 0L
                for (b in 7 downTo 0) v = (v shl 8) or (padded[block * RATE + lane * 8 + b].toLong() and 0xff)
                state[lane] = state[lane] xor v
            }
            permute(state)
        }
        val out = ByteArray(32)
        for (i in 0 until 32) out[i] = (state[i / 8] ushr (8 * (i % 8))).toByte()
        return out
    }

    private fun permute(a: LongArray) {
        val c = LongArray(5)
        val b = LongArray(25)
        for (round in 0 until 24) {
            for (x in 0 until 5) c[x] = a[x] xor a[x + 5] xor a[x + 10] xor a[x + 15] xor a[x + 20]
            for (x in 0 until 5) {
                val d = c[(x + 4) % 5] xor c[(x + 1) % 5].rotateLeft(1)
                for (y in 0 until 5) a[x + 5 * y] = a[x + 5 * y] xor d
            }
            for (x in 0 until 5) for (y in 0 until 5) {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotateLeft(ROT[x + 5 * y])
            }
            for (x in 0 until 5) for (y in 0 until 5) {
                a[x + 5 * y] = b[x + 5 * y] xor (b[(x + 1) % 5 + 5 * y].inv() and b[(x + 2) % 5 + 5 * y])
            }
            a[0] = a[0] xor RC[round]
        }
    }
}

/**
 * Just enough JSON for the custom-token store: an array of flat objects whose values are
 * strings, integers, booleans or null. Anything else ends the parse, keeping the objects
 * read so far — the stores are tolerant, never throwing at boot over a hand edit.
 */
internal object FlatJson {

    fun objects(json: String): List<Map<String, Any?>> {
        val r = Reader(json)
        val out = ArrayList<Map<String, Any?>>()
        if (!r.take('[')) return out
        if (r.take(']')) return out
        while (true) {
            val o = r.obj() ?: return out
            out.add(o)
            if (r.take(',')) continue
            return out
        }
    }

    fun quote(s: String): String = buildString {
        append('"')
        for (c in s) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c < ' ' -> append("\\u").append(c.code.toString(16).padStart(4, '0'))
            else -> append(c)
        }
        append('"')
    }

    private class Reader(private val s: String) {
        private var i = 0

        private fun ws() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun take(c: Char): Boolean {
            ws()
            if (i < s.length && s[i] == c) {
                i++
                return true
            }
            return false
        }

        fun obj(): Map<String, Any?>? {
            if (!take('{')) return null
            val m = LinkedHashMap<String, Any?>()
            if (take('}')) return m
            while (true) {
                val k = string() ?: return null
                if (!take(':')) return null
                val v = value()
                if (v === FAIL) return null
                m[k] = v
                if (take(',')) continue
                return if (take('}')) m else null
            }
        }

        /** A string, Long, Boolean or null (JSON null); [FAIL] when unparsable. */
        private fun value(): Any? {
            ws()
            if (i >= s.length) return FAIL
            return when (s[i]) {
                '"' -> string() ?: FAIL
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> number() ?: FAIL
            }
        }

        private fun literal(word: String, v: Any?): Any? =
            if (s.startsWith(word, i)) { i += word.length; v } else FAIL

        private fun number(): Long? {
            val start = i
            if (i < s.length && s[i] == '-') i++
            while (i < s.length && s[i] in '0'..'9') i++
            // A fraction or exponent is no integer: unparsable here.
            if (i < s.length && (s[i] == '.' || s[i] == 'e' || s[i] == 'E')) return null
            return s.substring(start, i).toLongOrNull()
        }

        fun string(): String? {
            ws()
            if (i >= s.length || s[i] != '"') return null
            i++
            val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (i >= s.length) return null
                        when (val e = s[i++]) {
                            'n' -> sb.append('\n')
                            't' -> sb.append('\t')
                            'r' -> sb.append('\r')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000c')
                            'u' -> {
                                val code = s.substring(i, minOf(i + 4, s.length)).takeIf { it.length == 4 }
                                    ?.toIntOrNull(16) ?: return null
                                sb.append(code.toChar())
                                i += 4
                            }
                            else -> sb.append(e)
                        }
                    }
                    else -> sb.append(c)
                }
            }
            return null
        }

        private companion object {
            val FAIL = Any()
        }
    }
}
