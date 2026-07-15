package io.myotis.jsonrpc

/**
 * Ethereum QUANTITY encoding/parsing without a bignum dependency. Wei values are
 * unsigned and capped at 256 bits by EVM semantics, so arbitrary-precision
 * base conversion over digit arrays (schoolbook divide/multiply) is all that's
 * needed — ~40 lines instead of a KMP BigInteger library. The JVM router used
 * java.math.BigInteger for exactly these three operations before the
 * multiplatform split; the wire behavior is pinned by RpcRouterTest.
 */
internal object RpcQuantities {

    /** QUANTITY-encode a non-negative long: minimal hex, no leading zeros, 0 → "0x0". */
    fun hexQuantity(v: Long): String = "0x" + v.toULong().toString(16)

    /**
     * QUANTITY-encode a decimal string (the FFI-neutral form the backend returns
     * for balances/fees). Throws [IllegalArgumentException] on a malformed value
     * — parity with the BigInteger constructor the JVM version used, where a
     * backend emitting garbage surfaced as an exception, never as silent data.
     */
    fun hexQuantityDecimal(decimal: String): String {
        require(decimal.isNotEmpty() && decimal.all { it in '0'..'9' }) {
            "not an unsigned decimal quantity"
        }
        return "0x" + decimalToHex(decimal)
    }

    /**
     * Parse a JSON-RPC QUANTITY (hex `0x…` or decimal) as a wei value, enforcing
     * EVM semantics: unsigned and <= 256 bits. Returns the NORMALIZED DECIMAL
     * string (what the backend seam takes), or null for malformed / negative /
     * out-of-range input. The length cap is checked before any conversion so an
     * absurdly long string can't amplify parsing cost (0x + 64 hex digits, or
     * ~78 decimal digits, covers the full 2^256 range). Shared by eth_call and
     * eth_estimateGas so both apply identical value validation.
     */
    fun parseWeiQuantity(s: String): String? {
        if (s.isEmpty() || s.length > 80) return null
        if (s.startsWith("0x") || s.startsWith("0X")) {
            // BigInteger(_, 16) accepted a leading sign after the prefix; keep
            // tolerating an explicit '+' (a '-' fails the unsigned check anyway).
            val h = s.substring(2).removePrefix("+").ifEmpty { "0" }.lowercase()
            if (!h.all { it in '0'..'9' || it in 'a'..'f' }) return null
            val minimal = h.trimStart('0').ifEmpty { "0" }
            if (minimal.length > 64) return null // > 2^256
            return hexToDecimal(minimal)
        }
        val d = s.removePrefix("+") // BigInteger(String) parity: explicit '+' allowed
        if (d.isEmpty() || !d.all { it in '0'..'9' }) return null // negatives and junk
        val minimal = d.trimStart('0').ifEmpty { "0" }
        // 2^256 is 78 decimal digits; check the exact bound via the hex width.
        if (decimalToHex(minimal).length > 64) return null
        return minimal
    }

    /** Unsigned decimal digits → minimal lowercase hex (no 0x). */
    fun decimalToHex(decimal: String): String {
        var digits = decimal.map { it - '0' }.toIntArray()
        val out = StringBuilder()
        while (digits.isNotEmpty()) {
            // One schoolbook division of the decimal digit array by 16.
            var remainder = 0
            val quotient = IntArray(digits.size)
            for (i in digits.indices) {
                val cur = remainder * 10 + digits[i]
                quotient[i] = cur / 16
                remainder = cur % 16
            }
            out.append(HEX_DIGITS[remainder])
            var start = 0
            while (start < quotient.size && quotient[start] == 0) start++
            digits = quotient.copyOfRange(start, quotient.size)
        }
        return if (out.isEmpty()) "0" else out.reverse().toString()
    }

    /** Minimal lowercase hex (no 0x) → unsigned decimal digits. */
    fun hexToDecimal(hex: String): String {
        var digits = intArrayOf(0) // little-endian decimal digit array
        for (c in hex) {
            val nibble = c.digitToInt(16)
            // digits = digits * 16 + nibble, schoolbook.
            var carry = nibble
            for (i in digits.indices) {
                val cur = digits[i] * 16 + carry
                digits[i] = cur % 10
                carry = cur / 10
            }
            while (carry > 0) {
                digits += carry % 10
                carry /= 10
            }
        }
        return digits.reversedArray().joinToString("") { it.toString() }
            .trimStart('0').ifEmpty { "0" }
    }

    private val HEX_DIGITS = "0123456789abcdef".toCharArray()
}
