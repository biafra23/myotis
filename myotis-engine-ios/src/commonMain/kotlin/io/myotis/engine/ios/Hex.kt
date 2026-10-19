package io.myotis.engine.ios

/** The 0x-hex the engine's C ABI speaks, strict both ways (the twin of
 *  `io.myotis.engines.common.Hex` on the JVM side). */
internal object Hex {

    private const val DIGITS = "0123456789abcdef"

    /** Lowercase `0x`-prefixed hex. */
    fun encode(bytes: ByteArray): String {
        val out = StringBuilder(2 + bytes.size * 2).append("0x")
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(DIGITS[v ushr 4]).append(DIGITS[v and 0x0f])
        }
        return out.toString()
    }

    /** `0x`-prefixed (or bare) hex to bytes; null, empty and `0x` are no bytes. Anything
     *  else that is not an even number of hex digits throws IllegalArgumentException. */
    fun decode(hex: String?): ByteArray {
        if (hex == null) return ByteArray(0)
        val digits = if (hex.startsWith("0x") || hex.startsWith("0X")) hex.substring(2) else hex
        require(digits.length % 2 == 0) { "odd-length hex" }
        return ByteArray(digits.length / 2) { i ->
            ((digit(digits[2 * i]) shl 4) or digit(digits[2 * i + 1])).toByte()
        }
    }

    private fun digit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("not a hex digit: '$c'")
    }
}
