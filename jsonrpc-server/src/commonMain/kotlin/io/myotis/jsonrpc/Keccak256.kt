package io.myotis.jsonrpc

/**
 * Keccak-256 — the pre-NIST-padding variant Ethereum uses — in pure Kotlin so
 * commonMain can serve `web3_sha3` without a per-platform crypto dependency
 * (the JVM ships no Keccak, and pulling BouncyCastle/Tuweni into the seam
 * would break the iOS target). Sponge with rate 1088 bits (136-byte blocks),
 * capacity 512, multi-rate padding `0x01 … 0x80`, 24-round Keccak-f[1600].
 *
 * This is a hashing convenience for a COMPAT method, not a trust surface:
 * nothing verified depends on it. Pinned by the official Keccak test vectors
 * and, on the JVM, cross-checked against Tuweni's implementation over random
 * inputs (KeccakTest).
 */
internal object Keccak256 {

    private const val RATE = 136 // bytes; 1088-bit rate for the 256-bit digest

    /** Keccak-f round constants (ι step), one per round. */
    private val RC = ulongArrayOf(
        0x0000000000000001uL, 0x0000000000008082uL, 0x800000000000808AuL, 0x8000000080008000uL,
        0x000000000000808BuL, 0x0000000080000001uL, 0x8000000080008081uL, 0x8000000000008009uL,
        0x000000000000008AuL, 0x0000000000000088uL, 0x0000000080008009uL, 0x000000008000000AuL,
        0x000000008000808BuL, 0x800000000000008BuL, 0x8000000000008089uL, 0x8000000000008003uL,
        0x8000000000008002uL, 0x8000000000000080uL, 0x000000000000800AuL, 0x800000008000000AuL,
        0x8000000080008081uL, 0x8000000000008080uL, 0x0000000080000001uL, 0x8000000080008008uL,
    )

    /** Rotation offsets (ρ step), lane order `x + 5y`. */
    private val ROT = intArrayOf(
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    )

    fun digest(input: ByteArray): ByteArray {
        val state = ULongArray(25)
        var offset = 0
        while (input.size - offset >= RATE) {
            absorb(state, input, offset)
            keccakF(state)
            offset += RATE
        }
        // Final block: the remaining < RATE bytes plus multi-rate padding. The
        // 0x01 and 0x80 land on the same byte for a remainder of RATE-1 (the
        // `or` below), per the spec's single-byte-pad case.
        val block = ByteArray(RATE)
        input.copyInto(block, 0, offset, input.size)
        block[input.size - offset] = 0x01
        block[RATE - 1] = (block[RATE - 1].toInt() or 0x80).toByte()
        absorb(state, block, 0)
        keccakF(state)
        // Squeeze: the first 4 lanes, little-endian, are the 32-byte digest.
        val out = ByteArray(32)
        for (i in 0 until 4) {
            val lane = state[i]
            for (j in 0 until 8) {
                out[i * 8 + j] = ((lane shr (8 * j)) and 0xFFu).toByte()
            }
        }
        return out
    }

    /** XOR one RATE-sized block into the state, lanes little-endian
     *  (unrolled — no per-byte loop bookkeeping on the 17 lanes per block). */
    private fun absorb(state: ULongArray, data: ByteArray, offset: Int) {
        for (i in 0 until RATE / 8) {
            val base = offset + i * 8
            val lane = data[base].toUByte().toULong() or
                (data[base + 1].toUByte().toULong() shl 8) or
                (data[base + 2].toUByte().toULong() shl 16) or
                (data[base + 3].toUByte().toULong() shl 24) or
                (data[base + 4].toUByte().toULong() shl 32) or
                (data[base + 5].toUByte().toULong() shl 40) or
                (data[base + 6].toUByte().toULong() shl 48) or
                (data[base + 7].toUByte().toULong() shl 56)
            state[i] = state[i] xor lane
        }
    }

    private fun keccakF(a: ULongArray) {
        val c = ULongArray(5)
        val b = ULongArray(25)
        for (round in 0 until 24) {
            // θ
            for (x in 0 until 5) {
                c[x] = a[x] xor a[x + 5] xor a[x + 10] xor a[x + 15] xor a[x + 20]
            }
            for (x in 0 until 5) {
                val d = c[(x + 4) % 5] xor c[(x + 1) % 5].rotl(1)
                for (y in 0 until 5) {
                    a[x + 5 * y] = a[x + 5 * y] xor d
                }
            }
            // ρ + π
            for (x in 0 until 5) {
                for (y in 0 until 5) {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotl(ROT[x + 5 * y])
                }
            }
            // χ
            for (x in 0 until 5) {
                for (y in 0 until 5) {
                    a[x + 5 * y] = b[x + 5 * y] xor (b[(x + 1) % 5 + 5 * y].inv() and b[(x + 2) % 5 + 5 * y])
                }
            }
            // ι
            a[0] = a[0] xor RC[round]
        }
    }

    private fun ULong.rotl(n: Int): ULong =
        if (n == 0) this else (this shl n) or (this shr (64 - n))
}
