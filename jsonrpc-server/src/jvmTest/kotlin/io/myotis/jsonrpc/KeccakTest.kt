package io.myotis.jsonrpc

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random

class KeccakTest {

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /** The Keccak team's published 256-bit vectors (pre-NIST padding — what
     *  Ethereum uses; the SHA3-256 digests of the same inputs differ). */
    @Test
    fun officialVectors() {
        assertEquals(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            hex(Keccak256.digest(ByteArray(0))),
        )
        assertEquals(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            hex(Keccak256.digest("abc".encodeToByteArray())),
        )
        assertEquals(
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
            hex(Keccak256.digest("The quick brown fox jumps over the lazy dog".encodeToByteArray())),
        )
    }

    /** Cross-check against Tuweni over sizes that exercise every padding case:
     *  empty, sub-block, the exact rate (136), rate±1 (the one-byte-pad merge),
     *  and multi-block. Deterministic seed so a failure reproduces. */
    @Test
    fun matchesTuweniAcrossBlockBoundaries() {
        // Tuweni resolves KECCAK-256 through JCA — register the provider.
        java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        val rnd = Random(42)
        for (size in intArrayOf(0, 1, 31, 32, 135, 136, 137, 271, 272, 273, 1000)) {
            val input = ByteArray(size).also { rnd.nextBytes(it) }
            assertArrayEquals(
                org.apache.tuweni.crypto.Hash.keccak256(org.apache.tuweni.bytes.Bytes.wrap(input)).toArrayUnsafe(),
                Keccak256.digest(input),
                "size $size",
            )
        }
    }
}
