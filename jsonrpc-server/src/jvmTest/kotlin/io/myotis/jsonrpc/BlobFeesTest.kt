package io.myotis.jsonrpc

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger

/**
 * `eth_blobBaseFee`'s computation (#715) against full nodes: each vector is a
 * real block's `timestamp` and `excessBlobGas` and the `baseFeePerBlobGas` the
 * node's own `eth_feeHistory` answered for that block (mainnet via
 * rpc.flashbots.net, Sepolia via sepolia.gateway.tenderly.co, Gnosis via
 * gnosis.drpc.org, fetched 2026-11-03; Chiado via gnosis-chiado-rpc.publicnode.com,
 * 2026-11-04), one or more per blob fee era.
 */
class BlobFeesTest {

    private class Vector(val chainId: Long, val block: Long, val timestamp: Long, val excess: Long, val fee: Long)

    private val vectors = listOf(
        // Mainnet: Cancun, Prague (fee at the floor), Osaka before BPO1 (Prague's
        // fraction), BPO1, BPO2.
        Vector(1, 22_000_000, 1_741_410_875, 22_151_168, 761),
        Vector(1, 22_300_000, 1_745_028_923, 58_195_968, 37_202_675),
        Vector(1, 23_600_000, 1_760_735_723, 1_966_080, 1),
        Vector(1, 23_940_000, 1_764_855_107, 76_677_072, 4_465_024),
        Vector(1, 23_980_000, 1_765_341_539, 134_563_573, 10_046_639),
        Vector(1, 24_000_000, 1_765_584_371, 117_695_473, 1_331_338),
        Vector(1, 24_200_000, 1_767_996_347, 170_475_583, 2_168_784),
        Vector(1, 25_000_000, 1_777_637_363, 194_935_605, 17_593_154),
        // Sepolia: Cancun, Prague, BPO2, and Amsterdam (BPO2's fraction kept).
        Vector(11_155_111, 5_500_000, 1_710_621_432, 80_216_064, 27_234_271_276),
        Vector(11_155_111, 9_000_000, 1_755_386_580, 88_866_816, 50_930_759),
        Vector(11_155_111, 9_200_000, 1_757_828_772, 123_207_680, 48_438_838_333),
        Vector(11_155_111, 11_000_000, 1_780_724_904, 233_457_503, 475_467_791),
        Vector(11_155_111, 11_800_000, 1_790_592_324, 208_534_403, 56_335_511),
        Vector(11_155_111, 12_050_000, 1_793_644_908, 198_006_004, 22_880_417),
        // Gnosis: the 1 gwei floor.
        Vector(100, 49_080_000, 1_793_666_620, 0, 1_000_000_000),
        // Chiado: Gnosis's 1 gwei floor (gnosis-chiado-rpc.publicnode.com, 2026-11-04).
        Vector(10_200, 23_837_766, 1_793_781_760, 0, 1_000_000_000),
    )

    @Test fun matchesFullNodes_inEveryEra() {
        for (v in vectors) {
            val answer = BlobFees.baseFeePerBlobGas(v.chainId, v.timestamp, v.excess.toULong())
            val hex = (answer as? BlobFees.Answer.Fee)?.hexWei
            assertEquals("0x" + v.fee.toString(16), hex, "chain ${v.chainId} block ${v.block}")
        }
    }

    @Test fun bigResults_matchTheReferenceArithmetic() {
        // EIP-4844's fake_exponential in arbitrary precision, past 64 bits.
        fun reference(factor: Long, numerator: Long, denominator: Long): String {
            val d = BigInteger.valueOf(denominator)
            val n = BigInteger.valueOf(numerator)
            var i = BigInteger.ONE
            var out = BigInteger.ZERO
            var acc = BigInteger.valueOf(factor) * d
            while (acc.signum() > 0) {
                out += acc
                acc = acc * n / (d * i)
                i += BigInteger.ONE
            }
            return "0x" + (out / d).toString(16)
        }
        for ((f, n, d) in listOf(
            Triple(1L, 400_000_000L, 3_338_477L),
            Triple(1L, 1_000_000_000L, 5_007_716L),
            Triple(1_000_000_000L, 60_000_000L, 1_112_826L),
            Triple(1L, 5_000_000_000L, 11_684_671L),   // a numerator past 32 bits
            Triple(1L, 0L, 11_684_671L),
        )) {
            assertEquals(reference(f, n, d), BlobFees.fakeExponential(f, n.toULong(), d)!!.toHexQuantity(), "$f $n $d")
        }
    }

    @Test fun refusals_sayWhy() {
        val unknown = BlobFees.baseFeePerBlobGas(5, 1_800_000_000, 0uL) as BlobFees.Answer.Refused
        assertTrue(unknown.why.contains("chain 5"), unknown.why)
        val early = BlobFees.baseFeePerBlobGas(1, 1_700_000_000, 0uL) as BlobFees.Answer.Refused
        assertTrue(early.why.contains("Cancun"), early.why)
        // An excess no header could carry sums past the term cap: refused, not a hang.
        val absurd = BlobFees.baseFeePerBlobGas(1, 1_800_000_000, ULong.MAX_VALUE)
        assertTrue(absurd is BlobFees.Answer.Refused)
    }

    @Test fun bigUnsigned_hexAndArithmetic() {
        assertEquals("0x0", BigUnsigned.ZERO.toHexQuantity())
        assertEquals("0x1", BigUnsigned.of(1uL).toHexQuantity())
        assertEquals("0xffffffffffffffff", BigUnsigned.of(ULong.MAX_VALUE).toHexQuantity())
        val big = BigUnsigned.of(ULong.MAX_VALUE).times(ULong.MAX_VALUE)
        assertEquals("0x" + BigInteger("ffffffffffffffff", 16).pow(2).toString(16), big.toHexQuantity())
        assertEquals("0x100000000", BigUnsigned.of(0xffff_ffffuL).plus(BigUnsigned.of(1uL)).toHexQuantity())
        assertEquals("0x" + (BigInteger("ffffffffffffffff", 16).pow(2) / BigInteger.valueOf(7)).toString(16),
            big.div32(7u).toHexQuantity())
    }
}
