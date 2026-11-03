package io.myotis.jsonrpc

/**
 * The EIP-4844 blob base fee of a block (`eth_blobBaseFee`, #715): EIP-4844's
 * `fake_exponential(MIN_BASE_FEE_PER_BLOB_GAS, excess_blob_gas,
 * BLOB_BASE_FEE_UPDATE_FRACTION)` over the block's own verified
 * `excessBlobGas`, with the update fraction of the fork the block's timestamp
 * falls in (EIP-7840's blob schedule: Prague changed it in EIP-7691, and every
 * BPO fork since) and the network's minimum.
 *
 * The schedules are the clients' own: go-ethereum's `params/chainspecs` for
 * mainnet and Sepolia (a fork without an entry keeps the previous fork's —
 * Osaka keeps Prague's, Sepolia's Amsterdam keeps BPO2's), Nethermind's
 * `gnosis.json` for Gnosis, whose one entry since Cancun carries its own
 * fraction and a 1 gwei minimum. Cross-checked against full nodes'
 * `eth_feeHistory` `baseFeePerBlobGas` in every era (`BlobFeesTest`).
 */
internal object BlobFees {

    /** One fork's blob fee parameters, from [fromTimestamp] on. */
    private class Era(val fromTimestamp: Long, val updateFraction: Long)

    private class Schedule(val minBaseFee: Long, val eras: List<Era>)

    private val SCHEDULES: Map<Long, Schedule> = mapOf(
        // Mainnet: Cancun, Prague (Osaka keeps it), BPO1, BPO2.
        1L to Schedule(1, listOf(
            Era(1_710_338_135, 3_338_477),
            Era(1_746_612_311, 5_007_716),
            Era(1_765_290_071, 8_346_193),
            Era(1_767_747_671, 11_684_671),
        )),
        // Sepolia: the same parameters on its own dates (Amsterdam keeps BPO2's).
        11_155_111L to Schedule(1, listOf(
            Era(1_706_655_072, 3_338_477),
            Era(1_741_159_776, 5_007_716),
            Era(1_761_017_184, 8_346_193),
            Era(1_761_607_008, 11_684_671),
        )),
        // Gnosis: one entry since its Cancun, and a 1 gwei minimum (EIP-4844 on Gnosis).
        100L to Schedule(1_000_000_000, listOf(
            Era(1_710_181_820, 1_112_826),
        )),
    )

    /** The largest exponent `excess / fraction` computed: a fee of e^1000 wei
     *  (past 2^1400) is no real header's, and the series for it already sums
     *  some 2,700 terms — larger ones would cost quadratic time for nothing. */
    private const val MAX_EXPONENT = 1_000uL

    /** A backstop on the terms [fakeExponential] sums: under [MAX_EXPONENT] the
     *  series ends after about `e * exponent` of them. */
    private const val MAX_TERMS = 10_000

    /**
     * The blob base fee, in wei, as a `0x` quantity — or why it cannot be given:
     * a chain without a schedule here, or a block before that chain's Cancun.
     */
    sealed interface Answer {
        class Fee(val hexWei: String) : Answer
        class Refused(val why: String) : Answer
    }

    fun baseFeePerBlobGas(chainId: Long, timestamp: Long, excessBlobGas: ULong): Answer {
        val schedule = SCHEDULES[chainId]
            ?: return Answer.Refused("this node has no blob fee schedule for chain $chainId")
        val era = schedule.eras.lastOrNull { timestamp >= it.fromTimestamp }
            ?: return Answer.Refused("the block predates blobs on chain $chainId (Cancun)")
        val fee = (if (excessBlobGas / era.updateFraction.toULong() > MAX_EXPONENT) null
            else fakeExponential(schedule.minBaseFee, excessBlobGas, era.updateFraction))
            ?: return Answer.Refused("excessBlobGas $excessBlobGas is beyond any blob fee this node computes")
        return Answer.Fee(fee.toHexQuantity())
    }

    /**
     * EIP-4844's `fake_exponential(factor, numerator, denominator)`, exactly:
     * `output += acc; acc = acc * numerator // (denominator * i)` until `acc`
     * is zero, then `output // denominator`. The division by `denominator * i`
     * is taken as a division by `denominator` and then by `i`, which floors the
     * same for positive integers. Null past [MAX_TERMS].
     */
    internal fun fakeExponential(factor: Long, numerator: ULong, denominator: Long): BigUnsigned? {
        require(factor > 0 && denominator in 1..0xffff_ffffL)
        var output = BigUnsigned.ZERO
        var acc = BigUnsigned.of(factor.toULong()).times(denominator.toULong())
        var i = 1L
        while (!acc.isZero()) {
            if (i > MAX_TERMS) return null
            output = output.plus(acc)
            acc = acc.times(numerator).div32(denominator.toUInt()).div32(i.toUInt())
            i += 1
        }
        return output.div32(denominator.toUInt())
    }
}

/**
 * The few unsigned big-integer operations [BlobFees.fakeExponential] needs, over
 * little-endian 32-bit limbs — common code has no `BigInteger`. Immutable.
 */
internal class BigUnsigned private constructor(private val limbs: IntArray) {

    companion object {
        val ZERO = BigUnsigned(IntArray(0))

        fun of(v: ULong): BigUnsigned =
            BigUnsigned(intArrayOf(v.toInt(), (v shr 32).toInt())).trimmed()
    }

    private fun limb(i: Int): ULong = if (i < limbs.size) limbs[i].toUInt().toULong() else 0uL

    private fun trimmed(): BigUnsigned {
        var n = limbs.size
        while (n > 0 && limbs[n - 1] == 0) n--
        return if (n == limbs.size) this else BigUnsigned(limbs.copyOf(n))
    }

    fun isZero(): Boolean = limbs.all { it == 0 }

    fun plus(o: BigUnsigned): BigUnsigned {
        val n = maxOf(limbs.size, o.limbs.size) + 1
        val out = IntArray(n)
        var carry = 0uL
        for (i in 0 until n) {
            val s = limb(i) + o.limb(i) + carry
            out[i] = s.toInt()
            carry = s shr 32
        }
        return BigUnsigned(out).trimmed()
    }

    /** `this * m` for a 64-bit [m]: as its two 32-bit halves, the high one a limb up. */
    fun times(m: ULong): BigUnsigned {
        val lo = timesSmall((m and 0xffff_ffffuL).toUInt())
        val hi = timesSmall((m shr 32).toUInt())
        return lo.plus(hi.shiftedLimb())
    }

    private fun timesSmall(m: UInt): BigUnsigned {
        if (m == 0u || isZero()) return ZERO
        val out = IntArray(limbs.size + 1)
        var carry = 0uL
        for (i in limbs.indices) {
            val p = limb(i) * m.toULong() + carry
            out[i] = p.toInt()
            carry = p shr 32
        }
        out[limbs.size] = carry.toInt()
        return BigUnsigned(out).trimmed()
    }

    private fun shiftedLimb(): BigUnsigned =
        if (isZero()) ZERO else BigUnsigned(IntArray(1) + limbs)

    /** `this / d`, floored, for a non-zero 32-bit [d]. */
    fun div32(d: UInt): BigUnsigned {
        require(d != 0u)
        val out = IntArray(limbs.size)
        var rem = 0uL
        for (i in limbs.indices.reversed()) {
            val cur = (rem shl 32) or limb(i)
            out[i] = (cur / d.toULong()).toInt()
            rem = cur % d.toULong()
        }
        return BigUnsigned(out).trimmed()
    }

    /** `0x`-prefixed minimal hex, the JSON-RPC QUANTITY form (`0x0` for zero). */
    fun toHexQuantity(): String {
        val t = trimmed()
        if (t.limbs.isEmpty()) return "0x0"
        val sb = StringBuilder("0x")
        sb.append(t.limbs.last().toUInt().toString(16))
        for (i in t.limbs.size - 2 downTo 0) sb.append(t.limbs[i].toUInt().toString(16).padStart(8, '0'))
        return sb.toString()
    }

    override fun toString(): String = toHexQuantity()
}
