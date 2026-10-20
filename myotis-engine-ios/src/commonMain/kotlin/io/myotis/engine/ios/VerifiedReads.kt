package io.myotis.engine.ios

/**
 * The verified `eth_*` reads of one handle: the Kotlin twin of `io.myotis.api.VerifiedReads`
 * (the part of it a wallet reads), as the JVM side's `RustVerifiedReads` answers it.
 * Every answer comes ONLY from cryptographically verified data. A null, or an
 * `UNAVAILABLE` result, means "cannot answer verified right now" (not synced, no peer,
 * the head not anchored, the handle paused or stopped); it never stands for an
 * unverified answer. Nothing here throws.
 *
 * [block] is the RPC block selector — a head tag (`latest`, `pending`), `finalized`,
 * or a number near the head — which the engine applies or refuses, never ignores.
 * Addresses are 20 bytes, hashes and storage positions 32; anything else cannot be
 * answered.
 */
class VerifiedReads internal constructor(private val handle: ChainHandle) {

    /** The chain these reads answer for. */
    val chainId: Long get() = handle.chainId

    /** The optimistic head's execution block number (`eth_blockNumber`), or null while
     *  no verified read can be served at it (paused, not synced, no head, no snap peer). */
    fun headBlockNumber(): Long? = answer { handle.servableHead() }

    /** The balance in decimal wei (0 for an account proven absent), or null. */
    fun getBalance(address: ByteArray, block: String): String? {
        val r = account(address, block) ?: return null
        return if (r.exists) r.balanceWei else "0"
    }

    /** The account's nonce (0 for one proven absent), or null. For [block] `pending`
     *  it counts this node's own sends that are not mined yet, so a second transfer
     *  right after a first does not reuse its nonce. */
    fun getTransactionCount(address: ByteArray, block: String): Long? {
        val r = account(address, block) ?: return null
        val mined = if (r.exists) r.nonce else 0L
        return if (block == "pending") answer { handle.pendingNonce(Hex.encode(address), mined) } else mined
    }

    /** The account's code (empty for one without), or null. */
    fun getCode(address: ByteArray, block: String): ByteArray? {
        if (address.size != ADDRESS_BYTES) return null
        return answer { handle.codeAt(Hex.encode(address), block) }
    }

    /** The 32-byte word at storage position [slot32] (zeros for an unset one), or null. */
    fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? {
        if (address.size != ADDRESS_BYTES || slot32.size != WORD_BYTES) return null
        return answer { handle.storageAt(Hex.encode(address), Hex.encode(slot32), block) }
    }

    /**
     * `eth_call` over verified state, its outcomes told apart ([CallResult]). A null [from]
     * is the anonymous zero sender, a null [to] contract creation; [valueWei] is decimal
     * wei. [stateOverridesJson], the `eth_call` state-override object, makes the call a
     * simulation of the caller's hypothesis, not a chain fact; null or empty is none.
     */
    fun callDetailed(
        from: ByteArray?,
        to: ByteArray?,
        data: ByteArray?,
        valueWei: String?,
        block: String,
        stateOverridesJson: String?,
    ): CallResult {
        if (to != null && to.size != ADDRESS_BYTES) return CallResult.unavailable("malformed to")
        if (from != null && from.size != ADDRESS_BYTES) return CallResult.unavailable("malformed from")
        return try {
            handle.call(
                from = from?.let(Hex::encode) ?: "",
                to = to?.let(Hex::encode) ?: "",
                data = data?.let(Hex::encode) ?: "",
                value = valueWei ?: "",
                block = block,
                overrides = stateOverridesJson ?: "",
            )
        } catch (e: Exception) {
            CallResult.unavailable(e.message)
        }
    }

    /** `eth_estimateGas` over verified state, its outcomes told apart ([EstimateResult]);
     *  the arguments as [callDetailed]'s. Contract creation is not estimated. */
    fun estimateGasDetailed(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): EstimateResult {
        if (to == null || to.size != ADDRESS_BYTES) return EstimateResult.unavailable("contract creation not estimated")
        if (from != null && from.size != ADDRESS_BYTES) return EstimateResult.unavailable("malformed from")
        return try {
            handle.estimateGas(
                from = from?.let(Hex::encode) ?: "",
                to = Hex.encode(to),
                data = data?.let(Hex::encode) ?: "",
                value = valueWei ?: "",
            )
        } catch (e: Exception) {
            EstimateResult.unavailable(e.message)
        }
    }

    /**
     * `eth_feeHistory`: the result object as JSON (`oldestBlock`, `baseFeePerGas`,
     * `gasUsedRatio` and, with [rewardPercentiles], `reward`), or null. A blank
     * [newestBlock] is `latest`.
     */
    fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? {
        if (blockCount < 1) return null
        if (rewardPercentiles != null && rewardPercentiles.any { !it.isFinite() }) return null
        val percentiles = rewardPercentiles?.joinToString(",", "[", "]") ?: ""
        return answer { handle.feeHistory(blockCount, newestBlock.ifBlank { "latest" }, percentiles) }
    }

    /** The receipt as JSON (verified against its block's receiptsRoot), the `"null"`
     *  literal for a transaction not seen in a verified block yet, or null. */
    fun getTransactionReceipt(txHash: ByteArray): String? {
        if (txHash.size != WORD_BYTES) return null
        return answer { handle.receipt(Hex.encode(txHash)) }
    }

    /**
     * Verified `eth_getLogs` over the engine's opt-in watch-list log index
     * ([ChainHandle.setLogIndexConfig]): the log-array JSON, the engine's `{"error":…}` object
     * carrying the coverage or config detail (a range the index does not cover is an error,
     * never an empty array), or null when no answer could be had.
     */
    fun getLogs(filterJson: String): String? = answer { handle.logs(filterJson) }

    /** Gossips a signed raw transaction to the peers (the engine never signs), its
     *  outcome told apart ([SendResult]). */
    fun sendRawTransactionDetailed(rawTx: ByteArray): SendResult {
        if (rawTx.isEmpty()) return SendResult.unavailable("empty raw transaction")
        return try {
            handle.send(Hex.encode(rawTx))
        } catch (e: Exception) {
            SendResult.unavailable(e.message)
        }
    }

    /** The account read behind the balance and the nonce: null without a verdict. */
    private fun account(address: ByteArray, block: String): AccountProofResult? {
        if (address.size != ADDRESS_BYTES) return null
        return answer { handle.accountAt(Hex.encode(address), block) }?.takeIf { it.verifyMethod != null }
    }

    /** A read that could not be answered (a transport or not-running failure, a payload
     *  the engine should not have sent) is null: nothing escapes this surface. */
    private inline fun <T> answer(read: () -> T): T? =
        try {
            read()
        } catch (e: Exception) {
            null
        }

    private companion object {
        const val ADDRESS_BYTES = 20
        const val WORD_BYTES = 32
    }
}
