package io.myotis.jsonrpc

import kotlinx.serialization.json.JsonObject

/**
 * JVM adapters from the `io.myotis.api` contracts onto the module's pure-Kotlin
 * seams, plus the factory the Java hosts call. The adapters are 1:1 delegation —
 * all semantics (null conventions, tri-state strings, blocking) pass through.
 */
object MyotisRpc {

    /**
     * Build a server the way the JVM hosts always have: loopback-bound, strict
     * unless [upstreamUrl] is set, backed by the api contracts.
     */
    @JvmStatic
    @JvmOverloads
    fun server(
        port: Int,
        upstreamUrl: String?,
        host: String,
        backend: io.myotis.api.VerifiedReads?,
        statusReads: io.myotis.api.NodeStatusReads?,
        lifecycle: io.myotis.api.NodeLifecycle? = null,
    ): MyotisRpcServer = MyotisRpcServer(
        port,
        upstreamUrl,
        host,
        backend?.let { VerifiedReadsBackend(it) },
        statusReads?.let { NodeStatusSource(it) },
        lifecycle?.let { NodeLifecycleSource(it) },
    )
}

/** [RpcBackend] over the api contract — pure delegation. */
class VerifiedReadsBackend(private val v: io.myotis.api.VerifiedReads) : RpcBackend {
    override fun chainId(): Long = v.chainId()
    override fun headBlockNumber(): Long? = v.headBlockNumber()
    override fun syncState(): RpcSyncState = when (v.syncState()) {
        io.myotis.api.SyncState.SYNCED -> RpcSyncState.SYNCED
        io.myotis.api.SyncState.CATCHING_UP -> RpcSyncState.CATCHING_UP
        io.myotis.api.SyncState.SYNCING -> RpcSyncState.SYNCING
        io.myotis.api.SyncState.STALE_ANCHOR -> RpcSyncState.STALE_ANCHOR
    }
    override fun call(from: ByteArray?, to: ByteArray?, data: ByteArray, valueWei: String?, block: String): ByteArray? =
        v.call(from, to, data, valueWei, block)

    override fun supportsStateOverrides(): Boolean = v.supportsStateOverrides()

    override fun supportsContractCreation(): Boolean = v.supportsContractCreation()

    override fun callWithOverrides(
        from: ByteArray?,
        to: ByteArray?,
        data: ByteArray,
        valueWei: String?,
        block: String,
        stateOverridesJson: String,
    ): ByteArray? = v.callWithOverrides(from, to, data, valueWei, block, stateOverridesJson)

    override fun callDetailed(
        from: ByteArray?,
        to: ByteArray?,
        data: ByteArray,
        valueWei: String?,
        block: String,
        stateOverridesJson: String?,
    ): RpcCallResult {
        val r = v.callDetailed(from, to, data, valueWei, block, stateOverridesJson)
        return when (r.status()!!) {
            io.myotis.api.CallResult.Status.OK -> RpcCallResult.ok(r.data() ?: ByteArray(0))
            io.myotis.api.CallResult.Status.REVERTED -> RpcCallResult.reverted(r.data() ?: ByteArray(0))
            io.myotis.api.CallResult.Status.UNAVAILABLE -> RpcCallResult.unavailable(r.detail())
        }
    }
    override fun getBalance(address: ByteArray, block: String): String? = v.getBalance(address, block)
    override fun getTransactionCount(address: ByteArray, block: String): Long? = v.getTransactionCount(address, block)
    override fun getCode(address: ByteArray, block: String): ByteArray? = v.getCode(address, block)
    override fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? =
        v.getStorageAt(address, slot32, block)
    override fun sendRawTransaction(rawTx: ByteArray): ByteArray? = v.sendRawTransaction(rawTx)
    override fun getTransactionReceipt(txHash: ByteArray): String? = v.getTransactionReceipt(txHash)
    override fun getTransactionByHash(txHash: ByteArray): String? = v.getTransactionByHash(txHash)
    override fun getBlockReceipts(blockSelector: String): String? = v.getBlockReceipts(blockSelector)

    override fun getLogs(filterJson: String): String? = v.getLogs(filterJson)
    override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? =
        v.getBlockByNumber(block, fullTransactions)
    override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? =
        v.getBlockByHash(blockHash32, fullTransactions)
    override fun gasPrice(): String? = v.gasPrice()
    override fun maxPriorityFeePerGas(): String? = v.maxPriorityFeePerGas()
    override fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? =
        v.feeHistory(blockCount, newestBlock, rewardPercentiles)
    override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): Long? =
        v.estimateGas(from, to, data, valueWei)

    override fun estimateGasDetailed(
        from: ByteArray?,
        to: ByteArray?,
        data: ByteArray?,
        valueWei: String?,
    ): RpcEstimateResult {
        val r = v.estimateGasDetailed(from, to, data, valueWei)
        return when (r.status()!!) {
            io.myotis.api.EstimateResult.Status.OK -> RpcEstimateResult.ok(r.gas())
            io.myotis.api.EstimateResult.Status.REVERTED ->
                RpcEstimateResult.reverted(r.revertData() ?: ByteArray(0))
            io.myotis.api.EstimateResult.Status.UNAVAILABLE -> RpcEstimateResult.unavailable(r.detail())
        }
    }
}

/** [RpcStatusSource] over the api contract + the pinned StatusJson shapes. */
class NodeStatusSource(private val sr: io.myotis.api.NodeStatusReads) : RpcStatusSource {
    override fun uptimeSeconds(): Long = sr.uptimeSeconds()
    override fun statusJson(uptimeSeconds: Long): JsonObject = StatusJson.status(sr.status(), uptimeSeconds)
    override fun beaconStatusJson(uptimeSeconds: Long): JsonObject =
        StatusJson.beaconStatus(sr.beaconStatus(), uptimeSeconds)
}

/** [RpcLifecycle] over the api contract — pure delegation.
 *
 *  On success the lifecycle name is the target state BY DEFINITION
 *  (`NodeLifecycle.pause` returns true iff PAUSED on return, `wakeUp` iff RUNNING),
 *  so it is NOT re-read: reading `lifecycleName()` in a second call would let a
 *  concurrent transition (the idle controller, another client) return an
 *  internally contradictory `{ok:true, lifecycle:"RUNNING"}` for a pause — a
 *  well-formed but misleading success (CLAUDE.md §Trust). Only the failure path,
 *  where `ok` already says the target was not reached, reads the current state as
 *  a best-effort diagnostic. */
class NodeLifecycleSource(private val lc: io.myotis.api.NodeLifecycle) : RpcLifecycle {
    override fun pause(): RpcLifecycleResult {
        val ok = lc.pause()
        return RpcLifecycleResult(ok, if (ok) "PAUSED" else lc.lifecycleName())
    }
    override fun wakeUp(): RpcLifecycleResult {
        val ok = lc.wakeUp()
        return RpcLifecycleResult(ok, if (ok) "RUNNING" else lc.lifecycleName())
    }
}
