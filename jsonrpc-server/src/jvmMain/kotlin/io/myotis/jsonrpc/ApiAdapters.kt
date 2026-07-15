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
    fun server(
        port: Int,
        upstreamUrl: String?,
        host: String,
        backend: io.myotis.api.VerifiedReads?,
        statusReads: io.myotis.api.NodeStatusReads?,
    ): MyotisRpcServer = MyotisRpcServer(
        port,
        upstreamUrl,
        host,
        backend?.let { VerifiedReadsBackend(it) },
        statusReads?.let { NodeStatusSource(it) },
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
    }
    override fun call(from: ByteArray?, to: ByteArray, data: ByteArray, valueWei: String?, block: String): ByteArray? =
        v.call(from, to, data, valueWei, block)
    override fun getBalance(address: ByteArray, block: String): String? = v.getBalance(address, block)
    override fun getTransactionCount(address: ByteArray, block: String): Long? = v.getTransactionCount(address, block)
    override fun getCode(address: ByteArray, block: String): ByteArray? = v.getCode(address, block)
    override fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? =
        v.getStorageAt(address, slot32, block)
    override fun sendRawTransaction(rawTx: ByteArray): ByteArray? = v.sendRawTransaction(rawTx)
    override fun getTransactionReceipt(txHash: ByteArray): String? = v.getTransactionReceipt(txHash)
    override fun getTransactionByHash(txHash: ByteArray): String? = v.getTransactionByHash(txHash)
    override fun getBlockReceipts(blockSelector: String): String? = v.getBlockReceipts(blockSelector)
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
}

/** [RpcStatusSource] over the api contract + the pinned StatusJson shapes. */
class NodeStatusSource(private val sr: io.myotis.api.NodeStatusReads) : RpcStatusSource {
    override fun uptimeSeconds(): Long = sr.uptimeSeconds()
    override fun statusJson(uptimeSeconds: Long): JsonObject = StatusJson.status(sr.status(), uptimeSeconds)
    override fun beaconStatusJson(uptimeSeconds: Long): JsonObject =
        StatusJson.beaconStatus(sr.beaconStatus(), uptimeSeconds)
}
