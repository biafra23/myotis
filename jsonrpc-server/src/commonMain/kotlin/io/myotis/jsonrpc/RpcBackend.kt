package io.myotis.jsonrpc

import kotlinx.serialization.json.JsonObject

/**
 * The verified-read surface the router serves, as a pure-Kotlin seam so
 * commonMain never references the JVM `io.myotis.api` contracts. Semantics are
 * exactly `io.myotis.api.VerifiedReads` (which the jvmMain adapter wraps
 * one-to-one): every method BLOCKS, `null` means "cannot answer verified right
 * now", and the `String`-returning JSON methods are tri-state — an object
 * string, the literal `"null"` (verified not-found, a valid result), or `null`.
 * Wei values cross as decimal strings (the FFI-neutral form).
 */
interface RpcBackend {
    fun chainId(): Long
    fun headBlockNumber(): Long?
    fun call(from: ByteArray?, to: ByteArray, data: ByteArray, valueWei: String?, block: String): ByteArray?
    fun getBalance(address: ByteArray, block: String): String?
    fun getTransactionCount(address: ByteArray, block: String): Long?
    fun getCode(address: ByteArray, block: String): ByteArray?
    fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray?
    fun sendRawTransaction(rawTx: ByteArray): ByteArray?
    fun getTransactionReceipt(txHash: ByteArray): String?
    fun getTransactionByHash(txHash: ByteArray): String?
    /** Tri-state like the other JSON methods, but the found form is an ARRAY
     *  string (the block's whole receipt list), not an object. */
    fun getBlockReceipts(blockSelector: String): String?
    fun getBlockByNumber(block: String, fullTransactions: Boolean): String?
    fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String?
    fun gasPrice(): String?
    fun maxPriorityFeePerGas(): String?
    fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String?
    fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): Long?
}

/**
 * The node-status introspection seam behind `myotis_status` /
 * `myotis_beaconStatus`. Hosts provide the already-shaped JSON objects: on the
 * JVM the adapter delegates to [io.myotis.api.NodeStatusReads] + StatusJson
 * (whose exact output the tests pin); the iOS host builds the same shape from
 * the engine's status JSON. Reads may cross an FFI and BLOCK.
 */
interface RpcStatusSource {
    fun uptimeSeconds(): Long
    fun statusJson(uptimeSeconds: Long): JsonObject
    fun beaconStatusJson(uptimeSeconds: Long): JsonObject
}
