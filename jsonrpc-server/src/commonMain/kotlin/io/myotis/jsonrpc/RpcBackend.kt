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
/** `io.myotis.api.SyncState`'s pure-Kotlin mirror (same three values, same
 *  meaning); the jvmMain adapter maps 1:1. */
enum class RpcSyncState { SYNCING, CATCHING_UP, SYNCED }

interface RpcBackend {
    fun chainId(): Long
    fun headBlockNumber(): Long?
    /** Non-blocking by contract (`VerifiedReads.syncState` semantics): answers
     *  from the current status snapshot — it may kick a wake but never holds
     *  the caller, because wallets probe this to decide whether the node is
     *  alive. Never null: an unreadable status reads as [RpcSyncState.SYNCING]. */
    fun syncState(): RpcSyncState
    /** `to` is NULL for contract creation (`eth_call` with no `to`): the calldata
     *  is init code and its return data is the answer. */
    fun call(from: ByteArray?, to: ByteArray?, data: ByteArray, valueWei: String?, block: String): ByteArray?

    /**
     * Whether this backend can APPLY state overrides. Distinguishes "overrides
     * unsupported" (permanent → -32602) from an ordinary null answer such as
     * not-synced or a revert (transient → -32000, retryable). Collapsing the two
     * would tell a client to stop asking over a condition that clears in
     * seconds.
     */
    fun supportsStateOverrides(): Boolean = false

    /**
     * [call] with the `eth_call` state-override object as JSON — caller-supplied
     * state layered over verified state for this call only.
     *
     * Default `null` means "this backend cannot apply overrides", which the
     * router turns into an honest refusal rather than an answer computed
     * against unmodified state (see the apply-or-refuse rule in CLAUDE.md).
     */
    fun callWithOverrides(
        from: ByteArray?,
        to: ByteArray?,
        data: ByteArray,
        valueWei: String?,
        block: String,
        stateOverridesJson: String,
    ): ByteArray? = null
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

    /** Verified eth_getLogs over the opt-in watch-list index: the log-array
     *  JSON, an {"error": ...} object (coverage/config detail the router
     *  surfaces at -32000), or null (backend has no index at all). Default
     *  null so hosts without the index (Java engine, older iOS) stay source-
     *  compatible and answer with the strict retryable error. */
    fun getLogs(filterJson: String): String? = null
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
