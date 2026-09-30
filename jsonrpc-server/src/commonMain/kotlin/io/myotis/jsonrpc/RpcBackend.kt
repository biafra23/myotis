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
/** `io.myotis.api.SyncState`'s pure-Kotlin mirror; the jvmMain adapter maps 1:1.
 *  `STALE_ANCHOR`: syncing is refused because the trust anchor is past the
 *  weak-subjectivity bound and the user hasn't consented — like SYNCING it gates
 *  every verified read closed, but unlike SYNCING it will not progress on its
 *  own. */
enum class RpcSyncState { SYNCING, CATCHING_UP, SYNCED, STALE_ANCHOR }

/**
 * `io.myotis.api.CallResult`'s pure-Kotlin mirror: the three-way outcome of a
 * detailed `eth_call`. REVERTED is a VERIFIED chain answer (the contract said
 * no) and carries the raw revert payload; the router maps it to the standard
 * `{code: 3, "execution reverted", data}` wallets parse. UNAVAILABLE keeps the
 * retryable -32000 path. REFUSED is the engine's PERMANENT "not on this build"
 * (e.g. an EVM fork it cannot price): the router serves -32602 with [detail].
 */
class RpcCallResult private constructor(
    val kind: Kind,
    val data: ByteArray?,
    val detail: String?,
) {
    /** [INFEASIBLE] is an answer, not a failure (#509): the transaction cannot
     *  succeed within the caller's own gas, fee cap or funds, and [detail] is
     *  geth's message, served verbatim under geth's -32000. A call carries it
     *  from [RpcBackend.callTx], and from a plain call only on the Rust engine,
     *  when its calldata alone costs more than the call budget (the Java
     *  engine's plain call charges no intrinsic gas); an estimate from any path
     *  (see [RpcEstimateResult]). */
    enum class Kind { OK, REVERTED, UNAVAILABLE, REFUSED, INFEASIBLE }

    companion object {
        fun ok(data: ByteArray): RpcCallResult = RpcCallResult(Kind.OK, data, null)
        fun reverted(data: ByteArray): RpcCallResult = RpcCallResult(Kind.REVERTED, data, null)
        fun unavailable(detail: String? = null): RpcCallResult = RpcCallResult(Kind.UNAVAILABLE, null, detail)
        fun refused(detail: String): RpcCallResult = RpcCallResult(Kind.REFUSED, null, detail)
        fun infeasible(detail: String): RpcCallResult = RpcCallResult(Kind.INFEASIBLE, null, detail)
    }
}

/**
 * `io.myotis.api.EstimateResult`'s pure-Kotlin mirror: the outcome of a
 * detailed `eth_estimateGas`. REVERTED means the ESTIMATED TRANSACTION cannot
 * succeed — a verified answer carrying the raw revert payload, served as the
 * standard code-3 error; UNAVAILABLE keeps the retryable -32000 path; REFUSED
 * is permanent (-32602), as for [RpcCallResult]. INFEASIBLE (#509) is also an
 * answer: the transaction does not fit the caller's gas or funds, and [detail]
 * is geth's message ("gas required exceeds allowance (N)", "insufficient funds
 * for transfer"), served verbatim under geth's -32000.
 */
class RpcEstimateResult private constructor(
    val kind: RpcCallResult.Kind,
    val gas: Long?,
    val data: ByteArray?,
    val detail: String?,
) {
    companion object {
        fun ok(gas: Long): RpcEstimateResult = RpcEstimateResult(RpcCallResult.Kind.OK, gas, null, null)
        fun reverted(data: ByteArray): RpcEstimateResult =
            RpcEstimateResult(RpcCallResult.Kind.REVERTED, null, data, null)
        fun unavailable(detail: String? = null): RpcEstimateResult =
            RpcEstimateResult(RpcCallResult.Kind.UNAVAILABLE, null, null, detail)
        fun refused(detail: String): RpcEstimateResult =
            RpcEstimateResult(RpcCallResult.Kind.REFUSED, null, null, detail)
        fun infeasible(detail: String): RpcEstimateResult =
            RpcEstimateResult(RpcCallResult.Kind.INFEASIBLE, null, null, detail)
    }
}

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
     * not-synced (transient → -32000, retryable). Collapsing the two would tell
     * a client to stop asking over a condition that clears in seconds. (A
     * contract REVERT is neither — it rides [callDetailed] as a verified answer
     * with its own error shape.)
     */
    fun supportsStateOverrides(): Boolean = false

    /**
     * Whether this backend can serve CONTRACT CREATION (`eth_call` with a null
     * `to`). Consulted BEFORE dispatch: an engine that can't would otherwise be
     * woken and made to wait for a verified head only to refuse — and the
     * refusal would read as retryable when it is permanent for that build.
     */
    fun supportsContractCreation(): Boolean = false

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

    /**
     * [call]/[callWithOverrides] with the three-way [RpcCallResult] outcome, so
     * a contract revert is not conflated with "cannot answer verified right
     * now". Default wraps the nullable methods (a revert stays UNAVAILABLE),
     * keeping every existing backend's behaviour until it overrides this to
     * surface the revert payload.
     *
     * @param stateOverridesJson override object as JSON; null ⇒ plain call
     */
    fun callDetailed(
        from: ByteArray?,
        to: ByteArray?,
        data: ByteArray,
        valueWei: String?,
        block: String,
        stateOverridesJson: String?,
    ): RpcCallResult {
        val out =
            if (stateOverridesJson.isNullOrEmpty()) call(from, to, data, valueWei, block)
            else callWithOverrides(from, to, data, valueWei, block, stateOverridesJson)
        return if (out == null) RpcCallResult.unavailable() else RpcCallResult.ok(out)
    }
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

    /**
     * [estimateGas] with the three-way [RpcEstimateResult] outcome, so the
     * estimated transaction REVERTING (a verified answer with a payload the
     * router serves as code 3) is not conflated with "cannot answer right
     * now". Default wraps the nullable method — every existing backend keeps
     * its behaviour until it overrides this to surface the payload.
     */
    fun estimateGasDetailed(
        from: ByteArray?,
        to: ByteArray?,
        data: ByteArray?,
        valueWei: String?,
    ): RpcEstimateResult {
        val gas = estimateGas(from, to, data, valueWei)
        return if (gas == null) RpcEstimateResult.unavailable() else RpcEstimateResult.ok(gas)
    }

    /**
     * Whether this backend APPLIES a transaction object's `accessList` and
     * EIP-7702 `authorizationList` in [estimateGasTx] (#509). Consulted BEFORE
     * dispatch: a request carrying either list is refused (-32602) on a backend
     * that would otherwise estimate a different transaction — a type-4 estimate
     * without its authorizations misses the whole delegated execution.
     */
    fun supportsTransactionLists(): Boolean = false

    /**
     * `eth_estimateGas` for the full transaction object at [block], with a
     * state override when [stateOverridesJson] is non-null (only asked of a
     * backend whose [supportsStateOverrides] is true). Every field is applied
     * or the outcome is REFUSED.
     *
     * Default: a backend that has not implemented the transaction object
     * answers exactly the subset it always could — from/to/data/value at the
     * head — and REFUSES anything else rather than estimate a transaction the
     * caller did not describe.
     */
    fun estimateGasTx(
        tx: RpcTransactionArgs,
        block: String,
        stateOverridesJson: String?,
    ): RpcEstimateResult {
        if (tx.hasExtendedFields) {
            return RpcEstimateResult.refused(
                "this engine does not apply the transaction object's gas, fee or list fields",
            )
        }
        if (!stateOverridesJson.isNullOrEmpty()) {
            return RpcEstimateResult.refused("this engine does not apply state overrides to eth_estimateGas")
        }
        if (block.trim().lowercase() !in setOf("", "latest", "pending", "safe")) {
            return RpcEstimateResult.refused("this engine estimates only against the head block")
        }
        return estimateGasDetailed(tx.from, tx.to, tx.data, tx.valueWei)
    }

    /**
     * `eth_call` for a transaction object that carries more than
     * from/to/data/value (#509) — `gas`, a fee, a list — at [block], with a state
     * override when [stateOverridesJson] is non-null. Every field is applied as
     * [estimateGasTx] applies it or the outcome is REFUSED; a call that cannot
     * succeed within the caller's gas, fee cap or funds is INFEASIBLE.
     *
     * Default: REFUSED, rather than run a call without the fields the caller set.
     */
    fun callTx(
        tx: RpcTransactionArgs,
        block: String,
        stateOverridesJson: String?,
    ): RpcCallResult = RpcCallResult.refused(
        "this engine does not apply the transaction object's gas, fee or list fields to eth_call",
    )
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

/**
 * The lifecycle-control seam behind `myotis_pause` / `myotis_wakeup` — the
 * JSON-RPC counterpart of the daemon's `pause` / `resume` IPC commands. Hosts
 * wire the same node object they wire for [RpcStatusSource]; on the JVM the
 * adapter delegates to [io.myotis.api.NodeLifecycle], on iOS to the engine's
 * pause/resume FFI. Both verbs BLOCK (they tear down / rebuild networking) and
 * may cross an FFI, so the router runs them off its event loop.
 */
interface RpcLifecycle {
    /** Idle-pause: quiesce P2P (sockets + periodic timers) while the RPC listener
     *  keeps listening. Returns the resulting transition. Blocking. */
    fun pause(): RpcLifecycleResult
    /** Wake a paused stack, recorded as the IPC/RPC wake reason. Returns the
     *  resulting transition. Blocking (seconds). */
    fun wakeUp(): RpcLifecycleResult
}

/** The outcome of an [RpcLifecycle] verb: [ok] is whether the target state was
 *  reached, [lifecycle] the coarse state now in effect ("RUNNING" | "PAUSED" |
 *  "STOPPED"). Mirrors the IPC command's `{"ok":…, "lifecycle":…}` shape. */
class RpcLifecycleResult(val ok: Boolean, val lifecycle: String)
