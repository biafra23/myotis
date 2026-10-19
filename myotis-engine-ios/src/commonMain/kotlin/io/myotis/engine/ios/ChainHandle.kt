package io.myotis.engine.ios

import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.TimeSource

/**
 * One network the engine hosts: the Kotlin twin of `io.myotis.api.ChainHandle` over the
 * C ABI, made by [MyotisEngine.create]. Its lifecycle is [start], [pause] and [resume]
 * (networking torn down and rebuilt, warm state kept) and [stop]; its chain data comes
 * from [requestAccount], [getStorageProof], [reads] and [ens].
 *
 * Unlike the JVM handle, this one does not hold a read that arrives while it is paused
 * or still starting until it can answer: such a read answers at once, as unavailable or
 * as the engine's error. The host resumes the handle before reading.
 *
 * Every call blocks; see [MyotisEngine].
 */
@OptIn(ExperimentalAtomicApi::class)
class ChainHandle internal constructor(
    private val native: NativeEngine,
    private val handle: Long,
    /** The network's canonical name. */
    val networkName: String,
    val chainId: Long,
    hasEns: Boolean,
) {

    /** The optimistic head last seen and when it was first seen: what [status] ages. */
    private class HeadMark(val block: Long, val since: TimeSource.Monotonic.ValueTimeMark)

    private val head = AtomicReference<HeadMark?>(null)

    private val verifiedReads = VerifiedReads(this)

    private val ensApi = if (hasEns) EnsApi(this) else null

    /** Serializes start/stop/pause/resume, which the C ABI requires per handle. */
    private val lifecycleLock = native.newLock()

    /** Starts the sync loop; false for a handle that is running already or could not start
     *  (the engine's log, `Myotis.drainLogs`, says why). */
    fun start(): Boolean = lifecycleLock.withLock { native.start(handle) }

    /** Stops the handle: its networking and its sync loop. Synchronous and final: the
     *  engine forgets the handle, so it cannot be started again. The network stays
     *  hosted, as on the JVM: [MyotisEngine.stop] is what releases it for a new create,
     *  and is the call a host normally makes. */
    fun stop() = lifecycleLock.withLock { native.stop(handle) }

    /** Tears networking down and keeps the warm state, for while the app is in the
     *  background; true only on an actual transition. */
    fun pause(): Boolean = lifecycleLock.withLock { native.pause(handle) }

    /** A warm restart after [pause]; false when it failed (still paused, retryable) or
     *  the handle was not paused. */
    fun resume(): Boolean = lifecycleLock.withLock { native.resume(handle) }

    /** Where the handle is in its lifecycle. */
    fun lifecycle(): LifecycleState = status().lifecycle

    fun isRunning(): Boolean = lifecycle() == LifecycleState.RUNNING

    /**
     * The handle's status now. Its [StatusSnapshot.verifiedHeadAgeMs] is measured here,
     * as the JVM handle measures it: from when this handle first saw the current
     * optimistic head, while a verified read can be served, and [Long.MAX_VALUE] while
     * one cannot. Throws [EngineException] on a status the engine should not have sent.
     */
    fun status(): StatusSnapshot {
        val s = EngineDecoding.status(native.statusJson(handle))
        return EngineDecoding.snapshot(networkName, s, headAgeMs(s))
    }

    /** The optimistic head's block number while a verified read can be served at it
     *  (running, SYNCED, an anchored head, a snap peer serving it), else null: a paused
     *  or catching-up handle's frozen head is not the chain's. */
    internal fun servableHead(): Long? {
        val s = EngineDecoding.status(native.statusJson(handle))
        return s.optimisticBlockNumber.takeIf { s.running && !s.paused && s.serveable }
    }

    private fun headAgeMs(s: EngineDecoding.ParsedStatus): Long {
        val now = TimeSource.Monotonic.markNow()
        if (!s.serveable) {
            // Pinned to now while nothing can be served, so the first serveable reading
            // starts near 0 instead of carrying the outage in.
            head.store(HeadMark(s.optimisticBlockNumber, now))
            return Long.MAX_VALUE
        }
        while (true) {
            val current = head.load()
            val next = if (current != null && current.block == s.optimisticBlockNumber) current else {
                HeadMark(s.optimisticBlockNumber, now)
            }
            if (next === current || head.compareAndSet(current, next)) {
                return (now - next.since).inWholeMilliseconds.coerceAtLeast(0L)
            }
        }
    }

    /** Overrides the weak-subjectivity bound on the anchor's age, in sync-committee
     *  periods (0: the network's default); applied live. False only for a handle the
     *  engine no longer knows. */
    fun setWsBoundPeriods(periods: Long): Boolean = native.setWsBoundPeriods(handle, periods)

    /** Consents, for this run only, to syncing forward from an anchor older than the
     *  weak-subjectivity bound (a handle parked in [BeaconState.STALE_ANCHOR]). False
     *  only for a handle the engine no longer knows. */
    fun acceptStaleAnchor(): Boolean = native.acceptStaleAnchor(handle)

    /**
     * A verified account read at the verified head. A verification failure is a result
     * with its `failReason` set; a transport or not-running failure throws
     * [EngineException].
     */
    fun requestAccount(hexAddress: String): AccountProofResult = accountAt(hexAddress, "")

    /**
     * A verified read of storage [slot] of [hexAddress], for [holderHexOrNull] where the
     * slot is a mapping keyed by an address (an ERC-20 balance), with the verdict rules
     * of [requestAccount].
     */
    fun getStorageProof(hexAddress: String, slot: Long, holderHexOrNull: String?): StorageProofResult =
        EngineDecoding.storage(hexAddress, slot, native.getStorageProofJson(handle, hexAddress, slot, holderHexOrNull))

    /** The verified `eth_*` reads. */
    fun reads(): VerifiedReads = verifiedReads

    /** ENS, or null on a network without a name registry. */
    fun ens(): EnsApi? = ensApi

    // ---- the reads' native hops, for VerifiedReads and EnsApi ----

    /** [requestAccount] at a block selector the engine applies or refuses. */
    internal fun accountAt(hexAddress: String, block: String): AccountProofResult =
        EngineDecoding.account(hexAddress, native.requestAccountJson(handle, hexAddress, block))

    internal fun codeAt(hexAddress: String, block: String): ByteArray? =
        EngineDecoding.code(native.getCodeJson(handle, hexAddress, block))

    internal fun storageAt(hexAddress: String, position32Hex: String, block: String): ByteArray? =
        EngineDecoding.storageValue(native.getStorageAtJson(handle, hexAddress, position32Hex, block))

    internal fun call(from: String, to: String, data: String, value: String, block: String, overrides: String): CallResult =
        EngineDecoding.call(
            if (overrides.isEmpty()) {
                native.ethCallJson(handle, from, to, data, value, block)
            } else {
                native.ethCallOverridesJson(handle, from, to, data, value, block, overrides)
            },
        )

    internal fun estimateGas(from: String, to: String, data: String, value: String): EstimateResult =
        EngineDecoding.estimate(native.estimateGasJson(handle, from, to, data, value))

    /** `max(minedNonce, this node's broadcast nonce + 1)` while its send is unmined; the
     *  mined nonce when the engine answers no overlay. */
    internal fun pendingNonce(hexAddress: String, minedNonce: Long): Long {
        val overlaid = native.pendingNonceOverlay(handle, hexAddress, minedNonce)
        return if (overlaid >= 0) overlaid else minedNonce
    }

    internal fun feeHistory(blockCount: Long, newestBlock: String, percentilesJson: String): String =
        EngineDecoding.objectOrNullLiteral(
            native.feeHistoryJson(handle, blockCount, newestBlock, percentilesJson),
            "feeHistory",
        )

    internal fun receipt(txHashHex: String): String =
        EngineDecoding.objectOrNullLiteral(native.getTransactionReceiptJson(handle, txHashHex), "receipt")

    /** Bytes that are no transaction are refused on the bytes alone, before the send. */
    internal fun send(rawTxHex: String): SendResult {
        EngineDecoding.sendGateRefusal(native.checkRawTransactionJson(rawTxHex))?.let { return SendResult.refused(it) }
        return EngineDecoding.send(native.sendRawTransactionJson(handle, rawTxHex))
    }

    internal fun ensRecord(paramsJson: String): String = native.ensRecordJson(handle, paramsJson)
}
