package io.myotis.engine.ios

// The values the typed engine API (MyotisEngine, ChainHandle, VerifiedReads, EnsApi)
// hands out: the Kotlin twins of io.myotis.api's records and enums, with the same
// names and the same meanings, so an iOS host reads the engine as a JVM host does.
// They carry only what the C ABI reports; where a JVM record has a field this engine
// has no source for, it is left out rather than filled with a made-up value.

/** Why an engine call could not be answered at all: a transport or not-running
 *  failure, malformed input, or a payload the engine should not have sent. A
 *  verification FAILURE is not one: it is a result whose `failReason` is set. */
class EngineException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** A network the engine knows, from its embedded catalog. */
data class NetworkInfo(
    val name: String,
    val displayName: String,
    val chainId: Long,
    val hasEns: Boolean,
    val defaultElPort: Int,
    val defaultDiscv5Port: Int,
    val defaultRpcPort: Int,
    /** The beacon chain's genesis, unix seconds. */
    val clGenesisTime: Long,
    val secondsPerSlot: Int,
)

/** What a chain handle is created with: the network (a name or an alias the
 *  catalog knows) and the directory the engine keeps its sync snapshot, peer
 *  caches and log index in. One directory per network and process. */
data class EngineConfig(
    val networkName: String,
    val dataDir: String,
)

/** The light client's sync state. */
enum class BeaconState { STARTING, SYNCING, CATCHING_UP, SYNCED, STALE_ANCHOR }

/** A handle's lifecycle: [PAUSED] keeps its warm state with networking torn down. */
enum class LifecycleState { STOPPED, RUNNING, PAUSED }

/** How far along a network upgrade peers announce is. */
enum class UpgradePhase { SCHEDULED, ACTIVE }

/**
 * A network upgrade this build does not support, as PEERS report it: derived from
 * what they announce and not verified, so never chain state. [activationTime] is unix
 * seconds; [observedPeers] how many peers announced it.
 */
data class UpgradeAdvisory(
    val phase: UpgradePhase,
    val activationTime: Long,
    val forkId: String,
    val observedPeers: Int,
)

/**
 * The host's word on the network the device is on now, for [DataUsage]'s metered
 * figures ([MyotisEngine.setNetworkMetering]). [UNKNOWN] is not counted as metered.
 */
enum class NetworkMetering { UNKNOWN, UNMETERED, METERED }

/**
 * One network's bytes on the wire (docs/data-usage.md), the JVM contract's `DataUsage`.
 * The `today*` figures cover the local calendar day [day] and survive a restart of the
 * network on the same day; the rest count since the handle was created. A host running
 * several networks adds them up for the app's total.
 */
data class DataUsage(
    val bytesIn: Long,
    val bytesOut: Long,
    val elBytesIn: Long,
    val elBytesOut: Long,
    val clBytesIn: Long,
    val clBytesOut: Long,
    val day: String,
    val todayBytesIn: Long,
    val todayBytesOut: Long,
    val todayMeteredBytesIn: Long,
    val todayMeteredBytesOut: Long,
) {
    val todayBytes: Long get() = todayBytesIn + todayBytesOut
    val todayMeteredBytes: Long get() = todayMeteredBytesIn + todayMeteredBytesOut

    companion object {
        /** Nothing measured. */
        val NONE = DataUsage(0, 0, 0, 0, 0, 0, "", 0, 0, 0, 0)
    }
}

/**
 * One reading of a handle's status. The JVM contract's `StatusSnapshot` and
 * `BeaconStatus` in one: the light client's slots and [bootstrapped] are here too,
 * since this engine reports both from one status object.
 *
 * [verifiedHeadAgeMs] is how long ago the optimistic head last advanced, while a
 * verified read can be served (SYNCED, an anchored head, a snap peer serving at it);
 * otherwise [Long.MAX_VALUE], "no verified head". [syncTargetPeriod] is never below
 * [syncCurrentPeriod]. [executionBlockNumber] is the finalized payload's block.
 */
data class StatusSnapshot(
    val running: Boolean,
    val lifecycle: LifecycleState,
    val network: String,
    val beaconState: BeaconState,
    val bootstrapped: Boolean,
    val elReaderAvailable: Boolean,
    val connectedPeers: Int,
    val readyPeers: Int,
    val snapPeers: Int,
    val snapServingPeers: Int,
    val snap2ServingPeers: Int,
    val discoveredPeers: Int,
    val backedOffPeers: Int,
    val blacklistedPeers: Int,
    val attemptedDials: Int,
    val discv5TableSize: Int,
    val servedPeersLastMinute: Int,
    val executionBlockNumber: Long,
    val optimisticBlockNumber: Long,
    val finalizedBlockNumber: Long,
    val finalizedSlot: Long,
    val optimisticSlot: Long,
    val syncStartPeriod: Long,
    val syncCurrentPeriod: Long,
    val syncTargetPeriod: Long,
    val finalizedPeriod: Long,
    val wallClockPeriod: Long,
    val verifiedHeadAgeMs: Long,
    val wsBoundPeriods: Long,
    val peerHeaderRequests: Long,
    val peerHeaderRequestsServed: Long,
    val peerBodyRequests: Long,
    val peerBodyRequestsServed: Long,
    val lcHunting: Boolean,
    val elHunting: Boolean,
    val upgradeAdvisory: UpgradeAdvisory?,
    val dataUsage: DataUsage,
    val networkMetering: NetworkMetering,
)

/**
 * A verified account read. [verifyMethod] set means a verdict; [failReason] set means
 * the verification failed, which is a result, not an error. [nonce] is -1 and
 * [balanceWei] null for an account proven absent; [blockTimestamp] is -1 unless the
 * block's timestamp is proven, and [blockHashHex] null unless the block's hash is (the
 * beacon anchor vouches for a block of that number with the proof's state root; ABI 52).
 */
data class AccountProofResult(
    val address: String,
    val exists: Boolean,
    val nonce: Long,
    val balanceWei: String?,
    val storageRootHex: String?,
    val codeHashHex: String?,
    val blockNumber: Long,
    val peerStateRootHex: String?,
    val peerProofValid: Boolean,
    val beaconChainVerified: Boolean,
    val blsVerified: Boolean,
    val matchedBeaconSlot: Long,
    val verifyMethod: String?,
    val failReason: String?,
    val accountHashHex: String?,
    val proofNodesHex: List<String>,
    val beaconSynced: Boolean,
    val finalizedPeriod: Long,
    val wallClockPeriod: Long,
    val finalizedBlockNumber: Long,
    val optimisticBlockNumber: Long,
    val blockTimestamp: Long,
    val blockHashHex: String? = null,
)

/** A verified storage-slot read, with the same verdict rules as [AccountProofResult]. */
data class StorageProofResult(
    val addressHex: String,
    val slot: Long,
    val holderHex: String?,
    val storageKeyHex: String?,
    val storageKeyHashHex: String?,
    val exists: Boolean,
    val valueHex: String?,
    val valueDecimal: String?,
    val slotsReturned: Int,
    val storageRootHex: String?,
    val proofNodesHex: List<String>,
    val storageProofValid: Boolean,
    val beaconSynced: Boolean,
    val beaconChainVerified: Boolean,
    val blsVerified: Boolean,
    val matchedBeaconSlot: Long,
    val verifyMethod: String?,
    val failReason: String?,
    val peerBlockNumber: Long,
    val finalizedBlockNumber: Long,
    val optimisticBlockNumber: Long,
    val finalizedSlot: Long,
    val optimisticSlot: Long,
    val maxHeaderChainGap: Int,
)

/**
 * A verified `eth_call`, its outcomes told apart. [data] is the return data for
 * [Status.OK] and the revert payload for [Status.REVERTED], null otherwise; [detail]
 * the reason for the others. [blockNumber] is the block an answered call ran against,
 * -1 when unknown, and [blockHashHex] that block's hash when it is proven (the beacon
 * anchor vouches for a block of that number with the state root the call ran against;
 * ABI 52), null otherwise.
 */
class CallResult(
    val status: Status,
    val data: ByteArray?,
    val detail: String?,
    val blockNumber: Long = -1L,
    val blockHashHex: String? = null,
) {

    /** The outcomes: [REFUSED] is permanent (no retry can succeed), [UNAVAILABLE]
     *  is not, and [INFEASIBLE] is a call that cannot succeed within the caller's
     *  gas, fee cap or funds, in geth's words. */
    enum class Status { OK, REVERTED, UNAVAILABLE, REFUSED, INFEASIBLE }

    /** This result, answered at [block], of proven hash [hashHex] (null: not proven). */
    fun atBlock(block: Long, hashHex: String? = null): CallResult = CallResult(status, data, detail, block, hashHex)

    override fun toString(): String =
        "CallResult($status, ${data?.size ?: "no"} bytes, $detail, block $blockNumber, hash $blockHashHex)"

    companion object {
        fun ok(data: ByteArray): CallResult = CallResult(Status.OK, data, null)
        fun reverted(revertData: ByteArray): CallResult = CallResult(Status.REVERTED, revertData, null)
        fun unavailable(detail: String?): CallResult = CallResult(Status.UNAVAILABLE, null, detail)
        fun refused(detail: String): CallResult = CallResult(Status.REFUSED, null, detail)
        fun infeasible(detail: String): CallResult = CallResult(Status.INFEASIBLE, null, detail)
    }
}

/** A verified `eth_estimateGas`, its outcomes told apart as [CallResult]'s are:
 *  [gas] for [Status.OK], [revertData] for [Status.REVERTED], [detail] otherwise. */
class EstimateResult(val status: Status, val gas: Long, val revertData: ByteArray?, val detail: String?) {

    /** The outcomes, with [CallResult.Status]'s meanings. */
    enum class Status { OK, REVERTED, UNAVAILABLE, REFUSED, INFEASIBLE }

    override fun toString(): String = "EstimateResult($status, gas $gas, $detail)"

    companion object {
        fun ok(gas: Long): EstimateResult = EstimateResult(Status.OK, gas, null, null)
        fun reverted(revertData: ByteArray): EstimateResult = EstimateResult(Status.REVERTED, 0L, revertData, null)
        fun unavailable(detail: String?): EstimateResult = EstimateResult(Status.UNAVAILABLE, 0L, null, detail)
        fun refused(detail: String): EstimateResult = EstimateResult(Status.REFUSED, 0L, null, detail)
        fun infeasible(detail: String): EstimateResult = EstimateResult(Status.INFEASIBLE, 0L, null, detail)
    }
}

/**
 * A raw transaction's send: [Status.SENT] with its 32-byte [txHash]; [Status.REJECTED]
 * with geth's reason for one that can never be mined as sent, and [Status.REFUSED] for
 * bytes that are no transaction the engine relays, neither broadcast; or
 * [Status.UNAVAILABLE] when no peer could be reached.
 */
class SendResult(val status: Status, val txHash: ByteArray?, val detail: String?) {

    /** The outcomes; only [SENT] broadcast anything. */
    enum class Status { SENT, REJECTED, REFUSED, UNAVAILABLE }

    override fun toString(): String = "SendResult($status, $detail)"

    companion object {
        fun sent(txHash: ByteArray): SendResult = SendResult(Status.SENT, txHash, null)
        fun rejected(detail: String): SendResult = SendResult(Status.REJECTED, null, detail)
        fun refused(detail: String): SendResult = SendResult(Status.REFUSED, null, detail)
        fun unavailable(detail: String?): SendResult = SendResult(Status.UNAVAILABLE, null, detail)
    }
}

/** Which state root an ENS lookup resolves against: [FINALIZED] fails closed,
 *  [AUTO] tries it first and falls back to the beacon-attested optimistic head, and
 *  [PEER_HEAD] is that head (this engine has no peer-claimed-head mode). */
enum class EnsRoot { FINALIZED, PEER_HEAD, AUTO }

/**
 * An ENS forward resolution. [addressHex] null with [error] null is a successful "no
 * record"; [error] set is a failure. [verified] means resolved against the
 * beacon-finalized root. [blockNumber] is -1 when nothing was resolved, as is
 * [blockTimestamp] when no timestamp is known.
 */
data class EnsResolutionResult(
    val name: String?,
    val addressHex: String?,
    val blockNumber: Long,
    val verified: Boolean,
    val error: String?,
    val blockTimestamp: Long = -1L,
)
