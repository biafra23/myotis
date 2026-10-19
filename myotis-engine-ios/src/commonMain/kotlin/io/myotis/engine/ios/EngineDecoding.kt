package io.myotis.engine.ios

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

/**
 * The engine's JSON payloads, decoded: the Kotlin twin of the JVM side's decoders
 * (`RustChainHandle`'s and `RustEnsApi`'s `fromJson` seams, `RustMyotisEngine.parseNetworks`),
 * rule for rule, and pinned by the same golden shapes (EngineDecodingTest, from
 * `RustVerifiedReadJsonTest`, `RustStatusJsonTest` and `RustEnsRecordJsonTest`).
 *
 * The rules, as there: a `{"error"}` object, a blank payload or one that is not
 * JSON throws [EngineException]; a field of the wrong type is shape drift and throws
 * too, never a silent default; an absent or JSON-null field reads as the documented
 * default; `{"error","code":-32602}` is the engine's PERMANENT refusal, a result where
 * the read has one, never the retryable failure.
 */
internal object EngineDecoding {

    private val json = Json

    /** JSON-RPC's "invalid params": the engine's permanent refusal. */
    private const val INVALID_PARAMS = -32602.0

    /** The sync-committee period's length in slots. */
    private const val SLOTS_PER_PERIOD = 8192L

    // ---- the catalog ----

    /** The network catalog, a JSON array of NetworkInfo objects (rust/testdata/networks_catalog.json). */
    fun networks(payload: String?): List<NetworkInfo> {
        val array = parse(payload, "network catalog") as? JsonArray
            ?: throw EngineException("malformed network catalog JSON from the Rust engine: not an array")
        return fields("network catalog") {
            array.map { element ->
                val o = element as? JsonObject ?: throw IllegalArgumentException("entry is not an object")
                NetworkInfo(
                    name = o.requiredString("name"),
                    displayName = o.requiredString("displayName"),
                    chainId = o.requiredLong("chainId"),
                    hasEns = o.requiredBoolean("hasEns"),
                    defaultElPort = o.requiredInt("defaultElPort"),
                    defaultDiscv5Port = o.requiredInt("defaultDiscv5Port"),
                    defaultRpcPort = o.requiredInt("defaultRpcPort"),
                    clGenesisTime = o.requiredLong("clGenesisTime"),
                    secondsPerSlot = o.requiredInt("secondsPerSlot"),
                )
            }
        }
    }

    // ---- status ----

    /** The status object as the engine reports it, before the handle ages its head. */
    data class ParsedStatus(
        val running: Boolean,
        val paused: Boolean,
        val elReaderAvailable: Boolean,
        val beaconState: BeaconState,
        val bootstrapped: Boolean,
        val finalizedSlot: Long,
        val optimisticSlot: Long,
        val currentPeriod: Long,
        val targetPeriod: Long,
        val peerCount: Long,
        val servedPeersLastMinute: Int,
        val discv5TableSize: Int,
        val syncStartPeriod: Long,
        val snapPeers: Int,
        val snapServingPeers: Int,
        val snap2ServingPeers: Int,
        val discoveredPeers: Int,
        val attemptedDials: Int,
        val backedOffPeers: Int,
        val blacklistedPeers: Int,
        val optimisticBlockNumber: Long,
        val finalizedBlockNumber: Long,
        val peerHeaderRequests: Long,
        val peerHeaderRequestsServed: Long,
        val peerBodyRequests: Long,
        val peerBodyRequestsServed: Long,
        val lcHunting: Boolean,
        val elHunting: Boolean,
        val wsBoundPeriods: Long,
        val upgradeAdvisory: UpgradeAdvisory?,
    ) {
        /** A verified read can be served now: SYNCED, an anchored optimistic head, and a
         *  pooled snap peer that can answer at it ([snapServingPeers], never the pooled
         *  count: a pool still syncing keeps that positive while every read fails, #465). */
        val serveable: Boolean
            get() = beaconState == BeaconState.SYNCED && optimisticBlockNumber > 0 && snapServingPeers > 0
    }

    /** The status JSON; `{}` or a blank payload is an unknown handle, read as not running. */
    fun status(payload: String?): ParsedStatus {
        if (payload.isNullOrBlank()) return NOT_RUNNING
        val o = parse(payload, "status") as? JsonObject
            ?: throw EngineException("malformed status JSON from the Rust engine: not an object")
        if (o.isEmpty()) return NOT_RUNNING
        return fields("status") {
            ParsedStatus(
                running = o.boolean("running"),
                paused = o.boolean("paused"),
                elReaderAvailable = o.boolean("elReaderAvailable"),
                // A state a newer engine added reads as STARTING: not ready, fail closed.
                beaconState = o.string("beaconState")
                    ?.let { name -> BeaconState.entries.firstOrNull { it.name == name } }
                    ?: BeaconState.STARTING,
                bootstrapped = o.boolean("bootstrapped"),
                finalizedSlot = o.long("finalizedSlot"),
                optimisticSlot = o.long("optimisticSlot"),
                currentPeriod = o.long("currentPeriod"),
                targetPeriod = o.long("targetPeriod"),
                peerCount = o.long("peerCount"),
                servedPeersLastMinute = o.int("servedPeersLastMinute"),
                discv5TableSize = o.int("discv5TableSize"),
                syncStartPeriod = o.long("syncStartPeriod", -1L),
                snapPeers = o.int("snapPeers"),
                // Absent → 0, fail closed, never the pooled count (#465).
                snapServingPeers = o.int("snapServingPeers"),
                snap2ServingPeers = o.int("snap2ServingPeers"),
                discoveredPeers = o.int("discoveredPeers"),
                attemptedDials = o.int("attemptedDials"),
                backedOffPeers = o.int("backedOffPeers"),
                blacklistedPeers = o.int("blacklistedPeers"),
                optimisticBlockNumber = o.long("optimisticBlockNumber"),
                finalizedBlockNumber = o.long("finalizedBlockNumber"),
                peerHeaderRequests = o.long("peerHeaderRequests"),
                peerHeaderRequestsServed = o.long("peerHeaderRequestsServed"),
                peerBodyRequests = o.long("peerBodyRequests"),
                peerBodyRequestsServed = o.long("peerBodyRequestsServed"),
                lcHunting = o.boolean("lcHunting"),
                elHunting = o.boolean("elHunting"),
                wsBoundPeriods = o.long("wsBoundPeriods"),
                upgradeAdvisory = advisory(o["upgradeAdvisory"]),
            )
        }
    }

    /** [ParsedStatus] mapped to the snapshot a host reads, with [verifiedHeadAgeMs] the
     *  handle's own measure of how long its head has stood. */
    fun snapshot(network: String, s: ParsedStatus, verifiedHeadAgeMs: Long): StatusSnapshot {
        val peers = s.peerCount.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        // An engine without targetPeriod reads 0 there: the target is never behind the current period.
        val targetPeriod = maxOf(s.targetPeriod, s.currentPeriod)
        return StatusSnapshot(
            running = s.running,
            lifecycle = when {
                s.running -> LifecycleState.RUNNING
                s.paused -> LifecycleState.PAUSED
                else -> LifecycleState.STOPPED
            },
            network = network,
            beaconState = s.beaconState,
            bootstrapped = s.bootstrapped,
            elReaderAvailable = s.elReaderAvailable,
            connectedPeers = peers,
            // The pool keeps only snap-ready peers.
            readyPeers = s.snapPeers,
            snapPeers = s.snapPeers,
            snapServingPeers = s.snapServingPeers,
            snap2ServingPeers = s.snap2ServingPeers,
            discoveredPeers = s.discoveredPeers,
            backedOffPeers = s.backedOffPeers,
            blacklistedPeers = s.blacklistedPeers,
            attemptedDials = s.attemptedDials,
            discv5TableSize = s.discv5TableSize,
            servedPeersLastMinute = s.servedPeersLastMinute,
            executionBlockNumber = s.finalizedBlockNumber,
            optimisticBlockNumber = s.optimisticBlockNumber,
            finalizedBlockNumber = s.finalizedBlockNumber,
            finalizedSlot = s.finalizedSlot,
            optimisticSlot = s.optimisticSlot,
            syncStartPeriod = s.syncStartPeriod,
            syncCurrentPeriod = s.currentPeriod,
            syncTargetPeriod = targetPeriod,
            finalizedPeriod = s.finalizedSlot / SLOTS_PER_PERIOD,
            wallClockPeriod = targetPeriod,
            verifiedHeadAgeMs = verifiedHeadAgeMs,
            wsBoundPeriods = s.wsBoundPeriods,
            peerHeaderRequests = s.peerHeaderRequests,
            peerHeaderRequestsServed = s.peerHeaderRequestsServed,
            peerBodyRequests = s.peerBodyRequests,
            peerBodyRequestsServed = s.peerBodyRequestsServed,
            lcHunting = s.lcHunting,
            elHunting = s.elHunting,
            upgradeAdvisory = s.upgradeAdvisory,
        )
    }

    /** The nested advisory; absent, null, not an object, a phase this build does not
     *  know or a field of the wrong type is no advisory, never a failed status read:
     *  the advisory is display-only. */
    private fun advisory(element: JsonElement?): UpgradeAdvisory? {
        val a = element as? JsonObject ?: return null
        return try {
            UpgradeAdvisory(
                phase = UpgradePhase.entries.firstOrNull { it.name == a.string("phase") } ?: return null,
                activationTime = a.long("activationTime"),
                forkId = a.string("forkId") ?: "",
                observedPeers = a.int("observedPeers"),
            )
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private val NOT_RUNNING = ParsedStatus(
        running = false, paused = false, elReaderAvailable = false, beaconState = BeaconState.STARTING,
        bootstrapped = false, finalizedSlot = 0, optimisticSlot = 0, currentPeriod = 0, targetPeriod = 0,
        peerCount = 0, servedPeersLastMinute = 0, discv5TableSize = 0, syncStartPeriod = -1, snapPeers = 0,
        snapServingPeers = 0, snap2ServingPeers = 0, discoveredPeers = 0, attemptedDials = 0,
        backedOffPeers = 0, blacklistedPeers = 0, optimisticBlockNumber = 0, finalizedBlockNumber = 0,
        peerHeaderRequests = 0, peerHeaderRequestsServed = 0, peerBodyRequests = 0,
        peerBodyRequestsServed = 0, lcHunting = false, elHunting = false, wsBoundPeriods = 0,
        upgradeAdvisory = null,
    )

    // ---- proofs ----

    fun account(address: String, payload: String?): AccountProofResult {
        val o = resultObject(payload, "account")
        return fields("account") {
            AccountProofResult(
                address = o.string("address") ?: address,
                exists = o.boolean("exists"),
                nonce = o.long("nonce", -1L),
                balanceWei = o.string("balanceWei"),
                storageRootHex = o.string("storageRootHex"),
                codeHashHex = o.string("codeHashHex"),
                blockNumber = o.long("blockNumber"),
                peerStateRootHex = o.string("peerStateRootHex"),
                peerProofValid = o.boolean("peerProofValid"),
                beaconChainVerified = o.boolean("beaconChainVerified"),
                blsVerified = o.boolean("blsVerified"),
                matchedBeaconSlot = o.long("matchedBeaconSlot", -1L),
                verifyMethod = o.string("verifyMethod"),
                failReason = o.string("failReason"),
                accountHashHex = o.string("accountHashHex"),
                proofNodesHex = o.stringList("proofNodesHex"),
                beaconSynced = o.boolean("beaconSynced"),
                finalizedPeriod = o.long("finalizedPeriod"),
                wallClockPeriod = o.long("wallClockPeriod"),
                finalizedBlockNumber = o.long("finalizedBlockNumber"),
                optimisticBlockNumber = o.long("optimisticBlockNumber"),
                // ABI 41: the proven block timestamp, -1 when none is proven.
                blockTimestamp = o.long("blockTimestamp", -1L),
            )
        }
    }

    fun storage(address: String, slot: Long, payload: String?): StorageProofResult {
        val o = resultObject(payload, "storage")
        return fields("storage") {
            StorageProofResult(
                addressHex = o.string("addressHex") ?: address,
                slot = o.long("slot", slot),
                holderHex = o.string("holderHex"),
                storageKeyHex = o.string("storageKeyHex"),
                storageKeyHashHex = o.string("storageKeyHashHex"),
                exists = o.boolean("exists"),
                valueHex = o.string("valueHex"),
                valueDecimal = o.string("valueDecimal"),
                slotsReturned = o.int("slotsReturned"),
                storageRootHex = o.string("storageRootHex"),
                proofNodesHex = o.stringList("proofNodesHex"),
                storageProofValid = o.boolean("storageProofValid"),
                beaconSynced = o.boolean("beaconSynced"),
                beaconChainVerified = o.boolean("beaconChainVerified"),
                blsVerified = o.boolean("blsVerified"),
                matchedBeaconSlot = o.long("matchedBeaconSlot", -1L),
                verifyMethod = o.string("verifyMethod"),
                failReason = o.string("failReason"),
                peerBlockNumber = o.long("peerBlockNumber"),
                finalizedBlockNumber = o.long("finalizedBlockNumber"),
                optimisticBlockNumber = o.long("optimisticBlockNumber"),
                finalizedSlot = o.long("finalizedSlot"),
                optimisticSlot = o.long("optimisticSlot"),
                maxHeaderChainGap = o.int("maxHeaderChainGap"),
            )
        }
    }

    /** Verified bytecode, empty for an account without code, or null without a verdict. */
    fun code(payload: String?): ByteArray? {
        val o = resultObject(payload, "code")
        return fields("code") {
            if (o.string("verifyMethod") == null) null else Hex.decode(o.string("codeHex"))
        }
    }

    /** A verified 32-byte storage word (a zero or unset slot is 32 zero bytes), or null
     *  without a verdict. */
    fun storageValue(payload: String?): ByteArray? {
        val o = resultObject(payload, "storage")
        return fields("storage") {
            if (o.string("verifyMethod") == null) {
                null
            } else {
                val value = Hex.decode(o.string("valueHex"))
                require(value.size <= 32) { "storage value exceeds 32 bytes: ${value.size}" }
                ByteArray(32 - value.size) + value
            }
        }
    }

    // ---- execution ----

    fun call(payload: String?): CallResult {
        val o = parseObject(payload, "call")
        permanentRefusal(o)?.let { return CallResult.refused(it) }
        throwIfError(o)
        return fields("call") {
            val block = o.long("blockNumber", -1L)
            when (o.string("status")) {
                "ok" -> CallResult.ok(Hex.decode(o.string("resultHex"))).atBlock(block)
                "revert" -> CallResult.reverted(Hex.decode(o.string("dataHex"))).atBlock(block)
                "infeasible" -> CallResult.infeasible(requiredReason(o, "call"))
                else -> CallResult.unavailable(o.string("reason"))
            }
        }
    }

    fun estimate(payload: String?): EstimateResult {
        val o = parseObject(payload, "estimateGas")
        permanentRefusal(o)?.let { return EstimateResult.refused(it) }
        throwIfError(o)
        return fields("estimateGas") {
            when (o.string("status")) {
                "ok" -> {
                    // ok without a numeric gas is shape drift, never a silent "unavailable".
                    val gas = o["gas"]
                    if (gas == null || gas is JsonNull) {
                        throw EngineException("estimateGas JSON: status=ok without a numeric 'gas' field")
                    }
                    EstimateResult.ok(o.long("gas"))
                }
                "revert" -> EstimateResult.reverted(Hex.decode(o.string("dataHex")))
                "infeasible" -> EstimateResult.infeasible(requiredReason(o, "estimateGas"))
                else -> EstimateResult.unavailable(o.string("reason"))
            }
        }
    }

    /** An infeasible outcome's reason; one without is shape drift. */
    private fun requiredReason(o: JsonObject, what: String): String =
        o.string("reason")?.takeIf { it.isNotBlank() }
            ?: throw EngineException("$what JSON: status=infeasible without a reason")

    // ---- sending ----

    /** The send gate's refusal, or null when the bytes may be sent or the answer is no
     *  refusal (bad hex, shape drift): the send itself then answers. */
    fun sendGateRefusal(payload: String?): String? =
        try {
            permanentRefusal(parseObject(payload, "checkRawTransaction"))
        } catch (e: EngineException) {
            null
        }

    fun send(payload: String?): SendResult {
        val o = parseObject(payload, "sendRawTransaction")
        permanentRefusal(o)?.let { return SendResult.refused(it) }
        throwIfError(o)
        return fields("sendRawTransaction") {
            if (o.string("status") == "rejected") {
                // A reason-less rejection would tell the wallet nothing: fail closed.
                val reason = o.string("reason")?.takeIf { it.isNotBlank() }
                    ?: throw EngineException("send-tx JSON rejected without a reason")
                return@fields SendResult.rejected(reason)
            }
            val hex = o.string("txHash") ?: throw EngineException("send-tx JSON missing txHash")
            val hash = Hex.decode(hex)
            if (hash.size != 32) throw EngineException("send-tx txHash is not 32 bytes: ${hash.size}")
            SendResult.sent(hash)
        }
    }

    // ---- pass-through JSON ----

    /** A receipt, block or fee-history payload: the object, or the `"null"` literal (a
     *  VERIFIED eth-null: not seen yet, unknown), passed through; an error throws. */
    fun objectOrNullLiteral(payload: String?, what: String): String {
        if (payload.isNullOrBlank()) throw EngineException("blank $what JSON from the Rust engine (native failure?)")
        if (payload == "null") return payload
        resultObject(payload, what)
        return payload
    }

    // ---- ENS ----

    /** The OffchainLookup this engine cannot drive: it has no CCIP-Read gateway. */
    private const val OFFCHAIN = "name resolves offchain (ERC-3668) but the OffchainLookup was not actionable"

    /** An `addr` record: its envelope (status, blockNumber, verified: each mandatory)
     *  and, for `ok`, the address. */
    fun ensAddress(name: String, payload: String?): EnsResolutionResult {
        val o = resultObject(payload, "ens-record")
        return fields("ens-record") {
            val status = o.string("status")
            val block = o["blockNumber"]
            val verified = o["verified"]
            if (status == null || block == null || block is JsonNull || verified == null || verified is JsonNull) {
                throw EngineException("ens-record JSON: missing status/blockNumber/verified")
            }
            val blockNumber = o.long("blockNumber")
            val isVerified = o.boolean("verified")
            val timestamp = o.long("blockTimestamp", -1L)
            when (status) {
                "ok" -> {
                    val address = o.string("addressHex")?.takeIf { it.isNotEmpty() }
                        ?: throw EngineException("ens-record JSON: status=ok without addressHex")
                    EnsResolutionResult(name, address, blockNumber, isVerified, null, timestamp)
                }
                "noRecord" -> EnsResolutionResult(name, null, blockNumber, isVerified, null, timestamp)
                "offchain" -> EnsResolutionResult(name, null, blockNumber, isVerified, OFFCHAIN, timestamp)
                else -> throw EngineException("ens-record JSON: unknown status '$status'")
            }
        }
    }

    // ---- the envelope ----

    private fun parse(payload: String?, what: String): JsonElement {
        if (payload.isNullOrBlank()) {
            throw EngineException("${if (payload == null) "null" else "blank"} $what JSON from the Rust engine (native failure?)")
        }
        return try {
            json.parseToJsonElement(payload)
        } catch (e: IllegalArgumentException) {
            throw EngineException("malformed $what JSON from the Rust engine: ${e.message}", e)
        }
    }

    /** A JSON object, error envelope or not. */
    private fun parseObject(payload: String?, what: String): JsonObject =
        parse(payload, what) as? JsonObject
            ?: throw EngineException("malformed $what JSON from the Rust engine: not an object")

    /** A JSON object that is no error envelope. */
    private fun resultObject(payload: String?, what: String): JsonObject =
        parseObject(payload, what).also(::throwIfError)

    private fun throwIfError(o: JsonObject) {
        val error = o["error"] ?: return
        if (error is JsonNull) return
        throw EngineException(error.message())
    }

    /** The message of `{"error","code":-32602}`, the permanent refusal; null for
     *  anything else, a plain error included. */
    private fun permanentRefusal(o: JsonObject): String? {
        val error = o["error"] ?: return null
        val code = o["code"] as? JsonPrimitive ?: return null
        if (error is JsonNull || code.isString || code.doubleOrNull != INVALID_PARAMS) return null
        return error.message()
    }

    /** An error value's text: the string itself, or a structured value as JSON. */
    private fun JsonElement.message(): String =
        (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: toString()

    /** Field extraction: a field of the wrong type is shape drift, reported as malformed. */
    private inline fun <T> fields(what: String, read: () -> T): T =
        try {
            read()
        } catch (e: EngineException) {
            throw e
        } catch (e: IllegalArgumentException) {
            throw EngineException("malformed $what JSON from the Rust engine: ${e.message}", e)
        }
}

// The field readers: absent or JSON null is the default, anything of the wrong type
// throws IllegalArgumentException, which `fields` reports as malformed JSON.

private fun JsonObject.primitive(key: String): JsonPrimitive? {
    val v = this[key] ?: return null
    if (v is JsonNull) return null
    return v as? JsonPrimitive ?: throw IllegalArgumentException("$key is not a primitive")
}

private fun JsonObject.long(key: String, default: Long = 0L): Long {
    val p = primitive(key) ?: return default
    if (p.isString) throw IllegalArgumentException("$key is a string, not a number")
    return p.longOrNull ?: throw IllegalArgumentException("$key is not an integer")
}

private fun JsonObject.int(key: String): Int {
    val v = long(key)
    if (v < Int.MIN_VALUE || v > Int.MAX_VALUE) throw IllegalArgumentException("$key is out of range")
    return v.toInt()
}

private fun JsonObject.boolean(key: String): Boolean {
    val p = primitive(key) ?: return false
    if (p.isString) throw IllegalArgumentException("$key is a string, not a boolean")
    return p.booleanOrNull ?: throw IllegalArgumentException("$key is not a boolean")
}

private fun JsonObject.string(key: String): String? {
    val p = primitive(key) ?: return null
    if (!p.isString) throw IllegalArgumentException("$key is not a string")
    return p.content
}

/** An absent list is empty (an older engine); a present one must be an array of strings. */
private fun JsonObject.stringList(key: String): List<String> {
    val v = this[key] ?: return emptyList()
    if (v is JsonNull) return emptyList()
    val array = v as? JsonArray ?: throw IllegalArgumentException("$key is not an array")
    return array.map { e ->
        (e as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw IllegalArgumentException("$key holds a non-string")
    }
}

private fun JsonObject.requiredString(key: String): String =
    string(key) ?: throw IllegalArgumentException("missing $key")

private fun JsonObject.requiredLong(key: String): Long {
    primitive(key) ?: throw IllegalArgumentException("missing $key")
    return long(key)
}

private fun JsonObject.requiredInt(key: String): Int {
    primitive(key) ?: throw IllegalArgumentException("missing $key")
    return int(key)
}

private fun JsonObject.requiredBoolean(key: String): Boolean {
    primitive(key) ?: throw IllegalArgumentException("missing $key")
    return boolean(key)
}
