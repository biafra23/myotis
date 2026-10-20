package io.myotis.engine.ios

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Kotlin/Native half of the engine's JSON golden contract: the exact shapes the Rust
 * side emits (pinned there by eljson's and host's shape tests) decoded as the JVM side
 * decodes them. The literals are those of `RustVerifiedReadJsonTest`, `RustStatusJsonTest`
 * and `RustEnsRecordJsonTest` in :myotis-engine-rust, so the three halves stay visibly
 * parallel; a change to one is a change to all.
 */
class EngineDecodingTest {

    // ---- the catalog (rust/testdata/networks_catalog.json's shape) ----

    @Test
    fun theCatalogDecodes() {
        val networks = EngineDecoding.networks(
            """[{"name":"sepolia","displayName":"Sepolia","chainId":11155111,"hasEns":true,""" +
                """"defaultElPort":30303,"defaultDiscv5Port":9000,"defaultRpcPort":8547,""" +
                """"clGenesisTime":1655733600,"secondsPerSlot":12}]""",
        )
        assertEquals(
            listOf(NetworkInfo("sepolia", "Sepolia", 11155111, true, 30303, 9000, 8547, 1655733600, 12)),
            networks,
        )
        // A missing field is drift, not a default.
        assertFailsWith<EngineException> { EngineDecoding.networks("""[{"name":"sepolia"}]""") }
        assertFailsWith<EngineException> { EngineDecoding.networks("""{"name":"sepolia"}""") }
        val wide = """[{"name":"sepolia","displayName":"Sepolia","chainId":11155111,"hasEns":true,""" +
            """"defaultElPort":30303,"defaultDiscv5Port":9000,"defaultRpcPort":4294975843,""" +
            """"clGenesisTime":1655733600,"secondsPerSlot":12}]"""
        assertFailsWith<EngineException>("a port out of Int range is drift") { EngineDecoding.networks(wide) }
    }

    // ---- status ----

    /** The committed not-started golden shape: byte for byte the Rust fallback const. */
    private val notStarted =
        """{"running":false,"paused":false,"network":"mainnet","beaconState":"STARTING",""" +
            """"bootstrapped":false,"finalizedSlot":0,"optimisticSlot":0,""" +
            """"currentPeriod":0,"targetPeriod":0,"peerCount":0,"servedPeersLastMinute":0,""" +
            """"discv5TableSize":0,"syncStartPeriod":-1,"lcHunting":false,"wsBoundPeriods":0,""" +
            """"finalizedRootHex":"0000000000000000000000000000000000000000000000000000000000000000",""" +
            """"elReaderAvailable":false,""" +
            """"snapPeers":0,"snapServingPeers":0,"snap2ServingPeers":0,"readyPeers":0,"discoveredPeers":0,"attemptedDials":0,""" +
            """"backedOffPeers":0,"blacklistedPeers":0,"optimisticBlockNumber":0,""" +
            """"finalizedBlockNumber":0,"executionBlockNumber":0,"elHunting":false,""" +
            """"peerHeaderRequests":0,"peerHeaderRequestsServed":0,""" +
            """"peerBodyRequests":0,"peerBodyRequestsServed":0,"upgradeAdvisory":null,""" +
            """"dataUsage":null,"networkMetering":"UNKNOWN"}"""

    /** A synthetic catching-up shape (real running numbers, the EL counts too). */
    private val catchingUp =
        """{"running":true,"network":"mainnet","beaconState":"CATCHING_UP",""" +
            """"bootstrapped":true,"finalizedSlot":14560000,"optimisticSlot":14560032,""" +
            """"currentPeriod":1777,"targetPeriod":1795,"peerCount":5,"servedPeersLastMinute":2,""" +
            """"discv5TableSize":7,"syncStartPeriod":1777,"lcHunting":true,"elHunting":true,""" +
            """"finalizedRootHex":"58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e",""" +
            """"elReaderAvailable":true,""" +
            """"snapPeers":6,"snapServingPeers":4,"snap2ServingPeers":1,"readyPeers":6,"discoveredPeers":240,"attemptedDials":14,""" +
            """"backedOffPeers":30,"blacklistedPeers":66,""" +
            """"optimisticBlockNumber":21000010,"finalizedBlockNumber":20999000,""" +
            """"executionBlockNumber":20999000,""" +
            """"peerHeaderRequests":6,"peerHeaderRequestsServed":2,""" +
            """"peerBodyRequests":1,"peerBodyRequestsServed":0}"""

    /** Idle-slept: running=false + paused=true, the beacon fields frozen at pause time. */
    private val paused =
        """{"running":false,"paused":true,"network":"mainnet","beaconState":"SYNCED",""" +
            """"bootstrapped":true,"finalizedSlot":14560000,"optimisticSlot":14560032,""" +
            """"currentPeriod":1777,"targetPeriod":1795,"peerCount":0,"servedPeersLastMinute":0,""" +
            """"discv5TableSize":0,"syncStartPeriod":1777,""" +
            """"finalizedRootHex":"58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e",""" +
            """"elReaderAvailable":false,""" +
            """"snapPeers":0,"snapServingPeers":0,"snap2ServingPeers":0,"readyPeers":0,"discoveredPeers":0,"attemptedDials":0,""" +
            """"backedOffPeers":0,"blacklistedPeers":0,""" +
            """"optimisticBlockNumber":0,"finalizedBlockNumber":0,"executionBlockNumber":0}"""

    private val scheduledAdvisory =
        """{"running":true,"network":"sepolia","beaconState":"SYNCED",""" +
            """"bootstrapped":true,"finalizedSlot":11000000,"optimisticSlot":11000032,""" +
            """"currentPeriod":1342,"targetPeriod":1342,"peerCount":5,""" +
            """"upgradeAdvisory":{"phase":"SCHEDULED","activationTime":1791294816,""" +
            """"forkId":"0x6c1d9423","observedPeers":4}}"""

    private fun snapshot(json: String, age: Long = Long.MAX_VALUE): StatusSnapshot =
        EngineDecoding.snapshot("mainnet", EngineDecoding.status(json), age)

    @Test
    fun aNotStartedStatusIsAStoppedStartingSnapshot() {
        val s = snapshot(notStarted)
        assertFalse(s.running)
        assertEquals(LifecycleState.STOPPED, s.lifecycle)
        assertEquals(BeaconState.STARTING, s.beaconState)
        assertEquals(-1L, s.syncStartPeriod)
        assertEquals(0L, s.optimisticBlockNumber)
        assertFalse(s.lcHunting)
        assertNull(s.upgradeAdvisory)
        assertFalse(EngineDecoding.status(notStarted).serveable)
    }

    @Test
    fun aCatchingUpStatusCarriesTheBeaconAndExecutionFields() {
        val s = snapshot(catchingUp)
        assertTrue(s.running)
        assertEquals(LifecycleState.RUNNING, s.lifecycle)
        assertEquals(BeaconState.CATCHING_UP, s.beaconState)
        assertTrue(s.bootstrapped)
        assertEquals(5, s.connectedPeers)
        assertEquals(14560000L, s.finalizedSlot)
        assertEquals(14560032L, s.optimisticSlot)
        assertEquals(1777L, s.syncCurrentPeriod)
        assertEquals(1795L, s.syncTargetPeriod)
        assertEquals(1795L, s.wallClockPeriod)
        assertEquals(14560000L / 8192L, s.finalizedPeriod)
        assertEquals(2, s.servedPeersLastMinute)
        assertEquals(7, s.discv5TableSize)
        assertEquals(6, s.snapPeers)
        assertEquals(6, s.readyPeers)
        assertEquals(4, s.snapServingPeers)
        assertEquals(1, s.snap2ServingPeers)
        assertEquals(240, s.discoveredPeers)
        assertEquals(14, s.attemptedDials)
        assertEquals(30, s.backedOffPeers)
        assertEquals(66, s.blacklistedPeers)
        assertEquals(21000010L, s.optimisticBlockNumber)
        assertEquals(20999000L, s.finalizedBlockNumber)
        assertEquals(20999000L, s.executionBlockNumber)
        assertEquals(6L, s.peerHeaderRequests)
        assertEquals(2L, s.peerHeaderRequestsServed)
        assertEquals(1L, s.peerBodyRequests)
        assertTrue(s.lcHunting)
        assertTrue(s.elHunting)
        // Not SYNCED: nothing can be served.
        assertFalse(EngineDecoding.status(catchingUp).serveable)
    }

    @Test
    fun aStatusIsServeableOnlySyncedWithAHeadAndAPeerServingAtIt() {
        val synced = catchingUp.replace("CATCHING_UP", "SYNCED")
        assertTrue(EngineDecoding.status(synced).serveable)
        // A pool of peers none of which can answer at the head (#465), or no key for them.
        assertFalse(EngineDecoding.status(synced.replace("\"snapServingPeers\":4", "\"snapServingPeers\":0")).serveable)
        assertFalse(EngineDecoding.status(synced.replace("\"snapServingPeers\":4,", "")).serveable)
        assertFalse(
            EngineDecoding.status(synced.replace("\"optimisticBlockNumber\":21000010", "\"optimisticBlockNumber\":0"))
                .serveable,
        )
    }

    @Test
    fun aPausedStatusIsPausedWithItsBeaconFieldsFrozen() {
        val s = snapshot(paused)
        assertFalse(s.running)
        assertEquals(LifecycleState.PAUSED, s.lifecycle)
        assertEquals(BeaconState.SYNCED, s.beaconState)
        assertEquals(14560000L, s.finalizedSlot)
        assertFalse(EngineDecoding.status(paused).serveable)
        // An older shape without the paused key is stopped, never paused.
        assertEquals(
            LifecycleState.STOPPED,
            snapshot("""{"running":false,"network":"mainnet","beaconState":"STARTING"}""").lifecycle,
        )
    }

    @Test
    fun anOlderShapeWithoutTargetPeriodFallsBackToTheCurrentPeriod() {
        val s = snapshot(
            """{"running":true,"network":"mainnet","beaconState":"CATCHING_UP",""" +
                """"bootstrapped":true,"finalizedSlot":14560000,"optimisticSlot":14560032,""" +
                """"currentPeriod":1777,"peerCount":5}""",
        )
        assertEquals(1777L, s.syncCurrentPeriod)
        assertEquals(1777L, s.syncTargetPeriod)
        assertEquals(0L, s.executionBlockNumber)
    }

    @Test
    fun aStaleAnchorParkCarriesTheBound() {
        val s = snapshot(
            """{"running":true,"network":"mainnet","beaconState":"STALE_ANCHOR",""" +
                """"bootstrapped":false,"finalizedSlot":0,"optimisticSlot":0,""" +
                """"currentPeriod":1825,"targetPeriod":1845,"peerCount":0,""" +
                """"discv5TableSize":3,"syncStartPeriod":-1,"wsBoundPeriods":13}""",
        )
        assertEquals(BeaconState.STALE_ANCHOR, s.beaconState)
        assertEquals(1825L, s.syncCurrentPeriod)
        assertEquals(1845L, s.syncTargetPeriod)
        assertEquals(13L, s.wsBoundPeriods)
    }

    @Test
    fun aBeaconStateFromANewerEngineReadsAsStarting() {
        val s = snapshot(
            """{"running":true,"network":"mainnet","beaconState":"SOME_FUTURE_STATE","currentPeriod":5,"targetPeriod":6}""",
        )
        assertEquals(BeaconState.STARTING, s.beaconState)
        assertEquals(5L, s.syncCurrentPeriod)
    }

    @Test
    fun anUnknownHandleIsNotRunning() {
        assertFalse(snapshot("{}").running)
        assertEquals(BeaconState.STARTING, snapshot("{}").beaconState)
        assertFailsWith<EngineException> { EngineDecoding.status("not json") }
        assertFailsWith<EngineException> { EngineDecoding.status("""{"running":"yes"}""") }
    }

    @Test
    fun theUpgradeAdvisoryIsDecodedAndNeverFailsAStatus() {
        val a = EngineDecoding.status(scheduledAdvisory).upgradeAdvisory
        assertEquals(UpgradeAdvisory(UpgradePhase.SCHEDULED, 1_791_294_816L, "0x6c1d9423", 4), a)
        assertNull(EngineDecoding.status(notStarted).upgradeAdvisory)
        assertNull(EngineDecoding.status(catchingUp).upgradeAdvisory)
        // A phase this build does not know, a non-object, a field of the wrong type: no
        // advisory, and the status still reads.
        val unknownPhase = EngineDecoding.status(scheduledAdvisory.replace("SCHEDULED", "IMMINENT"))
        assertTrue(unknownPhase.running)
        assertNull(unknownPhase.upgradeAdvisory)
        assertNull(
            EngineDecoding.status(
                scheduledAdvisory.replace(Regex("""\{"phase".*?\}"""), "\"soon\""),
            ).upgradeAdvisory,
        )
        assertNull(EngineDecoding.status(scheduledAdvisory.replace("\"SCHEDULED\"", "5")).upgradeAdvisory)
    }

    /** The ABI-50 data-usage keys, as the Rust status_object emits them. */
    private val dataUsageStatus =
        """{"running":true,"network":"gnosis","beaconState":"SYNCED",""" +
            """"dataUsage":{"bytesIn":40,"bytesOut":6,"elBytesIn":10,"elBytesOut":2,""" +
            """"clBytesIn":30,"clBytesOut":4,"day":"2026-10-20","todayBytesIn":400,""" +
            """"todayBytesOut":60,"todayMeteredBytesIn":100,"todayMeteredBytesOut":9},""" +
            """"networkMetering":"METERED"}"""

    @Test
    fun dataUsageAndMeteringAreDecodedAndNeverFailAStatus() {
        val s = snapshot(dataUsageStatus)
        assertEquals(DataUsage(40, 6, 10, 2, 30, 4, "2026-10-20", 400, 60, 100, 9), s.dataUsage)
        assertEquals(460L, s.dataUsage.todayBytes)
        assertEquals(109L, s.dataUsage.todayMeteredBytes)
        assertEquals(NetworkMetering.METERED, s.networkMetering)
        for (json in listOf(notStarted, catchingUp, "{}")) {
            assertEquals(DataUsage.NONE, snapshot(json).dataUsage, json)
            assertEquals(NetworkMetering.UNKNOWN, snapshot(json).networkMetering, json)
        }
        // A metering name this build does not know, a usage field of the wrong type.
        val odd = snapshot(
            dataUsageStatus.replace("\"METERED\"", "\"SATELLITE\"").replace("\"bytesIn\":40", "\"bytesIn\":\"lots\""),
        )
        assertTrue(odd.running)
        assertEquals(DataUsage.NONE, odd.dataUsage)
        assertEquals(NetworkMetering.UNKNOWN, odd.networkMetering)
    }

    // ---- the account ----

    /** A headerChain-verified account (the Rust eljson sample_account). */
    private val account =
        """{"address":"0xd8da6bf26964af9d7eed9e03e53415d37aa96045",""" +
            """"exists":true,"nonce":5898,"balanceWei":"1000000000000000000",""" +
            """"storageRootHex":"0x56e81f171bcac1a441cf3f1d5f0b8d5f0f3f0e5e5b5b5b5b5b5b5b5b5b5b5b5b5",""" +
            """"codeHashHex":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",""" +
            """"blockNumber":21000000,"blockTimestamp":1700000000,""" +
            """"peerStateRootHex":"0x5555555555555555555555555555555555555555555555555555555555555555",""" +
            """"peerProofValid":true,"beaconChainVerified":true,"blsVerified":true,""" +
            """"matchedBeaconSlot":7000000,"verifyMethod":"headerChain","failReason":null,""" +
            """"accountHashHex":"0x2222222222222222222222222222222222222222222222222222222222222222",""" +
            """"proofNodesHex":[],"beaconSynced":true,""" +
            """"finalizedPeriod":1777,"wallClockPeriod":1795,""" +
            """"finalizedBlockNumber":20999000,"optimisticBlockNumber":21000010}"""

    @Test
    fun anAccountDecodes() {
        val r = EngineDecoding.account("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", account)
        assertEquals("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", r.address)
        assertTrue(r.exists)
        assertEquals(5898L, r.nonce)
        assertEquals("1000000000000000000", r.balanceWei)
        assertEquals("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", r.codeHashHex)
        assertEquals(21000000L, r.blockNumber)
        assertTrue(r.peerProofValid)
        assertTrue(r.beaconChainVerified)
        assertTrue(r.blsVerified)
        assertEquals(7000000L, r.matchedBeaconSlot)
        assertEquals("headerChain", r.verifyMethod)
        assertNull(r.failReason)
        assertTrue(r.beaconSynced)
        assertEquals(1777L, r.finalizedPeriod)
        assertEquals(1795L, r.wallClockPeriod)
        assertEquals(20999000L, r.finalizedBlockNumber)
        assertEquals(21000010L, r.optimisticBlockNumber)
        assertTrue(r.proofNodesHex.isEmpty())
        assertEquals(1700000000L, r.blockTimestamp)
    }

    @Test
    fun anUnprovenTimestampIsMinusOne() {
        assertEquals(
            -1L,
            EngineDecoding.account("0x0", account.replace("\"blockTimestamp\":1700000000", "\"blockTimestamp\":null"))
                .blockTimestamp,
        )
        assertEquals(-1L, EngineDecoding.account("0x0", account.replace("\"blockTimestamp\":1700000000,", "")).blockTimestamp)
    }

    @Test
    fun anAbsentAccountAndAFailedVerificationAreResults() {
        val absent = EngineDecoding.account(
            "0x0",
            """{"address":"0x0","exists":false,"nonce":-1,"balanceWei":null,""" +
                """"beaconChainVerified":false,"verifyMethod":null,"failReason":"beaconNotSynced",""" +
                """"matchedBeaconSlot":-1,"proofNodesHex":[]}""",
        )
        assertFalse(absent.exists)
        assertEquals(-1L, absent.nonce)
        assertNull(absent.balanceWei)
        assertNull(absent.verifyMethod)
        assertEquals("beaconNotSynced", absent.failReason)
    }

    @Test
    fun anErrorOrADriftedAccountThrows() {
        val e = assertFailsWith<EngineException> {
            EngineDecoding.account("0x0", """{"error":"no snap peer available"}""")
        }
        assertTrue(e.message!!.contains("no snap peer available"))
        assertFailsWith<EngineException> {
            EngineDecoding.account("0x0", """{"error":{"code":-32000,"message":"boom"}}""")
        }
        assertFailsWith<EngineException> { EngineDecoding.account("0x0", null) }
        assertFailsWith<EngineException> { EngineDecoding.account("0x0", "") }
        assertFailsWith<EngineException> { EngineDecoding.account("0x0", "not json") }
        assertFailsWith<EngineException> { EngineDecoding.account("0x0", "42") }
        // A present field of the wrong shape fails closed, never reads as a default.
        assertFailsWith<EngineException> {
            EngineDecoding.account("0x0", """{"exists":true,"nonce":0,"proofNodesHex":{"unexpected":true}}""")
        }
        assertFailsWith<EngineException> {
            EngineDecoding.account("0x0", """{"exists":true,"nonce":"not-a-number","proofNodesHex":[]}""")
        }
    }

    // ---- storage ----

    /** A headerChain-verified storage slot (the Rust eljson storage sample). */
    private val storage =
        """{"addressHex":"0xC0","slot":3,"holderHex":null,""" +
            """"storageKeyHex":"0x0000000000000000000000000000000000000000000000000000000000000003",""" +
            """"storageKeyHashHex":"0x6666666666666666666666666666666666666666666666666666666666666666",""" +
            """"exists":true,"valueHex":"0x2a","valueDecimal":"42","slotsReturned":1,""" +
            """"storageRootHex":"0x3333333333333333333333333333333333333333333333333333333333333333",""" +
            """"proofNodesHex":[],"storageProofValid":true,"beaconSynced":true,""" +
            """"beaconChainVerified":true,"blsVerified":true,"matchedBeaconSlot":7000000,""" +
            """"verifyMethod":"headerChain","failReason":null,"peerBlockNumber":21000000,""" +
            """"finalizedBlockNumber":20999000,"optimisticBlockNumber":21000010,""" +
            """"finalizedSlot":14560000,"optimisticSlot":14560032,"maxHeaderChainGap":8192}"""

    @Test
    fun aStorageProofDecodes() {
        val r = EngineDecoding.storage("0xC0", 3, storage)
        assertEquals("0xC0", r.addressHex)
        assertEquals(3L, r.slot)
        assertNull(r.holderHex)
        assertTrue(r.exists)
        assertEquals("0x2a", r.valueHex)
        assertEquals("42", r.valueDecimal)
        assertEquals(1, r.slotsReturned)
        assertTrue(r.storageProofValid)
        assertTrue(r.beaconChainVerified)
        assertEquals("headerChain", r.verifyMethod)
        assertNull(r.failReason)
        assertEquals(21000000L, r.peerBlockNumber)
        assertEquals(14560000L, r.finalizedSlot)
        assertEquals(14560032L, r.optimisticSlot)
        assertEquals(8192, r.maxHeaderChainGap)
        assertFailsWith<EngineException> { EngineDecoding.storage("0x0", 1, """{"error":"handle not started"}""") }
    }

    @Test
    fun aStorageWordIsLeftPaddedAndNeedsAVerdict() {
        assertContentEquals(ByteArray(31) + byteArrayOf(0x2a), EngineDecoding.storageValue(storage))
        assertContentEquals(
            ByteArray(32),
            EngineDecoding.storageValue("""{"exists":false,"valueHex":null,"verifyMethod":"headerChain"}"""),
        )
        assertNull(EngineDecoding.storageValue("""{"valueHex":"0x2a","verifyMethod":null,"failReason":"beaconNotSynced"}"""))
        assertFailsWith<EngineException> {
            EngineDecoding.storageValue("""{"valueHex":"0x${"01".repeat(33)}","verifyMethod":"headerChain"}""")
        }
    }

    // ---- code ----

    @Test
    fun codeIsTheBytecodeEmptyOrNoVerdict() {
        val code =
            """{"address":"0xC0","exists":true,"codeHex":"0x60806040",""" +
                """"codeHashHex":"0x4444444444444444444444444444444444444444444444444444444444444444",""" +
                """"blockNumber":21000000,"beaconChainVerified":true,"blsVerified":true,""" +
                """"matchedBeaconSlot":7000000,"verifyMethod":"headerChain","failReason":null,""" +
                """"beaconSynced":true,"finalizedPeriod":1777,"wallClockPeriod":1795,""" +
                """"finalizedBlockNumber":20999000,"optimisticBlockNumber":21000010}"""
        assertContentEquals(byteArrayOf(0x60, 0x80.toByte(), 0x60, 0x40), EngineDecoding.code(code))
        assertContentEquals(
            ByteArray(0),
            EngineDecoding.code("""{"exists":false,"codeHex":"0x","verifyMethod":"headerChain"}"""),
        )
        assertNull(
            EngineDecoding.code("""{"exists":true,"codeHex":"0x6080","verifyMethod":null,"failReason":"beaconNotSynced"}"""),
        )
        assertFailsWith<EngineException> { EngineDecoding.code("""{"error":"no snap peer available"}""") }
    }

    // ---- eth_call ----

    @Test
    fun aCallIsOkRevertedUnavailableOrInfeasible() {
        val ok = EngineDecoding.call("""{"status":"ok","resultHex":"0x2a","blockNumber":21000000,"verified":false}""")
        assertEquals(CallResult.Status.OK, ok.status)
        assertContentEquals(byteArrayOf(0x2a), ok.data)
        assertEquals(21000000L, ok.blockNumber)
        val reverted = EngineDecoding.call("""{"status":"revert","dataHex":"0x08","blockNumber":20999936,"verified":true}""")
        assertEquals(CallResult.Status.REVERTED, reverted.status)
        assertContentEquals(byteArrayOf(0x08), reverted.data)
        assertEquals(20999936L, reverted.blockNumber)
        val unavailable = EngineDecoding.call(
            """{"status":"unavailable","reason":"state unavailable","blockNumber":20999936,"verified":false}""",
        )
        assertEquals(CallResult.Status.UNAVAILABLE, unavailable.status)
        assertNull(unavailable.data)
        assertEquals("state unavailable", unavailable.detail)
        assertEquals(-1L, unavailable.blockNumber)
        // A pre-ABI-30 envelope without the key: unknown, not block 0.
        assertEquals(-1L, EngineDecoding.call("""{"status":"ok","resultHex":"0x"}""").blockNumber)
        assertContentEquals(ByteArray(0), EngineDecoding.call("""{"status":"ok","resultHex":"0x"}""").data)
        val infeasible = EngineDecoding.call(
            """{"status":"infeasible","reason":"intrinsic gas too low: have 20000, want 21000",""" +
                """"blockNumber":21000000,"verified":false}""",
        )
        assertEquals(CallResult.Status.INFEASIBLE, infeasible.status)
        assertEquals("intrinsic gas too low: have 20000, want 21000", infeasible.detail)
        assertFailsWith<EngineException> { EngineDecoding.call("""{"status":"infeasible"}""") }
    }

    @Test
    fun theInvalidParamsEnvelopeIsAPermanentRefusalAndOnlyIt() {
        val refused = EngineDecoding.call("""{"error":"block \"0x1\" is too old","code":-32602}""")
        assertEquals(CallResult.Status.REFUSED, refused.status)
        assertEquals("block \"0x1\" is too old", refused.detail)
        assertNull(refused.data)
        val e = assertFailsWith<EngineException> { EngineDecoding.call("""{"error":"busy","code":-32000}""") }
        assertEquals("busy", e.message)
        assertFailsWith<EngineException> { EngineDecoding.call("""{"error":"no snap peer available"}""") }
        val why = "block 0x10 is an Amsterdam block without a slot number"
        val estimate = EngineDecoding.estimate("""{"error":"$why","code":-32602}""")
        assertEquals(EstimateResult.Status.REFUSED, estimate.status)
        assertEquals(why, estimate.detail)
        assertFailsWith<EngineException> { EngineDecoding.estimate("""{"error":"handle not started"}""") }
    }

    // ---- eth_estimateGas ----

    @Test
    fun anEstimateIsOkRevertedUnavailableOrInfeasible() {
        val ok = EngineDecoding.estimate("""{"status":"ok","gas":24150}""")
        assertEquals(EstimateResult.Status.OK, ok.status)
        assertEquals(24150L, ok.gas)
        val reverted = EngineDecoding.estimate("""{"status":"revert","dataHex":"0x08c379a0"}""")
        assertEquals(EstimateResult.Status.REVERTED, reverted.status)
        assertContentEquals(byteArrayOf(0x08, 0xc3.toByte(), 0x79, 0xa0.toByte()), reverted.revertData)
        val unavailable = EngineDecoding.estimate("""{"status":"unavailable","reason":"no verified head"}""")
        assertEquals(EstimateResult.Status.UNAVAILABLE, unavailable.status)
        assertEquals("no verified head", unavailable.detail)
        val infeasible = EngineDecoding.estimate(
            """{"status":"infeasible","reason":"gas required exceeds allowance (50000)"}""",
        )
        assertEquals(EstimateResult.Status.INFEASIBLE, infeasible.status)
        assertEquals("gas required exceeds allowance (50000)", infeasible.detail)
        assertFailsWith<EngineException> { EngineDecoding.estimate("""{"status":"infeasible"}""") }
        // ok without a numeric gas is drift, not a silent "unavailable".
        assertFailsWith<EngineException> { EngineDecoding.estimate("""{"status":"ok"}""") }
    }

    // ---- receipts, fee history ----

    @Test
    fun aReceiptOrAFeeHistoryPassesThroughAndTheNullLiteralToo() {
        val receipt = """{"transactionHash":"0x${"a1".repeat(32)}","transactionIndex":"0x2",""" +
            """"blockHash":"0x${"99".repeat(32)}","blockNumber":"0x1406f40","cumulativeGasUsed":"0xf4240",""" +
            """"gasUsed":"0xc738","from":"0x${"cc".repeat(20)}","to":"0x${"bb".repeat(20)}","contractAddress":null,""" +
            """"effectiveGasPrice":"0x2cb417800","status":"0x1","type":"0x2","logsBloom":"0x${"00".repeat(256)}",""" +
            """"logs":[{"address":"0x${"aa".repeat(20)}","topics":["0x${"11".repeat(32)}"],"data":"0xdead",""" +
            """"blockNumber":"0x1406f40","blockHash":"0x${"99".repeat(32)}","transactionHash":"0x${"a1".repeat(32)}",""" +
            """"transactionIndex":"0x2","logIndex":"0x7","removed":false}]}"""
        assertEquals(receipt, EngineDecoding.objectOrNullLiteral(receipt, "receipt"))
        assertEquals("null", EngineDecoding.objectOrNullLiteral("null", "receipt"))
        assertFailsWith<EngineException> {
            EngineDecoding.objectOrNullLiteral("""{"error":"no snap peer available"}""", "receipt")
        }
        assertFailsWith<EngineException> { EngineDecoding.objectOrNullLiteral(null, "receipt") }
        assertFailsWith<EngineException> { EngineDecoding.objectOrNullLiteral("", "receipt") }
        assertFailsWith<EngineException> { EngineDecoding.objectOrNullLiteral("not json", "receipt") }
        val feeHistory = """{"oldestBlock":"0x1406f40",""" +
            """"baseFeePerGas":["0x2540be400","0x28fa6ae00","0x2dfdc1c35"],"gasUsedRatio":[0.5,0.9932],""" +
            """"reward":[["0x3b9aca00","0x77359400"],["0x0","0xb2d05e00"]]}"""
        assertEquals(feeHistory, EngineDecoding.objectOrNullLiteral(feeHistory, "feeHistory"))
        assertFailsWith<EngineException> {
            EngineDecoding.objectOrNullLiteral(
                """{"error":"oldest block 20 is beyond the 512-block verify window"}""",
                "feeHistory",
            )
        }
    }

    // ---- sending ----

    @Test
    fun theSendGateIsARefusalOrLetsTheSendAnswer() {
        assertEquals(
            "invalid raw transaction: transaction type not supported (0x0)",
            EngineDecoding.sendGateRefusal(
                """{"error":"invalid raw transaction: transaction type not supported (0x0)","code":-32602}""",
            ),
        )
        assertNull(EngineDecoding.sendGateRefusal("""{"ok":true}"""))
        assertNull(EngineDecoding.sendGateRefusal("""{"error":"invalid raw transaction hex"}"""))
        assertNull(EngineDecoding.sendGateRefusal("not json"))
    }

    @Test
    fun aSendIsSentRejectedOrRefused() {
        val sent = EngineDecoding.send("""{"txHash":"0x${"ab".repeat(32)}"}""")
        assertEquals(SendResult.Status.SENT, sent.status)
        assertContentEquals(ByteArray(32) { 0xab.toByte() }, sent.txHash)
        val reason = "insufficient funds for gas * price + value: balance 1, tx cost 2, overshot 1"
        val rejected = EngineDecoding.send("""{"status":"rejected","reason":"$reason"}""")
        assertEquals(SendResult.Status.REJECTED, rejected.status)
        assertEquals(reason, rejected.detail)
        assertNull(rejected.txHash)
        val refused = EngineDecoding.send(
            """{"error":"invalid raw transaction: transaction type not supported (0x0)","code":-32602}""",
        )
        assertEquals(SendResult.Status.REFUSED, refused.status)
        assertEquals("invalid raw transaction: transaction type not supported (0x0)", refused.detail)
        // A plain error, a missing or short hash, a reason-less rejection: no answer.
        assertFailsWith<EngineException> { EngineDecoding.send("""{"error":"no peer available to broadcast"}""") }
        assertFailsWith<EngineException> { EngineDecoding.send("{}") }
        assertFailsWith<EngineException> { EngineDecoding.send("""{"txHash":"0xdead"}""") }
        assertFailsWith<EngineException> { EngineDecoding.send("""{"status":"rejected"}""") }
        assertFailsWith<EngineException> { EngineDecoding.send("""{"status":"rejected","reason":" "}""") }
    }

    // ---- ENS (the addr record) ----

    private val addr40 = "0x" + "d8".repeat(20)

    private fun ok(valueFields: String) =
        """{"status":"ok","blockNumber":21000010,"blockTimestamp":1700000120,"verified":true,$valueFields}"""

    @Test
    fun anAddressRecordIsOkNoRecordOrOffchain() {
        val ok = EngineDecoding.ensAddress("vitalik.eth", ok(""""addressHex":"$addr40""""))
        assertEquals(EnsResolutionResult("vitalik.eth", addr40, 21000010, true, null, 1700000120), ok)
        val none = EngineDecoding.ensAddress(
            "gone.eth",
            """{"status":"noRecord","blockNumber":21000010,"blockTimestamp":1700000120,"verified":false}""",
        )
        assertNull(none.addressHex)
        assertNull(none.error)
        assertFalse(none.verified)
        assertEquals(1700000120L, none.blockTimestamp)
        val offchain = EngineDecoding.ensAddress(
            "cb.id",
            """{"status":"offchain","blockNumber":21000010,"blockTimestamp":1700000120,"verified":false}""",
        )
        assertNull(offchain.addressHex)
        assertTrue(offchain.error!!.contains("offchain"))
    }

    @Test
    fun aDriftedAddressRecordThrows() {
        assertFailsWith<EngineException> { EngineDecoding.ensAddress("a.eth", ok(""""unrelated":1""")) }
        assertFailsWith<EngineException> {
            EngineDecoding.ensAddress("a.eth", """{"status":"ok","addressHex":"$addr40"}""")
        }
        assertFailsWith<EngineException>("verified is mandatory, null included") {
            EngineDecoding.ensAddress(
                "a.eth",
                """{"status":"ok","blockNumber":5,"verified":null,"addressHex":"$addr40"}""",
            )
        }
        assertFailsWith<EngineException> {
            EngineDecoding.ensAddress("a.eth", """{"status":"weird","blockNumber":1,"verified":false}""")
        }
        val e = assertFailsWith<EngineException> { EngineDecoding.ensAddress("a.eth", """{"error":"no snap peer"}""") }
        assertTrue(e.message!!.contains("no snap peer"))
    }
}
