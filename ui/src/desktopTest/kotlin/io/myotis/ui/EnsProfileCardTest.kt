package io.myotis.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test

/**
 * The Query tab's ENS card beyond the address: the contenthash decoded with its gateway
 * link, the text records that exist, a record's own error, and nothing of that on a host
 * without the profile actual.
 */
class EnsProfileCardTest {

    @get:Rule
    val rule = createComposeRule()

    private open class EnsController(private val profile: EnsProfile?) : FakeController() {
        override val running: Boolean = true
        // "Look up" is enabled only while the node runs (snap.running): hand the tab one.
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf("mainnet" to runningMainnetSnapshot()))
        override suspend fun resolveEns(network: String, name: String): EnsResult =
            EnsResult(name, "0xd8da6bf26964af9d7eed9e03e53415d37aa96045", 22_800_000, true, null)
        override suspend fun requestAccount(network: String, address: String): AccountResult =
            AccountResult(
                address = address, exists = true, nonce = 1, balanceWei = "1000000000000000000",
                storageRootHex = null, codeHashHex = null, blockNumber = 22_800_000,
                peerStateRootHex = null, peerProofValid = true, beaconChainVerified = true,
                blsVerified = true, matchedBeaconSlot = 1, verifyMethod = "stateRootMatch",
                failReason = null,
            )
        override suspend fun resolveEnsProfile(network: String, name: String): EnsProfile? = profile
    }

    @Test
    fun showsTheDecodedContenthashTheRecordsAndARecordsOwnError() {
        val profile = EnsProfile(
            "vitalik.eth",
            listOf(
                EnsRecord(ENS_CONTENTHASH_KEY, "0xe3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f", 22_800_000, true, null),
                EnsRecord("avatar", null, 22_800_000, true, null),
                EnsRecord("com.twitter", "VitalikButerin", 22_800_000, false, null),
                EnsRecord("url", null, -1, false, "resolves off-chain (CCIP-Read), which this app doesn't support yet"),
            ),
        )
        readRecords(EnsController(profile), "vitalik.eth")
        awaitText("ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4")
        rule.onNodeWithText("Open via eth.limo").assertExists()
        rule.onNodeWithText("Copy link").assertExists()
        rule.onNodeWithText("com.twitter: VitalikButerin (peer head)").assertExists()
        rule.onNodeWithText("url: resolves off-chain", substring = true).assertExists()
        rule.onAllNodes(hasText("avatar", substring = true)).assertCountEquals(0)
    }

    @Test
    fun anUndecodableContenthashOffersItsHexAndNoGateway() {
        val profile = EnsProfile("vitalik.eth", listOf(EnsRecord(ENS_CONTENTHASH_KEY, "0x90b2ca050102", 1, true, null)))
        readRecords(EnsController(profile), "vitalik.eth")
        awaitText("undecoded 0x90b2ca050102")
        rule.onNodeWithText("Copy hex").assertExists()
        rule.onAllNodes(hasText("Open via eth.limo")).assertCountEquals(0)
    }

    @Test
    fun aContenthashReadThatFailedShowsItsError() {
        val profile = EnsProfile("vitalik.eth", listOf(EnsRecord(ENS_CONTENTHASH_KEY, null, -1, false, "resolver call failed")))
        readRecords(EnsController(profile), "vitalik.eth")
        awaitText("resolver call failed")
        rule.onAllNodes(hasText("Copy hex")).assertCountEquals(0)
    }

    @Test
    fun aNameWithoutRecordsSaysSo() {
        val profile = EnsProfile("vitalik.eth", listOf(EnsRecord(ENS_CONTENTHASH_KEY, null, 1, true, null), EnsRecord("url", null, 1, true, null)))
        readRecords(EnsController(profile), "vitalik.eth")
        awaitText("No records beyond the address.")
    }

    @Test
    fun oneFailureSharedByEveryRecordIsOneLine() {
        val profile = EnsProfile(
            "vitalik.eth",
            (listOf(ENS_CONTENTHASH_KEY) + ENS_PROFILE_KEYS).map { EnsRecord(it, null, -1, false, "node not running on mainnet") },
        )
        readRecords(EnsController(profile), "vitalik.eth")
        awaitText("node not running on mainnet")
        rule.onAllNodes(hasText("node not running on mainnet", substring = true)).assertCountEquals(1)
    }

    @Test
    fun aProfileReadThatThrowsShowsOneRecordsRow() {
        val controller = object : EnsController(profile = null) {
            override suspend fun resolveEnsProfile(network: String, name: String): EnsProfile? =
                throw IllegalStateException("Node is not running on mainnet")
        }
        readRecords(controller, "vitalik.eth")
        awaitText("Node is not running on mainnet")
    }

    @Test
    fun aHostWithoutTheProfileActualShowsTheAddressOnly() {
        readRecords(EnsController(profile = null), "vitalik.eth")
        awaitText("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
        rule.onAllNodes(hasText("Open via eth.limo")).assertCountEquals(0)
        rule.onAllNodes(hasText("Content", substring = true)).assertCountEquals(0)
    }

    /** Look the name up, then press the card's "Read records". */
    private fun readRecords(controller: NodeController, name: String) {
        lookUp(controller, name)
        awaitText("Read records")
        rule.onNodeWithText("Read records").performClick()
    }

    private fun lookUp(controller: NodeController, name: String) {
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(controller = controller, settings = FakeSettings(), logs = NoLogs)
        }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performTextInput(name)
        pumpFrames()
        rule.onNodeWithText("Look up").performClick()
    }

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    private fun awaitText(text: String) {
        repeat(200) {
            rule.mainClock.advanceTimeBy(300)
            Thread.sleep(20)
            pumpFrames()
            if (rule.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes().isNotEmpty()) return
        }
        error("timed out waiting for \"$text\"")
    }

    private companion object {
        fun runningMainnetSnapshot() = NodeSnapshot(
            running = true, lifecycle = "RUNNING", network = "mainnet", engine = "java",
            beaconState = "SYNCED", connectedPeers = 3, readyPeers = 3, snapPeers = 2,
            snapServingPeers = 2, snap2ServingPeers = 0,
            clConnectedPeers = 0, clServedPeersLastMin = 2,
            clCachedPeers = 10, clCachedProven = 5, clCachedNolc = 1, elCachedPeers = 20,
            elCachedSnapOk = 8, elCachedSnapBad = 2, discoveredPeers = 50, backedOffPeers = 0,
            blacklistedPeers = 0, discv5Peers = 100, executionBlockNumber = 22_843_511,
            finalizedSlot = 1, syncStartPeriod = -1, syncCurrentPeriod = 0, syncTargetPeriod = 0,
            verifiedHeadAgeMs = 1_000, uptimeSeconds = 60, peerHeaderRequests = 0,
            peerHeaderRequestsServed = 0, peerBodyRequests = 0, peerBodyRequestsServed = 0,
            readyPeerList = emptyList(), pauseCount = 0, totalPausedMs = 0,
            lastPauseEpochMs = 0, lastResumeEpochMs = 0, lastWakeReason = null,
        )
    }

    private object NoLogs : LogSource {
        override fun version(): Long = 0
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.INFO
        override fun setLevel(level: LogLevel) {}
    }
}
