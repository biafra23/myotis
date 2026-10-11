package io.myotis.ui

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * A block number in normal mode comes with its age, computed from the absolute
 * timestamp the engine proved: on the Query card's "Block" figure and on the ENS
 * result's "Block" row. Without a proven timestamp the number stands alone.
 */
class BlockAgeTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun agesCountSecondsThenMinutesHoursAndDays() {
        assertEquals("just now", formatBlockAge(0))
        assertEquals("just now", formatBlockAge(-3)) // a clock a little behind the chain
        assertEquals("1 s ago", formatBlockAge(1))
        assertEquals("59 s ago", formatBlockAge(59))
        assertEquals("1 min ago", formatBlockAge(60))
        assertEquals("59 min ago", formatBlockAge(3_599))
        assertEquals("1 h ago", formatBlockAge(3_600))
        assertEquals("23 h ago", formatBlockAge(86_399))
        assertEquals("1 d ago", formatBlockAge(86_400))
    }

    @Test
    fun secondsTickEverySecondAndMinutesEveryHalfMinute() {
        assertEquals(1_000L, blockAgeRefreshMillis(5))
        assertEquals(1_000L, blockAgeRefreshMillis(59))
        assertEquals(30_000L, blockAgeRefreshMillis(60))
        assertEquals(30_000L, blockAgeRefreshMillis(7_200))
    }

    @Test
    fun theQueryCardShowsAProvenBlocksAge() {
        lookUp(Node(account(blockTimestamp = nowSeconds() - 125)), ADDR)
        rule.onNodeWithText("2 min ago").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun aFreshBlockCountsSeconds() {
        lookUp(Node(account(blockTimestamp = nowSeconds() - 3)), ADDR)
        assertTrue(
            "a block a few seconds old reads in seconds",
            rule.onAllNodes(hasTextMatching("^\\d+ s ago$")).fetchSemanticsNodes().isNotEmpty(),
        )
    }

    @Test
    fun withoutAProvenTimestampTheNumberStandsAlone() {
        lookUp(Node(account(blockTimestamp = -1)), ADDR)
        rule.onNodeWithText("22843511").assertIsDisplayed()
        assertTrue(
            "no age without a proven timestamp",
            rule.onAllNodes(hasTextMatching("ago$")).fetchSemanticsNodes().isEmpty(),
        )
    }

    @Test
    fun theEnsResultShowsItsBlocksAge() {
        val ens = EnsResult("vitalik.eth", ADDR, 22_843_500, true, null, blockTimestamp = nowSeconds() - 7_300)
        lookUp(Node(account(blockTimestamp = -1), ens), "vitalik.eth")
        rule.onNodeWithText("22843500 · 2 h ago").performScrollTo().assertIsDisplayed()
    }

    // ---- harness ----

    private class Node(private val result: AccountResult, private val ens: EnsResult? = null) : FakeController() {
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(mapOf("mainnet" to snapshot()))
        override suspend fun requestAccount(network: String, address: String): AccountResult = result
        override suspend fun resolveEns(network: String, name: String): EnsResult =
            ens ?: error("no ENS fixture")
    }

    private fun hasTextMatching(pattern: String) =
        SemanticsMatcher("text matches $pattern") { node ->
            val texts = node.config.getOrNull(SemanticsProperties.Text)
            texts?.any { Regex(pattern).containsMatchIn(it.text) } == true
        }

    private fun lookUp(controller: NodeController, input: String) {
        rule.mainClock.autoAdvance = false
        rule.setContent { NodeScreen(controller = controller, settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performTextInput(input)
        pumpFrames()
        rule.onNodeWithText("Look up").performClick()
        awaitText("Copy")
    }

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    private fun awaitText(text: String) {
        repeat(200) {
            rule.mainClock.advanceTimeBy(300)
            Thread.sleep(20)
            pumpFrames()
            if (rule.onAllNodes(hasText(text)).fetchSemanticsNodes().isNotEmpty()) return
        }
        error("timed out waiting for \"$text\"")
    }

    private object NoLogs : LogSource {
        override fun version(): Long = 0
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.INFO
        override fun setLevel(level: LogLevel) {}
    }

    private companion object {
        const val ADDR = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

        fun nowSeconds() = System.currentTimeMillis() / 1000

        fun account(blockTimestamp: Long) = AccountResult(
            address = ADDR, exists = true, nonce = 1412, balanceWei = "1234567800000000000000",
            storageRootHex = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            codeHashHex = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            blockNumber = 22_843_511, peerStateRootHex = null, peerProofValid = true,
            beaconChainVerified = true, blsVerified = true, matchedBeaconSlot = 1,
            verifyMethod = "stateRootMatch", failReason = null, blockTimestamp = blockTimestamp,
        )

        fun snapshot() = NodeSnapshot(
            running = true, lifecycle = "RUNNING", network = "mainnet", engine = "rust",
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
}
