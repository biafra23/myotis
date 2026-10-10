package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The Query tab's result card: balance first, a verification pill, the two numbers a
 * wallet user looks for, and the raw rows folded behind "Show raw details" — open from
 * the start under Expert mode.
 */
class QueryResultCardTest {

    @get:Rule
    val rule = createComposeRule()

    private class Node(private val result: AccountResult, private val network: String = "mainnet") : FakeController() {
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf(network to snapshot().copy(network = network)))
        override suspend fun requestAccount(network: String, address: String): AccountResult = result
    }

    @Test
    fun normalModeLeadsWithTheBalanceAndFoldsTheRawRows() {
        lookUp(Node(verified()), FakeSettings())
        rule.onNodeWithText("Balance (ETH)").assertIsDisplayed()
        rule.onNodeWithText("1234.567800").assertIsDisplayed()
        rule.onNodeWithText("✓ Verified · headerChain · BLS").assertIsDisplayed()
        rule.onNodeWithText("Transactions sent (nonce)").assertIsDisplayed()
        rule.onNodeWithText("1412").assertIsDisplayed()
        rule.onNodeWithText("Storage root").assertDoesNotExist()
        rule.onNodeWithText("Proof valid").assertDoesNotExist()

        rule.onNodeWithText("Show raw details").performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("Storage root").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Hide raw details").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun expertModeOpensTheRawRowsAtOnce() {
        lookUp(Node(verified()), FakeSettings(expert = true))
        rule.onNodeWithText("Balance (ETH)").assertIsDisplayed()
        rule.onNodeWithText("Storage root").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Hide raw details").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun anUnverifiedResultSaysWhy() {
        lookUp(
            Node(verified().copy(beaconChainVerified = false, blsVerified = false, verifyMethod = null, failReason = "beaconNotSynced")),
            FakeSettings(),
        )
        rule.onNodeWithText("✗ Unverified · beaconNotSynced").assertIsDisplayed()
        // A peer's claim is labelled as one, and the verdict leads the balance.
        rule.onNodeWithText("Balance (ETH) — unverified peer claim").assertIsDisplayed()
        rule.onNodeWithText("Balance (ETH)").assertDoesNotExist()
        val pillTop = rule.onNodeWithText("✗ Unverified · beaconNotSynced").fetchSemanticsNode().boundsInRoot.top
        val balanceTop = rule.onNodeWithText("1234.567800").fetchSemanticsNode().boundsInRoot.top
        assertTrue("the pill must sit above an unverified balance", pillTop < balanceTop)
    }

    @Test
    fun anUnverifiedMissingAccountIsAClaimToo() {
        lookUp(
            Node(verified().copy(exists = false, nonce = -1, balanceWei = null, beaconChainVerified = false, blsVerified = false, verifyMethod = null, failReason = "beaconNotSynced")),
            FakeSettings(),
        )
        rule.onNodeWithText("No account at this address yet — unverified peer claim").assertIsDisplayed()
        rule.onNodeWithText("No account at this address yet").assertDoesNotExist()
        rule.onNodeWithText("A peer reports nothing has been sent to it; the node could not verify that yet.").assertIsDisplayed()
        rule.onNodeWithText("✗ Unverified · beaconNotSynced").assertIsDisplayed()
    }

    @Test
    fun theKeyboardsSearchKeyRunsTheLookup() {
        rule.mainClock.autoAdvance = false
        rule.setContent { NodeScreen(controller = Node(verified()), settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performTextInput(ADDR)
        pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performImeAction()
        awaitText("Copy")
        rule.onNodeWithText("Balance (ETH)").assertIsDisplayed()
    }

    @Test
    fun gnosisCountsTheBalanceInXdai() {
        lookUp(Node(verified(), network = "gnosis"), FakeSettings(network = "gnosis"))
        rule.onNodeWithText("Balance (xDAI)").assertIsDisplayed()
        rule.onNodeWithText("1234.567800").assertIsDisplayed()
        rule.onNodeWithText("Balance (ETH)").assertDoesNotExist()
    }

    @Test
    fun anUnverifiedGnosisBalanceIsAnXdaiClaim() {
        lookUp(
            Node(verified().copy(beaconChainVerified = false, blsVerified = false, verifyMethod = null, failReason = "beaconNotSynced"), network = "gnosis"),
            FakeSettings(network = "gnosis"),
        )
        rule.onNodeWithText("Balance (xDAI) — unverified peer claim").assertIsDisplayed()
    }

    @Test
    fun theNativeCurrencyFollowsTheChain() {
        assertEquals("ETH", nativeCurrencySymbol("mainnet"))
        assertEquals("ETH", nativeCurrencySymbol("sepolia"))
        assertEquals("xDAI", nativeCurrencySymbol("gnosis"))
    }

    @Test
    fun aMissingAccountSaysSoInsteadOfABalance() {
        lookUp(Node(verified().copy(exists = false, nonce = -1, balanceWei = null)), FakeSettings())
        rule.onNodeWithText("No account at this address yet").assertIsDisplayed()
        rule.onNodeWithText("Balance (ETH)").assertDoesNotExist()
        rule.onNodeWithText("Transactions sent (nonce)").assertDoesNotExist()
    }

    // ---- harness ----

    private fun lookUp(controller: NodeController, settings: Settings) {
        rule.mainClock.autoAdvance = false
        rule.setContent { NodeScreen(controller = controller, settings = settings, logs = NoLogs) }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performTextInput(ADDR)
        pumpFrames()
        rule.onNodeWithText("Look up").performClick()
        awaitText("Copy")
    }

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    /** Advance virtual time + pump until [text] composes (the lookup hops to a real dispatcher). */
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

        fun verified() = AccountResult(
            address = ADDR, exists = true, nonce = 1412, balanceWei = "1234567800000000000000",
            storageRootHex = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            codeHashHex = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            blockNumber = 22_843_511, peerStateRootHex = null, peerProofValid = true,
            beaconChainVerified = true, blsVerified = true, matchedBeaconSlot = 1,
            verifyMethod = "headerChain", failReason = null,
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
