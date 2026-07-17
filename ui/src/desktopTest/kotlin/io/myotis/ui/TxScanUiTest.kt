package io.myotis.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test

/**
 * Pins the Query tab's streaming transaction-history mechanics:
 *
 *  - a Hit event renders a block-number placeholder immediately;
 *  - the matching Tx event upgrades that row IN PLACE (placeholder gone, headline shown);
 *  - Done renders the completion line; Stop cancels the collection and restores the button.
 *
 * The controller is scripted through a Channel so the test drives event timing explicitly.
 */
class TxScanUiTest {

    @get:Rule
    val rule = createComposeRule()

    private val addr = "0x1a5f9352af8af974bfc03399e3767df6370d82e4"

    private class ScriptedController : FakeController() {
        val events = Channel<TxScanEvent>(Channel.UNLIMITED)
        var scanCollected = false
            private set

        override val running: Boolean = true

        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf("mainnet" to runningMainnetSnapshot()))

        override suspend fun requestAccount(network: String, address: String): AccountResult =
            AccountResult(
                address = address, exists = true, nonce = 1, balanceWei = "1000000000000000000",
                storageRootHex = null, codeHashHex = null, blockNumber = 22_800_000,
                peerStateRootHex = null, peerProofValid = true, beaconChainVerified = true,
                blsVerified = true, matchedBeaconSlot = 1, verifyMethod = "stateRootMatch",
                failReason = null,
            )

        override fun supportsTransactionHistory(network: String): Boolean = network == "mainnet"

        override fun transactionHistory(network: String, address: String): Flow<TxScanEvent> {
            scanCollected = true
            return events.consumeAsFlow()
        }
    }

    @Test
    fun hitPlaceholderUpgradesInPlaceAndDoneCompletes() {
        val controller = ScriptedController()
        openQueryTabWithAccount(controller)

        rule.onNodeWithText("Find transactions").performClick()
        pumpFrames()

        controller.events.trySend(TxScanEvent.Started(
            manifestCid = "QmManifestManifestManifest", cidSource = "contract",
            totalChunks = 100, latestIndexedBlock = 22_841_000, headBlock = 22_843_511))
        controller.events.trySend(TxScanEvent.Hit(22_812_345, 41))
        awaitText("22,812,345")
        rule.onNodeWithText("fetching…", substring = true).assertIsDisplayed()
        rule.onNodeWithText("indexed to block 22,841,000", substring = true).assertIsDisplayed()
        // Fresh index (lag 2,511 blocks < the ~14-day threshold): no staleness banner.
        rule.onAllNodes(hasText("behind the chain head", substring = true)).assertCountEquals(0)

        // The Tx event replaces the placeholder row in place.
        controller.events.trySend(TxScanEvent.Tx(TxRowUi(
            blockNumber = 22_812_345, txIndex = 41,
            hash = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            from = "0x308686553a1eac2fe721ac8b814de638975a276e", to = addr,
            kind = "erc20", headline = "1250.50 USDC → 0x308686…276e")))
        awaitText("1250.50 USDC")
        rule.onAllNodes(hasText("fetching…", substring = true)).assertCountEquals(0)

        controller.events.trySend(TxScanEvent.Done(total = 1))
        awaitText("Scan complete — 1 transaction.")
    }

    @Test
    fun staleIndexShowsTheWarningBannerWithAge() {
        val controller = ScriptedController()
        openQueryTabWithAccount(controller)
        rule.onNodeWithText("Find transactions").performClick()
        pumpFrames()

        // ~2.54M blocks behind ≈ 353 days at 12s/block — the mid-2026 upstream reality.
        controller.events.trySend(TxScanEvent.Started(
            manifestCid = "QmManifestManifestManifest", cidSource = "contract",
            totalChunks = 5948, latestIndexedBlock = 22_997_660, headBlock = 25_542_119))
        awaitText("behind the chain head")
        rule.onNodeWithText("~353 days behind the chain head", substring = true).assertIsDisplayed()
        rule.onNodeWithText("will NOT appear", substring = true).assertIsDisplayed()
    }

    @Test
    fun stopCancelsTheScanAndRestoresTheButton() {
        val controller = ScriptedController()
        openQueryTabWithAccount(controller)

        rule.onNodeWithText("Find transactions").performClick()
        pumpFrames()
        controller.events.trySend(TxScanEvent.Started(
            manifestCid = "Qm", cidSource = "hardcoded",
            totalChunks = 100, latestIndexedBlock = 1, headBlock = null))
        controller.events.trySend(TxScanEvent.Hit(1_000, 0))
        awaitText("Stop")

        rule.onNodeWithText("Stop").performClick()
        pumpFrames(6)
        // Scan is over: the (re)scan button is back and the placeholder row remains listed.
        awaitText("Rescan")
        rule.onNodeWithText("Stop").assertDoesNotExist()
    }

    // ---- harness ----

    private fun openQueryTabWithAccount(controller: ScriptedController) {
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(controller = controller, settings = FakeSettings(), logs = EmptyLogs)
        }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performTextInput(addr)
        pumpFrames()
        rule.onNodeWithText("Look up").performClick()
        awaitText("Find transactions")
    }

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    /** Advance virtual time + pump until [text] composes (same regime as the Logs tests:
     *  some work hops to real dispatchers, so pair virtual advances with short sleeps). */
    private fun awaitText(text: String) {
        repeat(200) {
            rule.mainClock.advanceTimeBy(300)
            Thread.sleep(20)
            pumpFrames()
            if (rule.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes().isNotEmpty()) return
        }
        error("timed out waiting for \"$text\"")
    }

    private object EmptyLogs : LogSource {
        override fun version(): Long = 0
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.INFO
        override fun setLevel(level: LogLevel) {}
    }

    private companion object {
        fun runningMainnetSnapshot() = NodeSnapshot(
            running = true, lifecycle = "RUNNING", network = "mainnet", engine = "java",
            beaconState = "SYNCED", connectedPeers = 3, readyPeers = 3, snapPeers = 2,
            snapServingPeers = 2, clConnectedPeers = 0, clServedPeersLastMin = 2,
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
