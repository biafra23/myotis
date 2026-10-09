package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test

/**
 * The normal-mode Status screen: the readiness card with the one action the rung
 * needs, the four vitals tiles, and none of the Expert-mode rows — which come back,
 * under the same card, when Expert mode is on.
 */
class HomeStatusTest {

    @get:Rule
    val rule = createComposeRule()

    private class Running(private val s: NodeSnapshot = synced()) : FakeController() {
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(mapOf("mainnet" to s))
    }

    private class Offline : NetworkStatus {
        override fun online(): Flow<Boolean> = flowOf(false)
    }

    @Test
    fun normalModeShowsTheCardAndTilesButNoRows() {
        rule.setContent { NodeScreen(controller = Running(), settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Ready").assertIsDisplayed()
        rule.onNodeWithContentDescription("Execution peers: 2 usable, of 3 connected").assertIsDisplayed()
        rule.onNodeWithContentDescription("Consensus: Synced, 2 servers answering").assertIsDisplayed()
        rule.onNodeWithContentDescription("Verified head: 1 s, fresh").assertIsDisplayed()
        rule.onNodeWithText("Stop").assertIsDisplayed()
        rule.onNodeWithText("Start mainnet").assertDoesNotExist()
        rule.onNodeWithText("Head age").assertDoesNotExist()
        rule.onNodeWithText("Discovered").assertDoesNotExist()
        rule.onNodeWithText("Reset sync state").assertDoesNotExist()
        rule.onNodeWithContentDescription("Log index", substring = true).assertDoesNotExist()
    }

    @Test
    fun expertModeKeepsTheCardAndAddsTheRows() {
        rule.setContent { NodeScreen(controller = Running(), settings = FakeSettings(expert = true), logs = NoLogs) }
        rule.onNodeWithText("Ready").assertIsDisplayed()
        rule.onNodeWithText("Head age").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Reset sync state").performScrollTo().assertIsDisplayed()
        rule.onNodeWithContentDescription("Execution peers", substring = true).assertDoesNotExist()
    }

    @Test
    fun aStoppedNodeOffersStartAndEmptyTiles() {
        rule.setContent { NodeScreen(controller = FakeController(), settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Not running").assertIsDisplayed()
        rule.onNodeWithText("Start mainnet").assertIsDisplayed().assertIsEnabled()
        rule.onNodeWithText("Stop").assertDoesNotExist()
        rule.onNodeWithContentDescription("Execution peers: —").assertIsDisplayed()
    }

    @Test
    fun offlineOffersTheNetworkSettingsAndRefusesStart() {
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = FakeSettings(), logs = NoLogs, netStatus = Offline())
        }
        rule.onNodeWithText("No internet connection").assertIsDisplayed()
        rule.onNodeWithText("Open network settings").assertIsDisplayed()
        rule.onNodeWithText("Start mainnet").assertIsNotEnabled()
    }

    @Test
    fun aDismissedStaleAnchorQuestionCanBeReviewed() {
        rule.setContent {
            NodeScreen(
                controller = Running(synced().copy(beaconState = "STALE_ANCHOR", syncCurrentPeriod = 1400, syncTargetPeriod = 1419, wsBoundPeriods = 13)),
                settings = FakeSettings(),
                logs = NoLogs,
            )
        }
        rule.onNodeWithText("Sync anchor too old — Mainnet").assertIsDisplayed()
        rule.onNodeWithText("Stay paused").performClick()
        rule.onNodeWithText("Sync anchor too old — Mainnet").assertDoesNotExist()
        rule.onNodeWithText("Needs your decision").assertIsDisplayed()
        rule.onNodeWithText("Review").performClick()
        rule.onNodeWithText("Sync anchor too old — Mainnet").assertIsDisplayed()
    }

    @Test
    fun theIndexTileAppearsForAnEnabledIndex() {
        val json = "{\"enabled\":true,\"logCount\":12,\"maxSpeed\":false,\"backfillPaused\":false," +
            "\"targetLow\":100,\"blocksRemaining\":0,\"headGap\":2," +
            "\"entries\":[{\"address\":\"0x1111111111111111111111111111111111111111\",\"fromBlock\":100," +
            "\"coveredLow\":100,\"coveredHigh\":9000}]}"
        rule.setContent {
            NodeScreen(controller = Running(synced().copy(logIndexJson = json)), settings = FakeSettings(), logs = NoLogs)
        }
        rule.onNodeWithContentDescription("Log index: Up to date, history complete").assertIsDisplayed()
    }

    @Test
    fun aSyncingNodeShowsItsProgressOnTheCard() {
        rule.setContent {
            NodeScreen(
                controller = Running(synced().copy(beaconState = "CATCHING_UP", syncStartPeriod = 10, syncCurrentPeriod = 15, syncTargetPeriod = 20)),
                settings = FakeSettings(),
                logs = NoLogs,
            )
        }
        rule.onNodeWithText("Syncing").assertIsDisplayed()
        rule.onNodeWithText("Catching up sync committees — period 15 of 20.").assertIsDisplayed()
        rule.onNodeWithContentDescription("Consensus: Catching up, 2 servers answering").assertIsDisplayed()
    }

    private object NoLogs : LogSource {
        override fun version(): Long = 0
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.INFO
        override fun setLevel(level: LogLevel) {}
    }

    private companion object {
        fun synced() = NodeSnapshot(
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
