package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollTo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test

/**
 * Both Status-tab maintenance buttons are offered only while the network is down, so a
 * mis-click cannot throw out learned peers or the sync anchor mid-run. Pinned because the
 * gate is easy to "tidy away" later — especially on Clear peer caches, which would work
 * while running and is gated purely to make the accident impossible.
 *
 * The maintenance buttons sit below the fold in the Status tab's scrolling column, so
 * each assertion scrolls to its node first (same pattern as IndexTabVisibilityTest).
 */
class MaintenanceButtonGateTest {

    @get:Rule
    val rule = createComposeRule()

    private class Stopped : FakeController() {
        override val running: Boolean = false
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(emptyMap())
    }

    private class Running : FakeController() {
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf("mainnet" to runningMainnetSnapshot()))
    }

    @Test
    fun `both maintenance actions are offered while the network is down`() {
        rule.setContent { NodeScreen(controller = Stopped(), settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        rule.onNodeWithText("Reset sync state").performScrollTo().assertIsEnabled()
        rule.onNodeWithText("Clear peer caches").performScrollTo().assertIsEnabled()
    }

    @Test
    fun `both are withheld while the network runs, and say why`() {
        rule.setContent { NodeScreen(controller = Running(), settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        rule.onNodeWithText("Reset sync state").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("Clear peer caches").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("Stop mainnet first", substring = true).performScrollTo().assertIsDisplayed()
    }

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    private object NoLogs : LogSource {
        override fun version(): Long = 0
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.INFO
        override fun setLevel(level: LogLevel) {}
    }

    private companion object {
        fun runningMainnetSnapshot() = NodeSnapshot(
            running = true, lifecycle = "RUNNING", network = "mainnet", engine = "rust",
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
