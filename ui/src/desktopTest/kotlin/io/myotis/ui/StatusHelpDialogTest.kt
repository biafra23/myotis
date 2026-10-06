package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * Status-tab help: a single tap opens the explanation, and it stays up — no timeout —
 * until the user dismisses it. The buttons' own tap is their action, so their help sits
 * on a separate "ⓘ" and must not trigger the action.
 */
class StatusHelpDialogTest {

    @get:Rule
    val rule = createComposeRule()

    private class Stopped : FakeController() {
        var cleared = 0
        override val running: Boolean = false
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(emptyMap())
        override fun clearCaches(network: String) { cleared++ }
    }

    private class Running : FakeController() {
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf("mainnet" to snapshot()))
    }

    @Test
    fun `a single tap on a row opens its help, which stays until Close`() {
        rule.setContent { NodeScreen(controller = Running(), settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        rule.onNodeWithText("Head age").performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("no verified head yet", substring = true).assertIsDisplayed()

        // A tooltip would have auto-hidden by now; the dialog must still be up.
        rule.mainClock.advanceTimeBy(10_000)
        rule.onNodeWithText("no verified head yet", substring = true).assertIsDisplayed()

        rule.onNodeWithText("Close").performClick()
        pumpFrames()
        rule.onNodeWithText("no verified head yet", substring = true).assertDoesNotExist()
    }

    @Test
    fun `a button's help opens without running the button's action`() {
        val controller = Stopped()
        rule.setContent { NodeScreen(controller = controller, settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        rule.onNodeWithContentDescription("Help: Clear peer caches").performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("fresh discovery slate", substring = true).assertIsDisplayed()
        assertEquals(0, controller.cleared)
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
