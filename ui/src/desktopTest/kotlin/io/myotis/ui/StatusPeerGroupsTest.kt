package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Dp
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The Status tab's peer rows sit under an EL and a CL group header, each header
 * carrying the group's live-peer number and its cache total, with the discovery
 * rows under the layer they belong to — and a row whose label repeats across the
 * groups ("Peers") opens a help dialog that names its layer.
 */
class StatusPeerGroupsTest {

    @get:Rule
    val rule = createComposeRule()

    private class Running : FakeController() {
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf("mainnet" to snapshot()))
    }

    @Test
    fun `headers carry the group's peers and cache, and the rows sit under their layer`() {
        rule.setContent { NodeScreen(controller = Running(), settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        // readyPeers = 3, elCachedPeers = 20; clServedPeersLastMin = 2, clCachedPeers = 10.
        val el = top("EL · 3 peers · 20 cache")
        val discovered = top("Discovered")
        val blacklisted = top("Blacklisted")
        val cl = top("CL · served 2/min · 10 cache")
        val discv5 = top("Discv5 peers")
        assertTrue("discv4 table under EL", el < discovered && discovered < cl)
        assertTrue("wrong-chain list under EL", el < blacklisted && blacklisted < cl)
        assertTrue("discv5 table under CL", cl < discv5)
    }

    @Test
    fun `the EL Peers row's help is titled by its layer, not by the bare label`() {
        rule.setContent { NodeScreen(controller = Running(), settings = FakeSettings(), logs = NoLogs) }
        pumpFrames()
        // Two rows are labelled "Peers"; the first on screen is the EL group's.
        rule.onAllNodesWithText("Peers")[0].performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("EL peers").assertIsDisplayed()
        rule.onNodeWithText("ready peers total", substring = true).assertIsDisplayed()
    }

    private fun top(text: String): Dp = rule.onNodeWithText(text).getUnclippedBoundsInRoot().top

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
