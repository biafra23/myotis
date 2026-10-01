package io.myotis.ui

import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.assertContentDescriptionEquals
import androidx.compose.ui.test.assertRangeInfoEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Rule
import org.junit.Test

/**
 * A synced node whose log index trails the head is not "ready": the strip must
 * leave both greens for the amber catch-up state, and say so to a screen reader,
 * while every red or amber NODE state still outranks it.
 */
class ReadinessStripCatchUpTest {

    @get:Rule
    val rule = createComposeRule()

    private fun description(s: NodeSnapshot, catchUp: CatchUpProgress?): ReadinessStripCatchUpTest {
        rule.setContent { ReadinessStrip(s, deepPoolThreshold = 1, catchUp = catchUp) }
        return this
    }

    private fun assertLabel(expected: String) {
        rule.onNodeWithTag(READINESS_STRIP_TAG, useUnmergedTree = true)
            .assertContentDescriptionEquals(expected)
    }

    @Test
    fun catchingUpReplacesTheGreenStrip() {
        description(snapshot(), CatchUpProgress(800, 3200))
        assertLabel(
            "Node readiness: Log index catching up to the head — 800 blocks behind " +
                "(75% of 3,200); eth_getLogs near the head is refused until it has caught up",
        )
    }

    @Test
    fun theBarsValueReachesScreenReaders() {
        description(snapshot(), CatchUpProgress(800, 3200))
        rule.onNodeWithTag(READINESS_STRIP_TAG, useUnmergedTree = true)
            .assertRangeInfoEquals(ProgressBarRangeInfo(0.75f, 0f..1f))
    }

    @Test
    fun aGapTooWideToBridgeIsAmberWithoutPromisingProgress() {
        description(snapshot(), CatchUpProgress(600_000, 600_000))
        assertLabel(
            "Node readiness: Log index 600,000 blocks behind the head — too far to bridge, " +
                "not catching up; eth_getLogs near the head is refused",
        )
    }

    @Test
    fun withoutACatchUpTheDeepPoolIsGreen() {
        description(snapshot(), null)
        assertLabel("Node readiness: fully ready — deep peer pool, heavy confirm screens will load")
    }

    @Test
    fun anUnsyncedNodeOutranksTheCatchUp() {
        description(snapshot().copy(beaconState = "CATCHING_UP"), CatchUpProgress(800, 3200))
        assertLabel("Node readiness: not synced")
    }

    @Test
    fun aWarmingHeadOutranksTheCatchUp() {
        description(snapshot().copy(verifiedHeadAgeMs = 120_000), CatchUpProgress(800, 3200))
        assertLabel("Node readiness: warming up, not ready to transact")
    }

    private fun snapshot() = NodeSnapshot(
        running = true, lifecycle = "RUNNING", network = "mainnet", engine = "rust",
        beaconState = "SYNCED", connectedPeers = 17, readyPeers = 8, snapPeers = 8,
        snapServingPeers = 8, clConnectedPeers = 0, clServedPeersLastMin = 3,
        clCachedPeers = 10, clCachedProven = 5, clCachedNolc = 1, elCachedPeers = 20,
        elCachedSnapOk = 8, elCachedSnapBad = 2, discoveredPeers = 137, backedOffPeers = 0,
        blacklistedPeers = 0, discv5Peers = 100, executionBlockNumber = 26_097_901,
        finalizedSlot = 1, syncStartPeriod = -1, syncCurrentPeriod = 0, syncTargetPeriod = 0,
        verifiedHeadAgeMs = 1_000, uptimeSeconds = 60, peerHeaderRequests = 0,
        peerHeaderRequestsServed = 0, peerBodyRequests = 0, peerBodyRequestsServed = 0,
        readyPeerList = emptyList(), pauseCount = 0, totalPausedMs = 0,
        lastPauseEpochMs = 0, lastResumeEpochMs = 0, lastWakeReason = null,
    )
}
