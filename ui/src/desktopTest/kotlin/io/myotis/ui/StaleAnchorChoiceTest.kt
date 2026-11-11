package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * The stale-anchor dialog's three answers (ZK proof, fresh checkpoint, continue), the
 * "remember my choice" box, the re-ask without ZK when no proof is available, and a
 * remembered choice applied at the next park.
 */
class StaleAnchorChoiceTest {

    @get:Rule
    val rule = createComposeRule()

    private val parked = synced().copy(
        beaconState = "STALE_ANCHOR", syncCurrentPeriod = 1400, syncTargetPeriod = 1419, wsBoundPeriods = 13,
        engine = "rust",
    )

    private class Parked(
        private val s: NodeSnapshot,
        private val zk: FreshAnchorResult = FreshAnchorResult(false, "No ZK proof available: HTTP 404."),
        private val checkpoint: FreshAnchorResult = FreshAnchorResult(false, "No fresh checkpoint: REFUSED."),
    ) : FakeController() {
        val calls = mutableListOf<String>()
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(mapOf("mainnet" to s))
        override fun acceptStaleAnchor(network: String) { calls += "continue:$network" }
        override fun fetchZkProofForStaleAnchor(network: String): FreshAnchorResult { calls += "zk:$network"; return zk }
        override fun refreshAnchorFromCheckpointz(network: String): FreshAnchorResult { calls += "checkpoint:$network"; return checkpoint }
    }

    @Test
    fun allThreeChoicesAreOffered() {
        rule.setContent { NodeScreen(controller = Parked(parked), settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Fetch ZK proof").assertIsDisplayed()
        rule.onNodeWithText("Fetch fresh checkpoint").assertIsDisplayed()
        rule.onNodeWithText("Continue anyway (accept risk)").assertIsDisplayed()
        rule.onNodeWithText("Remember my choice and apply it automatically next time").assertIsDisplayed()
    }

    @Test
    fun noZkProofAsksAgainWithTheRemainingChoices() {
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Fetch ZK proof").performClick()
        rule.waitUntil(5_000) { c.calls.contains("zk:mainnet") }
        rule.waitForIdle()
        rule.onNodeWithText("Fetch ZK proof").assertDoesNotExist()
        rule.onNodeWithText("No ZK proof is available right now — choose one of the remaining options.").assertIsDisplayed()
        rule.onNodeWithText("Fetch fresh checkpoint").assertIsDisplayed()
        rule.onNodeWithText("Continue anyway (accept risk)").assertIsDisplayed()
    }

    @Test
    fun aRememberedChoiceIsStored() {
        val settings = FakeSettings()
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = settings, logs = NoLogs) }
        rule.onNodeWithText("Remember my choice and apply it automatically next time").performClick()
        rule.onNodeWithText("Fetch fresh checkpoint").performClick()
        rule.waitUntil(5_000) { c.calls.contains("checkpoint:mainnet") }
        assertEquals(StaleAnchorChoice.CHECKPOINT, settings.staleChoice)
    }

    @Test
    fun aRememberedContinueConsentsWithoutTheDialog() {
        val settings = FakeSettings().apply { staleChoice = StaleAnchorChoice.CONTINUE }
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = settings, logs = NoLogs) }
        rule.waitUntil(5_000) { c.calls.contains("continue:mainnet") }
        rule.onNodeWithText("Sync anchor too old — Mainnet").assertDoesNotExist()
    }

    @Test
    fun aRememberedZkProofRunsAtOnceAndFallsBackToTheRemainingChoices() {
        val settings = FakeSettings().apply { staleChoice = StaleAnchorChoice.ZK_PROOF }
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = settings, logs = NoLogs) }
        rule.waitUntil(5_000) { c.calls.contains("zk:mainnet") }
        rule.waitForIdle()
        rule.onNodeWithText("Fetch ZK proof").assertDoesNotExist()
        rule.onNodeWithText("Fetch fresh checkpoint").assertIsDisplayed()
        // Remembering the fallback replaces the remembered ZK proof.
        rule.onNodeWithText("Remember my choice and apply it automatically next time").performClick()
        rule.onNodeWithText("Continue anyway (accept risk)").performClick()
        assertEquals(StaleAnchorChoice.CONTINUE, settings.staleChoice)
        assert(c.calls.contains("continue:mainnet"))
    }

    @Test
    fun anUnavailableZkProofCanBeTriedAgain() {
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Fetch ZK proof").performClick()
        rule.waitUntil(5_000) { c.calls.count { it == "zk:mainnet" } == 1 }
        rule.waitForIdle()
        rule.onNodeWithText("Try the ZK proof again").performClick()
        rule.waitUntil(5_000) { c.calls.count { it == "zk:mainnet" } == 2 }
    }

    @Test
    fun aProofHandedOverCanStillBeFetchedAgain() {
        val c = Parked(parked, zk = FreshAnchorResult(true, "ZK proof of the committee of period 1419 verified."))
        rule.setContent { NodeScreen(controller = c, settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Fetch ZK proof").performClick()
        rule.waitUntil(5_000) { c.calls.contains("zk:mainnet") }
        rule.waitForIdle()
        rule.onNodeWithText("Fetch ZK proof again").assertIsDisplayed()
    }

    @Test
    fun aRememberedContinueSparesANetworkTheUserKeptPaused() {
        val settings = FakeSettings()
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = settings, logs = NoLogs) }
        rule.onNodeWithText("Stay paused").performClick()
        // Remembering "continue" afterwards (Settings) must not consent this park.
        settings.staleChoice = StaleAnchorChoice.CONTINUE
        rule.waitForIdle()
        assert(!c.calls.contains("continue:mainnet")) { c.calls.toString() }
    }

    @Test
    fun theJavaEngineOffersOnlyContinue() {
        rule.setContent { NodeScreen(controller = Parked(parked.copy(engine = "java")), settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Fetch ZK proof").assertDoesNotExist()
        rule.onNodeWithText("Fetch fresh checkpoint").assertDoesNotExist()
        rule.onNodeWithText("Continue anyway (accept risk)").assertIsDisplayed()
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
