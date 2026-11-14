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
 * The stale-anchor dialog's two answers (fresh checkpoint, continue), the "remember my
 * choice" box, and a remembered choice applied at the next park.
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
        private val checkpoint: FreshAnchorResult = FreshAnchorResult(false, "No fresh checkpoint: REFUSED"),
    ) : FakeController() {
        val calls = mutableListOf<String>()
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(mapOf("mainnet" to s))
        override fun acceptStaleAnchor(network: String) { calls += "continue:$network" }
        override fun refreshAnchorFromCheckpointz(network: String, allowUnconfirmed: Boolean): FreshAnchorResult {
            calls += if (allowUnconfirmed) "anyway:$network" else "checkpoint:$network"
            return if (allowUnconfirmed) FreshAnchorResult(true, "Re-anchored, NOT confirmed.") else checkpoint
        }
    }

    @Test
    fun bothChoicesAreOffered() {
        rule.setContent { NodeScreen(controller = Parked(parked), settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Fetch fresh checkpoint").assertIsDisplayed()
        rule.onNodeWithText("Continue anyway (accept risk)").assertIsDisplayed()
        rule.onNodeWithText("Remember my choice and apply it automatically next time").assertIsDisplayed()
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
    fun aRememberedCheckpointRunsAtOnceAndARefusalLeavesBothChoices() {
        val settings = FakeSettings().apply { staleChoice = StaleAnchorChoice.CHECKPOINT }
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = settings, logs = NoLogs) }
        rule.waitUntil(5_000) { c.calls.contains("checkpoint:mainnet") }
        rule.waitForIdle()
        rule.onNodeWithText("No fresh checkpoint: REFUSED").assertIsDisplayed()
        rule.onNodeWithText("Fetch fresh checkpoint").assertIsDisplayed()
        // Remembering the other choice replaces the remembered checkpoint.
        rule.onNodeWithText("Remember my choice and apply it automatically next time").performClick()
        rule.onNodeWithText("Continue anyway (accept risk)").performClick()
        assertEquals(StaleAnchorChoice.CONTINUE, settings.staleChoice)
        assert(c.calls.contains("continue:mainnet"))
    }

    @Test
    fun anUnconfirmedCheckpointIsFlaggedAndCanBeUsedAnywayExplicitly() {
        val settings = FakeSettings()
        val c = Parked(
            parked,
            checkpoint = FreshAnchorResult(false, "No fresh checkpoint: UNCONFIRMED: …", unconfirmed = true),
        )
        rule.setContent { NodeScreen(controller = c, settings = settings, logs = NoLogs) }
        rule.onNodeWithText("Use it anyway (eclipse not ruled out)").assertDoesNotExist()
        rule.onNodeWithText("Remember my choice and apply it automatically next time").performClick()
        rule.onNodeWithText("Fetch fresh checkpoint").performClick()
        rule.waitUntil(5_000) { c.calls.contains("checkpoint:mainnet") }
        rule.waitForIdle()
        rule.onNodeWithText("Use it anyway (eclipse not ruled out)").assertIsDisplayed().performClick()
        rule.waitUntil(5_000) { c.calls.contains("anyway:mainnet") }
        // Remembered: the checkpoint choice — never the override.
        assertEquals(StaleAnchorChoice.CHECKPOINT, settings.staleChoice)
    }

    @Test
    fun aConfirmedRefusalOffersNoOverride() {
        val c = Parked(parked)
        rule.setContent { NodeScreen(controller = c, settings = FakeSettings(), logs = NoLogs) }
        rule.onNodeWithText("Fetch fresh checkpoint").performClick()
        rule.waitUntil(5_000) { c.calls.contains("checkpoint:mainnet") }
        rule.waitForIdle()
        rule.onNodeWithText("Use it anyway (eclipse not ruled out)").assertDoesNotExist()
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
