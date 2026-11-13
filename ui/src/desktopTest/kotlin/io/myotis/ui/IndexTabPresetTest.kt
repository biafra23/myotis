package io.myotis.ui

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import io.myotis.logindex.LogIndexPresets
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The Index tab's predefined contracts: picking presets shows what they cost,
 * says when adding them together is cheaper, and "Add … and download" is the
 * trigger — the presets' contracts join the watch list from their creation
 * blocks, collection switches on and the config is pushed, "unmetered only"
 * unless the user allows metered downloads.
 */
class IndexTabPresetTest {

    @get:Rule
    val rule = createComposeRule()

    private class PresetSettings : Settings by FakeSettings(expert = true) {
        var watchJson = "[]"
        var enabled = false
        var configured = false
        var allowMetered = false
        override fun logIndexEnabled(network: String) = enabled
        override fun setLogIndexEnabled(network: String, on: Boolean) { enabled = on; configured = true }
        override fun logIndexConfigured(network: String) = configured
        override fun logIndexWatchJson(network: String) = watchJson
        override fun setLogIndexWatchJson(network: String, json: String) { watchJson = json }
        override fun logIndexAllowMetered(network: String) = allowMetered
        override fun setLogIndexAllowMetered(network: String, on: Boolean) { allowMetered = on }
        fun push() = LogIndexWatch.configJson(watchJson, enabled, configured = configured, allowMetered = allowMetered)
    }

    private class Engine(
        metering: String,
        status: String = """{"enabled":false,"logCount":0,"entries":[]}""",
    ) : FakeController() {
        var applied = 0
        private val snapshots = MutableStateFlow(
            mapOf("mainnet" to snapshot().copy(networkMetering = metering, logIndexJson = status)),
        )
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = snapshots
        override fun applyLogIndex(network: String) { applied++ }
    }

    @Test
    fun `picking presets shows their cost and adding them starts the download`() {
        val settings = PresetSettings()
        val engine = Engine("METERED")
        open(engine, settings)

        rule.onNodeWithText("Predefined contracts").performScrollTo()
        rule.onNodeWithTag(INDEX_PRESET_ADD_TAG).performScrollTo().assertIsNotEnabled()
        // The device is on a metered connection and metered downloads are off.
        rule.onNodeWithText(LogIndexPresetText.meteredLine(false, "METERED")).performScrollTo()

        rule.onNodeWithTag(indexPresetTag("railgun-mainnet")).performScrollTo().performClick()
        rule.onNodeWithTag(indexPresetTag("privacy-pools-mainnet")).performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("Download: ~", substring = true).performScrollTo()
        rule.onNodeWithText("Stored on this device: ~", substring = true).performScrollTo()
        rule.onNodeWithText("Adding these together is cheaper", substring = true).performScrollTo()
        // Tornado Cash is left out: the tab says what adding all three now would cost.
        rule.onNodeWithText("If you will want the others too", substring = true).performScrollTo()
        assertEquals(0, engine.applied)
        assertEquals("[]", settings.watchJson)

        rule.onNodeWithTag(INDEX_PRESET_ADD_TAG).performScrollTo().assertIsEnabled().performClick()
        pumpFrames()
        val watched = LogIndexWatch.parse(settings.watchJson)
        val expected = (LogIndexPresets.byId("railgun-mainnet")!!.contracts +
            LogIndexPresets.byId("privacy-pools-mainnet")!!.contracts).map { LogIndexWatch.Entry(it.address, it.fromBlock) }
        assertEquals(expected, watched)
        assertTrue("adding is the opt-in", settings.enabled)
        assertEquals(1, engine.applied)
        val push = settings.push()!!
        assertFalse("unmetered only by default: $push", push.contains("allowMetered"))
        // The added presets show as added; the remaining one can still be picked.
        rule.onNodeWithText("RAILGUN — added").performScrollTo()
        rule.onNodeWithText("Privacy Pools — added").performScrollTo()

        // Allowing metered downloads is re-pushed to the engine.
        rule.onNodeWithTag(INDEX_ALLOW_METERED_TAG).performScrollTo()
        rule.onNodeWithText("Download on metered connections on mainnet").performScrollTo().performClick()
        pumpFrames()
        assertTrue(settings.allowMetered)
        assertEquals(2, engine.applied)
        assertTrue(settings.push()!!.contains("\"allowMetered\":true"))
    }

    @Test
    fun `a contract the engine indexes for selected events only is never re-added unrestricted`() {
        // Pushing it without topics would be a topic conflict: the engine replaces the
        // whole index. So a preset made only of such contracts reads as added.
        val rg = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
        val settings = PresetSettings()
        val engine = Engine(
            "UNMETERED",
            """{"enabled":true,"logCount":5,"maxSpeed":false,"backfillPaused":false,"entries":[""" +
                """{"address":"$rg","fromBlock":14737691,"coveredLow":14737691,"coveredHigh":20000000,"restricted":true}]}""",
        )
        open(engine, settings)
        rule.onNodeWithText("RAILGUN — added").performScrollTo()
        assertEquals("[]", settings.watchJson)
    }

    private fun open(controller: NodeController, settings: Settings) {
        rule.setContent { NodeScreen(controller = controller, settings = settings, logs = NoLogs) }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Index")).performClick()
        pumpFrames()
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
            blacklistedPeers = 0, discv5Peers = 100, executionBlockNumber = 26_383_000,
            finalizedSlot = 1, syncStartPeriod = -1, syncCurrentPeriod = 0, syncTargetPeriod = 0,
            verifiedHeadAgeMs = 1_000, uptimeSeconds = 60, peerHeaderRequests = 0,
            peerHeaderRequestsServed = 0, peerBodyRequests = 0, peerBodyRequestsServed = 0,
            readyPeerList = emptyList(), pauseCount = 0, totalPausedMs = 0,
            lastPauseEpochMs = 0, lastResumeEpochMs = 0, lastWakeReason = null,
        )
    }
}
