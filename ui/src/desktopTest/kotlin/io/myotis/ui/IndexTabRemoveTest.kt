package io.myotis.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Remove on the Index tab has to REACH the engine. Its config push is additive,
 * so a contract that merely left the list stayed indexed — the walk kept going
 * and the logs stayed. These pin what the tab now does instead: mark the address
 * removed and push, after asking; and offer the contracts the engine indexes
 * behind the list's back (earlier removals, old imports) for the same treatment.
 */
class IndexTabRemoveTest {

    @get:Rule
    val rule = createComposeRule()

    private val a = "0x45a1502382541cd610cc9068e88727426b696293"
    private val b = "0xb20c66c4de72433f3ce747b58b86830c459ca911"
    private val c = "0x58e8dcc13be9780fc42e8723d8ead4cf46943df2"

    private class IndexSettings(
        var watchJson: String,
        private var enabled: Boolean = true,
    ) : Settings by FakeSettings() {
        private var configured = enabled
        var maxSpeed = false
        var backfillPaused = false
        override fun logIndexEnabled(network: String): Boolean = enabled
        override fun setLogIndexEnabled(network: String, on: Boolean) {
            enabled = on
            configured = true
        }
        override fun logIndexConfigured(network: String): Boolean = configured
        override fun logIndexWatchJson(network: String): String = watchJson
        override fun setLogIndexWatchJson(network: String, json: String) { watchJson = json }
        override fun logIndexMaxSpeed(network: String): Boolean = maxSpeed
        override fun setLogIndexMaxSpeed(network: String, on: Boolean) { maxSpeed = on }
        override fun logIndexBackfillPaused(network: String): Boolean = backfillPaused
        override fun setLogIndexBackfillPaused(network: String, on: Boolean) { backfillPaused = on }

        /** What the host would push right now. */
        fun push(): String? =
            LogIndexWatch.configJson(watchJson, enabled, maxSpeed, configured, backfillPaused)
    }

    /**
     * A running mainnet whose engine indexes [indexed] ([restricted]: the ones
     * indexed under a topic restriction). [report] swaps in a later status.
     */
    private class Engine(
        indexed: List<String>,
        private val backfillPaused: Boolean = false,
        private val restricted: Set<String> = emptySet(),
    ) : FakeController() {
        var applied = 0
        private val snapshots = MutableStateFlow(snapshotOf(status(indexed)))
        private fun status(indexed: List<String>) = indexed.joinToString(
            ",",
            """{"enabled":true,"logCount":12,"maxSpeed":false,"backfillPaused":$backfillPaused,"entries":[""",
            "]}",
        ) {
            """{"address":"$it","fromBlock":100,"coveredLow":100,"coveredHigh":200""" +
                (if (it in restricted) ""","restricted":true}""" else "}")
        }
        private fun snapshotOf(raw: String) =
            mapOf("mainnet" to runningMainnetSnapshot().copy(logIndexJson = raw))
        fun report(indexed: List<String>) { snapshots.value = snapshotOf(status(indexed)) }
        fun reportRaw(raw: String) { snapshots.value = snapshotOf(raw) }
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = snapshots
        override fun applyLogIndex(network: String) { applied++ }
    }

    private fun store(vararg addresses: String) =
        LogIndexWatch.serialize(addresses.map { LogIndexWatch.Entry(it, 100) })

    @Test
    fun `remove asks first, then marks the contract and pushes`() {
        val settings = IndexSettings(store(a, b))
        val engine = Engine(listOf(a, b))
        open(engine, settings)

        rule.onAllNodesWithText("Remove")[0].performScrollTo().performClick()
        pumpFrames()
        // Nothing happens until the user confirms: the logs are not recoverable.
        rule.onNodeWithText("Remove this contract?").assertIsDisplayed()
        assertEquals(store(a, b), settings.watchJson)
        assertEquals(0, engine.applied)

        rule.onNodeWithTag(INDEX_REMOVE_CONFIRM_TAG).performClick()
        pumpFrames()
        assertEquals(listOf(LogIndexWatch.Entry(b, 100)), LogIndexWatch.parse(settings.watchJson))
        assertEquals(1, engine.applied)
        assertTrue(settings.push()!!, settings.push()!!.contains(""""unwatch":["$a"]"""))
        // Until the engine has taken the push it still reports the contract;
        // the tab says what is happening to it rather than offering it again.
        rule.onNodeWithText("removing…").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Indexed, but not in your list").assertDoesNotExist()
        // A push the engine did not take is not repeated on its own.
        rule.onNodeWithText("Retry").performScrollTo().performClick()
        pumpFrames()
        assertEquals(2, engine.applied)

        // The host delivers it (its own thread drops the marker) and the engine's
        // next status no longer lists the contract: the row is gone.
        settings.watchJson = LogIndexWatch.delivered(settings.watchJson, settings.push()!!)
        engine.report(listOf(b))
        pumpFrames()
        rule.onNodeWithText("removing…").assertDoesNotExist()
        rule.onNodeWithText("Indexed, but not in your list").assertDoesNotExist()

        // Should the engine ever hold it again with no marker left here, it is
        // not hidden behind a stale "removing…": it shows as indexed and unlisted.
        engine.report(listOf(a, b))
        pumpFrames()
        rule.onNodeWithText("removing…").assertDoesNotExist()
        rule.onNodeWithText("Indexed, but not in your list").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun `a paused engine's error status is not read as an empty index`() {
        // The status probe is ungated: a handle in idle sleep answers it with an
        // error object, which parses to "no entries". Taking that for "nothing to
        // lose" would skip the confirmation for a contract with months of logs.
        val settings = IndexSettings(store(a))
        val engine = Engine(listOf(a))
        open(engine, settings)
        engine.reportRaw("""{"error":"handle is paused"}""")
        pumpFrames()

        rule.onNodeWithText("Remove").performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("Remove this contract?").assertIsDisplayed()
        assertEquals(store(a), settings.watchJson)
    }

    @Test
    fun `a topic-restricted contract can be removed but not listed`() {
        // The list carries no topics: listing it would make the next push name it
        // unrestricted, a conflict the engine answers by replacing the whole index.
        val settings = IndexSettings(store(a))
        val engine = Engine(listOf(a, b, c), restricted = setOf(b))
        open(engine, settings)

        rule.onNodeWithText("selected events only", substring = true).performScrollTo().assertIsDisplayed()
        rule.onAllNodesWithText("Keep").assertCountEquals(1) // c only
    }

    @Test
    fun `cancelling the dialog removes nothing`() {
        val settings = IndexSettings(store(a))
        val engine = Engine(listOf(a))
        open(engine, settings)

        rule.onNodeWithText("Remove").performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("Cancel").performClick()
        pumpFrames()
        assertEquals(store(a), settings.watchJson)
        assertEquals(0, engine.applied)
    }

    @Test
    fun `contracts the engine indexes behind the list are offered for cleanup`() {
        // b and c are indexed but not listed: removed back when Remove only
        // edited the list, or brought in by an old import.
        val settings = IndexSettings(store(a))
        val engine = Engine(listOf(a, b, c))
        open(engine, settings)
        rule.onNodeWithText("Indexed, but not in your list").performScrollTo().assertIsDisplayed()

        // Keep lists one; the engine already indexes it, so nothing is pushed.
        rule.onAllNodesWithText("Keep")[0].performScrollTo().performClick()
        pumpFrames()
        assertEquals(
            listOf(LogIndexWatch.Entry(a, 100), LogIndexWatch.Entry(b, 100)),
            LogIndexWatch.parse(settings.watchJson),
        )
        assertEquals(0, engine.applied)
        rule.onAllNodesWithText("Keep").assertCountEquals(1)
    }

    @Test
    fun `remove all unsubscribes every unlisted contract in one push`() {
        val settings = IndexSettings(store(a))
        val engine = Engine(listOf(a, b, c))
        open(engine, settings)

        rule.onNodeWithText("Remove all 2").performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("Remove 2 contracts?").assertIsDisplayed()
        rule.onNodeWithTag(INDEX_REMOVE_CONFIRM_TAG).performClick()
        pumpFrames()

        assertEquals(listOf(LogIndexWatch.Entry(a, 100)), LogIndexWatch.parse(settings.watchJson))
        assertEquals(1, engine.applied)
        val push = settings.push()!!
        assertTrue(push, push.endsWith(""","watch":[{"address":"$a","fromBlock":100}],"unwatch":["$b","$c"]}"""))
        rule.onNodeWithText("Indexed, but not in your list").assertDoesNotExist()
    }

    @Test
    fun `a contract the engine never indexed is removed without asking`() {
        // Typed in, never collected: nothing to lose, so no dialog.
        val settings = IndexSettings(store(a), enabled = false)
        val engine = Engine(emptyList())
        open(engine, settings)

        rule.onNodeWithText("Remove").performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("Remove this contract?").assertDoesNotExist()
        // …and without a marker: this host never pushed anything, so there is
        // nothing to deliver — a marker would only lie in wait for a contract
        // that arrived by other means.
        assertEquals("[]", settings.watchJson)
    }

    @Test
    fun `removing from an index this host never configured takes it over as the engine runs it`() {
        // A snapshot dropped into the data dir: the engine activated it (serving,
        // walk paused) and this host has never pushed anything — a push built from
        // its untouched settings would switch the index off. Removing one of its
        // contracts must reach the engine WITHOUT changing what the engine does.
        val settings = IndexSettings("[]", enabled = false)
        val engine = Engine(listOf(a, b), backfillPaused = true)
        open(engine, settings)
        assertEquals(null, settings.push())

        rule.onAllNodesWithText("Remove")[0].performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithTag(INDEX_REMOVE_CONFIRM_TAG).performClick()
        pumpFrames()

        assertEquals(1, engine.applied)
        assertEquals(
            """{"enabled":true,"maxSpeed":false,"backfillPaused":true,"watch":[],"unwatch":["$a"]}""",
            settings.push(),
        )
    }

    @Test
    fun `taking an index over pushes the rest of the list with it`() {
        // c was typed in while this host had nothing configured, so it was never
        // pushed. Taking the engine's index over records collection as on — and
        // from then on the list IS what is collected, so c goes out in the same
        // push (the next start's push would send it anyway). The engine's own
        // runtime bits are re-asserted, not changed.
        val settings = IndexSettings(store(c), enabled = false)
        val engine = Engine(listOf(a, b), backfillPaused = true)
        open(engine, settings)
        assertEquals(null, settings.push())

        // Row order: c (listed), then the unlisted a and b.
        rule.onAllNodesWithText("Remove")[1].performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithTag(INDEX_REMOVE_CONFIRM_TAG).performClick()
        pumpFrames()

        assertEquals(1, engine.applied)
        assertEquals(
            """{"enabled":true,"maxSpeed":false,"backfillPaused":true,""" +
                """"watch":[{"address":"$c","fromBlock":100}],"unwatch":["$a"]}""",
            settings.push(),
        )
    }

    @Test
    fun `removing a contract the engine does not hold takes nothing over`() {
        // Same untouched host, but the contract being removed was only ever typed
        // in — the engine indexes b, not a. Nothing has to reach the engine, so
        // collection must not be switched on for the rest of the list.
        val settings = IndexSettings(store(a, c), enabled = false)
        val engine = Engine(listOf(b), backfillPaused = true)
        open(engine, settings)

        rule.onAllNodesWithText("Remove")[0].performScrollTo().performClick()
        pumpFrames()
        rule.onNodeWithText("Remove this contract?").assertDoesNotExist()
        assertEquals(store(c), settings.watchJson)
        assertEquals(false, settings.logIndexEnabled("mainnet"))
        assertEquals("an untouched host must still have nothing to push", null, settings.push())
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
        fun runningMainnetSnapshot() = NodeSnapshot(
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
