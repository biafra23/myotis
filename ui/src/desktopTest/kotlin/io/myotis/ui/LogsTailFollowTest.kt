package io.myotis.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test

/**
 * Regression tests for the Logs tab's tail-follow behavior:
 *
 *  - While the user is at the tail, arbitrarily LARGE batches of appended lines must keep
 *    following (the old layout-derived "am I at bottom?" check broke follow as soon as one
 *    250ms poll delivered more than 2 lines, with platform-dependent timing).
 *  - Only an actual user scroll toward older lines stops following and shows "↓ Latest".
 *  - Pressing "↓ Latest" resumes following.
 */
class LogsTailFollowTest {

    @get:Rule
    val rule = createComposeRule()

    private val logs = MutableLogs()

    @Test
    fun followSurvivesBatchedAppendsUntilUserScrollsBack() {
        // Same clock regime as LogsFilterPersistenceTest: the tab polls in an infinite
        // delay(250) loop, so pause the clock and advance it manually.
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = FakeSettings(), logs = logs)
        }
        pumpFrames()
        tab("Logs").performClick()
        pumpFrames()

        // A large batch lands in ONE poll — far beyond the viewport. Follow must hold:
        // the newest line is on screen and no "↓ Latest" button appears.
        logs.append(120)
        awaitLine("line 119")
        rule.onNodeWithText("line 119", substring = true).assertIsDisplayed()
        rule.onAllLatestButtons().assertCountEquals(0)

        // A second big batch — still following.
        logs.append(120)
        awaitLine("line 239")
        rule.onNodeWithText("line 239", substring = true).assertIsDisplayed()
        rule.onAllLatestButtons().assertCountEquals(0)

        // The user scrolls back (touch drag toward older lines): following stops,
        // the button appears, and new appends no longer yank the list down.
        rule.onNodeWithText("line 239", substring = true).performTouchInput { swipeDown() }
        pumpFrames(20)  // let the fling settle
        rule.onLatestButton().assertIsDisplayed()

        logs.append(60)
        rule.mainClock.advanceTimeBy(600)
        Thread.sleep(50)  // off-main snapshot hop
        pumpFrames()
        rule.onLatestButton().assertIsDisplayed()
        rule.onAllNodes(hasText("line 299", substring = true)).assertCountEquals(0)

        // "↓ Latest" resumes following: newest line visible, button gone again.
        rule.onLatestButton().performClick()
        pumpFrames()
        rule.onNodeWithText("line 299", substring = true).assertIsDisplayed()
        rule.onAllLatestButtons().assertCountEquals(0)

        // And follow keeps holding for the next batch.
        logs.append(80)
        awaitLine("line 379")
        rule.onNodeWithText("line 379", substring = true).assertIsDisplayed()
        rule.onAllLatestButtons().assertCountEquals(0)
    }

    private fun androidx.compose.ui.test.junit4.ComposeContentTestRule.onAllLatestButtons() =
        onAllNodes(hasText("↓ Latest"))
    private fun androidx.compose.ui.test.junit4.ComposeContentTestRule.onLatestButton() =
        onNodeWithText("↓ Latest")

    /** The tab bar's tabs are the only selectable nodes on the screen. */
    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    /**
     * Drive the poll loop until [text] is composed. The 250ms poll delay is on the virtual
     * clock, but the snapshot itself hops to Dispatchers.Default (a real thread), so pair
     * each virtual advance with a short real-time sleep.
     */
    private fun awaitLine(text: String) {
        repeat(100) {
            rule.mainClock.advanceTimeBy(300)
            Thread.sleep(20)
            pumpFrames()
            if (rule.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes().isNotEmpty()) return
        }
        error("timed out waiting for log line containing \"$text\"")
    }

    // ---- fakes ----

    /** Appendable in-memory LogSource; snapshot() is called from Dispatchers.Default. */
    private class MutableLogs : LogSource {
        private val lines = mutableListOf<LogLine>()
        private var v = 0L
        @Synchronized override fun version(): Long = v
        @Synchronized override fun snapshot(): List<LogLine> = lines.toList()
        @Synchronized override fun clear() { lines.clear(); v++ }
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
        @Synchronized fun append(n: Int) {
            repeat(n) {
                val seq = lines.size.toLong()
                lines += LogLine(seq, 1_700_000_000_000 + seq, 'I', "test", "line $seq")
            }
            v++
        }
    }

    private class FakeController : NodeController {
        override val running: Boolean = false
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(emptyMap())
        override fun enableNetwork(name: String) {}
        override fun disableNetwork(name: String) {}
        override fun startNetwork(name: String) {}
        override fun stopNetwork(name: String) {}
        override fun rebootNetwork(name: String) {}
        override fun shutdown() {}
        override fun setTargetSnapPeers(target: Int) {}
        override fun setServedBlockWindow(blocks: Int) {}
        override fun applyBlsBackend() {}
        override fun applyEngineChoice() {}
        override fun clearCaches(network: String) {}
        override fun resetSyncState(network: String) {}
        override suspend fun requestAccount(network: String, address: String): AccountResult =
            error("not used in this test")
        override suspend fun resolveEns(network: String, name: String): EnsResult =
            error("not used in this test")
    }

    private class FakeSettings : Settings {
        override fun enabledNetworks(): List<String> = listOf("mainnet")
        override fun primaryNetwork(): String = "mainnet"
        override fun allNetworks(): List<String> = listOf("mainnet")
        override fun isNetworkEnabled(name: String): Boolean = name == "mainnet"
        override fun setNetworkEnabled(name: String, enabled: Boolean) {}
        override fun rpcPortFor(network: String): Int = 8545
        override fun setRpcPort(network: String, port: Int) {}
        override fun snapTarget(): Int = 3
        override fun setSnapTarget(v: Int) {}
        override fun servedBlockWindow(): Int = 32
        override fun setServedBlockWindow(v: Int) {}
        override fun displayName(network: String): String = network
        override fun defaultRpcPort(network: String): Int = 8545
        override fun hasEns(network: String): Boolean = true
        override fun deepPoolThreshold(): Int = 0
        override fun setDeepPool(v: Int) {}
        override fun strictStateFreshness(): Boolean = false
        override fun setStrictStateFreshness(v: Boolean) {}
        override fun nativeBlsEnabled(): Boolean = false
        override fun setNativeBlsEnabled(v: Boolean) {}
        override fun rustEngineEnabled(): Boolean = false
        override fun setRustEngineEnabled(v: Boolean) {}
    }
}
