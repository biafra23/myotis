package io.myotis.ui

import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test

/**
 * Regression test for the Logs-tab text filter's lifetime: `NodeScreen` switches
 * tab content via `when (tab)`, which DISPOSES the inactive tab's composition —
 * so any filter state remembered inside `LogsTab` dies on every tab switch. The
 * filter is therefore hoisted next to the tab selection in `NodeScreen`; this
 * test pins that, and fails if anyone moves it back into the tab composable.
 */
class LogsFilterPersistenceTest {

    @get:Rule
    val rule = createComposeRule()

    private val filterLabel = "Filter — tag or message"

    @Test
    fun logsFilterSurvivesLeavingAndReturningToTheTab() {
        // LogsTab polls its LogSource in an infinite `delay(250)` loop; with the
        // test clock auto-advancing, "idle" is never reached (each delay resolves
        // instantly and the loop spins forever). Pause the clock and pump frames
        // manually — with a paused clock, frame-waiting work counts as idle.
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = FakeSettings(), logs = FakeLogs())
        }
        pumpFrames()

        // Enter the Logs tab (match the SELECTABLE tab node, not arbitrary text)
        // and type a filter.
        tab("Logs").performClick()
        pumpFrames()
        rule.onNodeWithText(filterLabel).performTextInput("rpc")
        pumpFrames()
        rule.onNodeWithText(filterLabel).assertTextContains("rpc")

        // Leave (disposes the Logs tab's composition) and come back.
        tab("Status").performClick()
        pumpFrames()
        tab("Logs").performClick()
        pumpFrames()

        // The filter text must still be there (it lives beside the tab selection,
        // not inside the disposed tab composition).
        rule.onNodeWithText(filterLabel).assertTextContains("rpc")
    }

    /** The tab bar's tabs are the only selectable nodes on the screen. */
    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    /** Run a few frames so clicks/typing recompose while the clock stays paused. */
    private fun pumpFrames() = repeat(3) { rule.mainClock.advanceTimeByFrame() }

    // ---- minimal fakes for the NodeScreen seams (nothing backend-bound) ----

    private class FakeLogs : LogSource {
        override fun version(): Long = 0L
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
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
