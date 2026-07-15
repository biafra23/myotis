package io.myotis.ui

import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
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

    // FakeController/FakeSettings live in NodeScreenTestFakes.kt (shared fixtures).

    private class FakeLogs : LogSource {
        override fun version(): Long = 0L
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
    }

}
