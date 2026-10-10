package io.myotis.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The Logs tab's Save… button: shown only on a host with a save actual, hands the host the
 * WHOLE ring (not the filtered view) and a file name, and shows the host's one-line answer.
 */
class LogsSaveButtonTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun hiddenWithoutAHostActual() {
        openLogsTab(FakeLogs(canSave = false))
        // The tab is open (its own Copy button is there) and Save… is not.
        rule.onNodeWithText("Copy").assertIsDisplayed()
        rule.onAllNodes(hasText("Save…")).assertCountEquals(0)
    }

    @Test
    fun handsTheHostTheWholeRingAndShowsItsAnswer() {
        val logs = FakeLogs(canSave = true)
        openLogsTab(logs)
        // A filter narrows the VIEW; the save must still carry every line.
        rule.onNodeWithText("Filter — tag or message").performTextInput("second")
        awaitText("1 / 2 lines")
        rule.onNodeWithText("Save…").performClick()
        awaitText("Saved to /tmp/myotis.log.")
        val saved = logs.savedText ?: error("the host was not asked to save")
        assertTrue(saved.contains("first line"))
        assertTrue(saved.contains("second line"))
        assertTrue(logs.savedName!!.matches(Regex("myotis-\\d{8}-\\d{4}\\.log")))
    }

    private fun openLogsTab(logs: LogSource) {
        // LogsTab polls its LogSource in an infinite delay(250) loop; pause the clock and pump
        // frames by hand (see LogsFilterPersistenceTest).
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = FakeSettings(expert = true), logs = logs)
        }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Logs")).performClick()
        pumpFrames()
    }

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    /** The ring snapshot lands through Dispatchers.Default — a real thread the paused test
     *  clock does not drive — so wait for the composition to show [text] (LogsTailFollowTest). */
    private fun awaitText(text: String) {
        repeat(200) {
            rule.mainClock.advanceTimeBy(300)
            Thread.sleep(20)
            pumpFrames()
            if (rule.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes().isNotEmpty()) return
        }
        error("timed out waiting for \"$text\"")
    }

    private class FakeLogs(private val canSave: Boolean) : LogSource {
        var savedText: String? = null
        var savedName: String? = null
        private val lines = listOf(
            LogLine(1, 1_700_000_000_000, 'I', "test", "first line"),
            LogLine(2, 1_700_000_000_001, 'I', "test", "second line"),
        )
        override fun version(): Long = 1L
        override fun snapshot(): List<LogLine> = lines
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
        override val canSaveLog: Boolean get() = canSave
        override fun saveLog(suggestedName: String, write: (Appendable) -> Unit, onResult: (String) -> Unit): Boolean {
            if (!canSave) return false
            savedName = suggestedName
            savedText = StringBuilder().also(write).toString()
            onResult("Saved to /tmp/myotis.log.")
            return true
        }
    }
}
