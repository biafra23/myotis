package io.myotis.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performMouseInput
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import androidx.compose.ui.test.swipeUp
import org.junit.Rule
import org.junit.Test

/**
 * Regression tests for the Logs tab's tail-follow behavior:
 *
 *  - While the user is at the tail, arbitrarily LARGE batches of appended lines must keep
 *    following (the old layout-derived "am I at bottom?" check broke follow as soon as one
 *    250ms poll delivered more than 2 lines, with platform-dependent timing).
 *  - Only an actual user scroll toward older lines stops following and shows "↓ Latest" —
 *    covered for both touch drags and mouse-wheel scrolls (desktop's primary input, which
 *    takes a different dispatch path than drags).
 *  - Scrolling back down to the tail, or pressing "↓ Latest", resumes following.
 */
class LogsTailFollowTest {

    @get:Rule
    val rule = createComposeRule()

    private val logs = MutableLogs()

    @Test
    fun followSurvivesBatchedAppendsUntilUserScrollsBack() {
        openLogsTab()

        // A large batch lands in ONE poll — far beyond the viewport. Follow must hold:
        // the newest line is on screen and no "↓ Latest" button appears.
        logs.append(120)
        awaitText("line 119")
        rule.onNodeWithText("line 119", substring = true).assertIsDisplayed()
        latestButtons().assertCountEquals(0)

        // A second big batch — still following.
        logs.append(120)
        awaitText("line 239")
        rule.onNodeWithText("line 239", substring = true).assertIsDisplayed()
        latestButtons().assertCountEquals(0)

        // The user scrolls back (touch drag toward older lines): following stops and
        // the button appears.
        logList().performTouchInput { swipeDown() }
        pumpFrames(20)  // let the fling settle
        latestButton().assertIsDisplayed()

        // New appends no longer yank the list down. The counter proves the batch actually
        // reached the composition (otherwise the "tail not shown" check would pass vacuously
        // just because the poll hadn't landed yet).
        logs.append(60)
        awaitText("300 / 300 lines")
        latestButton().assertIsDisplayed()
        rule.onAllNodes(hasText("line 299", substring = true)).assertCountEquals(0)

        // "↓ Latest" resumes following: newest line visible, button gone again.
        latestButton().performClick()
        pumpFrames()
        rule.onNodeWithText("line 299", substring = true).assertIsDisplayed()
        latestButtons().assertCountEquals(0)

        // And follow keeps holding for the next batch.
        logs.append(80)
        awaitText("line 379")
        rule.onNodeWithText("line 379", substring = true).assertIsDisplayed()
        latestButtons().assertCountEquals(0)

        // Scrolling back down to the tail (no button press) also resumes following.
        logList().performTouchInput { swipeDown() }
        pumpFrames(20)
        latestButton().assertIsDisplayed()
        var attempts = 0
        while (latestButtons().fetchSemanticsNodes().isNotEmpty() && attempts++ < 8) {
            logList().performTouchInput { swipeUp() }
            pumpFrames(20)
        }
        latestButtons().assertCountEquals(0)
        logs.append(20)
        awaitText("line 399")
        rule.onNodeWithText("line 399", substring = true).assertIsDisplayed()
        latestButtons().assertCountEquals(0)
    }

    @Test
    fun mouseWheelScrollBackBreaksFollow() {
        openLogsTab()
        logs.append(120)
        awaitText("line 119")
        latestButtons().assertCountEquals(0)

        // Wheel toward older lines. Desktop wheel scrolling dispatches differently from touch
        // drags (this is the input path real desktop users take), so pin it separately.
        logList().performMouseInput {
            moveTo(center)
            repeat(3) { scroll(-3f) }
        }
        pumpFrames(20)
        latestButton().assertIsDisplayed()

        latestButton().performClick()
        pumpFrames()
        latestButtons().assertCountEquals(0)
        rule.onNodeWithText("line 119", substring = true).assertIsDisplayed()
    }

    // ---- harness ----

    /** Same clock regime as LogsFilterPersistenceTest: the tab polls in an infinite
     *  delay(250) loop, so pause the clock and advance it manually. */
    private fun openLogsTab() {
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = FakeSettings(), logs = logs)
        }
        pumpFrames()
        rule.onNode(isSelectable() and hasText("Logs")).performClick()
        pumpFrames()
    }

    private fun latestButtons() = rule.onAllNodes(hasText("↓ Latest"))
    private fun latestButton() = rule.onNodeWithText("↓ Latest")
    private fun logList() = rule.onNodeWithTag("logList")

    private fun pumpFrames(n: Int = 3) = repeat(n) { rule.mainClock.advanceTimeByFrame() }

    /**
     * Drive the poll loop until [text] is composed. The 250ms poll delay is on the virtual
     * clock, but the snapshot itself hops to Dispatchers.Default (a real thread), so pair
     * each virtual advance with a short real-time sleep; the loop retries until the hop
     * lands, so a slow CI thread costs iterations, not correctness.
     */
    private fun awaitText(text: String) {
        repeat(200) {
            rule.mainClock.advanceTimeBy(300)
            Thread.sleep(20)
            pumpFrames()
            if (rule.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes().isNotEmpty()) return
        }
        error("timed out waiting for \"$text\"")
    }

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
}
