package io.myotis.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import org.junit.Rule
import org.junit.Test

/**
 * Pins the top bar's title/version block as ONE merged semantics node. The two `Text`s
 * are separate composables, so without `Modifier.semantics(mergeDescendants = true)` on
 * their Column a screen reader announces "Myotis" and the version as two unrelated
 * labels. That merge is invisible on screen, which is exactly why a layout or modifier
 * refactor can drop it silently — hence this test rather than a visual check.
 */
class TopBarVersionTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun titleAndVersionAreOneMergedSemanticsNode() {
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = FakeSettings(), logs = FakeLogs())
        }
        repeat(3) { rule.mainClock.advanceTimeByFrame() }

        // Exactly one node carries BOTH strings — proof they merged rather than merely
        // both being on screen. useUnmergedTree stays false: the merged tree is what
        // accessibility services actually read.
        rule.onAllNodes(hasText("Myotis") and hasText("v$APP_VERSION"))
            .assertCountEquals(1)
    }

    // FakeController/FakeSettings live in NodeScreenTestFakes.kt (shared fixtures).

    private class FakeLogs : LogSource {
        override fun version(): Long = 0L
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
    }
}
