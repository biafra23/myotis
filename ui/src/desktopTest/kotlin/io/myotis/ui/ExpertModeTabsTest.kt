package io.myotis.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import org.junit.Rule
import org.junit.Test

/**
 * Pins the tab set per mode: normal mode is Status / Query / Settings — the screens a
 * wallet user needs — and Expert mode adds Logs and, under its own rule, Index. The
 * Settings switch takes effect at once, and a phone-width window shows the same tabs
 * in a bottom navigation bar.
 */
class ExpertModeTabsTest {

    private class JavaForced : Settings by FakeSettings(expert = true) {
        override fun preferJavaEngine(): Boolean = true
    }

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun normalModeShowsStatusQueryAndSettingsOnly() {
        show(FakeSettings())
        tab("Status").assertIsDisplayed()
        tab("Query").assertIsDisplayed()
        tab("Settings").assertIsDisplayed()
        tab("Logs").assertDoesNotExist()
        tab("Index").assertDoesNotExist()
    }

    @Test
    fun expertModeAddsLogsAndIndex() {
        show(FakeSettings(expert = true))
        tab("Logs").assertIsDisplayed()
        tab("Index").assertIsDisplayed()
    }

    @Test
    fun expertModeKeepsTheIndexTabsOwnRule() {
        // Index is Rust-engine-only: a forced Java engine hides it even under Expert mode.
        show(JavaForced())
        tab("Logs").assertIsDisplayed()
        tab("Index").assertDoesNotExist()
    }

    @Test
    fun theSettingsSwitchRevealsAndHidesTheTabsAtOnce() {
        show(FakeSettings())
        tab("Settings").performClick()
        tab("Logs").assertDoesNotExist()

        rule.toggleSwitchBeside("Expert mode")
        tab("Logs").assertIsDisplayed()
        tab("Index").assertIsDisplayed()

        rule.toggleSwitchBeside("Expert mode")
        tab("Logs").assertDoesNotExist()
        tab("Index").assertDoesNotExist()
    }

    @Test
    fun aPhoneWidthGetsTheSameTabsInABottomBar() {
        rule.setContent {
            Box(Modifier.width(360.dp).height(640.dp)) {
                NodeScreen(controller = FakeController(), settings = FakeSettings(), logs = FakeLogs())
            }
        }
        tab("Status").assertIsSelected()
        tab("Logs").assertDoesNotExist()
        tab("Query").performClick()
        tab("Query").assertIsSelected()
        rule.onNodeWithText("Address (0x…) or ENS name").assertIsDisplayed()
    }

    private fun show(settings: Settings) {
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = settings, logs = FakeLogs())
        }
    }

    /** The tab switcher's tabs are the only selectable nodes on the screen. */
    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    private class FakeLogs : LogSource {
        override fun version(): Long = 0L
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
    }
}
