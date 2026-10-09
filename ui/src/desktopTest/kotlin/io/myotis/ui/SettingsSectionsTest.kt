package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Pins the Settings tab's sections per mode and host: Networks and the Expert-mode
 * switch always; a Power section only where a host can actually sleep (macOS App Nap,
 * Android's idle controller); the node-tuning knobs only under Expert mode.
 */
class SettingsSectionsTest {

    private class PowerSettings(
        private val nap: Boolean,
        private val idle: Boolean,
        expert: Boolean = false,
    ) : Settings by FakeSettings(expert) {
        var allowNap = false
        override fun supportsAppNap(): Boolean = nap
        override fun allowAppNap(): Boolean = allowNap
        override fun setAllowAppNap(v: Boolean) { allowNap = v }
        override fun supportsIdleSleep(): Boolean = idle
    }

    private class NapController : FakeController() {
        var applied = 0
        override fun applyAppNap() { applied++ }
    }

    /** Records the live-applies Save makes, so a test can see what a Save in each mode touches. */
    private class TuningController : FakeController() {
        var wsBoundApplied = mutableListOf<Int>()
        override fun setWsBoundPeriods(periods: Int) { wsBoundApplied += periods }
    }

    /** [FakeSettings] whose weak-subjectivity bound is real, so a Save can be seen to write it. */
    private class BoundSettings(expert: Boolean) : Settings by FakeSettings(expert) {
        var wsBound = 0
        override fun wsBoundPeriods(): Int = wsBound
        override fun setWsBoundPeriods(v: Int) { wsBound = v }
    }

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun normalModeHidesTheTuningKnobs() {
        show(FakeSettings())
        tab("Settings").performClick()
        rule.onNodeWithText("Networks").assertIsDisplayed()
        rule.onNodeWithText("Expert mode").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Node tuning").assertDoesNotExist()
        rule.onNodeWithText("Prefer Java engine").assertDoesNotExist()
        rule.onNodeWithText("Relaxed state freshness").assertDoesNotExist()
        rule.onNodeWithText("Power").assertDoesNotExist()
        // The port field keeps its label — the one normal-mode knob beside the switch.
        rule.onNodeWithText("JSON-RPC port (default 8545)").assertIsDisplayed()
    }

    @Test
    fun expertModeShowsTheTuningKnobs() {
        show(FakeSettings(expert = true))
        tab("Settings").performClick()
        rule.onNodeWithText("Node tuning").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Prefer Java engine").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Relaxed state freshness").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun thePowerSectionAppearsOnlyWhereAHostCanSleep() {
        show(PowerSettings(nap = false, idle = false))
        tab("Settings").performClick()
        rule.onNodeWithText("Power").assertDoesNotExist()
        rule.onNodeWithText("Sleep when not in focus").assertDoesNotExist()
        rule.onNodeWithText("Idle sleep after (minutes, 0 = never)").assertDoesNotExist()
    }

    @Test
    fun macOsGetsTheAppNapRow() {
        show(PowerSettings(nap = true, idle = false))
        tab("Settings").performClick()
        rule.onNodeWithText("Power").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Sleep when not in focus").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Idle sleep after (minutes, 0 = never)").assertDoesNotExist()
    }

    @Test
    fun androidGetsTheIdleSleepRows() {
        show(PowerSettings(nap = false, idle = true))
        tab("Settings").performClick()
        rule.onNodeWithText("Power").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Idle sleep after (minutes, 0 = never)").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Stay awake while charging").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Sleep when not in focus").assertDoesNotExist()
    }

    @Test
    fun theAppNapSwitchPersistsAndAppliesLive() {
        val settings = PowerSettings(nap = true, idle = false)
        val controller = NapController()
        rule.setContent { NodeScreen(controller = controller, settings = settings, logs = FakeLogs()) }
        tab("Settings").performClick()
        rule.toggleSwitchBeside("Sleep when not in focus")
        assertTrue("the opt-in must persist", settings.allowNap)
        assertEquals("the controller re-applies it at once", 1, controller.applied)
    }

    @Test
    fun everySwitchIsOneNamedNode() {
        // The row is the toggleable and the label merges into it, so a screen reader hears
        // "Expert mode, off" — one named switch — rather than a label beside an unnamed toggle.
        show(PowerSettings(nap = true, idle = false))
        tab("Settings").performClick()
        rule.onNode(isToggleable() and hasText("mainnet")).assertExists()
        rule.onNode(isToggleable() and hasText("Sleep when not in focus")).performScrollTo().assertExists()
        rule.onNode(isToggleable() and hasText("Expert mode")).performScrollTo().assertExists()
    }

    @Test
    fun aNormalModeSaveLeavesHiddenExpertEditsAlone() {
        // Expert on, type a wider bound, Expert off, Save: the bound must stay untouched —
        // the field is gone from the screen, so Save must not write what it no longer shows.
        val settings = BoundSettings(expert = true)
        val controller = TuningController()
        rule.setContent { NodeScreen(controller = controller, settings = settings, logs = FakeLogs()) }
        tab("Settings").performClick()
        rule.onNodeWithText("Weak-subjectivity bound in periods (0 = network default)").performScrollTo()
            .performTextReplacement("99")
        rule.toggleSwitchBeside("Expert mode")
        rule.onNodeWithText("Save").performScrollTo().performClick()
        assertEquals(0, settings.wsBound)
        assertEquals(emptyList<Int>(), controller.wsBoundApplied)

        // Back in Expert mode the edit is still on screen, and Save applies it.
        rule.toggleSwitchBeside("Expert mode")
        rule.onNodeWithText("Save").performScrollTo().performClick()
        assertEquals(99, settings.wsBound)
        assertEquals(listOf(99), controller.wsBoundApplied)
    }

    private fun show(settings: Settings) {
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = settings, logs = FakeLogs())
        }
    }

    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    private class FakeLogs : LogSource {
        override fun version(): Long = 0L
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
    }
}
