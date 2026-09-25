package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import org.junit.Rule
import org.junit.Test

/**
 * Pins the Settings rule for hosts that cannot run the Java engine at all (Android
 * below API 33): the "Prefer Java engine" toggle is replaced by the host's reason, so
 * Settings never offers an engine the host would refuse to start. Hosts that can run
 * it (the default) keep the toggle.
 */
class JavaEngineAvailabilityTest {

    private class EngineSettings(private val reason: String?) : Settings by FakeSettings() {
        override fun javaEngineUnavailableReason(): String? = reason
    }

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun toggleIsReplacedByTheReasonWhenTheJavaEngineIsUnavailable() {
        val reason = "This device runs Android API 29. The Java engine needs API 33."
        show(EngineSettings(reason))
        tab("Settings").performClick()

        rule.onNodeWithText("Engine: Rust only").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText(reason).performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Prefer Java engine").assertDoesNotExist()
    }

    @Test
    fun toggleIsOfferedWhenTheHostCanRunTheJavaEngine() {
        show(EngineSettings(null))
        tab("Settings").performClick()

        rule.onNodeWithText("Prefer Java engine").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Engine: Rust only").assertDoesNotExist()
    }

    private fun show(settings: Settings) {
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = settings, logs = FakeLogs())
        }
    }

    /** The tab bar's tabs are the only selectable nodes on the screen. */
    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    private class FakeLogs : LogSource {
        override fun version(): Long = 0L
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
    }
}
