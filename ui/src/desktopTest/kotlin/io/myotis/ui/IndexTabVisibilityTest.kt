package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import org.junit.Rule
import org.junit.Test

/**
 * Pins the Index tab's visibility rule: the tab is the log-index feature's home
 * (contracts are added and snapshots imported THERE), so it shows whenever the
 * engine choice can serve the feature — anything but a forced Java engine, the
 * log index being Rust-engine-only — and reacts live to the Settings toggle.
 */
class IndexTabVisibilityTest {

    /** [FakeSettings] with the knob the visibility rule reads made real. */
    private class IndexSettings(
        private var preferJava: Boolean = false,
    ) : Settings by FakeSettings() {
        private val logIndex = mutableMapOf<String, Boolean>()
        private val watch = mutableMapOf<String, String>()
        override fun preferJavaEngine(): Boolean = preferJava
        override fun setPreferJavaEngine(v: Boolean) { preferJava = v }
        override fun logIndexEnabled(network: String): Boolean = logIndex[network] == true
        override fun setLogIndexEnabled(network: String, on: Boolean) { logIndex[network] = on }
        override fun logIndexWatchJson(network: String): String = watch[network] ?: "[]"
        override fun setLogIndexWatchJson(network: String, json: String) { watch[network] = json }
    }

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun indexTabVisibleByDefault() {
        // auto is the default engine choice, so the feature's home is reachable
        // out of the box — that is where a user discovers it.
        show(IndexSettings())
        tab("Settings").assertIsDisplayed()
        tab("Index").assertIsDisplayed()
    }

    @Test
    fun indexTabHiddenWhenJavaEngineForced() {
        // The log index is Rust-engine-only: forcing Java gives the feature up,
        // and a tab whose every control would be inert should not be offered.
        show(IndexSettings(preferJava = true))
        tab("Index").assertDoesNotExist()
    }

    @Test
    fun forcingJavaInSettingsHidesTheIndexTabImmediately() {
        show(IndexSettings())
        tab("Index").assertIsDisplayed()

        tab("Settings").performClick()
        toggle("Prefer Java engine")
        tab("Index").assertDoesNotExist()
    }

    @Test
    fun turningJavaPreferenceBackOffRevealsTheTabAgain() {
        show(IndexSettings(preferJava = true))
        tab("Index").assertDoesNotExist()

        tab("Settings").performClick()
        toggle("Prefer Java engine")
        tab("Index").assertIsDisplayed()
    }

    private fun show(settings: Settings) {
        rule.setContent {
            NodeScreen(controller = FakeController(), settings = settings, logs = FakeLogs())
        }
    }

    /** The tab bar's tabs are the only selectable nodes on the screen. */
    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    /**
     * Click the SwitchRow switch sitting beside [label] (scrolling it into view
     * first). Every switch in a tab is a semantics SIBLING of every label (the
     * Rows aren't semantic boundaries), so the pairing goes by vertical overlap.
     */
    private fun toggle(label: String) {
        val labelBounds =
            rule.onNodeWithText(label).performScrollTo().fetchSemanticsNode().boundsInRoot
        val switches = rule.onAllNodes(isToggleable())
        val beside = switches.fetchSemanticsNodes().indexOfFirst {
            it.boundsInRoot.top < labelBounds.bottom && it.boundsInRoot.bottom > labelBounds.top
        }
        check(beside >= 0) { "no switch beside '$label'" }
        switches[beside].performClick()
    }

    private class FakeLogs : LogSource {
        override fun version(): Long = 0L
        override fun snapshot(): List<LogLine> = emptyList()
        override fun clear() {}
        override fun level(): LogLevel = LogLevel.DEBUG
        override fun setLevel(level: LogLevel) {}
    }
}
