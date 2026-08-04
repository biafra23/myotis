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
 * Pins the Index tab's visibility rule: the tab exists only while the Kohaku log
 * index reads as enabled in Settings — the persisted per-network flags AND the
 * Rust engine (without it the Settings switch shows off/disabled and no engine
 * serves the index) — and reacts live to the toggles that change either.
 */
class IndexTabVisibilityTest {

    @get:Rule
    val rule = createComposeRule()

    /** [FakeSettings] with the two knobs the visibility rule reads made real. */
    private class IndexSettings(
        private var rust: Boolean,
        kohakuOn: Set<String> = emptySet(),
    ) : Settings by FakeSettings() {
        private val logIndex = kohakuOn.associateWith { true }.toMutableMap()
        override fun rustEngineEnabled(): Boolean = rust
        override fun setRustEngineEnabled(v: Boolean) { rust = v }
        override fun logIndexEnabled(network: String): Boolean = logIndex[network] == true
        override fun setLogIndexEnabled(network: String, on: Boolean) { logIndex[network] = on }
    }

    @Test
    fun indexTabHiddenByDefault() {
        show(IndexSettings(rust = false))
        tab("Settings").assertIsDisplayed()
        tab("Index").assertDoesNotExist()
    }

    @Test
    fun indexTabHiddenWhenKohakuFlagsSetButRustEngineOff() {
        // Persisted flags survive a Rust-engine opt-out; the Settings switch then
        // reads off/disabled, so the tab must read the same.
        show(IndexSettings(rust = false, kohakuOn = KohakuPreset.byNetwork.keys))
        tab("Index").assertDoesNotExist()
    }

    @Test
    fun indexTabVisibleWhenKohakuEnabledInSettings() {
        show(IndexSettings(rust = true, kohakuOn = setOf("mainnet")))
        tab("Index").assertIsDisplayed()
    }

    @Test
    fun togglingKohakuOnInSettingsRevealsTheIndexTab() {
        show(IndexSettings(rust = true))
        tab("Index").assertDoesNotExist()

        tab("Settings").performClick()
        toggle("Log index — Kohaku contracts (experimental)")
        tab("Index").assertIsDisplayed()
    }

    @Test
    fun turningOffTheLastCollectingNetworkHidesTheTabAndFallsBackToStatus() {
        show(IndexSettings(rust = true, kohakuOn = setOf("mainnet")))
        tab("Index").performClick()

        toggle("Collect Kohaku contract logs on mainnet")
        tab("Index").assertDoesNotExist()
        // The vanished selection falls back to the Status tab's content.
        rule.onNode(isSelectable() and hasText("Status")).assertIsDisplayed()
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
