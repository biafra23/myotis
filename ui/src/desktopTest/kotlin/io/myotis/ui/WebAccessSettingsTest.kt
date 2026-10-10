package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * The Web page access section and the Status tab's refusal banner (#502): the
 * default is Specific sites with none, a mode change persists and live-applies, a
 * refused page is allowed from the recent list or the banner, and a typed site is
 * normalized or refused.
 */
class WebAccessSettingsTest {

    private class PolicySettings : Settings by FakeSettings() {
        var mode = WebAccessMode.ALLOWLIST
        var origins = listOf<String>()
        override fun supportsWebAccess(): Boolean = true
        override fun webAccessMode(): WebAccessMode = mode
        override fun setWebAccessMode(mode: WebAccessMode) { this.mode = mode }
        override fun webAccessOrigins(): List<String> = origins
        override fun setWebAccessOrigins(origins: List<String>) { this.origins = origins }
    }

    private class PolicyController(rows: List<WebOriginRow>) : FakeController() {
        var applied = 0
        private val snapshots = flowOf(mapOf("mainnet" to testSnapshot().copy(webOrigins = rows)))
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> = snapshots
        override fun applyWebAccess() { applied++ }
    }

    @get:Rule
    val rule = createComposeRule()

    private val refused = WebOriginRow("https://app.example", 2, 1_000, false, "mainnet")

    private fun show(settings: Settings, controller: NodeController) {
        rule.setContent { NodeScreen(controller = controller, settings = settings, logs = NoTestLogs) }
    }

    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    @Test fun aHostWithoutTheSeamShowsNeitherTheSectionNorTheBanner() {
        // FakeSettings answers supportsWebAccess() = false (iOS today): a control whose
        // writes the host drops must not be offered.
        show(FakeSettings(), PolicyController(listOf(refused)))
        rule.onNodeWithText("A web page was refused").assertDoesNotExist()
        tab("Settings").performClick()
        rule.onNodeWithText("Web page access").assertDoesNotExist()
    }

    @Test fun defaultIsSpecificSitesWithNoneYet() {
        show(PolicySettings(), PolicyController(emptyList()))
        tab("Settings").performClick()
        rule.onNodeWithText("Web page access").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Specific sites").performScrollTo().assertIsSelected()
        rule.onNodeWithText("Allowed sites").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("No web page has tried to use the node since it started.")
            .performScrollTo().assertIsDisplayed()
    }

    @Test fun modeChangePersistsAndAppliesLive() {
        val settings = PolicySettings()
        val controller = PolicyController(emptyList())
        show(settings, controller)
        tab("Settings").performClick()
        rule.onNodeWithText("All sites").performScrollTo().performClick()
        assertEquals(WebAccessMode.ALL, settings.mode)
        assertEquals(1, controller.applied)
        rule.onNodeWithText("All sites").assertIsSelected()
        rule.onNodeWithText("Prefer Specific sites.", substring = true).performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Off").performScrollTo().performClick()
        assertEquals(WebAccessMode.OFF, settings.mode)
        assertEquals(2, controller.applied)
    }

    @Test fun allowFromTheRecentListAddsTheSite() {
        val settings = PolicySettings()
        val controller = PolicyController(listOf(refused))
        show(settings, controller)
        tab("Settings").performClick()
        rule.onNodeWithText("https://app.example").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Allow").performScrollTo().performClick()
        assertEquals(listOf("https://app.example"), settings.origins)
        assertEquals(1, controller.applied)
        // Allowed now: the row offers Remove, and the site is in the list above.
        rule.onNodeWithText("Allow").assertDoesNotExist()
        rule.onAllNodes(hasText("Remove")).fetchSemanticsNodes().size.let { check(it == 2) { "list + row: $it" } }
    }

    @Test fun typedSiteIsNormalizedAndNonSitesAreRefused() {
        val settings = PolicySettings()
        val controller = PolicyController(emptyList())
        show(settings, controller)
        tab("Settings").performClick()
        rule.onNodeWithText("Add a site").performScrollTo().performTextReplacement("App.Example/")
        rule.onNodeWithText("Add").performScrollTo().performClick()
        assertEquals(listOf("https://app.example"), settings.origins)
        assertEquals(1, controller.applied)
        rule.onNodeWithText("Add a site").performScrollTo().performTextReplacement("not a site")
        rule.onNodeWithText("Add").performScrollTo().performClick()
        assertEquals(listOf("https://app.example"), settings.origins)
        rule.onNodeWithText("Not a site.", substring = true).performScrollTo().assertIsDisplayed()
    }

    @Test fun statusBannerAllowsOrDismissesARefusedPage() {
        val settings = PolicySettings()
        val controller = PolicyController(listOf(refused))
        show(settings, controller)
        rule.onNodeWithText("A web page was refused").assertIsDisplayed()
        rule.onNodeWithText("Dismiss").performClick()
        rule.onNodeWithText("A web page was refused").assertDoesNotExist()
        assertEquals(emptyList<String>(), settings.origins)
    }

    @Test fun statusBannerAllowPersistsTheSite() {
        val settings = PolicySettings()
        val controller = PolicyController(listOf(refused))
        show(settings, controller)
        rule.onNodeWithText("Allow").performClick()
        assertEquals(listOf("https://app.example"), settings.origins)
        assertEquals(1, controller.applied)
        rule.onNodeWithText("A web page was refused").assertDoesNotExist()
        // Off hides the banner altogether: the user said no web pages.
        tab("Settings").performClick()
        rule.onNodeWithText("Off").performScrollTo().performClick()
        tab("Status").performClick()
        rule.onNodeWithText("A web page was refused").assertDoesNotExist()
    }
}
