package io.myotis.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsNotSelected
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test

/**
 * A host can bring the Status tab forward (the desktop does when a refused-web-page
 * notification is clicked, #502): each bump of `statusRequests` selects it, and the
 * initial 0 leaves the selection alone.
 */
class StatusRequestTest {

    @get:Rule
    val rule = createComposeRule()

    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))

    @Test
    fun bumpingStatusRequestsSelectsTheStatusTab() {
        var requests by mutableStateOf(0)
        rule.setContent {
            NodeScreen(FakeController(), FakeSettings(), NoTestLogs, statusRequests = requests)
        }
        tab("Settings").performClick()
        tab("Settings").assertIsSelected()
        tab("Status").assertIsNotSelected()

        requests++
        rule.waitForIdle()
        tab("Status").assertIsSelected()

        // A second request after the user moved away works too.
        tab("Query").performClick()
        tab("Query").assertIsSelected()
        requests++
        rule.waitForIdle()
        tab("Status").assertIsSelected()
    }
}
