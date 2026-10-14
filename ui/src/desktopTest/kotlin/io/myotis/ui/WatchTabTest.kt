package io.myotis.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * The Watch tab: present only where the host checks watched balances, edits the list
 * the host's watcher reads, shows what the checks stored, and runs Check now through
 * the controller.
 */
class WatchTabTest {

    @get:Rule
    val rule = createComposeRule()

    private val alice = "0x" + "a1".repeat(20)
    private val bob = "0x" + "b2".repeat(20)

    /** A host with the balance watch: the list and state live in two maps. */
    private class WatchSettings : Settings by FakeSettings() {
        val lists = HashMap<String, String>()
        val states = HashMap<String, String>()
        override fun supportsBalanceWatch(): Boolean = true
        override fun watchListJson(network: String): String = lists[network] ?: "[]"
        override fun setWatchListJson(network: String, json: String) { lists[network] = json }
        override fun watchStateJson(network: String): String = states[network] ?: "{}"
        override fun setWatchStateJson(network: String, json: String) { states[network] = json }
    }

    private class Node(
        private val runningNode: Boolean = true,
        private val onCheck: suspend (String) -> List<WatchChange>? = { emptyList() },
    ) : FakeController() {
        var checks = 0
        override val running: Boolean = runningNode
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(if (runningNode) mapOf("mainnet" to testSnapshot()) else emptyMap())
        override suspend fun checkWatched(network: String): List<WatchChange>? {
            checks++
            return onCheck(network)
        }
        override val watchSchedule: String = "Checked while the app is open."
    }

    @Test
    fun aHostWithoutTheWatchHasNoWatchTab() {
        rule.setContent { NodeScreen(controller = Node(), settings = FakeSettings(), logs = NoTestLogs) }
        tab("Status").assertIsDisplayed()
        tab("Watch").assertDoesNotExist()
    }

    @Test
    fun anAddressIsAddedNamedAndRemoved() {
        val settings = WatchSettings()
        val node = Node()
        show(node, settings)
        rule.onNodeWithText("Checked while the app is open.").assertIsDisplayed()

        rule.onNodeWithTag(WATCH_ADDRESS_TAG).performTextInput("0x1234")
        rule.onNodeWithTag(WATCH_ADD_TAG).performClick()
        rule.onNodeWithText("Enter an address: 0x followed by 40 hex digits.").assertIsDisplayed()
        assertEquals("[]", settings.watchListJson("mainnet"))

        // Mixed case is accepted and stored lowercase.
        rule.onNodeWithTag(WATCH_ADDRESS_TAG).performTextReplacement("0x" + "a1".repeat(19) + "A1")
        rule.onNodeWithTag(WATCH_LABEL_TAG).performTextInput("Savings")
        rule.onNodeWithTag(WATCH_ADD_TAG).performClick()
        assertEquals(listOf(WatchEntry(alice, "Savings")), BalanceWatch.parseList(settings.watchListJson("mainnet")))
        rule.onNodeWithText("Savings").assertIsDisplayed()
        rule.onNodeWithText(alice).assertIsDisplayed()
        rule.onNodeWithText("Not checked yet").assertIsDisplayed()
        // Adding runs a check at once, so the new address gets its baseline now.
        assertEquals(1, node.checks)
        rule.onNodeWithText("No change.").assertIsDisplayed()

        rule.onNodeWithText("Remove").performScrollTo().performClick()
        assertEquals("[]", settings.watchListJson("mainnet"))
        rule.onNodeWithText("Savings").assertDoesNotExist()
    }

    @Test
    fun theStoredStateShowsBalancesErrorsAndChanges() {
        val settings = WatchSettings().apply {
            setWatchListJson("mainnet", BalanceWatch.serializeList(listOf(WatchEntry(alice, "Savings"), WatchEntry(bob, ""))))
            setWatchStateJson("mainnet", BalanceWatch.serializeState(WatchState(
                addresses = mapOf(
                    alice to WatchAddressState(WatchSeen("1500000000000000000", 4, 21_000_123, -1, 1)),
                    bob to WatchAddressState(null, "beaconNotSynced", 1),
                ),
                changes = listOf(
                    WatchChange(
                        alice, "Savings", "1000000000000000000", "1500000000000000000", 4, 4,
                        21_000_100, 21_000_123, -1, 1, WatchSearch.COMPLETE, 21_000_101,
                        listOf(WatchCause(WatchCauseKind.RECEIVED, 21_000_110, "0x" + "ab".repeat(32), bob, "500000000000000000")),
                    ),
                ),
                lastCheckMs = 1, lastAttemptMs = 1,
            )))
        }
        show(Node(), settings)
        rule.onNodeWithText("1.5 ETH").assertIsDisplayed()
        rule.onNodeWithText("✓ Verified at block 21,000,123").assertIsDisplayed()
        rule.onNodeWithText("Last check had no verified answer: beaconNotSynced", substring = true)
            .performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Recent changes").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Savings: +0.5 ETH").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Received 0.5 ETH from ${BalanceWatch.shortAddress(bob)}", substring = true)
            .performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("0x" + "ab".repeat(32)).performScrollTo().assertIsDisplayed()
    }

    @Test
    fun checkNowGoesThroughTheController() {
        val settings = WatchSettings().apply {
            setWatchListJson("mainnet", BalanceWatch.serializeList(listOf(WatchEntry(alice, ""))))
        }
        val change = WatchChange(alice, "", "1", "2", 0, 0, 1, 2, -1, 1, WatchSearch.NONE, -1, emptyList())
        val node = Node(onCheck = { listOf(change) })
        show(node, settings)
        rule.onNodeWithTag(WATCH_CHECK_TAG).assertIsEnabled().performClick()
        rule.onNodeWithText("1 change.").assertIsDisplayed()
        assertEquals(1, node.checks)
    }

    @Test
    fun checkNowWaitsForARunningNode() {
        val settings = WatchSettings().apply {
            setWatchListJson("mainnet", BalanceWatch.serializeList(listOf(WatchEntry(alice, ""))))
        }
        show(Node(runningNode = false), settings)
        rule.onNodeWithTag(WATCH_CHECK_TAG).assertIsNotEnabled()
        rule.onNodeWithText("Start mainnet on the Status tab to check.").assertIsDisplayed()
    }

    @Test
    fun aWatchRequestBringsTheTabForward() {
        var requests by mutableStateOf(0)
        rule.setContent {
            NodeScreen(controller = Node(), settings = WatchSettings(), logs = NoTestLogs, watchRequests = requests)
        }
        tab("Status").assertIsSelected()
        requests++
        rule.waitForIdle()
        tab("Watch").assertIsSelected()
    }

    @Test
    fun aPhoneWidthRendersTheWatchIcon() {
        // NavIcons.of is reached only from the bottom bar: a tab without an icon fails here.
        rule.setContent {
            Box(Modifier.width(360.dp).height(640.dp)) {
                NodeScreen(controller = Node(), settings = WatchSettings(), logs = NoTestLogs)
            }
        }
        tab("Watch").assertIsDisplayed().performClick()
        tab("Watch").assertIsSelected()
    }

    private fun show(node: NodeController, settings: Settings) {
        rule.setContent { NodeScreen(controller = node, settings = settings, logs = NoTestLogs) }
        tab("Watch").performClick()
        rule.waitForIdle()
    }

    /** The tab switcher's tabs are the only selectable nodes on the screen. */
    private fun tab(label: String) = rule.onNode(isSelectable() and hasText(label))
}
