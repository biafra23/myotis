package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * The Query tab's recent queries: one tappable card per past query, with the resolved
 * address beneath an ENS name and how long ago it ran. Tapping re-runs the stored input.
 */
class QueryHistoryCardTest {

    @get:Rule
    val rule = createComposeRule()

    private class Node(private val stackRunning: Boolean = true) : FakeController() {
        val looked = mutableListOf<String>()
        override val running: Boolean = stackRunning
        // A running mainnet stack by default: a card re-runs only on a running node, like Look up.
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(if (stackRunning) mapOf("mainnet" to testSnapshot()) else emptyMap())
        override suspend fun requestAccount(network: String, address: String): AccountResult {
            looked += address
            return AccountResult(
                address = address, exists = false, nonce = -1, balanceWei = null,
                storageRootHex = null, codeHashHex = null, blockNumber = 1,
                peerStateRootHex = null, peerProofValid = true, beaconChainVerified = true,
                blsVerified = false, matchedBeaconSlot = 1, verifyMethod = "headerChain", failReason = null,
            )
        }
    }

    private class History(private val list: List<QueryHistoryEntry>) : QueryHistory {
        override fun entries(): List<QueryHistoryEntry> = list
        override fun add(input: String, label: String) {}
        override fun clear() {}
    }

    @Test
    fun eachPastQueryIsATappableCardWithItsAge() {
        val now = System.currentTimeMillis()
        val node = Node()
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(
                controller = node, settings = FakeSettings(), logs = NoTestLogs,
                history = History(listOf(
                    QueryHistoryEntry("vitalik.eth", now - 5 * 60_000, VITALIK),
                    QueryHistoryEntry(OTHER, now - 2 * 3_600_000, ""),
                )),
            )
        }
        rule.pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        rule.awaitText("Recent")

        rule.onNodeWithText("vitalik.eth").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText(VITALIK).performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("5 min ago").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("2 h ago").performScrollTo().assertIsDisplayed()

        // The whole card is the tap target, and it re-runs the stored input.
        // A clickable card merges its texts into one node, so match the merged text.
        rule.onNode(hasClickAction() and hasText(OTHER)).performScrollTo().performClick()
        rule.awaitText("Copy")
        assertEquals(listOf(OTHER), node.looked)
    }

    @Test
    fun aStoppedNodeOffersNoReRun() {
        val node = Node(stackRunning = false)
        rule.mainClock.autoAdvance = false
        rule.setContent {
            NodeScreen(
                controller = node, settings = FakeSettings(), logs = NoTestLogs,
                history = History(listOf(QueryHistoryEntry(OTHER, System.currentTimeMillis(), ""))),
            )
        }
        rule.pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        rule.awaitText("Recent")
        rule.onNode(hasClickAction() and hasText(OTHER)).performScrollTo().assertIsNotEnabled()
        assertEquals(emptyList<String>(), node.looked)
    }

    @Test
    fun agesReadLikeAWalletWould() {
        val t = 1_000_000_000_000L
        assertEquals("just now", historyAge(t, t + 59_000))
        assertEquals("1 min ago", historyAge(t, t + 60_000))
        assertEquals("59 min ago", historyAge(t, t + 3_599_000))
        assertEquals("1 h ago", historyAge(t, t + 3_600_000))
        assertEquals("23 h ago", historyAge(t, t + 86_399_000))
        assertEquals("1 d ago", historyAge(t, t + 86_400_000))
        // A clock that stepped back never shows a negative age.
        assertEquals("just now", historyAge(t, t - 10_000))
    }

    private companion object {
        const val VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        const val OTHER = "0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4"
    }
}
