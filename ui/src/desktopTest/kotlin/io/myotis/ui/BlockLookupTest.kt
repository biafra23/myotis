package io.myotis.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The Query tab's block lookup by height: input parsing, the RPC-path parser, the card. */
class BlockLookupTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun heightsAreDecimalDigitsAndNeverAnAddressOrName() {
        assertEquals(21_000_000L, parseBlockHeight("21000000"))
        assertEquals(21_000_000L, parseBlockHeight(" 21,000,000 "))
        assertEquals(21_000_000L, parseBlockHeight("21_000_000"))
        assertEquals(21_000_000L, parseBlockHeight("#21000000"))
        assertEquals(0L, parseBlockHeight("0"))
        assertNull(parseBlockHeight("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
        assertNull(parseBlockHeight("0x1"))
        assertNull(parseBlockHeight("vitalik.eth"))
        assertNull(parseBlockHeight("123.eth"))
        assertNull(parseBlockHeight("-5"))
        assertNull(parseBlockHeight(""))
        assertNull(parseBlockHeight("1".repeat(19)))
        // Separators only in thousands, and one kind of them.
        assertEquals(21_000_000L, parseBlockHeight("21 000 000"))
        assertNull(parseBlockHeight("21,0000,00"))
        assertNull(parseBlockHeight("1 2 3"))
        assertNull(parseBlockHeight("21,000_000"))
        assertNull(parseBlockHeight("1,000,"))
    }

    @Test
    fun onlyTheRustRefusalFallsBack() {
        assertTrue(isOperatorQueryRefusal(
            "not available on the Rust engine (a Java-engine operator query: get-headers, get-block, dial)"))
        assertFalse(isOperatorQueryRefusal("Node is not running"))
        assertFalse(isOperatorQueryRefusal("node did not become ready within 90s"))
        assertFalse(isOperatorQueryRefusal(null))
    }

    @Test
    fun aBlockUnderAnotherNumberIsAFailedFetch() {
        val other = blockLookupFromRpcJson(8, """{"number":"0x9","transactions":[]}""").forHeight(8)
        assertEquals(8L, other.number)
        assertEquals("asked for block 8, got block 9 back", other.error)
        val same = blockLookupFromRpcJson(9, """{"number":"0x9","transactions":[]}""")
        assertEquals(same, same.forHeight(9))
    }

    @Test
    fun rpcBlockObjectIsAVerifiedLookup() {
        val r = blockLookupFromRpcJson(
            21_000_000,
            """{"number":"0x1406f40","hash":"0xaa","parentHash":"0xbb","stateRoot":"0xcc",
               "transactionsRoot":"0xdd","receiptsRoot":"0xee","timestamp":"0x6788a2f3",
               "gasUsed":"0x1c9c380","gasLimit":"0x1c9c380","baseFeePerGas":"0x3b9aca00",
               "transactions":["0x01","0x02"],"uncles":[],"withdrawals":[{}, {}, {}]}""",
        )
        assertNull(r.error)
        assertTrue(r.verified)
        assertEquals(21_000_000L, r.number)
        assertEquals("0xaa", r.hashHex)
        assertEquals(0x6788a2f3L, r.timestamp)
        assertEquals(30_000_000L, r.gasUsed)
        assertEquals("1000000000", r.baseFeePerGasWei)
        assertEquals(2, r.transactionCount)
        assertEquals(0, r.uncleCount)
        assertEquals(3, r.withdrawalCount)
        assertEquals(BLOCK_PATH_RPC_READ, r.path)
    }

    @Test
    fun rpcTriStateMisses() {
        assertTrue(blockLookupFromRpcJson(7, null).error!!.contains("no verified answer"))
        assertTrue(blockLookupFromRpcJson(7, "null").error!!.contains("no verifiable block 7"))
        assertEquals("too deep", blockLookupFromRpcJson(7, """{"error":"too deep"}""").error)
        assertTrue(blockLookupFromRpcJson(7, "{oops").error!!.contains("malformed"))
        // A failed lookup keeps the height asked for.
        assertEquals(7L, blockLookupFromRpcJson(7, null).number)
        // No baseFeePerGas (pre-London) / no withdrawals (pre-Shanghai).
        val old = blockLookupFromRpcJson(7, """{"number":"0x7","transactions":[]}""")
        assertNull(old.baseFeePerGasWei)
        assertEquals(-1, old.withdrawalCount)
    }

    @Test
    fun elapsedFormatting() {
        assertEquals("840 ms", formatElapsed(840))
        assertEquals("1.00 s", formatElapsed(1_000))
        assertEquals("12.34 s", formatElapsed(12_345))
    }

    private class Node(private val result: BlockLookupResult) : FakeController() {
        var asked: Long? = null
        override val running: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf("mainnet" to testSnapshot("mainnet")))
        override val supportsBlockLookup: Boolean get() = true
        override suspend fun requestBlock(network: String, number: Long): BlockLookupResult {
            asked = number
            return result
        }
        override suspend fun requestAccount(network: String, address: String): AccountResult =
            throw AssertionError("a block height must not be looked up as an account")
    }

    @Test
    fun aHeightFetchesTheBlockAndShowsAnUnverifiedFetchAsSuch() {
        val node = Node(
            BlockLookupResult(
                12_000_000, "0xaa", "0xbb", "0xcc", "0xdd", "0xee", 1_618_000_000, 12_000_000, 15_000_000,
                "100", 150, 0, 0, verified = false, blsVerified = false, matchedBeaconSlot = -1,
                verifyMethod = null, failReason = "preMergeBlock", error = null, path = BLOCK_PATH_VERIFIED_FETCH,
            ),
        )
        lookUp(node, "12,000,000")
        assertEquals(12_000_000L, node.asked)
        rule.onNodeWithText("Block #12,000,000").assertIsDisplayed()
        rule.onNodeWithText("Fetched in ", substring = true).assertIsDisplayed()
        rule.onNodeWithText("✗ Fetched, unverified · preMergeBlock").assertIsDisplayed()
        rule.onNodeWithText("Available, but not verified", substring = true).assertIsDisplayed()
        rule.onNodeWithText("from before the Merge", substring = true).assertIsDisplayed()
        rule.onNodeWithText("150").assertIsDisplayed()
    }

    @Test
    fun aFailedFetchShowsTheError() {
        lookUp(Node(BlockLookupResult.failed(5, BLOCK_PATH_VERIFIED_FETCH, "No header returned for block 5")), "5")
        rule.onNodeWithText("Failed after ", substring = true).assertIsDisplayed()
        rule.onNodeWithText("Fetch failed: No header returned for block 5").assertIsDisplayed()
        assertFalse(rule.onAllNodes(hasText("✓ Verified", substring = true)).fetchSemanticsNodes().isNotEmpty())
    }

    private fun lookUp(controller: NodeController, input: String) {
        rule.mainClock.autoAdvance = false
        rule.setContent { NodeScreen(controller = controller, settings = FakeSettings(), logs = NoTestLogs) }
        rule.pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        rule.pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performTextInput(input)
        rule.pumpFrames()
        rule.onNodeWithText("Look up").performClick()
        rule.awaitText("Copy")
    }
}
