package io.myotis.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

/**
 * The Query tab's token balances: built-in tokens read after a lookup, the add-token form,
 * removing a token, and a custom token whose decimals disagree with its contract.
 */
class TokenBalancesUiTest {

    @get:Rule
    val rule = createComposeRule()

    /** A running node answering eth_call from [balances] (contract key → raw amount). */
    private open class Node(
        private val network: String = "mainnet",
        val balances: Map<String, Long> = mapOf(USDC.lowercase() to 1_234_500_000L),
        val decimals: Map<String, Long> = emptyMap(),
    ) : FakeController() {
        val calls = ConcurrentHashMap<String, Int>()
        override val running: Boolean = true
        override val supportsEthCall: Boolean = true
        override fun snapshots(): Flow<Map<String, NodeSnapshot>> =
            flowOf(mapOf(network to testSnapshot(network)))
        override suspend fun requestAccount(network: String, address: String): AccountResult = account()
        override suspend fun ethCall(network: String, to: String, data: String): EthCallResult {
            calls.merge(to.lowercase(), 1, Int::plus)
            val v = when (data) {
                Erc20.DECIMALS_CALL -> decimals[to.lowercase()] ?: return EthCallResult(EthCallStatus.OK, "0x")
                else -> balances[to.lowercase()] ?: 0L
            }
            return EthCallResult(EthCallStatus.OK, "0x" + toHex(word(v)))
        }
    }

    @Test
    fun aLookupShowsThePopularTokensBalances() {
        lookUp(Node(), FakeSettings())
        rule.awaitText("1,234.5")
        rule.onNodeWithText("Tokens").assertExists()
        rule.onNodeWithText("USDC").assertExists()
        rule.onNodeWithText("1,234.5").assertExists()
        rule.onNodeWithText("WBTC").assertExists()
    }

    @Test
    fun zeroBalancesCanBeHidden() {
        lookUp(Node(), FakeSettings())
        rule.onNodeWithText("Hide zero balances").click()
        rule.pumpFrames()
        rule.onNodeWithText("USDT").assertDoesNotExist()
        rule.onNodeWithText("USDC").assertExists()
        rule.onNodeWithText("Show zero balances").click()
        rule.pumpFrames()
        rule.onNodeWithText("USDT").assertExists()
    }

    @Test
    fun aTokenAddedByAddressNameAndDecimalsIsReadAndStored() {
        val node = Node(balances = mapOf(MINE.lowercase() to 2_500_000L), decimals = mapOf(MINE.lowercase() to 6L))
        val settings = FakeSettings()
        lookUp(node, settings)
        rule.onNodeWithText("+ Add token").click()
        rule.pumpFrames()
        field("Contract address (0x…)").performTextInput(MINE.lowercase())
        field("Name (e.g. the token's symbol)").performTextInput("MINE")
        field("Decimals").performTextInput("6")
        rule.pumpFrames()
        rule.onNodeWithText("Add").click()
        rule.awaitText("2.5")
        awaitTokenReads()
        rule.onNodeWithText("MINE · custom").assertExists()
        // Stored checksummed, under the network it was added on.
        assertEquals(
            listOf(Token(MINE, "MINE", 6, custom = true)),
            CustomTokens.parse(settings.customTokensJson("mainnet")),
        )

        rule.onNodeWithText("Remove").click()
        rule.pumpFrames()
        rule.onNodeWithText("MINE · custom").assertDoesNotExist()
        assertEquals("[]", settings.customTokensJson("mainnet"))
    }

    @Test
    fun theFormSaysWhyItRefusesAnAddress() {
        val settings = FakeSettings()
        lookUp(Node(), settings)
        rule.onNodeWithText("+ Add token").click()
        rule.pumpFrames()
        // USDC's address with one letter's case flipped: a typo the checksum catches.
        field("Contract address (0x…)").performTextInput("0xa0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        field("Name (e.g. the token's symbol)").performTextInput("FAKE")
        field("Decimals").performTextInput("6")
        rule.pumpFrames()
        rule.onNodeWithText("Add").click()
        rule.pumpFrames()
        rule.onNodeWithText("That address fails its checksum (EIP-55) — check it for a typo.")
            .assertExists()
        assertEquals("[]", settings.customTokensJson("mainnet"))
    }

    @Test
    fun readFromContractFillsTheForm() {
        val node = object : Node() {
            override suspend fun ethCall(network: String, to: String, data: String): EthCallResult =
                if (data == Erc20.SYMBOL_CALL && to.equals(MINE, ignoreCase = true)) {
                    EthCallResult(EthCallStatus.OK, "0x" + toHex(abiString("CHAIN")))
                } else if (data == Erc20.DECIMALS_CALL && to.equals(MINE, ignoreCase = true)) {
                    EthCallResult(EthCallStatus.OK, "0x" + toHex(word(8)))
                } else {
                    super.ethCall(network, to, data)
                }
        }
        lookUp(node, FakeSettings())
        rule.onNodeWithText("+ Add token").click()
        rule.pumpFrames()
        field("Contract address (0x…)").performTextInput(MINE)
        rule.pumpFrames()
        rule.onNodeWithText("Read from contract").click()
        rule.awaitText("The contract calls itself CHAIN and reports 8 decimals.")
        awaitTokenReads()
        rule.onNodeWithText("CHAIN").assertExists()
        rule.onNodeWithText("8").assertExists()
    }

    @Test
    fun aCustomTokenWhoseDecimalsDisagreeWithItsContractSaysSo() {
        val node = Node(balances = mapOf(MINE.lowercase() to 2_500_000L), decimals = mapOf(MINE.lowercase() to 6L))
        val settings = FakeSettings().apply {
            setCustomTokensJson("mainnet", CustomTokens.serialize(listOf(Token(MINE, "MINE", 18, custom = true))))
        }
        lookUp(node, settings)
        rule.awaitText("Use 6 decimals")
        rule.onNodeWithText("The contract reports 6 decimals, this entry says 18 — the amount above is scaled by 18.")
            .assertExists()
        rule.onNodeWithText("Use 6 decimals").click()
        rule.awaitText("2.5")
        awaitTokenReads()
        rule.onNodeWithText("Use 6 decimals").assertDoesNotExist()
        assertEquals(6, CustomTokens.parse(settings.customTokensJson("mainnet")).single().decimals)
    }

    @Test
    fun aFailureEveryRowSharesIsSaidOnce() {
        val node = object : Node() {
            override suspend fun ethCall(network: String, to: String, data: String): EthCallResult =
                throw IllegalStateException("Verified reads are not available on mainnet")
        }
        lookUp(node, FakeSettings())
        rule.onNodeWithText("Could not read any balance: Verified reads are not available on mainnet")
            .assertExists()
        rule.onNodeWithText("Could not read: Verified reads are not available on mainnet").assertDoesNotExist()
    }

    @Test
    fun aHostWithoutEthCallShowsNoTokens() {
        val node = object : Node() {
            override val supportsEthCall: Boolean = false
        }
        lookUp(node, FakeSettings())
        rule.onNodeWithText("Balance (ETH)").assertExists()
        rule.onNodeWithText("Tokens").assertDoesNotExist()
        assertTrue(node.calls.isEmpty())
    }

    // ---- harness ----

    private fun field(label: String) = rule.onNode(hasSetTextAction() and hasText(label))

    /** Click through semantics: the tab is laid out unscrolled, partly below the window. */
    private fun SemanticsNodeInteraction.click() = performSemanticsAction(SemanticsActions.OnClick)

    /** Pump until no row is reading any more, so assertions see every row's final state. */
    private fun awaitTokenReads() {
        val spinner = SemanticsMatcher.keyIsDefined(SemanticsProperties.ProgressBarRangeInfo)
        repeat(200) {
            rule.mainClock.advanceTimeBy(300)
            Thread.sleep(20)
            rule.pumpFrames()
            if (rule.onAllNodes(spinner).fetchSemanticsNodes().isEmpty()) return
        }
        error("token reads did not finish")
    }

    private fun lookUp(controller: NodeController, settings: Settings) {
        rule.mainClock.autoAdvance = false
        rule.setContent {
            // Tall enough for the whole Query tab to lay out without scrolling: a scroll
            // animation never finishes under the hand-driven clock these tests need.
            Box(Modifier.wrapContentSize(Alignment.TopStart, unbounded = true).requiredSize(1024.dp, 6000.dp)) {
                NodeScreen(controller = controller, settings = settings, logs = NoTestLogs)
            }
        }
        rule.pumpFrames()
        rule.onNode(isSelectable() and hasText("Query")).performClick()
        rule.pumpFrames()
        rule.onNodeWithText("Address (0x…) or ENS name").performTextInput(HOLDER)
        rule.pumpFrames()
        rule.onNodeWithText("Look up").performClick()
        rule.awaitText("Balance (ETH)")
        awaitTokenReads()
    }

    private companion object {
        const val HOLDER = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        const val USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        const val MINE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

        fun account() = AccountResult(
            address = HOLDER, exists = true, nonce = 1, balanceWei = "1000000000000000000",
            storageRootHex = null, codeHashHex = null, blockNumber = 22_843_511,
            peerStateRootHex = null, peerProofValid = true, beaconChainVerified = true,
            blsVerified = true, matchedBeaconSlot = 1, verifyMethod = "headerChain", failReason = null,
        )
    }
}
