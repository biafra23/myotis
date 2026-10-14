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
 * Token balances in the Query tab's result — what the looked-up address holds, the zero
 * balances one tap away, a custom token whose decimals disagree with its contract — and the
 * Settings tab's Tokens section, where tokens are added and removed.
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

    // ---- the query result ----

    @Test
    fun theResultShowsTheTokensTheAddressHolds() {
        show(Node(), FakeSettings())
        lookUp()
        rule.onNodeWithText("Tokens").assertExists()
        rule.onNodeWithText("USDC").assertExists()
        rule.onNodeWithText("1,234.5").assertExists()
        // Zero balances are one tap away, not a wall of zeros.
        rule.onNodeWithText("USDT").assertDoesNotExist()
        val all = PopularTokens.forNetwork("mainnet").size
        rule.onNodeWithText("Show all $all tokens").click()
        rule.pumpFrames()
        rule.onNodeWithText("USDT").assertExists()
        rule.onNodeWithText("Hide zero balances").click()
        rule.pumpFrames()
        rule.onNodeWithText("USDT").assertDoesNotExist()
    }

    @Test
    fun anAddressWithoutTokensSaysSo() {
        show(Node(balances = emptyMap()), FakeSettings())
        lookUp()
        rule.onNodeWithText("No balance in any of the ${PopularTokens.forNetwork("mainnet").size} tokens checked.")
            .assertExists()
    }

    @Test
    fun aCustomTokenWhoseDecimalsDisagreeWithItsContractSaysSo() {
        val node = Node(balances = mapOf(MINE.lowercase() to 2_500_000L), decimals = mapOf(MINE.lowercase() to 6L))
        val settings = FakeSettings().apply {
            setCustomTokensJson("mainnet", CustomTokens.serialize(listOf(Token(MINE, "MINE", 18, custom = true))))
        }
        show(node, settings)
        lookUp()
        rule.onNodeWithText("MINE · custom").assertExists()
        rule.onNodeWithText("The contract reports 6 decimals, this entry says 18 — the amount above is scaled by 18.")
            .assertExists()
        rule.onNodeWithText("Use 6 decimals").click()
        rule.awaitText("2.5")
        awaitTokenReads()
        rule.onNodeWithText("Use 6 decimals").assertDoesNotExist()
        assertEquals(6, CustomTokens.parse(settings.customTokensJson("mainnet")).single().decimals)
    }

    @Test
    fun aZeroBalanceStillShowsADecimalsMismatch() {
        val node = Node(balances = emptyMap(), decimals = mapOf(MINE.lowercase() to 6L))
        val settings = FakeSettings().apply {
            setCustomTokensJson("mainnet", CustomTokens.serialize(listOf(Token(MINE, "MINE", 18, custom = true))))
        }
        show(node, settings)
        lookUp()
        // Collapsed view, zero balance: the wrong entry is still worth a warning.
        rule.onNodeWithText("Use 6 decimals").assertExists()
    }

    @Test
    fun refreshReadsEveryRowAgain() {
        val node = Node()
        show(node, FakeSettings())
        lookUp()
        assertEquals(1, node.calls[USDC.lowercase()])
        rule.onNodeWithText("Refresh").click()
        rule.pumpFrames()
        awaitTokenReads()
        assertEquals(2, node.calls[USDC.lowercase()])
        rule.onNodeWithText("1,234.5").assertExists()
    }

    @Test
    fun aFailureEveryRowSharesIsSaidOnce() {
        val node = object : Node() {
            override suspend fun ethCall(network: String, to: String, data: String): EthCallResult =
                throw IllegalStateException("Verified reads are not available on mainnet")
        }
        show(node, FakeSettings())
        lookUp()
        rule.onNodeWithText("Could not read any token balance: Verified reads are not available on mainnet")
            .assertExists()
        rule.onNodeWithText("Could not read: Verified reads are not available on mainnet").assertDoesNotExist()
    }

    @Test
    fun theResultsCopyTextCarriesTheTokens() {
        val usdc = PopularTokens.forNetwork("mainnet").first { it.symbol == "USDC" }
        val mine = Token(MINE, "MINE", 18, custom = true)
        val state = TokenBalancesState(
            listOf(usdc, mine),
            mapOf(usdc.key to TokenBalance(usdc, "1234500000"), mine.key to TokenBalance(mine, null, "the contract reverted")),
            onRetry = {}, onUseChainDecimals = { _, _ -> },
        )
        assertEquals(
            "tokens:\n" +
                "  USDC: 1,234.5 (raw 1234500000, 6 decimals) — $USDC\n" +
                "  MINE (custom): error: the contract reverted — $MINE\n",
            formatTokenBalances(state),
        )
    }

    @Test
    fun aHostWithoutEthCallShowsNoTokens() {
        val node = object : Node() {
            override val supportsEthCall: Boolean = false
        }
        show(node, FakeSettings())
        lookUp()
        rule.onNodeWithText("Balance (ETH)").assertExists()
        rule.onNodeWithText("Tokens").assertDoesNotExist()
        openTab("Settings")
        rule.onNodeWithText("Tokens").assertDoesNotExist()
        assertTrue(node.calls.isEmpty())
    }

    // ---- the Settings tab ----

    @Test
    fun settingsListsTheBuiltInTokensAndAddsOneByAddressNameAndDecimals() {
        val node = Node(balances = mapOf(MINE.lowercase() to 2_500_000L), decimals = mapOf(MINE.lowercase() to 6L))
        val settings = FakeSettings()
        show(node, settings)
        openTab("Settings")
        rule.onNodeWithText("Tokens").assertExists()
        rule.onNode(hasText("USDT · USDC · DAI", substring = true)).assertExists()
        rule.onNodeWithText("None yet.").assertExists()

        rule.onNodeWithText("Add token").click()
        rule.pumpFrames()
        field("Contract address (0x…)").performTextInput(MINE.lowercase())
        field("Name (e.g. the token's symbol)").performTextInput("MINE")
        field("Decimals").performTextInput("6")
        rule.pumpFrames()
        rule.onNodeWithText("Add").click()
        rule.pumpFrames()
        rule.onNodeWithText("MINE · 6 decimals").assertExists()
        rule.onNodeWithText(MINE).assertExists()  // stored checksummed
        assertEquals(
            listOf(Token(MINE, "MINE", 6, custom = true)),
            CustomTokens.parse(settings.customTokensJson("mainnet")),
        )

        // The next lookup reads it.
        openTab("Query")
        lookUp()
        rule.onNodeWithText("MINE · custom").assertExists()
        rule.onNodeWithText("2.5").assertExists()
    }

    @Test
    fun settingsRefusesAnAddressThatFailsItsChecksum() {
        val settings = FakeSettings()
        show(Node(), settings)
        openTab("Settings")
        rule.onNodeWithText("Add token").click()
        rule.pumpFrames()
        // USDC's address with one letter's case flipped: a typo the checksum catches.
        field("Contract address (0x…)").performTextInput("0xa0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        field("Name (e.g. the token's symbol)").performTextInput("FAKE")
        field("Decimals").performTextInput("6")
        rule.pumpFrames()
        rule.onNodeWithText("Add").click()
        rule.pumpFrames()
        rule.onNodeWithText("That address fails its checksum (EIP-55) — check it for a typo.").assertExists()
        assertEquals("[]", settings.customTokensJson("mainnet"))
    }

    @Test
    fun settingsReadsANameAndDecimalsFromTheContract() {
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
        show(node, FakeSettings())
        openTab("Settings")
        rule.onNodeWithText("Add token").click()
        rule.pumpFrames()
        field("Contract address (0x…)").performTextInput(MINE)
        rule.pumpFrames()
        rule.onNodeWithText("Read from contract").click()
        rule.awaitText("The contract calls itself CHAIN and reports 8 decimals.")
        rule.onNodeWithText("CHAIN").assertExists()
        rule.onNodeWithText("8").assertExists()
    }

    @Test
    fun settingsMarksAnEntryAReleaseNowBuildsIn() {
        val settings = FakeSettings().apply {
            setCustomTokensJson("mainnet", CustomTokens.serialize(listOf(Token(USDC, "MyUSDC", 6, custom = true))))
        }
        show(Node(), settings)
        openTab("Settings")
        rule.onNodeWithText("MyUSDC · 6 decimals · now built in, not used").assertExists()
    }

    @Test
    fun settingsRemovesAToken() {
        val settings = FakeSettings().apply {
            setCustomTokensJson("mainnet", CustomTokens.serialize(listOf(Token(MINE, "MINE", 6, custom = true))))
        }
        show(Node(), settings)
        openTab("Settings")
        rule.onNodeWithText("MINE · 6 decimals").assertExists()
        rule.onNodeWithText("Remove").click()
        rule.pumpFrames()
        rule.onNodeWithText("MINE · 6 decimals").assertDoesNotExist()
        rule.onNodeWithText("None yet.").assertExists()
        assertEquals("[]", settings.customTokensJson("mainnet"))
    }

    // ---- harness ----

    private fun field(label: String) = rule.onNode(hasSetTextAction() and hasText(label))

    /** Click through semantics: the screen is laid out unscrolled, partly below the window. */
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

    private fun show(controller: NodeController, settings: Settings) {
        rule.mainClock.autoAdvance = false
        rule.setContent {
            // Tall enough for a whole tab to lay out without scrolling: a scroll animation
            // never finishes under the hand-driven clock these tests need.
            Box(Modifier.wrapContentSize(Alignment.TopStart, unbounded = true).requiredSize(1024.dp, 6000.dp)) {
                NodeScreen(controller = controller, settings = settings, logs = NoTestLogs)
            }
        }
        rule.pumpFrames()
    }

    private fun openTab(label: String) {
        rule.onNode(isSelectable() and hasText(label)).performClick()
        rule.pumpFrames()
    }

    /** Look [HOLDER] up on the Query tab and wait for every token read to land. */
    private fun lookUp() {
        if (rule.onAllNodes(hasText("Address (0x…) or ENS name")).fetchSemanticsNodes().isEmpty()) openTab("Query")
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
