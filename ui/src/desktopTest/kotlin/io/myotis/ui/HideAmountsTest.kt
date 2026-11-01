package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/** The masks Hide amounts puts over the amounts that reach the screens as text. */
class HideAmountsTest {

    @Test
    fun maskAmountHidesTheWholeNumber() {
        assertEquals("1.5", maskAmount("1.5", hidden = false))
        assertEquals(AMOUNT_MASK, maskAmount("1,234.567800", hidden = true))
    }

    @Test
    fun aTransactionHeadlineKeepsEverythingButItsAmount() {
        // The shapes :tx-history's TxSummary.headline() formats.
        assertEquals("$AMOUNT_MASK ETH → 0xab12cd…9e4f", maskTxHeadline("eth", "1.25 ETH → 0xab12cd…9e4f", true))
        assertEquals("$AMOUNT_MASK USDC → 0x3086…76e", maskTxHeadline("erc20", "1250.50 USDC → 0x3086…76e", true))
        assertEquals("$AMOUNT_MASK ? → ?", maskTxHeadline("erc20", "? ? → ?", true))
        assertEquals(
            "call · 132 bytes calldata · 0x38ed1739 · $AMOUNT_MASK ETH",
            maskTxHeadline("call", "call · 132 bytes calldata · 0x38ed1739 · 0.5 ETH", true),
        )
        // A call without value and a creation carry no amount.
        assertEquals("call · 132 bytes calldata", maskTxHeadline("call", "call · 132 bytes calldata", true))
        assertEquals("contract creation · 4 bytes", maskTxHeadline("create", "contract creation · 4 bytes", true))
        // A kind the mask does not know is hidden whole: drift over-masks, never leaks.
        assertEquals(AMOUNT_MASK, maskTxHeadline("swap", "2 ETH → 3000 USDC", true))
        // Shown, nothing changes.
        assertEquals("1.25 ETH → 0xab12cd…9e4f", maskTxHeadline("eth", "1.25 ETH → 0xab12cd…9e4f", false))
    }

    @Test
    fun aZeroValueCauseIsMaskedLikeAnyOther() {
        val alice = "0x" + "a1".repeat(20)
        val bob = "0x" + "b2".repeat(20)
        val c = WatchChange(
            alice, "Savings", "2", "1", 0, 1, 1, 2, -1, 1, WatchSearch.COMPLETE, 2,
            listOf(WatchCause(WatchCauseKind.SENT, 2, "0xfeed", bob, "0")),
        )
        // Shown, a zero-value send names no amount; hidden, it reads like a real one.
        assertEquals("Sent to ${BalanceWatch.shortAddress(bob)} (tx 0xfeed).", BalanceWatch.causeSummary(c, "ETH"))
        assertEquals(
            "Sent $AMOUNT_MASK ETH to ${BalanceWatch.shortAddress(bob)} (tx 0xfeed).",
            BalanceWatch.causeSummary(c, "ETH", hideAmounts = true),
        )
    }
}
