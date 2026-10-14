package io.myotis.ui

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The balance watch's pure core: the stores, the comparison, the cause search, the texts. */
class BalanceWatchTest {

    private val alice = "0x" + "a1".repeat(20)
    private val bob = "0x" + "b2".repeat(20)

    // ---- the list ----

    @Test
    fun theListParserKeepsWhatChecksOut() {
        val json = """[
            {"address":"0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1","label":"  Savings\u0007 "},
            {"address":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","label":"duplicate"},
            {"address":"0x1234","label":"too short"},
            {"label":"no address"},
            "not an object",
            {"address":"$bob"}
        ]"""
        assertEquals(listOf(WatchEntry(alice, "Savings"), WatchEntry(bob, "")), BalanceWatch.parseList(json))
        assertEquals(emptyList<Any>(), BalanceWatch.parseList("{broken"))
    }

    @Test
    fun aLabelSurvivesTheStoreVerbatim() {
        val entries = listOf(WatchEntry(alice, "Mom's \"cold\" wallet — ü"))
        assertEquals(entries, BalanceWatch.parseList(BalanceWatch.serializeList(entries)))
    }

    @Test
    fun theAddFormRefusesWhatCannotBeWatched() {
        val listed = listOf(WatchEntry(alice, ""))
        assertTrue(BalanceWatch.addError(listed, "0x12")!!.contains("40 hex"))
        assertTrue(BalanceWatch.addError(listed, "0x" + "0".repeat(40))!!.contains("zero"))
        assertTrue(BalanceWatch.addError(listed, alice.uppercase().replace("0X", "0x"))!!.contains("already"))
        assertNull(BalanceWatch.addError(listed, bob))
        val full = (1..BalanceWatch.MAX_ADDRESSES).map { WatchEntry("0x" + it.toString().padStart(40, '0'), "") }
        assertTrue(BalanceWatch.addError(full, bob)!!.contains("At most"))
        assertEquals(alice, BalanceWatch.normalizeAddress(" ${alice.uppercase().replace("0X", "0x")} "))
        // A mixed-case address carries an EIP-55 checksum, and a typo breaks it.
        val usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        assertNull(BalanceWatch.addError(listed, usdc))
        assertTrue(BalanceWatch.addError(listed, usdc.replace("A0b8", "a0B8"))!!.contains("checksum"))
    }

    // ---- the state ----

    @Test
    fun theStateRoundTrips() {
        val state = WatchState(
            addresses = mapOf(
                alice to WatchAddressState(WatchSeen("1500000000000000000", 7, 100, 1_700_000_000, 42)),
                bob to WatchAddressState(null, "beaconNotSynced", 43),
            ),
            changes = listOf(
                WatchChange(
                    alice, "Savings", "1", "2", 1, 2, 90, 100, 1_700_000_000, 44,
                    WatchSearch.PARTIAL, 37,
                    listOf(
                        WatchCause(WatchCauseKind.RECEIVED, 99, "0x" + "cc".repeat(32), bob, "1"),
                        WatchCause(WatchCauseKind.FEE_RECIPIENT, 98),
                    ),
                ),
            ),
            lastCheckMs = 44, lastAttemptMs = 45,
        )
        assertEquals(state, BalanceWatch.parseState(BalanceWatch.serializeState(state)))
        assertEquals(WatchState(), BalanceWatch.parseState("not json"))
        assertEquals(WatchState(), BalanceWatch.parseState("{}"))
    }

    @Test
    fun aCheckIsDueOnlyWhenBothClocksAllowIt() {
        val s = WatchState(lastCheckMs = 1_000, lastAttemptMs = 5_000)
        assertTrue(!BalanceWatch.isDue(s, 6_000, intervalMs = 10_000, retryMs = 2_000))
        assertTrue(!BalanceWatch.isDue(s, 11_500, intervalMs = 10_000, retryMs = 7_000))
        assertTrue(BalanceWatch.isDue(s, 12_000, intervalMs = 10_000, retryMs = 7_000))
        assertTrue(BalanceWatch.isDue(WatchState(), 0, intervalMs = 10_000, retryMs = 1))
        // Stamps from a clock that ran ahead and was corrected must not stall every check.
        assertTrue(BalanceWatch.isDue(WatchState(lastCheckMs = 90_000, lastAttemptMs = 90_000), 1_000, 10_000, 2_000))
    }

    // ---- the check ----

    @Test
    fun theFirstVerifiedReadIsTheBaseline() = runBlocking {
        val r = FakeReader().apply { balances[alice] = account(alice, "5", block = 100) }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), WatchState(), r, nowMs = 1)
        assertEquals(emptyList<Any>(), out.changes)
        assertEquals("5", out.state.addresses[alice]?.seen?.balance)
        assertEquals(1L, out.state.lastCheckMs)
    }

    @Test
    fun anUnchangedBalanceMovesTheBlockOnly() = runBlocking {
        val prev = stateWith(alice, "5", block = 100)
        val r = FakeReader().apply { balances[alice] = account(alice, "5", block = 120) }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 2)
        assertEquals(emptyList<Any>(), out.changes)
        assertEquals(120L, out.state.addresses[alice]?.seen?.blockNumber)
    }

    @Test
    fun anUnverifiedReadChangesNothing() = runBlocking {
        val prev = stateWith(alice, "5", block = 100)
        val r = FakeReader().apply {
            balances[alice] = account(alice, "999", block = 120, verified = false, failReason = "headerChainGapTooLarge")
        }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 2)
        assertEquals(emptyList<Any>(), out.changes)
        val a = out.state.addresses[alice]!!
        assertEquals("5", a.seen?.balance)
        assertEquals("headerChainGapTooLarge", a.error)
        // No verified read: the last-check clock stays, the attempt clock moves.
        assertEquals(0L, out.state.lastCheckMs)
        assertEquals(2L, out.state.lastAttemptMs)
    }

    @Test
    fun aReadThatThrowsIsRecordedAsTheError() = runBlocking {
        val prev = stateWith(alice, "5", block = 100)
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, FakeReader(), nowMs = 2)
        assertEquals("Node is not running", out.state.addresses[alice]?.error)
        assertEquals("5", out.state.addresses[alice]?.seen?.balance)
    }

    @Test
    fun anOlderAnchorIsNeverAStepBack() = runBlocking {
        val prev = stateWith(alice, "5", block = 100)
        val r = FakeReader().apply { balances[alice] = account(alice, "4", block = 90) }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 2)
        assertEquals(emptyList<Any>(), out.changes)
        assertEquals(100L, out.state.addresses[alice]?.seen?.blockNumber)
        assertEquals("5", out.state.addresses[alice]?.seen?.balance)
    }

    @Test
    fun aChangeIsTracedToItsTransaction() = runBlocking {
        val prev = stateWith(alice, "1000000000000000000", block = 100, nonce = 3)
        val r = FakeReader().apply {
            balances[alice] = account(alice, "1500000000000000000", block = 104, nonce = 3)
            (101L..104L).forEach { blocks[it] = blockJson(it) }
            blocks[103] = blockJson(103, tx(hash = "0xfeed", from = bob, to = alice, valueHex = "0x6f05b59d3b20000"))
        }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "Savings")), prev, r, nowMs = 9)
        val c = out.changes.single()
        assertEquals(WatchSearch.COMPLETE, c.search)
        assertEquals(101L, c.scannedFrom)
        assertEquals(listOf(WatchCause(WatchCauseKind.RECEIVED, 103, "0xfeed", bob, "500000000000000000")), c.causes)
        assertEquals(c, out.state.changes.first())
        assertEquals("Savings: +0.5 ETH", BalanceWatch.notificationTitle(c, "ETH"))
        val text = BalanceWatch.notificationText(c, "ETH")
        assertTrue(text, text.startsWith("Balance 1 → 1.5 ETH at block 104."))
        assertTrue(text, "Received 0.5 ETH from ${BalanceWatch.shortAddress(bob)} (tx 0xfeed)" in text)
        // Scanned newest first, and never below the old observation.
        assertEquals(listOf(104L, 103L, 102L, 101L), r.blockReads)
    }

    @Test
    fun aWideGapScansOnlyTheNewestBlocks() = runBlocking {
        val prev = stateWith(alice, "10", block = 100, nonce = 1)
        val r = FakeReader().apply {
            balances[alice] = account(alice, "4", block = 200, nonce = 3)
            (101L..200L).forEach { blocks[it] = blockJson(it) }
        }
        val c = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 9, maxScanBlocks = 8).changes.single()
        assertEquals(WatchSearch.PARTIAL, c.search)
        assertEquals(193L, c.scannedFrom)
        assertEquals(8, r.blockReads.size)
        val summary = BalanceWatch.causeSummary(c, "ETH")
        assertTrue(summary, "blocks 193–200" in summary && "100 blocks since the last check" in summary)
        assertTrue(summary, "sent 2 transactions" in summary)
        assertEquals("−< 0.000001", BalanceWatch.formatDelta(c.oldBalance, c.newBalance))
    }

    @Test
    fun anUnreadableBlockStopsTheScanButKeepsWhatItFound() = runBlocking {
        val prev = stateWith(alice, "10", block = 100)
        val r = FakeReader().apply {
            balances[alice] = account(alice, "20", block = 103)
            blocks[103] = blockJson(103, tx(hash = "0x01", from = bob, to = alice, valueHex = "0xa"))
            // 102 has no verified answer; 101 is never asked for.
        }
        val c = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 9).changes.single()
        assertEquals(WatchSearch.UNAVAILABLE, c.search)
        assertEquals(103L, c.scannedFrom)
        assertEquals(1, c.causes.size)
        assertEquals(listOf(103L, 102L), r.blockReads)
    }

    @Test
    fun noScanWindowMeansNoSearch() = runBlocking {
        val prev = stateWith(alice, "10", block = 100)
        val r = FakeReader().apply { balances[alice] = account(alice, "20", block = 103) }
        val c = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 9, maxScanBlocks = 0).changes.single()
        assertEquals(WatchSearch.NONE, c.search)
        assertEquals(emptyList<Any>(), r.blockReads)
    }

    @Test
    fun aSpentBudgetLeavesTheUnreadAddressesForTheNextCheck() = runBlocking {
        val prev = stateWith(alice, "5", block = 100)
        val r = FakeReader().apply { balances[alice] = account(alice, "6", block = 101) }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 2, budget = Duration.ZERO)
        assertEquals(emptyList<Any>(), out.changes)
        assertEquals(prev.addresses[alice], out.state.addresses[alice])
        assertEquals(0L, out.state.lastCheckMs)
    }

    @Test
    fun aSpentBudgetCutsTheScanShortButKeepsTheChange() = runBlocking {
        val prev = stateWith(alice, "5", block = 100)
        val r = object : FakeReader() {
            override suspend fun block(number: Long): String? {
                delay(100)
                return super.block(number)
            }
        }.apply {
            balances[alice] = account(alice, "6", block = 110)
            (101L..110L).forEach { blocks[it] = blockJson(it) }
        }
        val c = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 2, budget = 50.milliseconds)
            .changes.single()
        assertEquals(WatchSearch.PARTIAL, c.search)
        assertEquals(110L, c.scannedFrom)
        assertEquals(listOf(110L), r.blockReads)
    }

    @Test
    fun theLeastRecentlyAttemptedAddressIsReadFirst() = runBlocking {
        val carol = "0x" + "c3".repeat(20)
        val dave = "0x" + "d4".repeat(20)
        val prev = WatchState(addresses = mapOf(
            alice to WatchAddressState(WatchSeen("1", 0, 100, -1, checkedAtMs = 50)),
            bob to WatchAddressState(WatchSeen("1", 0, 100, -1, checkedAtMs = 10)),
            // Never verified, but its read failed most recently: it goes to the back, so a
            // slowly failing address cannot lead, and eat, every budgeted check.
            dave to WatchAddressState(null, "headerChainGapTooLarge", errorAtMs = 55),
        ))
        val read = ArrayList<String>()
        val r = object : FakeReader() {
            override suspend fun account(address: String): AccountResult {
                read += address
                return account(address, "1", block = 101)
            }
        }
        BalanceWatch.check(
            listOf(WatchEntry(alice, ""), WatchEntry(bob, ""), WatchEntry(carol, ""), WatchEntry(dave, "")),
            prev, r, nowMs = 60,
        )
        // Never attempted first, then by the last attempt: what a spent budget left out leads
        // the next check.
        assertEquals(listOf(carol, bob, alice, dave), read)
    }

    @Test
    fun aRemovedAddressLosesItsStateButNotItsHistory() = runBlocking {
        val prev = stateWith(alice, "10", block = 100).let {
            it.copy(changes = listOf(change(alice)))
        }
        val r = FakeReader().apply { balances[bob] = account(bob, "1", block = 101) }
        val out = BalanceWatch.check(listOf(WatchEntry(bob, "")), prev, r, nowMs = 9)
        assertEquals(setOf(bob), out.state.addresses.keys)
        assertEquals(1, out.state.changes.size)
    }

    // ---- what a block says ----

    @Test
    fun theBlockParserNamesEveryKindOfCause() {
        val json = """{
            "number":"0x10","miner":"${alice.uppercase().replace("0X", "0x")}",
            "transactions":[
                ${tx("0x01", alice, bob, "0x1")},
                ${tx("0x02", alice, null, "0x0")},
                ${tx("0x03", alice, alice, "0x0")},
                ${tx("0x04", bob, bob, "0x5")},
                {"hash":"0x05","from":"$bob","to":"$alice","value":"0x2",
                 "accessList":[{"address":"$bob","storageKeys":["0x00"]}]}
            ],
            "withdrawals":[
                {"index":"0x1","validatorIndex":"0x2","address":"$alice","amount":"0x3b9aca00"}
            ]
        }"""
        assertEquals(
            listOf(
                WatchCause(WatchCauseKind.SENT, 16, "0x01", bob, "1"),
                WatchCause(WatchCauseKind.SENT, 16, "0x02", null, "0"),
                WatchCause(WatchCauseKind.SELF, 16, "0x03", null, "0"),
                WatchCause(WatchCauseKind.RECEIVED, 16, "0x05", bob, "2"),
                // A withdrawals list is not read: no engine verifies one into its block JSON.
                WatchCause(WatchCauseKind.FEE_RECIPIENT, 16),
            ),
            BalanceWatch.causesIn(json, alice, 16),
        )
    }

    @Test
    fun aBlockItCannotSeeIsNotAnEmptyOne() {
        assertNull(BalanceWatch.causesIn("null", alice, 1))
        assertNull(BalanceWatch.causesIn("""{"error":"no snap peer available"}""", alice, 1))
        assertNull(BalanceWatch.causesIn("""{"transactions":["0xabc"]}""", alice, 1))
        assertNull(BalanceWatch.causesIn("garbage", alice, 1))
        assertEquals(emptyList<Any>(), BalanceWatch.causesIn("""{"transactions":[]}""", alice, 1))
    }

    // ---- amounts ----

    @Test
    fun hexQuantitiesBecomeDecimals() {
        assertEquals("0", BalanceWatch.hexToDecimal("0x0"))
        assertEquals("255", BalanceWatch.hexToDecimal("0xff"))
        assertEquals("1000000000000000000", BalanceWatch.hexToDecimal("0xde0b6b3a7640000"))
        assertEquals(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
            BalanceWatch.hexToDecimal("0x" + "f".repeat(64)),
        )
        assertNull(BalanceWatch.hexToDecimal("0x"))
        assertNull(BalanceWatch.hexToDecimal("0xzz"))
        assertNull(BalanceWatch.hexToDecimal("0x" + "1".repeat(65)))
    }

    @Test
    fun amountsAreTruncatedGroupedAndNeverAFalseZero() {
        assertEquals("0", BalanceWatch.formatUnits("0"))
        assertEquals("1", BalanceWatch.formatUnits("1000000000000000000"))
        assertEquals("1.5", BalanceWatch.formatUnits("1500000000000000000"))
        assertEquals("0.123456", BalanceWatch.formatUnits("123456789000000000"))
        assertEquals("1,234,567.01", BalanceWatch.formatUnits("1234567010000000000000000"))
        assertEquals("< 0.000001", BalanceWatch.formatUnits("999999999999"))
        assertEquals("+0.25", BalanceWatch.formatDelta("750000000000000000", "1000000000000000000"))
        assertEquals("−0.25", BalanceWatch.formatDelta("1000000000000000000", "750000000000000000"))
        assertEquals("±0", BalanceWatch.formatDelta("7", "007"))
        assertEquals("9", BalanceWatch.subtractDecimal("10", "1"))
        assertEquals("0", BalanceWatch.subtractDecimal("1000", "1000"))
        assertEquals("999999999999999999", BalanceWatch.subtractDecimal("1000000000000000000", "1"))
    }

    // ---- tokens ----

    private val usdc = Token("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC", 6)
    private fun usdcKey(holder: String) = BalanceWatch.key(holder, BalanceWatch.tokenAsset(usdc))

    @Test
    fun aTokenChangeIsTracedToItsTransfer() = runBlocking {
        val prev = WatchState(addresses = mapOf(
            alice to WatchAddressState(WatchSeen("5", 3, 100, -1, 0)),
            usdcKey(alice) to WatchAddressState(WatchSeen("1000000", 0, 100, -1, 0)),
        ))
        val r = FakeReader().apply {
            balances[alice] = account(alice, "5", block = 104, nonce = 3)
            tokenBalances[usdc.key] = hashMapOf(alice to "101000000")
            (101L..104L).forEach { receipts[it] = receiptsJson() }
            receipts[103] = receiptsJson(transferLog(usdc.address, bob, alice, "0x5f5e100"))
        }
        val c = BalanceWatch.check(listOf(WatchEntry(alice, "Savings")), prev, r, nowMs = 9, tokens = listOf(usdc))
            .changes.single()
        assertEquals(BalanceWatch.tokenAsset(usdc), c.asset)
        assertEquals("USDC", c.symbol)
        assertEquals(6, c.decimals)
        assertEquals(WatchSearch.COMPLETE, c.search)
        assertEquals(listOf(WatchCause(WatchCauseKind.RECEIVED, 103, "0xfeed", bob, "100000000")), c.causes)
        assertEquals("Savings: +100 USDC", BalanceWatch.notificationTitle(c, "ETH"))
        val text = BalanceWatch.notificationText(c, "ETH")
        assertTrue(text, text.startsWith("Balance 1 → 101 USDC at block 104."))
        assertTrue(text, "Received 100 USDC from ${BalanceWatch.shortAddress(bob)} (tx 0xfeed)" in text)
        // The token's search reads receipts, newest first, in a quarter of the block window.
        assertEquals(listOf(104L, 103L, 102L, 101L), r.receiptReads)
        assertEquals(emptyList<Any>(), r.blockReads)
    }

    @Test
    fun theFirstTokenReadIsItsBaselineAnchoredToTheAccountRead() = runBlocking {
        val r = FakeReader().apply {
            balances[alice] = account(alice, "5", block = 104)
            tokenBalances[usdc.key] = hashMapOf(alice to "7")
        }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), WatchState(), r, nowMs = 9, tokens = listOf(usdc))
        assertEquals(emptyList<Any>(), out.changes)
        assertEquals(WatchSeen("7", 0, 104, 1_700_000_000, 9), out.state.addresses[usdcKey(alice)]?.seen)
    }

    @Test
    fun tokensWaitForAVerifiedAccountReadOnACurrentAnchor() = runBlocking {
        val prev = WatchState(addresses = mapOf(
            alice to WatchAddressState(WatchSeen("5", 0, 100, -1, 0)),
            usdcKey(alice) to WatchAddressState(WatchSeen("1", 0, 100, -1, 0)),
        ))
        val unverified = FakeReader().apply {
            balances[alice] = account(alice, "5", block = 104, verified = false, failReason = "beaconNotSynced")
            tokenBalances[usdc.key] = hashMapOf(alice to "999")
        }
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, unverified, nowMs = 9, tokens = listOf(usdc))
        assertEquals(prev.addresses[usdcKey(alice)], out.state.addresses[usdcKey(alice)])
        assertEquals(emptyList<Any>(), unverified.calls)
        val older = FakeReader().apply {
            balances[alice] = account(alice, "5", block = 90)
            tokenBalances[usdc.key] = hashMapOf(alice to "999")
        }
        val out2 = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, older, nowMs = 9, tokens = listOf(usdc))
        assertEquals(emptyList<Any>(), out2.changes)
        assertEquals(emptyList<Any>(), older.calls)
    }

    @Test
    fun anEmptyTokenReplyIsNotAZeroBalance() = runBlocking {
        val prev = WatchState(addresses = mapOf(usdcKey(alice) to WatchAddressState(WatchSeen("5", 0, 100, -1, 0))))
        val r = FakeReader().apply { balances[alice] = account(alice, "5", block = 104) } // no token contract answers
        val out = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 9, tokens = listOf(usdc))
        assertEquals(emptyList<Any>(), out.changes)
        val a = out.state.addresses[usdcKey(alice)]!!
        assertEquals("5", a.seen?.balance)
        assertTrue(a.error, a.error!!.contains("no reply"))
    }

    @Test
    fun aTokenThatChangesWithoutATransferIsSaidToRebase() = runBlocking {
        val steth = Token("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "stETH", 18)
        val k = BalanceWatch.key(alice, BalanceWatch.tokenAsset(steth))
        val prev = WatchState(addresses = mapOf(
            alice to WatchAddressState(WatchSeen("5", 0, 100, -1, 0)),
            k to WatchAddressState(WatchSeen("1000000000000000000", 0, 100, -1, 0)),
        ))
        val r = FakeReader().apply {
            balances[alice] = account(alice, "5", block = 102)
            tokenBalances[steth.key] = hashMapOf(alice to "1000100000000000000")
            receipts[101] = receiptsJson(); receipts[102] = receiptsJson()
        }
        val c = BalanceWatch.check(listOf(WatchEntry(alice, "")), prev, r, nowMs = 9, tokens = listOf(steth)).changes.single()
        assertEquals(WatchSearch.COMPLETE, c.search)
        assertTrue(BalanceWatch.causeSummary(c, "ETH"), "rebasing" in BalanceWatch.causeSummary(c, "ETH"))
    }

    @Test
    fun theReceiptParserReadsOnlyThisTokensTransfersOfThisHolder() {
        val other = "0x" + "99".repeat(20)
        val json = receiptsJson(
            transferLog(usdc.address, alice, bob, "0x1", tx = "0x01"),
            transferLog(usdc.address, alice, alice, "0x2", tx = "0x02"),
            transferLog(other, bob, alice, "0x3", tx = "0x03"),             // another contract
            transferLog(usdc.address, bob, "0x" + "cc".repeat(20), "0x4"), // not this holder
            // An ERC-721 Transfer indexes the id: four topics, no balance move.
            """{"address":"${usdc.address}","topics":["${BalanceWatch.TRANSFER_TOPIC}","${topic(bob)}","${topic(alice)}","${topic(bob)}"],"data":"0x"}""",
            """{"address":"${usdc.address}","topics":["0x${"11".repeat(32)}","${topic(bob)}","${topic(alice)}"],"data":"0x5"}""",
        )
        assertEquals(
            listOf(
                WatchCause(WatchCauseKind.SENT, 7, "0x01", bob, "1"),
                WatchCause(WatchCauseKind.SELF, 7, "0x02", null, "2"),
            ),
            BalanceWatch.transfersIn(json, alice, usdc, 7),
        )
        assertNull(BalanceWatch.transfersIn("null", alice, usdc, 7))
        assertNull(BalanceWatch.transfersIn("""{"error":"no snap peer available"}""", alice, usdc, 7))
        assertEquals(emptyList<Any>(), BalanceWatch.transfersIn("[]", alice, usdc, 7))
    }

    @Test
    fun aTokenRemovedInSettingsLosesItsStoredBalance() = runBlocking {
        val store = StoreSettings()
        val mine = Token("0x" + "ab".repeat(20), "MINE", 18, custom = true)
        store.setCustomTokensJson(NET, CustomTokens.serialize(listOf(mine)))
        store.setWatchListJson(NET, BalanceWatch.serializeList(listOf(WatchEntry(alice, ""))))
        val r = FakeReader().apply {
            balances[alice] = account(alice, "5", block = 10)
            tokenBalances[mine.key] = hashMapOf(alice to "3")
        }
        val watcher = BalanceWatcher(store) { 100 }
        watcher.check(NET, r)
        val k = BalanceWatch.key(alice, BalanceWatch.tokenAsset(mine))
        assertEquals("3", BalanceWatch.parseState(store.watchStateJson(NET)).addresses[k]?.seen?.balance)
        store.setCustomTokensJson(NET, "[]")
        watcher.prune(NET)
        assertEquals(setOf(alice), BalanceWatch.parseState(store.watchStateJson(NET)).addresses.keys)
    }

    // ---- the watcher over a Settings store ----

    @Test
    fun theWatcherStoresWhatItFoundAndDropsWhatWasRemovedMeanwhile() = runBlocking {
        val store = StoreSettings()
        store.setWatchListJson(NET, BalanceWatch.serializeList(listOf(WatchEntry(alice, ""), WatchEntry(bob, ""))))
        val reader = object : FakeReader() {
            override suspend fun account(address: String): AccountResult {
                // The user removes bob while the proofs are read.
                if (address == bob) store.setWatchListJson(NET, BalanceWatch.serializeList(listOf(WatchEntry(alice, ""))))
                return account(address, "1", block = 5)
            }
        }
        val watcher = BalanceWatcher(store) { 100 }
        assertEquals(emptyList<Any>(), watcher.check(NET, reader))
        assertEquals(setOf(alice), BalanceWatch.parseState(store.watchStateJson(NET)).addresses.keys)
    }

    @Test
    fun pruningAnEmptiedListForgetsTheOldBaseline() = runBlocking {
        val store = StoreSettings()
        store.setWatchStateJson(NET, BalanceWatch.serializeState(stateWith(alice, "5", block = 100)))
        val watcher = BalanceWatcher(store) { 100 }
        // The last address was removed: no check follows, so the edit prunes.
        watcher.prune(NET)
        assertEquals(emptySet<String>(), BalanceWatch.parseState(store.watchStateJson(NET)).addresses.keys)
        // Re-adding it later starts from a fresh baseline, not the forgotten balance.
        store.setWatchListJson(NET, BalanceWatch.serializeList(listOf(WatchEntry(alice, ""))))
        val r = FakeReader().apply { balances[alice] = account(alice, "9", block = 500) }
        assertEquals(emptyList<Any>(), watcher.check(NET, r))
    }

    @Test
    fun aCancelledCheckFreesItsSlot() = runBlocking {
        val store = StoreSettings()
        store.setWatchListJson(NET, BalanceWatch.serializeList(listOf(WatchEntry(alice, ""))))
        val entered = CompletableDeferred<Unit>()
        val stuck = object : FakeReader() {
            override suspend fun account(address: String): AccountResult {
                entered.complete(Unit)
                awaitCancellation()
            }
        }
        val watcher = BalanceWatcher(store) { 100 }
        val job = launch { watcher.check(NET, stuck) }
        entered.await()
        job.cancelAndJoin()
        assertTrue(!watcher.isChecking(NET))
        val r = FakeReader().apply { balances[alice] = account(alice, "1", block = 5) }
        assertEquals(emptyList<Any>(), watcher.check(NET, r))
    }

    @Test
    fun theWatcherRunsOneCheckPerNetworkAtATime() = runBlocking {
        val store = StoreSettings()
        store.setWatchListJson(NET, BalanceWatch.serializeList(listOf(WatchEntry(alice, ""))))
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val slow = object : FakeReader() {
            override suspend fun account(address: String): AccountResult {
                entered.complete(Unit)
                release.await()
                return account(address, "1", block = 5)
            }
        }
        val watcher = BalanceWatcher(store) { 100 }
        val first = async { watcher.check(NET, slow) }
        entered.await()
        assertTrue(watcher.isChecking(NET))
        assertNull("a second check of the same network must not run", watcher.check(NET, slow))
        release.complete(Unit)
        assertEquals(emptyList<Any>(), first.await())
        assertTrue(!watcher.isChecking(NET))
        assertNull("nothing watched, nothing checked", BalanceWatcher(StoreSettings()).check(NET, slow))
    }

    // ---- fixtures ----

    /** A network without built-in tokens: the watcher tests check the watcher, not a token list. */
    private val NET = "devnet"

    private fun topic(a: String) = "0x" + "0".repeat(24) + a.drop(2).lowercase()

    private fun transferLog(token: String, from: String, to: String, amountHex: String, tx: String = "0xfeed") =
        """{"address":"$token","topics":["${BalanceWatch.TRANSFER_TOPIC}","${topic(from)}","${topic(to)}"],""" +
            """"data":"$amountHex","transactionHash":"$tx"}"""

    private fun receiptsJson(vararg logs: String) =
        """[{"transactionHash":"0xaa","status":"0x1","logs":[${logs.joinToString(",")}]}]"""

    private fun stateWith(address: String, wei: String, block: Long, nonce: Long = 0) = WatchState(
        addresses = mapOf(address to WatchAddressState(WatchSeen(wei, nonce, block, -1, 0))),
        lastCheckMs = 0,
    )

    private fun change(address: String) = WatchChange(
        address, "", "1", "2", 0, 0, 1, 2, -1, 0, WatchSearch.NONE, -1, emptyList(),
    )

    private fun tx(hash: String, from: String, to: String?, valueHex: String) =
        """{"hash":"$hash","from":"$from","to":${to?.let { "\"$it\"" } ?: "null"},"value":"$valueHex","input":"0x"}"""

    private fun blockJson(n: Long, vararg txs: String) =
        """{"number":"0x${n.toString(16)}","miner":"0x${"00".repeat(20)}","transactions":[${txs.joinToString(",")}]}"""

    private open class FakeReader : WatchReader {
        val balances = HashMap<String, AccountResult>()
        val blocks = HashMap<Long, String>()
        val blockReads = ArrayList<Long>()
        /** token contract (lowercase) → holder (lowercase) → raw balance; absent = empty reply. */
        val tokenBalances = HashMap<String, HashMap<String, String>>()
        val receipts = HashMap<Long, String>()
        val receiptReads = ArrayList<Long>()
        val calls = ArrayList<String>()
        override suspend fun account(address: String): AccountResult =
            balances[address] ?: throw IllegalStateException("Node is not running")
        override suspend fun block(number: Long): String? {
            blockReads += number
            return blocks[number]
        }
        override suspend fun call(to: String, data: String): EthCallResult {
            synchronized(calls) { calls += to.lowercase() }
            val raw = tokenBalances[to.lowercase()]?.get("0x" + data.takeLast(40))
                ?: return EthCallResult(EthCallStatus.OK, "0x")
            return EthCallResult(EthCallStatus.OK, "0x" + java.math.BigInteger(raw).toString(16).padStart(64, '0'))
        }
        override suspend fun receipts(number: Long): String? {
            receiptReads += number
            return receipts[number]
        }
    }

    private class StoreSettings : Settings by FakeSettings() {
        private val lists = HashMap<String, String>()
        private val states = HashMap<String, String>()
        private val customTokens = HashMap<String, String>()
        override fun customTokensJson(network: String): String = customTokens[network] ?: "[]"
        override fun setCustomTokensJson(network: String, json: String) { customTokens[network] = json }
        override fun supportsBalanceWatch(): Boolean = true
        override fun watchListJson(network: String): String = lists[network] ?: "[]"
        override fun setWatchListJson(network: String, json: String) { lists[network] = json }
        override fun watchStateJson(network: String): String = states[network] ?: "{}"
        override fun setWatchStateJson(network: String, json: String) { states[network] = json }
    }
}

/** A verified (or, with [verified] false, unverified) account read of [balanceWei] at [block]. */
internal fun account(
    address: String,
    balanceWei: String,
    block: Long,
    nonce: Long = 0,
    verified: Boolean = true,
    failReason: String? = null,
) = AccountResult(
    address = address, exists = true, nonce = nonce, balanceWei = balanceWei,
    storageRootHex = null, codeHashHex = null, blockNumber = block, peerStateRootHex = "0x00",
    peerProofValid = true, beaconChainVerified = verified, blsVerified = verified,
    matchedBeaconSlot = if (verified) 1 else -1, verifyMethod = if (verified) "headerChain" else null,
    failReason = failReason, blockTimestamp = if (verified) 1_700_000_000 else -1,
)
