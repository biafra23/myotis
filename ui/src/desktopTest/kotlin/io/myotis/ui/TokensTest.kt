package io.myotis.ui

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The token plumbing under the Query tab's balances: hashing and checksums, the hand-rolled
 * ABI, amount formatting, the pinned token lists, the custom-token store and the reads.
 */
class TokensTest {

    @Test
    fun keccakMatchesTheKnownVectors() {
        assertEquals(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            toHex(Keccak256.digest(ByteArray(0))),
        )
        assertEquals(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            toHex(Keccak256.digest("abc".encodeToByteArray())),
        )
        // The ERC-20 selectors this file hard-codes are keccak256(signature)[0..4].
        fun selector(sig: String) = toHex(Keccak256.digest(sig.encodeToByteArray())).take(8)
        assertEquals("70a08231", selector("balanceOf(address)"))
        assertEquals("313ce567", selector("decimals()"))
        assertEquals("95d89b41", selector("symbol()"))
        assertEquals("08c379a0", selector("Error(string)"))
        // A multi-block input: 136 bytes is exactly one rate, so padding spills into a second block.
        assertEquals(
            toHex(Keccak256.digest(ByteArray(136) { 0x61 })).length, 64,
        )
    }

    @Test
    fun eip55ChecksumsMatchTheSpecVectors() {
        listOf(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ).forEach {
            assertEquals(it, Eip55.checksum(it.lowercase()))
            assertTrue(Eip55.isValid(it))
        }
        // One flipped case is a failed checksum; a single-case address carries none.
        assertFalse(Eip55.isValid("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"))
        assertTrue(Eip55.isValid("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))
        assertTrue(Eip55.isValid("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"))
    }

    @Test
    fun everyPinnedTokenAddressCarriesItsChecksumAndAppearsOnce() {
        listOf("mainnet", "gnosis", "sepolia").forEach { net ->
            val tokens = PopularTokens.forNetwork(net)
            assertTrue("$net lists tokens", tokens.isNotEmpty())
            tokens.forEach {
                assertEquals("$net ${it.symbol}", Eip55.checksum(it.address), it.address)
                assertTrue(it.decimals in 0..36)
                assertFalse(it.custom)
            }
            assertEquals(tokens.size, tokens.map { it.key }.toSet().size)
        }
        assertTrue(PopularTokens.forNetwork("hoodi").isEmpty())
    }

    @Test
    fun uint256DecodesWithoutBigInteger() {
        assertEquals("0", unsignedDecimal(ByteArray(32)))
        assertEquals("1234500000", Erc20.decodeUint256(word(1_234_500_000L)))
        val max = ByteArray(32) { -1 }
        assertEquals(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
            Erc20.decodeUint256(max),
        )
        assertNull("no reply is not a zero balance", Erc20.decodeUint256(ByteArray(0)))
        assertNull(Erc20.decodeUint256(ByteArray(31)))
    }

    @Test
    fun amountsFormatWithTheirDecimals() {
        assertEquals("0", formatTokenAmount("0", 6))
        assertEquals("1,234.5", formatTokenAmount("1234500000", 6))
        assertEquals("1", formatTokenAmount("1000000000000000000", 18))
        assertEquals("0.123456", formatTokenAmount("123456789000000000", 18))  // truncated, not rounded
        assertEquals("< 0.000001", formatTokenAmount("1", 18))
        assertEquals("0.00000001", formatTokenAmount("1", 8, maxFraction = 8))
        assertEquals("42", formatTokenAmount("42", 0))
        assertEquals("1,000,000,000,000", formatTokenAmount("1000000000000000000000000000000", 18))
        assertEquals("not-a-number", formatTokenAmount("not-a-number", 18))
    }

    @Test
    fun replyDecodersHandleTheShapesTokensReallyUse() {
        assertEquals(6, Erc20.decodeDecimals(word(6)))
        assertNull("decimals() is a uint8", Erc20.decodeDecimals(word(256)))
        assertNull(Erc20.decodeDecimals(ByteArray(0)))

        assertEquals("USDC", Erc20.decodeText(abiString("USDC")))
        assertEquals("", Erc20.decodeText(abiString("")))
        // MKR answers symbol() with a bytes32, not a string.
        val mkr = ByteArray(32).also { "MKR".encodeToByteArray().copyInto(it) }
        assertEquals("MKR", Erc20.decodeText(mkr))
        assertNull(Erc20.decodeText(ByteArray(7)))
        // An offset that points outside the reply is no string.
        assertNull(Erc20.decodeText(word(4096) + word(4)))

        assertEquals("not enough", Erc20.revertReason(hexToBytes("08c379a0")!! + abiString("not enough")))
        assertNull(Erc20.revertReason(hexToBytes("deadbeef")!!))
    }

    @Test
    fun aHolderTypedWithoutItsPrefixIsStillAnAddress() {
        assertEquals("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", asHexAddress(" d8dA6BF26964aF9D7eEd9e03E53415D37aA96045 "))
        assertEquals("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", asHexAddress("0Xd8da6bf26964af9d7eed9e03e53415d37aa96045"))
        assertNull(asHexAddress("vitalik.eth"))
        assertNull(asHexAddress("0x1234"))
    }

    @Test
    fun balanceOfCalldataPadsTheHolder() {
        assertEquals(
            "0x70a08231000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045",
            Erc20.balanceOfCall("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
        )
    }

    @Test
    fun theStoreRoundTripsAndDropsWhatDoesNotCheckOut() {
        val t = Token("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "My \"T\" \\ token", 9, custom = true)
        assertEquals(listOf(t), CustomTokens.parse(CustomTokens.serialize(listOf(t))))

        val stored = """
            [ {"decimals": 6, "name": "Lower", "address": "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"},
              {"address":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD","name":"Bad checksum","decimals":18},
              {"address":"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359","name":"Duplicate","decimals":18},
              {"address":"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB","name":"Too many","decimals":256},
              {"address":"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb","name":"  ","decimals":1},
              {"address":"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb","name":"Ok\u0007","decimals":0,"extra":null} ]
        """.trimIndent()
        assertEquals(
            listOf(
                Token("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "Lower", 6, custom = true),
                Token("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", "Ok", 0, custom = true),
            ),
            CustomTokens.parse(stored),
        )
        assertEquals(emptyList<Token>(), CustomTokens.parse("not json"))
        // A broken tail keeps what parsed before it.
        assertEquals(1, CustomTokens.parse("""[{"address":"0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359","name":"A","decimals":6},{"addr""").size)
    }

    @Test
    fun theFormRefusesWhatWouldShowAWrongBalance() {
        val listed = PopularTokens.forNetwork("mainnet")
        fun reason(a: String, n: String = "T", d: String = "18") =
            (CustomTokens.validate(a, n, d, listed) as? CustomTokens.Check.Invalid)?.reason

        assertTrue(reason("0x1234")!!.contains("40 hex digits"))
        assertTrue(reason("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")!!.contains("checksum"))
        assertTrue(reason("0x" + "0".repeat(40))!!.contains("zero address"))
        assertTrue(reason("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")!!.contains("already listed as USDC"))
        assertTrue(reason("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", n = " ")!!.contains("name"))
        assertTrue(reason("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", n = "x".repeat(25))!!.contains("24"))
        assertTrue(reason("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", d = "")!!.contains("whole number"))
        assertTrue(reason("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", d = "256")!!.contains("between 0 and 255"))

        // Accepted input is stored checksummed and trimmed.
        assertEquals(
            CustomTokens.Check.Ok(Token("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "MY T", 9, custom = true)),
            CustomTokens.validate(" 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed ", "  MY   T ", "9", listed),
        )
    }

    @Test
    fun aReadTellsAnEmptyReplyFromAZeroBalance() = runBlocking {
        val usdc = PopularTokens.forNetwork("mainnet").first { it.symbol == "USDC" }
        fun read(r: EthCallResult, t: Token = usdc) =
            runBlocking { readTokenBalance(CallFake { _, _ -> r }, "mainnet", HOLDER, t) }

        assertEquals("1234500000", read(EthCallResult(EthCallStatus.OK, "0x" + toHex(word(1_234_500_000L)))).raw)
        assertEquals("0", read(EthCallResult(EthCallStatus.OK, "0x" + toHex(word(0)))).raw)
        read(EthCallResult(EthCallStatus.OK, "0x")).let {
            assertNull(it.raw)
            assertTrue(it.error!!.contains("no token contract"))
        }
        read(EthCallResult(EthCallStatus.REVERTED, "0x08c379a0" + toHex(abiString("paused")))).let {
            assertNull(it.raw)
            assertEquals("the contract reverted: paused", it.error)
        }
        assertTrue(read(EthCallResult(EthCallStatus.UNAVAILABLE, null, "beacon not synced")).error!!.contains("beacon not synced"))
        assertEquals(
            "boom",
            readTokenBalance(CallFake { _, _ -> error("boom") }, "mainnet", HOLDER, usdc).error,
        )
    }

    @Test
    fun aCustomTokensDecimalsAreCheckedAgainstTheContract() = runBlocking {
        val custom = Token("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "MINE", 18, custom = true)
        val node = CallFake { _, data ->
            when (data) {
                Erc20.DECIMALS_CALL -> EthCallResult(EthCallStatus.OK, "0x" + toHex(word(6)))
                else -> EthCallResult(EthCallStatus.OK, "0x" + toHex(word(5_000_000)))
            }
        }
        val r = readTokenBalance(node, "mainnet", HOLDER, custom)
        assertEquals("5000000", r.raw)
        assertEquals(6, r.chainDecimals)
        assertTrue(r.decimalsMismatch)
        assertFalse(readTokenBalance(node, "mainnet", HOLDER, custom.copy(decimals = 6)).decimalsMismatch)
        // A built-in token's decimals are pinned: no second call.
        assertNull(readTokenBalance(node, "mainnet", HOLDER, PopularTokens.forNetwork("mainnet")[0]).chainDecimals)
        // An answer already known from an earlier read is reused, not asked again.
        val balanceOnly = CallFake { _, data ->
            check(data != Erc20.DECIMALS_CALL) { "decimals() asked again" }
            EthCallResult(EthCallStatus.OK, "0x" + toHex(word(5_000_000)))
        }
        assertEquals(6, readTokenBalance(balanceOnly, "mainnet", HOLDER, custom, knownChainDecimals = 6).chainDecimals)
    }

    @Test
    fun anEthCallNeedsAContractAddress() {
        val (to, data) = ethCallArgs(HOLDER, Erc20.DECIMALS_CALL)
        assertEquals(20, to.size)
        assertEquals("313ce567", toHex(data))
        // An empty `to` is contract creation to an engine: refused here, never sent.
        listOf("", "0x", "0x1234").forEach { bad ->
            assertTrue(runCatching { ethCallArgs(bad, Erc20.DECIMALS_CALL) }.exceptionOrNull() is IllegalArgumentException)
        }
        assertTrue(runCatching { ethCallArgs(HOLDER, "0xzz") }.exceptionOrNull() is IllegalArgumentException)
        assertEquals(
            EthCallResult(EthCallStatus.REVERTED, "0x08c379a0", null),
            EthCallResult.of("REVERTED", hexToBytes("08c379a0"), null),
        )
    }

    @Test
    fun metadataFillsTheForm() = runBlocking {
        val node = CallFake { _, data ->
            when (data) {
                Erc20.SYMBOL_CALL -> EthCallResult(EthCallStatus.OK, "0x" + toHex(abiString("TKN")))
                Erc20.DECIMALS_CALL -> EthCallResult(EthCallStatus.OK, "0x" + toHex(word(8)))
                else -> error("unexpected call $data")
            }
        }
        assertEquals(TokenMetadata("TKN", 8, null), readTokenMetadata(node, "mainnet", HOLDER))
        val eoa = CallFake { _, _ -> EthCallResult(EthCallStatus.OK, "0x") }
        assertTrue(readTokenMetadata(eoa, "mainnet", HOLDER).error!!.contains("not an ERC-20"))
    }

    private class CallFake(private val answer: (String, String) -> EthCallResult) : FakeController() {
        override val supportsEthCall: Boolean = true
        override suspend fun ethCall(network: String, to: String, data: String): EthCallResult = answer(to, data)
    }

    private companion object {
        const val HOLDER = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    }
}

/** One ABI word holding [v]. */
internal fun word(v: Long): ByteArray = ByteArray(32).also { w ->
    for (i in 0 until 8) w[31 - i] = (v ushr (8 * i)).toByte()
}

/** [s] ABI-encoded as a lone `string` return value. */
internal fun abiString(s: String): ByteArray {
    val b = s.encodeToByteArray()
    val padded = ByteArray((b.size + 31) / 32 * 32).also { b.copyInto(it) }
    return word(32) + word(b.size.toLong()) + padded
}
