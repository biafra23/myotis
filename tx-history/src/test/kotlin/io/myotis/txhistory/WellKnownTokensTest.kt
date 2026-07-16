package io.myotis.txhistory

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WellKnownTokensTest {

    @Test
    fun allKeysAreLowercase40HexAddresses() {
        val re = Regex("^0x[0-9a-f]{40}$")
        WellKnownTokens.MAINNET.keys.forEach { addr ->
            assertTrue(re.matches(addr), "bad key: $addr")
        }
    }

    @Test
    fun decimalsAreSane() {
        WellKnownTokens.MAINNET.values.forEach { t ->
            assertTrue(t.decimals in 0..18, "${t.symbol}: decimals ${t.decimals}")
            assertTrue(t.symbol.isNotBlank())
        }
    }

    @Test
    fun spotCheckStablecoins() {
        assertEquals(
            WellKnownTokens.Token("USDC", 6),
            WellKnownTokens.lookup("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"))
        assertEquals(
            WellKnownTokens.Token("USDT", 6),
            WellKnownTokens.lookup("0xdac17f958d2ee523a2206206994597c13d831ec7"))
        assertEquals(null, WellKnownTokens.lookup(null))
        assertEquals(null, WellKnownTokens.lookup("0x1111111111111111111111111111111111111111"))
    }
}
