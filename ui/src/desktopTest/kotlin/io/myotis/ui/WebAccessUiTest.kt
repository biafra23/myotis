package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pure helpers behind the Web page access section (#502). The normalize cases
 * mirror the engine's (`WebAccessTest` in :jsonrpc-server) — the two reductions
 * must agree, or a typed site and the origin the gate records never compare equal.
 */
class WebAccessUiTest {

    @Test fun normalizeMatchesTheEngine() {
        assertEquals("https://app.example", WebAccessUi.normalize("app.example"))
        assertEquals("https://app.example", WebAccessUi.normalize("HTTPS://App.Example:443/"))
        assertEquals("http://app.example", WebAccessUi.normalize("http://app.example:80"))
        assertEquals("http://localhost:3000", WebAccessUi.normalize("http://localhost:3000"))
        assertEquals("http://[::1]:3000", WebAccessUi.normalize("http://[::1]:3000"))
        assertEquals("chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn",
            WebAccessUi.normalize("chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn"))
        for (bad in listOf("", "null", "https://app.example/path", "https://user@app.example",
            "https://app.example:0", "*.example.org", "ht tp://x", "http://[::1",
            "https://münchen.example", "https://аpp.example")) {
            assertNull(bad, WebAccessUi.normalize(bad))
        }
        assertEquals("https://xn--mnchen-3ya.example", WebAccessUi.normalize("https://xn--mnchen-3ya.example"))
    }

    @Test fun isAllowedFollowsTheMode() {
        val list = listOf("https://app.example")
        assertTrue(WebAccessUi.isAllowed(WebAccessMode.ALLOWLIST, list, "https://app.example"))
        assertFalse(WebAccessUi.isAllowed(WebAccessMode.ALLOWLIST, list, "http://app.example"))
        assertFalse(WebAccessUi.isAllowed(WebAccessMode.ALLOWLIST, list, "null"))
        assertFalse(WebAccessUi.isAllowed(WebAccessMode.OFF, list, "https://app.example"))
        assertTrue(WebAccessUi.isAllowed(WebAccessMode.ALL, emptyList(), "https://anything.example"))
    }

    @Test fun mergeFoldsNetworksIntoOneRowPerOrigin() {
        val mainnet = listOf(
            WebOriginRow("https://app.example", 2, 1_000, false, "mainnet"),
            WebOriginRow("https://old.example", 1, 500, true, "mainnet"),
        )
        val gnosis = listOf(WebOriginRow("https://app.example", 3, 2_000, true, "gnosis"))
        val merged = WebAccessUi.merge(listOf(mainnet, gnosis))
        assertEquals(listOf("https://app.example", "https://old.example"), merged.map { it.origin })
        assertEquals(WebOriginRow("https://app.example", 5, 2_000, true, "gnosis"), merged[0])
    }

    @Test fun pendingRefusalsAreTheRefusedNotAllowedNotDismissedOnes() {
        val rows = listOf(
            WebOriginRow("https://app.example", 1, 3_000, false, "mainnet"),
            WebOriginRow("https://ok.example", 1, 2_000, true, "mainnet"),
            WebOriginRow("https://listed.example", 1, 1_500, false, "mainnet"),
            WebOriginRow("https://gone.example", 1, 1_000, false, "mainnet"),
            WebOriginRow("null", 1, 500, false, "mainnet"),
            // A value the engine kept verbatim (a non-browser client's malformed
            // Origin): nothing Allow could admit, so never a banner.
            WebOriginRow("foo bar", 1, 400, false, "mainnet"),
        )
        val pending = WebAccessUi.pendingRefusals(
            rows, WebAccessMode.ALLOWLIST, listOf("https://listed.example"), setOf("https://gone.example"))
        assertEquals(listOf("https://app.example"), pending.map { it.origin })
        assertTrue(WebAccessUi.pendingRefusals(rows, WebAccessMode.OFF, emptyList(), emptySet()).isEmpty())
        assertTrue(WebAccessUi.pendingRefusals(rows, WebAccessMode.ALL, emptyList(), emptySet()).isEmpty())
    }
}
