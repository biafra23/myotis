package io.myotis.jsonrpc

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The web-page gate's rules (#502), decided in isolation: origin syntax, the
 * three modes, browser-vs-native telling, the Host check, and the bounded
 * recent-origins list. [WebAccessHttpTest] drives the same gate over HTTP.
 */
class WebAccessTest {

    // ---- origin syntax ----

    @Test fun bareDomainMeansHttps() {
        assertEquals("https://app.example", WebOrigins.normalize("app.example"))
        assertEquals("https://app.example", WebOrigins.normalize("  App.Example/ "))
    }

    @Test fun normalizeLowercasesAndDropsDefaultPortAndTrailingSlash() {
        assertEquals("https://app.example", WebOrigins.normalize("HTTPS://App.Example:443/"))
        assertEquals("http://app.example", WebOrigins.normalize("http://app.example:80"))
        assertEquals("http://localhost:3000", WebOrigins.normalize("http://localhost:3000"))
        assertEquals("https://app.example:8443", WebOrigins.normalize("https://app.example:8443"))
        assertEquals("http://[::1]:3000", WebOrigins.normalize("http://[::1]:3000"))
        assertEquals("http://[::1]", WebOrigins.normalize("http://[::1]"))
    }

    @Test fun extensionOriginsAreOrdinaryOrigins() {
        assertEquals("chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn",
            WebOrigins.normalize("chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn"))
        assertEquals("moz-extension://3c8d0f2a-1b2c-4d5e-8f90-123456789abc",
            WebOrigins.normalize("moz-extension://3C8D0F2A-1b2c-4d5e-8f90-123456789abc/"))
    }

    @Test fun normalizeRefusesWhatIsNotAPlainOrigin() {
        for (bad in listOf(
            "", "   ", "null", "NULL",
            "https://app.example/path", "https://app.example?x=1", "https://app.example#f",
            "https://user@app.example", "https://app.example:0", "https://app.example:99999",
            "https://app.example:abc", "https://app.example:", "ht tp://app.example",
            "*.example.org", "https://*.example.org", "://app.example", "1http://app.example",
            "http://[::1", "http://[::1]x", "http://[zz::1]", "https://",
        )) {
            assertNull(WebOrigins.normalize(bad), "'$bad' must not normalize")
        }
    }

    @Test fun headerKeepsTheOpaqueOriginAndMalformedValuesMatchNothing() {
        assertEquals("null", WebOrigins.fromHeader("null"))
        assertEquals("https://app.example", WebOrigins.fromHeader(" https://App.Example "))
        val policy = WebAccessPolicy.of(WebAccessMode.ALLOWLIST, listOf("https://app.example/evil"))
        assertTrue(policy.origins.isEmpty(), "an entry with a path is dropped, not admitted")
        assertFalse(policy.allows(WebOrigins.fromHeader("https://app.example/evil")))
    }

    @Test fun hostNameStripsThePortAndCase() {
        assertEquals("localhost", WebOrigins.hostName("LocalHost:8545"))
        assertEquals("127.0.0.1", WebOrigins.hostName("127.0.0.1"))
        assertEquals("[::1]", WebOrigins.hostName("[::1]:8545"))
        assertEquals("evil.example", WebOrigins.hostName("evil.example:8545"))
    }

    // ---- the three modes ----

    @Test fun allowlistAdmitsExactOriginsOnly() {
        val policy = WebAccessPolicy.of(WebAccessMode.ALLOWLIST, listOf("App.Example", "http://localhost:3000"))
        assertEquals(setOf("https://app.example", "http://localhost:3000"), policy.origins)
        assertTrue(policy.allows("https://app.example"))
        assertTrue(policy.allows("http://localhost:3000"))
        assertFalse(policy.allows("http://app.example"), "scheme is part of the origin")
        assertFalse(policy.allows("https://app.example:8443"), "port is part of the origin")
        assertFalse(policy.allows("https://sub.app.example"), "no subdomain wildcard")
        assertFalse(policy.allows("https://other.example"))
        assertFalse(policy.allows("null"), "the opaque origin is never allowlisted")
    }

    @Test fun offAdmitsNothingAndAllAdmitsEverything() {
        val off = WebAccessPolicy.of(WebAccessMode.OFF, listOf("https://app.example"))
        assertFalse(off.allows("https://app.example"), "Off refuses even a listed site")
        val all = WebAccessPolicy.of(WebAccessMode.ALL, emptyList())
        assertTrue(all.allows("https://anything.example"))
        assertTrue(all.allows("null"))
    }

    @Test fun defaultIsSpecificSitesWithNoneYet() {
        assertEquals(WebAccessMode.ALLOWLIST, WebAccessPolicy.DEFAULT.mode)
        assertTrue(WebAccessPolicy.DEFAULT.origins.isEmpty())
        assertFalse(WebAccess().decide("POST", "127.0.0.1:8545", "https://app.example", null).let {
            it is WebAccessVerdict.Serve
        })
    }

    // ---- browser vs native, Host, preflight ----

    @Test fun nativeClientPassesWithoutCorsHeaders() {
        val v = WebAccess().decide("POST", "127.0.0.1:8545", null, null)
        assertTrue(v is WebAccessVerdict.Serve)
        assertNull((v as WebAccessVerdict.Serve).echo)
        // No Host at all (HTTP/1.0) passes too.
        assertTrue(WebAccess().decide("POST", null, null, null) is WebAccessVerdict.Serve)
    }

    @Test fun refusedPageIsRefusedWhateverTheMethod() {
        val gate = WebAccess()
        for (m in listOf("POST", "GET", "OPTIONS")) {
            val v = gate.decide(m, "localhost:8545", "https://evil.example", "cross-site")
            assertTrue(v is WebAccessVerdict.Refuse, m)
            assertEquals(WebAccess.REASON_ORIGIN, (v as WebAccessVerdict.Refuse).reason)
            assertEquals("https://evil.example", v.origin)
        }
    }

    @Test fun allowedPageGetsServeOrPreflightWithTheHeaderEchoed() {
        val gate = WebAccess(WebAccessPolicy.of(WebAccessMode.ALLOWLIST, listOf("https://app.example")))
        val post = gate.decide("POST", "127.0.0.1:8545", "https://app.example", "cross-site")
        assertTrue(post is WebAccessVerdict.Serve)
        assertEquals("https://app.example", (post as WebAccessVerdict.Serve).echo)
        val pre = gate.decide("OPTIONS", "127.0.0.1:8545", "https://app.example", "cross-site")
        assertTrue(pre is WebAccessVerdict.Preflight)
        assertEquals("https://app.example", (pre as WebAccessVerdict.Preflight).echo)
        assertTrue(gate.decide("POST", "127.0.0.1:8545", "http://app.example", null) is WebAccessVerdict.Refuse)
        assertTrue(gate.decide("POST", "127.0.0.1:8545", "null", null) is WebAccessVerdict.Refuse)
    }

    @Test fun noCorsProbeWithoutOriginIsRefused_navigationsAreNot() {
        val gate = WebAccess(WebAccessPolicy.of(WebAccessMode.ALL, emptyList()))
        for (site in listOf("cross-site", "same-site", "same-origin")) {
            for (mode in listOf("no-cors", null)) {
                val v = gate.decide("GET", "localhost:8545", null, site, mode)
                assertTrue(v is WebAccessVerdict.Refuse, "$site/$mode")
                assertEquals(WebAccess.REASON_PROBE, (v as WebAccessVerdict.Refuse).reason)
            }
        }
        // A URL typed into the address bar carries Sec-Fetch-Site: none — not a page.
        assertTrue(gate.decide("GET", "localhost:8545", null, "none", "navigate") is WebAccessVerdict.Serve)
        // A link clicked on some page is cross-site but a top-level navigation: the user
        // sees the response, the linking page learns nothing. Served.
        assertTrue(gate.decide("GET", "localhost:8545", null, "cross-site", "navigate") is WebAccessVerdict.Serve)
        // A form POST navigation carries an Origin and is judged by the policy, not by
        // this rule: served under All sites (this gate), refused under the default.
        assertTrue(gate.decide("POST", "localhost:8545", "https://evil.example", "cross-site", "navigate")
            is WebAccessVerdict.Serve)
        assertTrue(WebAccess().decide("POST", "localhost:8545", "https://evil.example", "cross-site", "navigate")
            is WebAccessVerdict.Refuse)
    }

    @Test fun hostMustNameTheLoopbackListenerInEveryMode() {
        val gate = WebAccess(WebAccessPolicy.of(WebAccessMode.ALL, emptyList()))
        for (ok in listOf("localhost:8545", "LOCALHOST", "127.0.0.1:1", "[::1]:8545", "[::1]")) {
            assertTrue(gate.decide("POST", ok, null, null) is WebAccessVerdict.Serve, ok)
        }
        for (bad in listOf("evil.example:8545", "127.0.0.2:8545", "localhost.evil.example")) {
            val v = gate.decide("POST", bad, "https://app.example", null)
            assertTrue(v is WebAccessVerdict.Refuse, bad)
            assertEquals(WebAccess.REASON_HOST, (v as WebAccessVerdict.Refuse).reason)
        }
        // The bound address is allowed too, whatever it is.
        assertTrue(WebAccess(boundHost = "10.0.0.5").decide("POST", "10.0.0.5:8545", null, null) is WebAccessVerdict.Serve)
        assertTrue(WebAccess(boundHost = "::1").decide("POST", "[::1]:8545", null, null) is WebAccessVerdict.Serve)
    }

    @Test fun policySwapIsLive() {
        val gate = WebAccess()
        assertTrue(gate.decide("POST", "127.0.0.1:8545", "https://app.example", null) is WebAccessVerdict.Refuse)
        gate.policy = WebAccessPolicy.of(WebAccessMode.ALLOWLIST, listOf("https://app.example"))
        assertTrue(gate.decide("POST", "127.0.0.1:8545", "https://app.example", null) is WebAccessVerdict.Serve)
        gate.policy = WebAccessPolicy.of(WebAccessMode.OFF, listOf("https://app.example"))
        assertTrue(gate.decide("POST", "127.0.0.1:8545", "https://app.example", null) is WebAccessVerdict.Refuse)
    }

    // ---- the recent-origins list ----

    @Test fun recentListCountsFlagsNewsAndCapsAtTheOldest() = runBlocking {
        var now = 1_000L
        val gate = WebAccess(maxRecent = 2, clock = { now })
        assertTrue(gate.record("https://a.example", allowed = false), "first sighting is news")
        now = 2_000
        assertFalse(gate.record("https://a.example", allowed = false), "a retry is not")
        now = 3_000
        assertTrue(gate.record("https://a.example", allowed = true), "an outcome flip is")
        now = 4_000
        gate.record("https://b.example", allowed = false)
        var rows = gate.recentOrigins()
        assertEquals(listOf("https://b.example", "https://a.example"), rows.map { it.origin }, "most recent first")
        assertEquals(WebOriginRecord("https://a.example", 3, 3_000, true), rows[1])
        assertEquals(WebOriginRecord("https://b.example", 1, 4_000, false), rows[0])
        now = 5_000
        gate.record("https://c.example", allowed = false)
        rows = gate.recentOrigins()
        assertEquals(listOf("https://c.example", "https://b.example"), rows.map { it.origin },
            "the cap drops the least recently seen origin")
    }
}
