package io.myotis.desktop

import io.myotis.ui.WebAccessMode
import io.myotis.ui.WebOriginRow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The desktop's refused-web-page announcements (#502): once per site, folded across
 * networks, re-armed once allowed, silent under Off and All sites, capped per run.
 */
class WebRefusalAlertsTest {

    private fun row(origin: String, seen: Long, allowed: Boolean, network: String = "mainnet") =
        WebOriginRow(origin, 1, seen, allowed, network)

    private val list = WebAccessMode.ALLOWLIST

    @Test
    fun `a refused site is announced once, however often it retries`() {
        val alerts = WebRefusalAlerts()
        val first = alerts.next(listOf(listOf(row("https://app.example", 1_000, false))), list, emptyList())
        assertEquals(listOf("https://app.example"), first.map { it.origin })
        val retry = alerts.next(listOf(listOf(row("https://app.example", 2_000, false))), list, emptyList())
        assertTrue(retry.isEmpty())
    }

    @Test
    fun `allowing a site re-arms it, so a later refusal is news again`() {
        val alerts = WebRefusalAlerts()
        alerts.next(listOf(listOf(row("https://app.example", 1_000, false))), list, emptyList())
        // Allowed in the app: the policy admits it, and its next request is served.
        assertTrue(alerts.next(listOf(listOf(row("https://app.example", 2_000, true))),
            list, listOf("https://app.example")).isEmpty())
        // Removed again and refused again: announced again.
        val again = alerts.next(listOf(listOf(row("https://app.example", 3_000, false))), list, emptyList())
        assertEquals(listOf("https://app.example"), again.map { it.origin })
    }

    @Test
    fun `a policy round trip with no request in between does not re-announce an old refusal`() {
        val alerts = WebRefusalAlerts()
        val old = listOf(listOf(row("https://app.example", 1_000, false)))
        assertEquals(1, alerts.next(old, list, emptyList()).size)
        // Allowed in Settings, then removed again: the site sent nothing meanwhile.
        assertTrue(alerts.next(old, list, listOf("https://app.example")).isEmpty())
        assertTrue(alerts.next(old, list, emptyList()).isEmpty())
        // Specific sites -> All sites -> back: same.
        assertTrue(alerts.next(old, WebAccessMode.ALL, emptyList()).isEmpty())
        assertTrue(alerts.next(old, list, emptyList()).isEmpty())
    }

    @Test
    fun `a request served under All sites re-arms the site for when Specific sites is back`() {
        val alerts = WebRefusalAlerts()
        assertEquals(1, alerts.next(listOf(listOf(row("https://app.example", 1_000, false))), list, emptyList()).size)
        // All sites: the page's next request is served. Nothing is announced, but the pass
        // sees it — which is why the desktop watcher runs the pass in every mode.
        assertTrue(alerts.next(listOf(listOf(row("https://app.example", 2_000, true))),
            WebAccessMode.ALL, emptyList()).isEmpty())
        // Back to Specific sites, the page is refused again: news again.
        val again = alerts.next(listOf(listOf(row("https://app.example", 3_000, false))), list, emptyList())
        assertEquals(listOf("https://app.example"), again.map { it.origin })
    }

    @Test
    fun `a stale allowed sighting on another network does not hide a fresh refusal`() {
        val alerts = WebRefusalAlerts()
        val mainnet = listOf(row("https://app.example", 5_000, false, "mainnet"))
        val gnosis = listOf(row("https://app.example", 1_000, true, "gnosis"))
        val out = alerts.next(listOf(mainnet, gnosis), list, emptyList())
        assertEquals(listOf("https://app.example"), out.map { it.origin })
        // And the stale sighting does not re-arm it on the next pass either.
        assertTrue(alerts.next(listOf(mainnet, gnosis), list, emptyList()).isEmpty())
    }

    @Test
    fun `nothing is announced under Off or All sites, nor for what Allow could not admit`() {
        val refused = listOf(listOf(row("https://app.example", 1_000, false)))
        assertTrue(WebRefusalAlerts().next(refused, WebAccessMode.OFF, emptyList()).isEmpty())
        assertTrue(WebRefusalAlerts().next(refused, WebAccessMode.ALL, emptyList()).isEmpty())
        assertTrue(WebRefusalAlerts().next(listOf(listOf(row("null", 1_000, false))), list, emptyList()).isEmpty())
    }

    @Test
    fun `the per-run cap holds announcements back and says so`() {
        val alerts = WebRefusalAlerts(maxPerRun = 2)
        val rows = (1..3).map { row("https://site$it.example", it * 1_000L, false) }
        val out = alerts.next(listOf(rows), list, emptyList())
        assertEquals(2, out.size)
        assertTrue(alerts.capped)
        // Re-arming does not refill the budget: the cap counts announcements, not sites.
        alerts.next(listOf(rows.map { it.copy(lastAllowed = true) }), list, emptyList())
        assertTrue(alerts.next(listOf(rows.map { it.copy(lastSeenEpochMs = it.lastSeenEpochMs + 10_000) }),
            list, emptyList()).isEmpty())
    }

    @Test
    fun `the notification names one site, a few, or a few and a count`() {
        val (t1, m1) = refusalNotificationText(listOf(row("https://app.example", 1, false)))
        assertEquals("A web page was refused", t1)
        assertTrue(m1.startsWith("https://app.example tried to use the node."), m1)
        val (_, metamask) = refusalNotificationText(
            listOf(row("chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn", 1, false)))
        assertTrue(metamask.startsWith("MetaMask (Chrome extension) tried"), metamask)
        val five = (1..5).map { row("https://s$it.example", it.toLong(), false) }
        val (t5, m5) = refusalNotificationText(five)
        assertEquals("5 web pages were refused", t5)
        assertTrue(m5.startsWith("https://s1.example, https://s2.example, https://s3.example and 2 more tried"), m5)
        assertFalse(m5.contains("s4.example"))
    }
}
