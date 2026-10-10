package io.myotis.desktop

import io.myotis.ui.WebAccessMode
import io.myotis.ui.WebAccessUi
import io.myotis.ui.WebOriginRow

/**
 * Which refused web pages the desktop host raises a native notification for (#502) —
 * the desktop twin of the Android service's refusal poll, kept free of AWT and Compose
 * so it can be tested on its own.
 *
 * Each pass folds every network's recent list into one row per origin, the newest
 * sighting winning ([WebAccessUi.merge]), so a stale "allowed" sighting on one network
 * cannot cancel a fresh refusal on another. What is pending is exactly what the Status
 * banner shows ([WebAccessUi.pendingRefusals]: refused, allowable, not admitted by the
 * current policy, nothing under Off). Of that, an origin is announced ONCE — until a
 * request of its is SERVED (its newest sighting allowed), after which a later refusal
 * (the user removed the site again) is news again — and at most [maxPerRun] times per
 * run in total, so no local client can turn the notifications into a stream. Re-arming
 * on a served request, not on the policy admitting the site, is deliberate: a policy
 * round trip with no request in between (Specific sites → All sites → back, or allow
 * and remove again) must not re-announce a refusal that happened before it.
 */
internal class WebRefusalAlerts(private val maxPerRun: Int = MAX_PER_RUN) {

    companion object {
        /** Announcements per run at most; a real user never sees twenty refused sites. */
        const val MAX_PER_RUN = 20
    }

    private val announced = HashSet<String>()
    private var sent = 0

    /** True once the per-run cap held an announcement back (the caller logs it once). */
    var capped: Boolean = false
        private set

    /** The refused origins to announce now, newest first; empty most of the time. */
    fun next(
        perNetwork: Collection<List<WebOriginRow>>,
        mode: WebAccessMode,
        allowed: Collection<String>,
    ): List<WebOriginRow> {
        val rows = WebAccessUi.merge(perNetwork)
        for (r in rows) {
            if (r.lastAllowed) announced.remove(r.origin)
        }
        val out = ArrayList<WebOriginRow>()
        for (r in WebAccessUi.pendingRefusals(rows, mode, allowed, emptySet())) {
            if (r.origin in announced) continue
            if (sent >= maxPerRun) {
                capped = true
                break
            }
            announced += r.origin
            sent++
            out += r
        }
        return out
    }
}

/**
 * The native notification for [fresh] refusals as (title, message). One notification per
 * pass, never one per site: desktop notifications carry no buttons, so they point at the
 * app, where the Status banner has Allow — and Compose hands a notification to the tray
 * only while its collector is idle, so a burst would lose all but the first.
 */
internal fun refusalNotificationText(fresh: List<WebOriginRow>): Pair<String, String> {
    fun name(r: WebOriginRow) = WebAccessUi.knownClient(r.origin) ?: r.origin
    return if (fresh.size == 1) {
        "A web page was refused" to
            "${name(fresh[0])} tried to use the node. Open Myotis to allow it, but only if you trust that site."
    } else {
        val shown = fresh.take(3).joinToString(", ", transform = ::name)
        val more = if (fresh.size > 3) " and ${fresh.size - 3} more" else ""
        "${fresh.size} web pages were refused" to
            "$shown$more tried to use the node. Open Myotis to allow them, but only if you trust those sites."
    }
}
