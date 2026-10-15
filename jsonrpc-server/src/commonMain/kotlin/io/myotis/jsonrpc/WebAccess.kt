package io.myotis.jsonrpc

import io.myotis.jsonrpc.policy.WebAccessMode
import io.myotis.jsonrpc.policy.WebAccessPolicy
import io.myotis.jsonrpc.policy.WebOrigins
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile

/** One web origin the gate has judged: how often, when last, and how the last attempt ended. */
data class WebOriginRecord(
    val origin: String,
    /** Requests judged, CORS preflights included (a refused page gets no further than its preflight). */
    val attempts: Long,
    val lastSeenEpochMs: Long,
    /** The outcome of the latest attempt — not whether the policy admits the origin now. */
    val lastAllowed: Boolean,
)

/** What the gate decided for one request. [origin] is the normalized origin, for the record. */
sealed class WebAccessVerdict {
    abstract val origin: String?

    /** Serve it. A page ([origin] and [echo], the `Origin` header as received, both set)
     *  gets [echo] as `Access-Control-Allow-Origin`; a native client (no `Origin`: both
     *  null) gets no CORS headers. */
    class Serve(override val origin: String?, val echo: String?) : WebAccessVerdict()

    /** Answer a CORS preflight for an allowed page; it never reaches the router. */
    class Preflight(override val origin: String, val echo: String) : WebAccessVerdict()

    /** Refuse before routing. [reason] is one of [WebAccess.REASON_HOST], [WebAccess.REASON_ORIGIN],
     *  [WebAccess.REASON_PROBE]. */
    class Refuse(override val origin: String?, val reason: String) : WebAccessVerdict()
}

/**
 * The request gate in front of the router, and the state behind the apps'
 * "Web page access" setting (#502): a [policy] the host swaps live (no restart —
 * every request reads the current one), and the bounded in-memory list of
 * [recentOrigins] that tried, with their outcome, so a refused page can be
 * allowed from the app with one tap.
 *
 * Telling browsers from native clients: a browser sends `Origin` on every
 * fetch/XHR POST and on every cross-origin GET, and page script cannot set,
 * change or remove it (a forbidden request header), so a request WITH one is a
 * web page and is judged by the policy; a request with NEITHER `Origin` nor a
 * browser-initiated `Sec-Fetch-Site` is a native client (MetaMask Mobile, curl,
 * the daemon's tools) and is served as before. Browser-extension wallets carry
 * their extension origin (`chrome-extension://…`, `moz-extension://…`) and are
 * allowed like any site. The two remaining browser paths a CORS grant alone
 * would miss are closed here too: a cross-origin `text/plain` POST is a CORS
 * "simple request" (no preflight) that would otherwise reach the router, and
 * an `<img>`/`<script>`/no-cors probe sends no `Origin` but does send
 * `Sec-Fetch-Site` — refused when that names anything but `none`, unless
 * `Sec-Fetch-Mode` says `navigate`: a top-level navigation (a link clicked, a
 * bookmark) shows the user the response and leaks nothing to the page that
 * linked it, and a navigation that could carry a body (a form POST) sends an
 * `Origin` and is judged by it.
 *
 * The `Host` header must name the loopback listener (geth's `--http.vhosts`):
 * a DNS-rebinding page reaches the node under the attacker's hostname, which is
 * what the check catches, in every mode. A request with no `Host` at all is an
 * HTTP/1.0 client, not a browser, and passes.
 *
 * What this does NOT stop: another native app on the device. `Origin` protects
 * only because browsers enforce it for page script; a native client can send any
 * value or none, and a loopback listener cannot learn which app connected.
 */
class WebAccess(
    initial: WebAccessPolicy = WebAccessPolicy.DEFAULT,
    /** The address the listener binds, allowed as a `Host` beside the loopback names. */
    boundHost: String = "127.0.0.1",
    private val maxRecent: Int = MAX_RECENT,
    private val clock: () -> Long = ::rpcEpochMillis,
) {
    companion object {
        /** Distinct origins remembered; the least recently seen is dropped past it. */
        const val MAX_RECENT = 50
        const val REASON_HOST = "host"
        const val REASON_ORIGIN = "origin"
        const val REASON_PROBE = "probe"
    }

    /** The live policy. Written by the host (Settings), read per request; a plain volatile swap. */
    @Volatile
    var policy: WebAccessPolicy = initial

    private val allowedHosts: Set<String> = buildSet {
        add("localhost"); add("127.0.0.1"); add("[::1]")
        val b = boundHost.trim().lowercase()
        add(if (b.contains(':') && !b.startsWith("[")) "[$b]" else b)
    }

    // Copy-on-write behind a Mutex (commonMain has no synchronized/ConcurrentHashMap;
    // writers are the gate's suspend path), with a Volatile snapshot for the hosts'
    // lock-free reader (recentOrigins is polled from a plain thread).
    @Volatile
    private var recent: Map<String, WebOriginRecord> = emptyMap()
    private val mutex = Mutex()

    /** Whether a request with this `Host` header may be served. */
    fun hostAllowed(host: String?): Boolean = host == null || WebOrigins.hostName(host) in allowedHosts

    /**
     * Judge one request from its method and the four headers the gate reads.
     * Pure: recording is the caller's ([record]) so the decision is testable alone.
     */
    fun decide(
        method: String,
        host: String?,
        origin: String?,
        secFetchSite: String?,
        secFetchMode: String? = null,
    ): WebAccessVerdict {
        val normalized = origin?.let(WebOrigins::fromHeader)
        if (!hostAllowed(host)) return WebAccessVerdict.Refuse(normalized, REASON_HOST)
        if (origin != null && normalized != null) {
            if (!policy.allows(normalized)) return WebAccessVerdict.Refuse(normalized, REASON_ORIGIN)
            val echo = origin.trim()
            return if (method.equals("OPTIONS", ignoreCase = true)) WebAccessVerdict.Preflight(normalized, echo)
            else WebAccessVerdict.Serve(normalized, echo)
        }
        val browserInitiated = secFetchSite != null && !secFetchSite.trim().equals("none", ignoreCase = true)
        val navigation = secFetchMode != null && secFetchMode.trim().equals("navigate", ignoreCase = true)
        if (browserInitiated && !navigation) return WebAccessVerdict.Refuse(null, REASON_PROBE)
        return WebAccessVerdict.Serve(null, null)
    }

    /**
     * Record one judged browser request. Returns true when the outcome is news —
     * a first sighting, or a flip from the previous outcome — so the caller logs
     * that at INFO and the rest at DEBUG (a page retrying in a loop is one line,
     * not a flood).
     */
    suspend fun record(origin: String, allowed: Boolean): Boolean = mutex.withLock {
        val now = clock()
        val prev = recent[origin]
        val next = LinkedHashMap(recent)
        if (prev == null && next.size >= maxRecent) {
            next.values.minByOrNull { it.lastSeenEpochMs }?.let { next.remove(it.origin) }
        }
        next[origin] = WebOriginRecord(origin, (prev?.attempts ?: 0L) + 1, now, allowed)
        recent = next
        prev == null || prev.lastAllowed != allowed
    }

    /** The origins seen this run, most recent first. In memory only — it is browsing history. */
    fun recentOrigins(): List<WebOriginRecord> = recent.values.sortedByDescending { it.lastSeenEpochMs }
}
