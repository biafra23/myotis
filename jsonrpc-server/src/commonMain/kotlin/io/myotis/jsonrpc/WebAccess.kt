package io.myotis.jsonrpc

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile

/**
 * Which web pages may use the JSON-RPC listener (#502). Mirrors
 * `io.myotis.api.WebAccessMode` — this module's commonMain cannot see the Java
 * api, so the hosts' enum is mapped onto this one in jvmMain ([WebAccessApi]).
 */
enum class WebAccessMode {
    /** No web page may use the node. Native wallets (no `Origin` header) still can. */
    OFF,
    /** Only the listed origins, matched exactly (scheme + host + port). The
     *  default, with an empty list: every page is refused until the operator
     *  allows it — from the refusal the apps show, or by typing it in. */
    ALLOWLIST,
    /** Every web page — the behaviour before #502: any page open on the device
     *  can detect the node and read from it. */
    ALL,
}

/**
 * The operator's web-page policy: a [mode] and, for [WebAccessMode.ALLOWLIST], the
 * exact [origins] it admits. Immutable; origins are normalized by
 * [WebOrigins.normalize] at construction, so a match is a string compare against
 * the normalized `Origin` header.
 */
class WebAccessPolicy private constructor(val mode: WebAccessMode, val origins: Set<String>) {

    /** Whether a browser request from [origin] (as [WebOrigins.fromHeader] renders
     *  it) may be served. The opaque origin `null` (file:, data:, sandboxed
     *  frames) never matches a list entry — only [WebAccessMode.ALL] admits it. */
    fun allows(origin: String): Boolean = when (mode) {
        WebAccessMode.OFF -> false
        WebAccessMode.ALL -> true
        WebAccessMode.ALLOWLIST -> origin != WebOrigins.OPAQUE && origin in origins
    }

    override fun equals(other: Any?): Boolean =
        other is WebAccessPolicy && other.mode == mode && other.origins == origins

    override fun hashCode(): Int = 31 * mode.hashCode() + origins.hashCode()

    override fun toString(): String = "WebAccessPolicy($mode, $origins)"

    companion object {
        /** Specific sites, none yet: web pages are refused until allowed. */
        val DEFAULT: WebAccessPolicy = WebAccessPolicy(WebAccessMode.ALLOWLIST, emptySet())

        /** Build a policy; entries [WebOrigins.normalize] rejects are dropped. */
        fun of(mode: WebAccessMode, origins: Iterable<String>): WebAccessPolicy =
            WebAccessPolicy(mode, origins.mapNotNull(WebOrigins::normalize).toSet())
    }
}

/** Origin syntax: the one canonical form both the policy and the `Origin` header are reduced to. */
object WebOrigins {
    /** The opaque origin a browser sends for file:, data:, blob: and sandboxed documents. */
    const val OPAQUE = "null"

    private val DEFAULT_PORTS = mapOf("http" to 80, "https" to 443, "ws" to 80, "wss" to 443)

    /**
     * The canonical `scheme://host[:port]` of a typed or received origin, or null
     * when [input] is not a plain origin. A bare domain means `https://<domain>`
     * (type `http://` for a local dev server); scheme and host are lowercased; a
     * scheme's default port is dropped; a trailing slash is tolerated (pasted from
     * an address bar); a path, query, fragment or userinfo is refused; so is the
     * literal `null` — the opaque origin can never be allowed by name. No
     * wildcards: `*.example.org` on a platform that hosts user content on
     * subdomains would admit anyone who can publish there. ASCII only: a
     * browser serializes an international host in its `xn--` (punycode) form,
     * so a typed `münchen.example` could never match and is refused rather than
     * stored inert — allow it as the `xn--` form the recent list shows.
     */
    fun normalize(input: String): String? {
        val s = input.trim()
        if (s.isEmpty() || s.equals(OPAQUE, ignoreCase = true) || s.any { it.isWhitespace() }) return null
        val schemeEnd = s.indexOf("://")
        val scheme: String
        var rest: String
        if (schemeEnd < 0) {
            scheme = "https"
            rest = s
        } else {
            scheme = s.substring(0, schemeEnd).lowercase()
            rest = s.substring(schemeEnd + 3)
        }
        if (scheme.isEmpty() || scheme[0] !in 'a'..'z' ||
            !scheme.all { it in 'a'..'z' || it in '0'..'9' || it == '+' || it == '-' || it == '.' }) return null
        if (rest.endsWith("/")) rest = rest.dropLast(1)
        if (rest.isEmpty() || rest.any { it == '/' || it == '?' || it == '#' || it == '@' || it == '\\' }) return null
        val host: String
        val portText: String?
        if (rest.startsWith("[")) {
            // IPv6 literal, brackets kept (that is how both a Host and an Origin carry one).
            val close = rest.indexOf(']')
            if (close < 0) return null
            host = rest.substring(0, close + 1).lowercase()
            val inner = host.substring(1, host.length - 1)
            if (inner.isEmpty() || !inner.all { it in '0'..'9' || it in 'a'..'f' || it == ':' || it == '.' }) return null
            val after = rest.substring(close + 1)
            portText = when {
                after.isEmpty() -> null
                after.startsWith(":") -> after.substring(1)
                else -> return null
            }
        } else {
            val colon = rest.lastIndexOf(':')
            if (colon >= 0) {
                host = rest.substring(0, colon).lowercase()
                portText = rest.substring(colon + 1)
            } else {
                host = rest.lowercase()
                portText = null
            }
            if (host.isEmpty() || !host.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' || it == '_' }) return null
        }
        var port: Int? = null
        if (portText != null) {
            if (portText.isEmpty() || portText.length > 5 || !portText.all { it in '0'..'9' }) return null
            port = portText.toInt()
            if (port !in 1..65535) return null
            if (DEFAULT_PORTS[scheme] == port) port = null
        }
        return if (port == null) "$scheme://$host" else "$scheme://$host:$port"
    }

    /**
     * An `Origin` header as the policy compares it: the opaque origin stays
     * [OPAQUE]; anything else is [normalize]d, or kept lowercase verbatim when
     * malformed — it then matches nothing a list can hold, which is the point.
     */
    fun fromHeader(value: String): String {
        val v = value.trim()
        if (v.equals(OPAQUE, ignoreCase = true)) return OPAQUE
        return normalize(v) ?: v.lowercase()
    }

    /**
     * Whether a recorded origin belongs in the recent list: a real origin (one
     * "Allow" could admit) or the opaque [OPAQUE] (shown, never allowable). A
     * malformed `Origin` — no browser sends one — is refused but not listed: a
     * row the list's Allow could never satisfy is a dead button.
     */
    fun listable(origin: String): Boolean = origin == OPAQUE || normalize(origin) != null

    /** A `Host` header's name: lowercase, without the port; an IPv6 literal keeps its brackets. */
    fun hostName(header: String): String {
        val h = header.trim()
        val name = if (h.startsWith("[")) {
            val i = h.indexOf(']')
            if (i < 0) h else h.substring(0, i + 1)
        } else {
            val i = h.lastIndexOf(':')
            if (i < 0) h else h.substring(0, i)
        }
        return name.lowercase()
    }
}

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
