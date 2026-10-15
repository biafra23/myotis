package io.myotis.jsonrpc.policy

/**
 * Which web pages may use the JSON-RPC listener (#502). Mirrors
 * `io.myotis.api.WebAccessMode` — this multiplatform module cannot see the Java
 * api, so the hosts' enum is mapped onto this one by `:jsonrpc-server`'s jvmMain
 * (`WebAccessApi`) and by the Rust engine's handle.
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

    /**
     * [normalize] applied per ENTRY, multiplicity kept: the list a host gets back
     * from `setWebAccessPolicy` (CLAUDE.md, Trust — applied or refused, never
     * silently ignored). Two spellings of one origin stay two entries, as a set
     * would not, so `normalizeEach(asked).size != asked.size` is exactly "an entry
     * was no origin and was dropped" — the one definition both the listener's
     * adapter and a handle without a listener answer with.
     */
    fun normalizeEach(input: Iterable<String>): List<String> = input.mapNotNull(::normalize)

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
