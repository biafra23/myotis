package io.myotis.ui

/**
 * The "Web page access" setting (#502): which browser origins may use the
 * JSON-RPC listener. Mirrors `io.myotis.api.WebAccessMode`; hosts map by name.
 */
enum class WebAccessMode {
    /** No web page may use the node. Native wallets are unaffected. */
    OFF,
    /** Only the sites in [Settings.webAccessOrigins]. The default, with none yet. */
    ALLOWLIST,
    /** Every web page — any page open on the device can detect the node and read from it. */
    ALL,
}

/**
 * One web origin that tried to use a network's listener this run, as the host
 * maps `io.myotis.api.WebOrigin` — the "recent web pages" list and the refusal
 * banner. [lastAllowed] is the latest attempt's outcome, not whether the policy
 * admits the origin now (that is [WebAccessUi.isAllowed]).
 */
data class WebOriginRow(
    val origin: String,
    val attempts: Long,
    val lastSeenEpochMs: Long,
    val lastAllowed: Boolean,
    /** The network whose listener saw it (each has its own port). */
    val network: String,
)

/** Pure helpers behind the Web page access section — testable without Compose. */
object WebAccessUi {

    /** The MetaMask extension's Chrome Web Store id, so the row can say who it is;
     *  Firefox gives every install a random `moz-extension://` id, so there is no
     *  table to keep for it. */
    private val KNOWN_CLIENTS = mapOf(
        "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn" to "MetaMask (Chrome extension)",
    )

    /** A friendly name for an origin the user is likely to recognize, or null. */
    fun knownClient(origin: String): String? = KNOWN_CLIENTS[origin]

    /**
     * The canonical `scheme://host[:port]` of a typed site, or null when it is not
     * a plain origin — the SAME reduction the engine applies to the `Origin` header
     * (`io.myotis.jsonrpc.WebOrigins.normalize`; keep the two in step, the engine's
     * test pins the rules), so a stored entry and a recent-list origin compare as
     * strings. A bare domain means `https://<domain>`; a scheme's default port is
     * dropped; a trailing slash is tolerated; a path, query, userinfo, wildcard or
     * the literal `null` is refused.
     */
    fun normalize(input: String): String? {
        val s = input.trim()
        if (s.isEmpty() || s.equals("null", ignoreCase = true) || s.any { it.isWhitespace() }) return null
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
        if (scheme.isEmpty() || !scheme[0].isLetter() ||
            !scheme.all { it.isLetterOrDigit() || it == '+' || it == '-' || it == '.' }) return null
        if (rest.endsWith("/")) rest = rest.dropLast(1)
        if (rest.isEmpty() || rest.any { it == '/' || it == '?' || it == '#' || it == '@' || it == '\\' }) return null
        val host: String
        val portText: String?
        if (rest.startsWith("[")) {
            val close = rest.indexOf(']')
            if (close < 0) return null
            host = rest.substring(0, close + 1).lowercase()
            val inner = host.substring(1, host.length - 1)
            if (inner.isEmpty() || !inner.all { it.isDigit() || it in 'a'..'f' || it == ':' || it == '.' }) return null
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
            if (host.isEmpty() || !host.all { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' }) return null
        }
        var port: Int? = null
        if (portText != null) {
            if (portText.isEmpty() || portText.length > 5 || !portText.all { it.isDigit() }) return null
            port = portText.toInt()
            if (port !in 1..65535) return null
            if (DEFAULT_PORTS[scheme] == port) port = null
        }
        return if (port == null) "$scheme://$host" else "$scheme://$host:$port"
    }

    private val DEFAULT_PORTS = mapOf("http" to 80, "https" to 443, "ws" to 80, "wss" to 443)

    /** Whether the current setting admits [origin] — what the row's action and the banner key off. */
    fun isAllowed(mode: WebAccessMode, origins: Collection<String>, origin: String): Boolean = when (mode) {
        WebAccessMode.OFF -> false
        WebAccessMode.ALL -> true
        WebAccessMode.ALLOWLIST -> origin != "null" && origin in origins
    }

    /**
     * The recent rows of every network folded into one list, most recent first:
     * one row per origin (the user allows a SITE, not a site-per-chain), attempts
     * summed, the newest sighting's outcome and network kept.
     */
    fun merge(perNetwork: Collection<List<WebOriginRow>>): List<WebOriginRow> {
        val byOrigin = LinkedHashMap<String, WebOriginRow>()
        perNetwork.flatten().forEach { row ->
            val prev = byOrigin[row.origin]
            byOrigin[row.origin] = when {
                prev == null -> row
                row.lastSeenEpochMs >= prev.lastSeenEpochMs -> row.copy(attempts = prev.attempts + row.attempts)
                else -> prev.copy(attempts = prev.attempts + row.attempts)
            }
        }
        return byOrigin.values.sortedByDescending { it.lastSeenEpochMs }
    }

    /**
     * The origins the Status screen should raise a refusal for: refused by their
     * latest attempt, not admitted by the current setting, and not dismissed. The
     * opaque origin `null` is left out — "Allow" could not admit it — and so is
     * everything under [WebAccessMode.OFF]: the user said no web pages, so a
     * refusal there is the setting working, not news.
     */
    fun pendingRefusals(
        rows: List<WebOriginRow>,
        mode: WebAccessMode,
        origins: Collection<String>,
        dismissed: Set<String>,
    ): List<WebOriginRow> = if (mode == WebAccessMode.OFF) emptyList() else rows.filter {
        !it.lastAllowed && it.origin != "null" && it.origin !in dismissed && !isAllowed(mode, origins, it.origin)
    }
}
