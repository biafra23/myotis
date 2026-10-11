package io.myotis.jsonrpc

/**
 * The `io.myotis.api` ↔ commonMain mapping for the web-page policy (#502): the
 * engines hand a host's [io.myotis.api.WebAccessPolicy] to the listener's
 * [WebAccess], and read its records back as flat api rows. Pure delegation.
 */
object WebAccessApi {

    /** The listener's policy for an api one (entries the engine cannot parse as an origin are dropped). */
    @JvmStatic
    fun toPolicy(policy: io.myotis.api.WebAccessPolicy): WebAccessPolicy =
        WebAccessPolicy.of(WebAccessMode.valueOf(policy.mode().name), policy.origins())

    /**
     * Install [policy] on [webAccess] — live, no restart — and return what applies: the
     * same mode with the origins as normalized, minus the entries that are not origins,
     * so a caller can see a dropped entry and refuse or warn (CLAUDE.md, Trust). The
     * returned list is per ENTRY, multiplicity kept (two spellings of one origin stay
     * two entries, as the gate's own set would not), so `applied.origins().size() !=
     * asked.origins().size()` is exactly "an entry was dropped" and never a duplicate.
     */
    @JvmStatic
    fun apply(webAccess: WebAccess, policy: io.myotis.api.WebAccessPolicy): io.myotis.api.WebAccessPolicy {
        webAccess.policy = toPolicy(policy)
        return io.myotis.api.WebAccessPolicy(policy.mode(), policy.origins().mapNotNull(WebOrigins::normalize))
    }

    /** The recent-origins list as api rows, most recent first. */
    @JvmStatic
    fun recent(webAccess: WebAccess): List<io.myotis.api.WebOrigin> =
        webAccess.recentOrigins().map {
            io.myotis.api.WebOrigin(it.origin, it.attempts, it.lastSeenEpochMs, it.lastAllowed)
        }
}
