package io.myotis.ui

import kotlin.concurrent.Volatile

/**
 * Live peer-cache counts for the Status UI, parsed from the cache FILES — the
 * cross-engine source of truth (both engines read/write the same files, so
 * host in-memory cache objects go stale for Rust-hosted chains). Shared by all
 * hosts: the parsing and the (mtime, size) memoization live here in commonMain;
 * only the stat/read primitives are expect/actual (java.nio on the JVM hosts,
 * Foundation on iOS). The steady-state 2 s status poll costs one stat per file.
 *
 * Formats (authoritative docs on the cache classes `PeerCache`/`CLPeerCache`):
 * EL `ip\tport\tpubkey[\tsnap][\tsnapok|\tsnapbad]`; CL
 * `multiaddr[\t<low>-<high>][\tb<period>][\tlc|\tnolc]` — only lines starting
 * with `/` are CL peers, ranges mark proven catch-up servers.
 */
object CacheFileStats {

    /**
     * CL: total cached peers, proven LC servers (served catch-up range, served
     * bootstrap `b<period>`, or `lc` token), nolc-flagged. Buckets are mutually
     * exclusive (proven wins over nolc), so `total - proven - nolc` is the
     * untried remainder the UI shows.
     */
    data class ClStats(val total: Int, val proven: Int, val nolc: Int) {
        companion object { val EMPTY = ClStats(0, 0, 0) }
    }

    /** EL: total cached peers, snap-serving confirmed (snapok), denied (snapbad). */
    data class ElStats(val total: Int, val snapOk: Int, val snapBad: Int) {
        companion object { val EMPTY = ElStats(0, 0, 0) }
    }

    private class Memo(val mtime: Long, val size: Long, val stats: Any)

    // Copy-on-write map behind a volatile read: no common lock primitive needed,
    // and the worst a concurrent-update race can do is drop the other writer's
    // fresh memo entry — the next poll simply re-parses. Never wrong, at most
    // one redundant parse.
    @Volatile
    private var memo: Map<String, Memo> = emptyMap()

    // Memo keys carry the parser kind: cl() and el() on the SAME path (a caller
    // bug, but a cheap one to make impossible) must never serve each other's
    // cached stats through the unchecked fast-path cast.
    fun cl(path: String): ClStats = memoized("cl|$path", path, ClStats.EMPTY, ::parseCl)

    fun el(path: String): ElStats = memoized("el|$path", path, ElStats.EMPTY, ::parseEl)

    /** Internal (not private) so the module's own tests can pin the formats. */
    internal fun parseCl(lines: List<String>): ClStats {
        var total = 0; var proven = 0; var nolc = 0
        for (line in lines) {
            val t = line.trim()
            if (!t.startsWith("/")) continue
            total++
            // Per-PEER flags (the loader merges multiple range tokens by
            // widening): proven = ANY positive LC signal (served catch-up
            // range, Identify-confirmed `lc`, or served bootstrap `b<period>`),
            // and proven beats nolc — mutually exclusive buckets so the derived
            // `untried = total - proven - nolc` always sums and never goes
            // negative.
            var hasLcSignal = false; var hasNolc = false
            val tokens = t.split('\t')
            for (i in 1 until tokens.size) {
                when {
                    tokens[i] == "nolc" -> hasNolc = true
                    tokens[i] == "lc" || isBootstrapToken(tokens[i]) ||
                        isServedRange(tokens[i]) -> hasLcSignal = true
                }
            }
            if (hasLcSignal) proven++ else if (hasNolc) nolc++
        }
        return ClStats(total, proven, nolc)
    }

    /** Internal (not private) so the module's own tests can pin the formats. */
    internal fun parseEl(lines: List<String>): ElStats {
        var total = 0; var snapOk = 0; var snapBad = 0
        for (line in lines) {
            val t = line.trim()
            if (t.isEmpty()) continue
            val tokens = t.split('\t')
            if (tokens.size < 3) {
                // The daemon/desktop PeerCache still LOADS the legacy colon form
                // (ip:port:pubkey[:snap], IPv4 — first char is a digit) and only
                // migrates it on the first full rewrite — count those lines too
                // or a pre-existing data dir under-reports until a rewrite. The
                // leading-digit gate keeps comment lines with colons out; count
                // instead of split avoids the substring allocations.
                if (!t.contains('\t') && t[0] in '0'..'9' && t.count { it == ':' } >= 2) total++
                continue
            }
            total++
            // Loader parity: index 3 is the snap flag; quality tokens are
            // recognized from index 4, LAST one wins.
            var quality: String? = null
            for (i in 4 until tokens.size) {
                if (tokens[i] == "snapok" || tokens[i] == "snapbad") quality = tokens[i]
            }
            when (quality) {
                "snapok" -> snapOk++
                "snapbad" -> snapBad++
            }
        }
        return ElStats(total, snapOk, snapBad)
    }

    private fun <T : Any> memoized(key: String, path: String, empty: T, parse: (List<String>) -> T): T {
        val cached = memo[key]
        val id = when (val stat = statCacheFile(path)) {
            is CacheFileStat.Present -> stat
            // Affirmatively gone: a purged cache really is empty — forget the
            // memo rather than showing stale counts forever.
            CacheFileStat.Missing -> {
                if (cached != null) memo = memo - key
                return empty
            }
            // TRANSIENT stat failure: show last-known counts rather than
            // flashing zeros, and keep the memo for when the stat recovers.
            CacheFileStat.Unreadable -> {
                @Suppress("UNCHECKED_CAST")
                return (cached?.stats as? T) ?: empty
            }
        }
        if (cached != null && cached.mtime == id.mtimeMillis && cached.size == id.size) {
            @Suppress("UNCHECKED_CAST")
            return cached.stats as T
        }
        val lines = readCacheFileLines(path)
        if (lines == null) {
            // Read raced a rewrite: show last-known counts rather than flashing zeros.
            @Suppress("UNCHECKED_CAST")
            return (cached?.stats as? T) ?: empty
        }
        val stats = parse(lines)
        // Re-stat after the read: the writers rewrite in place, so only memoize
        // when the identity held across the read — a torn parse is shown once
        // but never sticks.
        val after = statCacheFile(path)
        if (after is CacheFileStat.Present &&
            after.mtimeMillis == id.mtimeMillis && after.size == id.size
        ) {
            memo = memo + (key to Memo(id.mtimeMillis, id.size, stats))
        }
        return stats
    }

    /** `b<period>` — the peer served a light_client_bootstrap at that period. */
    private fun isBootstrapToken(tok: String): Boolean =
        tok.length > 1 && tok[0] == 'b' && tok.substring(1).all { it in '0'..'9' }

    /** A proven served range `<low>-<high>` (or legacy bare integer floor). */
    private fun isServedRange(tok: String): Boolean {
        if (tok.isEmpty()) return false
        val dash = tok.indexOf('-')
        // ASCII range check — isDigit() accepts any Unicode digit class.
        if (dash < 0) return tok.all { it in '0'..'9' }
        val low = tok.substring(0, dash)
        val high = tok.substring(dash + 1)
        return low.isNotEmpty() && high.isNotEmpty() &&
            low.all { it in '0'..'9' } && high.all { it in '0'..'9' }
    }
}

/**
 * A cache file's stat outcome. [Missing] (affirmatively not a regular file)
 * evicts the memo — a purged cache really is empty; [Unreadable] (transient
 * stat failure) keeps showing last-known counts instead of flashing zeros.
 */
internal sealed interface CacheFileStat {
    /** Change identity: parse results are memoized against it. */
    data class Present(val mtimeMillis: Long, val size: Long) : CacheFileStat
    data object Missing : CacheFileStat
    data object Unreadable : CacheFileStat
}

internal expect fun statCacheFile(path: String): CacheFileStat

/** Read [path] as UTF-8 lines; null when the read fails (e.g. raced a rewrite). */
internal expect fun readCacheFileLines(path: String): List<String>?
