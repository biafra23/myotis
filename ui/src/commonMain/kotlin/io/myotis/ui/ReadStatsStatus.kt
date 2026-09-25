package io.myotis.ui

/**
 * Shared reader for the engines' read-fetch shadow-cache JSON
 * (`ChainHandle.readStatsJson()`, schema 1 — docs/read-stats.md), so every
 * host's Status tab renders the identical rows and a serializer change
 * degrades one pinned place instead of per-host regex copies.
 *
 * The rows answer the three caching questions the counters exist for, in
 * phone width: how many verified fetches happened, what share of them a
 * SOUND cache keying would have served (and the time it would have saved),
 * and how often a value up to a minute old would still have been right.
 */
object ReadStatsStatus {

    /** One kind's counters (account / storage / code). Fields that a kind
     *  doesn't emit stay 0. */
    data class Kind(
        val fetches: Long,
        val repeats: Long,
        val sameStateRoot: Long,
        val sameStorageRoot: Long,
        val unchanged: Long,
        val fetchMs: Long,
        /** The ms the kind's sound keying would have saved: sameStateRoot for
         *  accounts, sameStorageRoot for storage, every repeat for code. */
        val avoidableMs: Long,
        /** Repeats whose previous fetch was ≤ 60 s ago, and how many of those
         *  were value-unchanged (the le12s + le60s buckets). */
        val recentReads: Long,
        val recentUnchanged: Long,
    ) {
        /** Fetches the sound keying would have served. */
        val avoidable: Long
            get() = sameStorageRoot.takeIf { it > 0 } ?: sameStateRoot.takeIf { it > 0 } ?: 0L
    }

    data class Parsed(
        val windowSeconds: Long,
        val account: Kind,
        val storage: Kind,
        val code: Kind,
    )

    /** Structured parse of the engine's JSON (regex over the fixed serializer
     *  shape; an absent section parses as zeros). Null for the engines'
     *  error envelope / the API default, so callers hide the rows. */
    fun parse(json: String): Parsed? {
        if (!json.contains("\"schema\":1") || !json.contains("\"account\":{")) return null
        val window = num(json, "windowSeconds")
        return Parsed(
            windowSeconds = window,
            account = kind(section(json, "account"), avoidableKey = "sameStateRootFetchMs"),
            storage = kind(section(json, "storage"), avoidableKey = "sameStorageRootFetchMs"),
            code = kind(section(json, "code"), avoidableKey = "repeatFetchMs"),
        )
    }

    /** The section's own text: from its key to the next top-level key.
     *  Sections nest one level (byAge), so a brace count finds the end. */
    private fun section(json: String, name: String): String {
        val start = json.indexOf("\"$name\":{")
        if (start < 0) return ""
        var depth = 0
        var i = start + name.length + 4   // past `"name":{` — inside the object
        while (i < json.length) {
            when (json[i]) {
                '{' -> depth++
                '}' -> if (depth == 0) return json.substring(start, i + 1) else depth--
            }
            i++
        }
        return json.substring(start)
    }

    private fun num(text: String, key: String): Long =
        Regex("\"$key\":(\\d+)").find(text)?.groupValues?.get(1)?.toLongOrNull() ?: 0L

    private fun kind(text: String, avoidableKey: String): Kind {
        val le12 = section(text, "le12s")
        val le60 = section(text, "le60s")
        return Kind(
            fetches = num(text.substringBefore("\"byAge\""), "fetches"),
            repeats = num(text.substringBefore("\"byAge\""), "repeats"),
            sameStateRoot = num(text, "sameStateRoot"),
            sameStorageRoot = num(text, "sameStorageRoot"),
            unchanged = num(text.substringBefore("\"byAge\""), "unchanged"),
            fetchMs = num(text, "fetchMs"),
            avoidableMs = num(text, avoidableKey),
            recentReads = num(le12, "reads") + num(le60, "reads"),
            recentUnchanged = num(le12, "unchanged") + num(le60, "unchanged"),
        )
    }

    /** Whether anything has been observed yet (the rows show only then). */
    fun hasReads(p: Parsed): Boolean =
        p.account.fetches + p.storage.fetches + p.code.fetches > 0

    /** "acct 412 · slot 2,210 · code 31" — verified fetches that crossed the
     *  network since start. */
    fun fetchesLine(p: Parsed): String =
        "acct ${grouped(p.account.fetches)} · slot ${grouped(p.storage.fetches)} · code ${grouped(p.code.fetches)}"

    /** "slot 81% (5.5 min) · acct 2% · code 77%" — the share of each kind's
     *  fetches a sound cache would have served, with the storage time it
     *  would have saved (the storage-root scheme is the one worth building). */
    fun cacheableLine(p: Parsed): String {
        val slot = pct(p.storage.avoidable, p.storage.fetches)
        val acct = pct(p.account.avoidable, p.account.fetches)
        val code = pct(p.code.repeats, p.code.fetches)
        val saved = p.storage.avoidableMs.takeIf { it > 0 }?.let { " (${formatMs(it)})" } ?: ""
        return "slot $slot$saved · acct $acct · code $code"
    }

    /** "slot 91% · acct 83%" — of the repeats within a minute of the previous
     *  fetch, how often the value was still the same: what serving a
     *  minute-old value would have got right. Null until there are any. */
    fun staleLine(p: Parsed): String? {
        if (p.storage.recentReads + p.account.recentReads == 0L) return null
        return "slot ${pct(p.storage.recentUnchanged, p.storage.recentReads)} · " +
            "acct ${pct(p.account.recentUnchanged, p.account.recentReads)}"
    }

    private fun pct(part: Long, whole: Long): String =
        if (whole <= 0L) "—" else "${(part * 100 + whole / 2) / whole}%"

    private fun formatMs(ms: Long): String {
        val s = ms / 1000
        return when {
            s >= 3600 -> "${s / 3600}h ${(s % 3600) / 60}m"
            s >= 60 -> "${s / 60}m ${s % 60}s"
            s >= 10 -> "${s}s"
            else -> "${ms / 100 / 10}.${ms / 100 % 10}s"
        }
    }

    /** Thousands-grouped decimal (multiplatform-safe). */
    private fun grouped(n: Long): String =
        n.toString().reversed().chunked(3).joinToString(",").reversed()
}
