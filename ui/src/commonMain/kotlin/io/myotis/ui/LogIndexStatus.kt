package io.myotis.ui

/**
 * Shared formatter for the engine's log-index status JSON, so every host
 * renders the identical line and a serializer change degrades one pinned
 * place instead of silently breaking per-host regex copies.
 */
object LogIndexStatus {

    /** One watch entry's parsed status. Coverage is null while nothing is indexed. */
    data class Entry(
        val address: String,
        val fromBlock: Long,
        val coveredLow: Long?,
        val coveredHigh: Long?,
    )

    data class Parsed(val enabled: Boolean, val logCount: Long, val entries: List<Entry>)

    /** Structured parse of the engine's status JSON (regex over the fixed
     *  serializer shape — the same shape [format] reads). */
    fun parse(json: String): Parsed {
        val enabled = json.contains("\"enabled\":true")
        val logCount = Regex("\"logCount\":(\\d+)").find(json)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
        val entries = Regex(
            "\\{\"address\":\"(0x[0-9a-fA-F]{40})\",\"fromBlock\":(\\d+)" +
                "(?:,\"coveredLow\":(\\d+),\"coveredHigh\":(\\d+))?\\}"
        ).findAll(json).map { m ->
            Entry(
                address = m.groupValues[1].lowercase(),
                fromBlock = m.groupValues[2].toLongOrNull() ?: 0L,
                coveredLow = m.groupValues[3].takeIf { it.isNotEmpty() }?.toLongOrNull(),
                coveredHigh = m.groupValues[4].takeIf { it.isNotEmpty() }?.toLongOrNull(),
            )
        }.toList()
        return Parsed(enabled, logCount, entries)
    }

    /** Short status line, or a waiting note when the engine has no index yet. */
    fun format(json: String): String {
        if (!json.contains("\"enabled\":true")) return "enabled \u2014 waiting for engine"
        val count = Regex("\"logCount\":(\\d+)").find(json)?.groupValues?.get(1) ?: "0"
        val entries = Regex("\"address\":").findAll(json).count()
        val lows = Regex("\"coveredLow\":(\\d+)").findAll(json).map { it.groupValues[1].toLong() }.toList()
        val highs = Regex("\"coveredHigh\":(\\d+)").findAll(json).map { it.groupValues[1].toLong() }.toList()
        if (lows.isEmpty()) return "$count logs \u2014 backfill starting"
        // The NARROWEST common span: the range every covered entry can serve.
        // Anything wider would claim blocks some entry cannot answer for; if
        // entries are still at different depths (or some have no span yet),
        // say "backfilling" instead of overstating.
        val commonLow = lows.max()
        val commonHigh = highs.min()
        return when {
            lows.size < entries -> "$count logs \u2014 backfilling (some contracts not covered yet)"
            commonLow <= commonHigh -> "$count logs \u2014 blocks $commonLow\u2013$commonHigh"
            else -> "$count logs \u2014 backfilling (entries at different depths)"
        }
    }
}
