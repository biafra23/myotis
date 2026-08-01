package io.myotis.ui

/**
 * Shared formatter for the engine's log-index status JSON, so every host
 * renders the identical line and a serializer change degrades one pinned
 * place instead of silently breaking per-host regex copies.
 */
object LogIndexStatus {

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
