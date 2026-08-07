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

    data class Parsed(
        val enabled: Boolean,
        val logCount: Long,
        val entries: List<Entry>,
        /** Lowest watched fromBlock — the backfill's walk target. */
        val targetLow: Long? = null,
        /** Blocks between the walk cursor and the target (null before the walker seeds). */
        val blocksRemaining: Long? = null,
        /** Rolling backfill throughput; null until the walker has measured progress. */
        val blocksPerSec: Double? = null,
        /** remaining/rate, engine-computed; null whenever the rate is unknown. */
        val etaSeconds: Long? = null,
        /** Blocks between the top of coverage and the finalized head. While
         *  this is non-zero, `toBlock: "latest"` queries are outside coverage
         *  and refused — the engine's head bridge is closing it. */
        val headGap: Long? = null,
    )

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
        val targetLow = Regex("\"targetLow\":(\\d+)").find(json)?.groupValues?.get(1)?.toLongOrNull()
        val remaining = Regex("\"blocksRemaining\":(\\d+)").find(json)?.groupValues?.get(1)?.toLongOrNull()
        val bps = Regex("\"blocksPerSec\":([0-9.]+)").find(json)?.groupValues?.get(1)?.toDoubleOrNull()
        val eta = Regex("\"etaSeconds\":(\\d+)").find(json)?.groupValues?.get(1)?.toLongOrNull()
        val headGap = Regex("\"headGap\":(\\d+)").find(json)?.groupValues?.get(1)?.toLongOrNull()
        return Parsed(enabled, logCount, entries, targetLow, remaining, bps, eta, headGap)
    }

    /** Human progress line for the Index tab: an ETA when the engine has a
     *  measured rate, otherwise x/y blocks (or a waiting note). Pure Kotlin —
     *  commonMain compiles for Kotlin/Native too, so no String.format. */
    /** The head-side line: while coverage trails the finalized head, queries
     *  reaching `latest` are refused, so say so rather than claim completion.
     *  A small gap is the normal one-epoch lag of finality and reads as
     *  caught-up. Null when there is nothing to report. */
    private fun headLine(p: Parsed): String? {
        val gap = p.headGap ?: return null
        return if (gap <= NORMAL_HEAD_LAG) null
        else "catching up to the head (${grouped(gap)} blocks behind)"
    }

    /** One finalized epoch of slots plus slack: below this the index is
     *  following the head normally, not lagging. */
    private const val NORMAL_HEAD_LAG = 128L

    fun progressLine(p: Parsed): String? {
        val remaining = p.blocksRemaining ?: return null
        if (remaining == 0L) return headLine(p) ?: "backfill complete"
        val eta = p.etaSeconds
        if (eta != null && p.blocksPerSec != null) {
            return "~${formatDuration(eta)} remaining " +
                "(${grouped(remaining)} blocks, ${formatRate(p.blocksPerSec)} blk/s)"
        }
        // No rate yet — x/y anchored on the TARGET-DEFINING entry's covered
        // high edge (the entry whose fromBlock is the walk target), so the
        // fraction reflects one coherent span rather than a blend of entries
        // at different depths. The high edge still creeps upward as the
        // appender follows the head (a slow drift of the total, ~32 blocks
        // per epoch, dwarfed by backfill strides) — acceptable for a display
        // that is replaced by the ETA as soon as a rate exists.
        val target = p.targetLow
        val high = p.entries.firstOrNull { it.fromBlock == target }?.coveredHigh
        if (high != null && target != null && high > target) {
            val total = high - target
            val done = (total - remaining).coerceAtLeast(0)
            return "${grouped(done)} / ${grouped(total)} blocks"
        }
        return "${grouped(remaining)} blocks remaining"
    }

    /** One decimal below 10 (a slow walk must not read as "0 blk/s"),
     *  rounded integer above (multiplatform-safe — no String.format). */
    private fun formatRate(bps: Double): String {
        val tenths = kotlin.math.round(bps * 10).toLong()
        return if (tenths < 100) "${tenths / 10}.${tenths % 10}" else (tenths / 10).toString()
    }

    /** Thousands-grouped decimal (multiplatform-safe). */
    private fun grouped(n: Long): String =
        n.toString().reversed().chunked(3).joinToString(",").reversed()

    private fun formatDuration(secs: Long): String {
        val d = secs / 86_400
        val h = (secs % 86_400) / 3600
        val m = (secs % 3600) / 60
        return when {
            d > 0 -> "${d}d ${h}h"
            h > 0 -> "${h}h ${m}m"
            m > 0 -> "${m}m"
            else -> "<1m"
        }
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
