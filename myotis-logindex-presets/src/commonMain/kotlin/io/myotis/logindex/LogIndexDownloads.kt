package io.myotis.logindex

import io.myotis.logindex.LogIndexPresets.Contract
import io.myotis.logindex.LogIndexPresets.Preset
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/**
 * What downloading and verifying a set of [LogIndexPresets] costs, and the
 * engine config push that starts it.
 *
 * ## How the walk spends bytes
 *
 * The engine's backfill walk descends ONCE from the head to the lowest
 * `fromBlock` it watches (docs/design-history/eth-getlogs-design.md §3). For
 * every block it downloads the header (~0.6 KB); where the header's bloom
 * matches any watched contract it downloads that block's receipts and checks
 * them against `receiptsRoot`; it downloads a body only for a block that really
 * holds a watched log. On mainnet the blooms are nearly full, so a large share
 * of all blocks are candidates and their receipts are most of the cost.
 *
 * ## Why together is cheaper
 *
 * One walk serves every contract it watches: a header is fetched once for all of
 * them, and a block whose bloom matches two contracts has its receipts fetched
 * once. A contract added LATER to an index that already walked joins through a
 * re-walk: the engine merges it in and descends from the head again, fetching
 * every header a second time and the receipts of the new contract's candidates
 * (eth-getlogs-design.md, `set_log_index_config`: a new address re-indexes
 * through the walker's re-descent). [Estimate.separateDownloadBytes] is that
 * one-at-a-time cost; [Estimate.cheaperTogether] says when the difference is
 * worth telling the user.
 *
 * ## What is stored
 *
 * Only the verified logs of the watched contracts, in the index file
 * (`logindex[-<network>].db`). It is checkpointed by writing a new file and
 * renaming it over the old one, so the disk briefly holds two copies
 * ([Estimate.peakDiskBytes]).
 *
 * Every figure is an ESTIMATE from the presets' census (see
 * [LogIndexPresets.Census]): hosts must present it as one.
 */
object LogIndexDownloads {

    /**
     * Blocks the census found per block holding a watched log: a log-heavy
     * transaction (a RAILGUN transact, a postage top-up) emits several, so the
     * walk fetches fewer bodies than there are logs. Conservative.
     */
    private const val LOGS_PER_HIT_BLOCK = 2

    /** Below this share of the combined cost, adding presets one by one is not worth a warning. */
    private const val TOGETHER_HINT_SHARE = 0.10

    /**
     * The cost of walking [presets] (all on one network) from [headBlock]. A
     * null [headBlock] (the host does not know the head yet) estimates as of
     * the newest census among them.
     */
    data class Estimate(
        /** Ids of the presets this estimate covers, in the order given. */
        val presetIds: List<String>,
        /** The head the estimate assumes. */
        val headBlock: Long,
        /** Blocks the walk descends through: head down to the lowest fromBlock. */
        val blocksToWalk: Long,
        /** Bytes received for the walk when all of [presetIds] are added together. */
        val downloadBytes: Long,
        /** Bytes received when each preset is added on its own, one after the other. */
        val separateDownloadBytes: Long,
        /** Size of the stored logs once the walk is complete. */
        val storageBytes: Long,
        /** Logs the presets' contracts hold up to [headBlock] (extrapolated from the census). */
        val logs: Long,
    ) {
        /** What adding them together saves over one at a time. */
        val savedBytes: Long get() = (separateDownloadBytes - downloadBytes).coerceAtLeast(0)

        /** Whether adding the presets together saves enough to say so (≥ 10 % of the combined cost). */
        val cheaperTogether: Boolean
            get() = presetIds.size > 1 && savedBytes >= (downloadBytes * TOGETHER_HINT_SHARE).toLong()

        /** Free disk the checkpoints need at their peak: the index file plus its replacement. */
        val peakDiskBytes: Long get() = 2 * storageBytes
    }

    /**
     * The estimate for [presets] on one network (see [Estimate]). Duplicates
     * are ignored. Refuses presets from different networks — one walk is one
     * chain's. An empty list estimates to zero.
     */
    @JvmStatic
    @JvmOverloads
    fun estimate(presets: List<Preset>, headBlock: Long? = null): Estimate {
        val set = presets.distinctBy { it.id }
        if (set.isEmpty()) return Estimate(emptyList(), headBlock ?: 0, 0, 0, 0, 0, 0)
        val network = set.first().network
        require(set.all { it.network == network }) { "presets from different networks: ${set.map { it.id }}" }
        val cost = LogIndexPresets.chainCost(network)
            ?: throw IllegalArgumentException("no chain costs for $network")
        val head = headBlock ?: set.maxOf { it.census.atBlock }
        val together = walkBytes(set, head, cost)
        val separate = set.sumOf { walkBytes(listOf(it), head, cost) }
        val logs = set.sumOf { logsAt(it, head) }
        val storage = set.sumOf { logsAt(it, head) * it.census.bytesPerLog }
        val blocks = (head - set.minOf { it.fromBlock } + 1).coerceAtLeast(0)
        return Estimate(set.map { it.id }, head, blocks, together, separate.coerceAtLeast(together), storage, logs)
    }

    /**
     * The presets' logs at [head]: the census count, plus the census's average
     * rate since creation over the blocks the chain grew since.
     */
    private fun logsAt(p: Preset, head: Long): Long {
        val c = p.census
        if (head < p.fromBlock) return 0
        val span = (c.atBlock - p.fromBlock).coerceAtLeast(1)
        val grown = (head - c.atBlock).coerceAtLeast(0)
        val shrunk = (c.atBlock - head).coerceAtLeast(0) // an estimate for an older head
        return (c.logs + c.logs * grown / span - c.logs * shrunk / span).coerceAtLeast(0)
    }

    /**
     * One walk over [set]: every header from the head to the lowest fromBlock,
     * the receipts of every bloom candidate, the bodies of the blocks holding a
     * watched log. Candidate shares combine per stretch of blocks — between two
     * presets' fromBlocks only the presets that already exist there count — as
     * independent bloom matches: 1 − Π(1 − share).
     */
    private fun walkBytes(set: List<Preset>, head: Long, cost: LogIndexPresets.ChainCost): Long {
        val low = set.minOf { it.fromBlock }
        if (head < low) return 0
        val headers = (head - low + 1) * cost.headerBytes
        // Stretches between consecutive fromBlocks, top down.
        val edges = (set.map { it.fromBlock } + (head + 1)).distinct().sorted()
        var receipts = 0.0
        for (i in 0 until edges.size - 1) {
            val from = edges[i]
            val to = edges[i + 1] // exclusive
            if (from > head) break
            val active = set.filter { it.fromBlock <= from }
            val miss = active.fold(1.0) { acc, p -> acc * (1.0 - p.census.candidateShare) }
            // A candidate's receipts: the active presets' sampled sizes, weighted by
            // how often each one makes a block a candidate.
            val weight = active.sumOf { it.census.candidateShare }
            val perCandidate = if (weight > 0) {
                active.sumOf { it.census.candidateShare * it.census.receiptBytesPerCandidate } / weight
            } else 0.0
            receipts += (to - from).toDouble() * (1.0 - miss) * perCandidate
        }
        val bodies = set.sumOf { logsAt(it, head) / LOGS_PER_HIT_BLOCK } * cost.bodyBytes
        return headers + receipts.toLong() + bodies
    }

    /**
     * The watch entries [presets] add: every contract once (an address in two
     * presets keeps its LOWEST fromBlock — the safe direction), minus the
     * addresses in [alreadyWatched] (compared case-insensitively), whose
     * existing entry is left as it is.
     */
    @JvmStatic
    @JvmOverloads
    fun watchEntries(presets: List<Preset>, alreadyWatched: Set<String> = emptySet()): List<Contract> =
        dedup(presets.flatMap { it.contracts }, alreadyWatched)

    private fun dedup(contracts: List<Contract>, alreadyWatched: Set<String>): List<Contract> {
        val skip = alreadyWatched.mapTo(HashSet()) { it.lowercase() }
        val byKey = LinkedHashMap<String, Contract>()
        for (c in contracts) {
            val key = c.address.lowercase()
            if (key in skip) continue
            val prev = byKey[key]
            if (prev == null || c.fromBlock < prev.fromBlock) byKey[key] = c
        }
        return byKey.values.toList()
    }

    /**
     * The engine config push (`ChainHandle.setLogIndexConfig`) that indexes
     * [presets]: the download trigger for an app embedding the engine library.
     * The engine's push is ADDITIVE — it unions with what the index already
     * subscribes — so this adds the presets' contracts to an existing index and
     * removes nothing; [extraWatch] carries the app's own entries along, in the
     * same `(address, fromBlock)` shape.
     *
     * [allowMetered] false (the default) is "unmetered only": while the host
     * reports a metered network (`MyotisEngine.setNetworkMetering`) the engine
     * holds the backfill walk — head-follow keeps running — and its status
     * says so (`meteredHold`). A host that never reports metering is never
     * held. Needs engine ABI ≥ 56; an older engine ignores the key.
     */
    @JvmStatic
    @JvmOverloads
    fun configJson(
        presets: List<Preset>,
        maxSpeed: Boolean = false,
        allowMetered: Boolean = false,
        backfillPaused: Boolean = false,
        extraWatch: List<Contract> = emptyList(),
    ): String {
        val entries = dedup(extraWatch + presets.flatMap { it.contracts }, emptySet())
        val watch = entries.joinToString(",") { """{"address":"${it.address}","fromBlock":${it.fromBlock}}""" }
        return """{"enabled":true,"maxSpeed":$maxSpeed,"backfillPaused":$backfillPaused,""" +
            """"allowMetered":$allowMetered,"watch":[$watch]}"""
    }

    /**
     * The "add them together" advice for a user about to add [selected] on a
     * network that offers [available]: null when there is nothing to say,
     * otherwise the estimate for ALL of [available] next to what adding them
     * one at a time would cost. Shown when a user adds fewer than all — the
     * moment a later addition would pay for a re-walk.
     */
    @JvmStatic
    @JvmOverloads
    fun togetherAdvice(selected: List<Preset>, available: List<Preset>, headBlock: Long? = null): Estimate? {
        val rest = available.filter { a -> selected.none { it.id == a.id } }
        if (selected.isEmpty() || rest.isEmpty()) return null
        val all = estimate(available, headBlock)
        return all.takeIf { it.cheaperTogether }
    }

    /**
     * Bytes in human units, decimal (as the OS and the data-usage screen count):
     * "870 KB", "12.4 MB", "1.2 TB". Pure Kotlin for Kotlin/Native.
     */
    @JvmStatic
    fun formatBytes(b: Long): String {
        val units = listOf("B" to 1L, "KB" to 1_000L, "MB" to 1_000_000L, "GB" to 1_000_000_000L, "TB" to 1_000_000_000_000L)
        var i = units.indexOfLast { b >= it.second || it.second == 1L }
        // A value that rounds up to 1000 of a unit is shown in the next one ("1.0 GB", not "1000 MB").
        if (i in 1 until units.lastIndex && (b * 10 + units[i].second / 2) / units[i].second >= 10_000) i++
        val (name, unit) = units[i]
        if (unit == 1L) return "$b B"
        val tenths = (b * 10 + unit / 2) / unit
        return if (tenths >= 1000) "${tenths / 10} $name" else "${tenths / 10}.${tenths % 10} $name"
    }
}
