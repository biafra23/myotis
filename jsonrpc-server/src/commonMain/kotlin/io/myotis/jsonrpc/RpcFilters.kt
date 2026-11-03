package io.myotis.jsonrpc

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * A filter request refused or failed with a JSON-RPC [code] and a [message] the
 * router serves verbatim — `-32000 filter not found` is geth's wording, which
 * clients match on (viem re-creates a filter on any `-32000` from a poll).
 */
internal class FilterError(val code: Int, override val message: String) : RuntimeException(message)

/** One canonical block as a filter walks the chain: its number, hash and parent
 *  hash, `0x`-hex lowercase. */
internal class FilterBlock(val number: Long, val hash: String, val parentHash: String)

/** What a block read answered a filter's walk with. */
internal sealed interface FilterBlockRead {
    class Found(val block: FilterBlock) : FilterBlockRead
    /** Not readable right now (no peer, a head that moved, an engine hiccup). */
    class Unavailable(val reason: String) : FilterBlockRead
    /** Never readable: the engine's permanent (`-32602`) refusal of the block. */
    class Refused(val reason: String) : FilterBlockRead
}

/** What the log index answered a filter's query with. */
internal sealed interface FilterLogs {
    /** The verified logs. */
    class Ok(val logs: JsonArray) : FilterLogs
    /** Not answerable right now — coverage, a lag, no head; [reason] is the engine's. */
    class Unavailable(val reason: String) : FilterLogs
    /** Never answerable as asked: the engine's permanent (`-32602`) refusal. */
    class Refused(val reason: String) : FilterLogs
    /** The backend has no log index at all (the Java engine, the iOS backend). */
    data object NoIndex : FilterLogs
}

/**
 * The chain reads a filter is served from — the router's backend, kept behind a
 * seam so the filter table stays free of the backend's string conventions. Every
 * read is a VERIFIED one: the head `eth_blockNumber` reports, the canonical block
 * `eth_getBlockByNumber` serves, and `eth_getLogs` over the log index.
 */
internal interface FilterChain {
    /** The verified head's number, or null when there is none right now. */
    suspend fun head(): Long?

    /** The canonical block at [number]. */
    suspend fun block(number: Long): FilterBlockRead

    /** `eth_getLogs` with [criteria] (a filter object as `eth_getLogs` takes it). */
    suspend fun logs(criteria: JsonObject): FilterLogs
}

/**
 * The polled filter family (#714): `eth_newFilter`, `eth_newBlockFilter`,
 * `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter` — what
 * viem, ethers and web3.js fall back to without a WebSocket transport.
 *
 * Every filter keeps the last [REORG_WINDOW] blocks it delivered (number, hash,
 * and for a log filter the logs it delivered in them). A poll walks the verified
 * chain down from the head, by number, checking each block's hash against the
 * parent hash of the one above it, until a block's parent is a block the filter
 * delivered. Blocks it delivered ABOVE that parent were orphaned by a reorg:
 * their logs are delivered again with `removed: true`, ahead of the new branch's.
 * A walk that cannot meet the window — a reorg deeper than it, a head that moved
 * more than [MAX_BRIDGE_BLOCKS] since the last poll, a block the engine refuses
 * for good — drops the filter and says why, naming the last block it delivered:
 * the client re-creates it and backfills from there with `eth_getLogs`.
 *
 * Refuse, never silence (CLAUDE.md's apply-or-refuse rule): a log filter is
 * created only when `eth_getLogs` answers its criteria at both ends of its
 * range — an address the index does not watch, or a range it has not covered,
 * is refused at creation with `eth_getLogs`'s error. (Both ends rather than the
 * whole range: the index covers one contiguous span per contract, and
 * `eth_getFilterLogs` asks the index again anyway, which refuses honestly.) A
 * poll whose blocks cannot be read or whose logs the index cannot serve yet does
 * NOT advance the filter: it answers no changes and keeps them for a later poll
 * — delayed, never skipped — and when that lasts past [STALL_LIMIT] it answers
 * the retryable `-32000` with the reason and the last block delivered, every
 * poll, until the filter can advance again.
 *
 * A filter not polled for [TIMEOUT] expires (geth's deadline); at most
 * [MAX_FILTERS] are installed at once, and one poll delivers at most
 * [MAX_LOGS_PER_POLL] logs — a filter past that is dropped, rather than served
 * a part of its changes. [dropAll] forgets every filter (a paused node: the
 * client's next poll re-creates its filter, the same path as an expiry).
 */
@OptIn(ExperimentalAtomicApi::class)
internal class RpcFilters(
    private val time: TimeSource = TimeSource.Monotonic,
    private val random: Random = Random.Default,
) {
    internal companion object {
        /** The most filters installed at once. */
        const val MAX_FILTERS = 64

        /** A filter not polled for this long is forgotten — geth's `filterTimeout`. */
        val TIMEOUT: Duration = 5.minutes

        /** How many delivered blocks a filter keeps to recognise a reorg by. */
        const val REORG_WINDOW = 32

        /** The most blocks one poll walks to reach the blocks it delivered last. */
        const val MAX_BRIDGE_BLOCKS = 256

        /** The most logs one `eth_getFilterChanges` delivers. */
        const val MAX_LOGS_PER_POLL = 10_000

        /** How long a filter may fail to advance before its polls say so. */
        val STALL_LIMIT: Duration = 2.minutes

        const val NOT_FOUND = "filter not found"

        /** [id] as the table keys it: lowercase, no leading zeros — geth's ids
         *  carry none, and a client that round-trips one as a quantity drops
         *  them, so either spelling names the same filter. */
        fun canonicalId(id: String): String {
            val s = id.trim().lowercase()
            val digits = (if (s.startsWith("0x")) s.substring(2) else s).trimStart('0')
            return "0x" + digits.ifEmpty { "0" }
        }
    }

    /** A block a filter delivered, and the logs it delivered in it. */
    private class Delivered(val number: Long, val hash: String, val logs: List<JsonObject>)

    /** A log filter's criteria and block bounds: null = open (the head). */
    private class LogCriteria(val criteria: JsonObject, val from: Long?, val to: Long?)

    private inner class Filter(val id: String, val log: LogCriteria?, first: FilterBlock, val epoch: Int) {
        val mutex = Mutex()
        var lastPolled: TimeMark = time.markNow()
        val window = ArrayDeque<Delivered>().apply { addLast(Delivered(first.number, first.hash, emptyList())) }
        var stalledSince: TimeMark? = null
        /** Why the last poll could not advance; only read and written under [mutex]. */
        var stallReason = "the filter cannot advance right now"
    }

    private val tableMutex = Mutex()
    private val filters = HashMap<String, Filter>()

    /** Bumped by [dropAll]: a filter created under an older epoch is gone. An
     *  atomic counter rather than a lock, so a host can drop every filter from
     *  any thread without suspending, and two pauses racing each other (the
     *  engine's own and `myotis_pause`'s) both count. */
    private val epoch = AtomicInt(0)

    /** Forget every filter. Safe from any thread; the next lookup of one
     *  answers [NOT_FOUND]. */
    fun dropAll() {
        epoch.addAndFetch(1)
    }

    // ---- creation ----------------------------------------------------------

    /** `eth_newBlockFilter`: the id of a filter starting at the verified head. */
    suspend fun newBlockFilter(chain: FilterChain): String {
        val epochAtStart = epoch.load()
        val head = chain.head() ?: throw unavailable("there is no verified head yet")
        return install(null, startBlock(chain, head), epochAtStart)
    }

    /**
     * `eth_newFilter` over [criteria]: the id of a filter starting at the
     * verified head. Refused with `eth_getLogs`'s own error when the index
     * cannot serve its criteria now ([FilterError]).
     */
    suspend fun newLogFilter(criteria: JsonObject, chain: FilterChain): String {
        val epochAtStart = epoch.load()
        criteria["blockHash"]?.takeUnless { it is JsonNull }?.let {
            throw FilterError(-32602, "eth_newFilter takes no 'blockHash': a filter on one block has no changes " +
                "to poll; ask eth_getLogs for that block's logs")
        }
        val from = bound(criteria["fromBlock"], "fromBlock", lower = true)
        val to = bound(criteria["toBlock"], "toBlock", lower = false)
        if (from != null && to != null && from > to) {
            throw FilterError(-32602, "fromBlock $from is above toBlock $to: no block can match")
        }
        val log = LogCriteria(criteria, from, to)
        val head = chain.head() ?: throw unavailable("there is no verified head yet")
        if (from == null && to != null && to < head) {
            throw FilterError(-32602, "toBlock $to is below the head ($head), and an open fromBlock starts at " +
                "the head: no block can match; give a fromBlock, or ask eth_getLogs")
        }
        // Created only when the index serves this filter as eth_getLogs would.
        // A filter that would answer `[]` for logs the index does not hold is
        // refused here, with the index's own reason, never accepted. Each end of
        // the range that exists is asked on its own (see the class comment); a
        // range that starts past the head is checked at the head, for its
        // address and topics.
        val ends = ArrayList<String>()
        if (from != null && from <= head) ends += hex(from)
        ends += if (to != null && to <= head) hex(to) else "latest"
        for (end in ends.distinct()) {
            val probe = JsonObject(criteria + mapOf("fromBlock" to JsonPrimitive(end), "toBlock" to JsonPrimitive(end)))
            when (val answer = chain.logs(probe)) {
                is FilterLogs.Ok -> {}
                is FilterLogs.Unavailable -> throw FilterError(-32000, answer.reason)
                is FilterLogs.Refused -> throw FilterError(-32602, answer.reason)
                FilterLogs.NoIndex -> throw noIndex()
            }
        }
        return install(log, startBlock(chain, head), epochAtStart)
    }

    private fun hex(n: Long) = "0x" + n.toString(16)

    private fun unavailable(why: String) = FilterError(-32000, "cannot be served verified right now: $why")

    private fun noIndex() = FilterError(-32000, "cannot be served verified right now: this node's engine holds " +
        "no log index (the Rust engine on Android, desktop and the daemon does); block filters are served")

    /** [log]'s criteria over the blocks that exist: a `toBlock` past [head] is
     *  read as the head, as geth reads it — the blocks above it have no logs
     *  yet, and they are the filter's changes when they come. */
    private fun existingRange(log: LogCriteria, head: Long): JsonObject =
        if (log.to != null && log.to > head) {
            JsonObject(log.criteria + ("toBlock" to JsonPrimitive("latest")))
        } else {
            log.criteria
        }

    /** A filter's block bound, applied or refused: absent, `latest` and
     *  `pending` are open; `earliest` is block 0 (a lower bound only); a
     *  `0x` number is that block. `finalized` and `safe` name a block that
     *  moves on its own schedule, not the head's, and are refused. */
    private fun bound(el: JsonElement?, name: String, lower: Boolean): Long? {
        if (el == null || el is JsonNull) return null
        val s = (el as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.trim()
            ?: throw FilterError(-32602, "'$name' must be a block tag or a 0x-prefixed hex block number")
        when (s) {
            "latest", "pending" -> return null
            "earliest" -> if (lower) return 0L
        }
        if (!s.startsWith("0x") || s.length <= 2 || !s.drop(2).all { it.isHexDigitChar() }) {
            throw FilterError(-32602, "'$name' $s is not served for a polled filter: use latest, pending, " +
                (if (lower) "earliest, " else "") + "or a 0x-prefixed hex block number")
        }
        // Leading zeros are tolerated; past 63 bits no block exists to name.
        val digits = s.drop(2).trimStart('0')
        if (digits.isEmpty()) return 0L
        return digits.takeIf { it.length <= 16 }?.toLongOrNull(16)
            ?: throw FilterError(-32602, "'$name' $s is out of range")
    }

    private fun Char.isHexDigitChar() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private suspend fun startBlock(chain: FilterChain, head: Long): FilterBlock =
        when (val read = chain.block(head)) {
            is FilterBlockRead.Found -> read.block
            is FilterBlockRead.Unavailable -> throw unavailable(read.reason)
            is FilterBlockRead.Refused -> throw unavailable(read.reason)
        }

    /** Install a filter starting at [start]. [epochAtStart] is the epoch the
     *  creation began in: a [dropAll] since then (the node paused while the
     *  head was read) drops this filter with the rest. */
    private suspend fun install(log: LogCriteria?, start: FilterBlock, epochAtStart: Int): String =
        tableMutex.withLock {
            sweep()
            if (filters.size >= MAX_FILTERS) {
                throw FilterError(-32000, "too many filters installed ($MAX_FILTERS): uninstall one with " +
                    "eth_uninstallFilter, or let an unused one expire (${TIMEOUT.inWholeMinutes} minutes unpolled)")
            }
            var id: String
            do {
                id = canonicalId(random.nextLong().toULong().toString(16))
            } while (id in filters)
            filters[id] = Filter(id, log, start, epochAtStart)
            id
        }

    // ---- lookup ------------------------------------------------------------

    private suspend fun lookup(id: String): Filter = tableMutex.withLock {
        sweep()
        val f = filters[canonicalId(id)] ?: throw FilterError(-32000, NOT_FOUND)
        f.lastPolled = time.markNow()
        f
    }

    /** Whether [f] is still installed — a poll queued behind one that dropped
     *  it, or across a [dropAll], answers [NOT_FOUND] instead of advancing it. */
    private suspend fun installed(f: Filter): Boolean = tableMutex.withLock {
        sweep()
        filters[f.id] === f
    }

    /** Forget expired filters and those [dropAll] dropped. Under [tableMutex]. */
    private fun sweep() {
        val now = epoch.load()
        filters.values.removeAll { it.epoch != now || it.lastPolled.elapsedNow() > TIMEOUT }
    }

    /** `eth_uninstallFilter`: whether a filter was installed under [id]. */
    suspend fun uninstall(id: String): Boolean = tableMutex.withLock {
        sweep()
        filters.remove(canonicalId(id)) != null
    }

    /** How many filters are installed (tests). */
    internal suspend fun size(): Int = tableMutex.withLock { sweep(); filters.size }

    // ---- polling -----------------------------------------------------------

    /**
     * `eth_getFilterLogs`: `eth_getLogs` over the log filter's own criteria. A
     * block filter has no logs — [NOT_FOUND], as geth answers.
     */
    suspend fun filterLogs(id: String, chain: FilterChain): JsonArray {
        val log = lookup(id).log ?: throw FilterError(-32000, NOT_FOUND)
        val head = chain.head()
        // A range that starts past the head holds no block yet: no logs, truly.
        if (head != null && log.from != null && log.from > head) return JsonArray(emptyList())
        val criteria = if (head == null) log.criteria else existingRange(log, head)
        return when (val a = chain.logs(criteria)) {
            is FilterLogs.Ok -> a.logs
            is FilterLogs.Unavailable -> throw FilterError(-32000, a.reason)
            is FilterLogs.Refused -> throw FilterError(-32602, a.reason)
            FilterLogs.NoIndex -> throw noIndex()
        }
    }

    /** `eth_getFilterChanges`: the block hashes (a block filter) or logs (a log
     *  filter) since the last poll — see the class comment. */
    suspend fun changes(id: String, chain: FilterChain): JsonArray {
        val f = lookup(id)
        return f.mutex.withLock {
            if (!installed(f)) throw FilterError(-32000, NOT_FOUND)
            advance(f, chain)
        }
    }

    private suspend fun advance(f: Filter, chain: FilterChain): JsonArray {
        val head = chain.head() ?: return stall(f, "there is no verified head right now")
        val last = f.window.last()
        // Nothing past what was delivered. A head that went BACK (this node's
        // view regressed, as a lagging head can) is no reorg by itself: the
        // blocks above it are not known to be orphaned, so nothing is removed —
        // a real reorg shows when the head passes them again.
        if (head <= last.number) {
            f.stalledSince = null
            return JsonArray(emptyList())
        }
        // A jump no walk may bridge is known before any block is read.
        if (head - last.number > MAX_BRIDGE_BLOCKS) {
            drop(f, "the head moved more than $MAX_BRIDGE_BLOCKS blocks past the filter's last poll")
        }
        // Walk down from the head until a block whose parent the filter delivered.
        val walked = ArrayList<FilterBlock>()
        var n = head
        var expect: String? = null
        val fork: Long
        while (true) {
            val blk = when (val read = chain.block(n)) {
                is FilterBlockRead.Found -> read.block
                is FilterBlockRead.Unavailable -> return stall(f, "block $n cannot be read right now: ${read.reason}")
                is FilterBlockRead.Refused -> drop(f, "block $n cannot be read: ${read.reason}")
            }
            if (expect != null && blk.hash != expect) {
                return stall(f, "the chain moved while the filter walked it")
            }
            walked += blk
            if (walked.size > MAX_BRIDGE_BLOCKS) {
                // The head moved at most MAX_BRIDGE_BLOCKS (checked above), so
                // the walk ran past it only by descending below the last
                // delivered block, through a reorg.
                drop(f, "the walk needed more than $MAX_BRIDGE_BLOCKS blocks to reach the blocks the filter " +
                    "delivered (a reorg on top of a long gap)")
            }
            val parent = n - 1
            if (parent <= last.number) {
                val delivered = f.window.firstOrNull { it.number == parent }
                    ?: drop(f, "the chain reorganized deeper than the $REORG_WINDOW blocks a filter keeps")
                if (delivered.hash == blk.parentHash) {
                    fork = parent
                    break
                }
            }
            expect = blk.parentHash
            n = parent
        }
        walked.reverse()   // ascending: fork + 1 .. head
        val orphaned = f.window.filter { it.number > fork }
        val log = f.log
        val newLogs: Map<Long, List<JsonObject>> =
            if (log == null) emptyMap() else newLogs(f, log, walked, chain) ?: return stall(f, f.stallReason)
        // The cap counts everything this poll delivers: the orphaned logs
        // re-delivered as removed, and the new branch's.
        val delivered = orphaned.sumOf { it.logs.size } + newLogs.values.sumOf { it.size }
        if (delivered > MAX_LOGS_PER_POLL) {
            drop(f, "more than $MAX_LOGS_PER_POLL logs since the last poll, removed ones included")
        }
        // Commit: drop the orphaned blocks, record the new ones, keep the window.
        while (f.window.isNotEmpty() && f.window.last().number > fork) f.window.removeLast()
        for (blk in walked) f.window.addLast(Delivered(blk.number, blk.hash, newLogs[blk.number].orEmpty()))
        while (f.window.size > REORG_WINDOW) f.window.removeFirst()
        f.stalledSince = null
        if (log == null) return JsonArray(walked.map { JsonPrimitive(it.hash) })
        val out = ArrayList<JsonElement>()
        // Orphaned logs first, oldest block first (geth's order), as removed.
        for (d in orphaned) for (l in d.logs) out += JsonObject(l + ("removed" to JsonPrimitive(true)))
        for (blk in walked) out.addAll(newLogs[blk.number].orEmpty())
        return JsonArray(out)
    }

    /** The logs the new blocks [walked] carry under [log]'s criteria, by block —
     *  each checked to sit in a block the walk saw, under that block's hash — or
     *  null (with [Filter.stallReason] set) when they cannot be served right now. */
    private suspend fun newLogs(
        f: Filter,
        log: LogCriteria,
        walked: List<FilterBlock>,
        chain: FilterChain,
    ): Map<Long, List<JsonObject>>? {
        val lo = maxOf(walked.first().number, log.from ?: 0L)
        val hi = minOf(walked.last().number, log.to ?: Long.MAX_VALUE)
        if (lo > hi) return emptyMap()
        val query = JsonObject(log.criteria + mapOf("fromBlock" to JsonPrimitive(hex(lo)), "toBlock" to JsonPrimitive(hex(hi))))
        val logs = when (val a = chain.logs(query)) {
            is FilterLogs.Ok -> a.logs
            is FilterLogs.Unavailable -> { f.stallReason = a.reason; return null }
            is FilterLogs.Refused -> drop(f, a.reason)
            FilterLogs.NoIndex -> { f.stallReason = "this node's engine holds no log index"; return null }
        }
        if (logs.size > MAX_LOGS_PER_POLL) {
            drop(f, "more than $MAX_LOGS_PER_POLL logs since the last poll")
        }
        val hashes = walked.associate { it.number to it.hash }
        val byBlock = LinkedHashMap<Long, MutableList<JsonObject>>()
        for (el in logs) {
            val o = el as? JsonObject
            val number = (o?.get("blockNumber") as? JsonPrimitive)?.contentOrNull
                ?.takeIf { it.startsWith("0x") }?.drop(2)?.toLongOrNull(16)
            val hash = (o?.get("blockHash") as? JsonPrimitive)?.contentOrNull?.lowercase()
            if (o == null || number == null || number !in lo..hi) {
                f.stallReason = "the log index answered a log outside the blocks asked for"
                return null
            }
            if (hash != hashes[number]) {
                // The index holds another branch at that height than the chain
                // just walked: not yet consistent, so nothing is delivered.
                f.stallReason = "the log index has not caught up with block $number on the current chain"
                return null
            }
            byBlock.getOrPut(number) { ArrayList() } += o
        }
        return byBlock
    }

    /** No changes yet — the filter keeps them for a later poll — until the
     *  stall has lasted [STALL_LIMIT]; past it, the retryable error. */
    private fun stall(f: Filter, reason: String): JsonArray {
        val since = f.stalledSince ?: time.markNow().also { f.stalledSince = it }
        if (since.elapsedNow() > STALL_LIMIT) {
            throw FilterError(-32000, "filter ${f.id} has not advanced for over ${STALL_LIMIT.inWholeMinutes} " +
                "minutes: $reason; its changes after block ${f.window.last().number} are kept for when it can, " +
                "and a client that re-creates it instead must backfill them with eth_getLogs")
        }
        return JsonArray(emptyList())
    }

    /** Forget [f] and say why: its changes can no longer be told from verified
     *  data. */
    private suspend fun drop(f: Filter, reason: String): Nothing {
        tableMutex.withLock {
            if (filters[f.id] === f) filters.remove(f.id)
        }
        throw FilterError(-32000, "filter ${f.id} was dropped: $reason; re-create it and backfill with eth_getLogs " +
            "from block ${f.window.last().number + 1}")
    }
}
