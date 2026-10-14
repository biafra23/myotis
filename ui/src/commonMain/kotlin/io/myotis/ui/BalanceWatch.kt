package io.myotis.ui

import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmStatic
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.TimeSource
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/*
 * Balance watch: the user lists addresses per network, the host checks their verified
 * balances now and then (Android: while the app is in the foreground, and around the
 * node's sleep and wake while the phone charges on an unmetered network; desktop:
 * while the app runs), and a change becomes a notification and an entry on the Watch
 * tab — with the transaction behind it when a short scan of the blocks in between
 * finds one.
 *
 * This file is the host-neutral part: the stored list and state, the comparison, the
 * search for the cause, and the notification text. Hosts supply the reads
 * ([WatchReader], over their engine), the trigger schedule, and the notification
 * route. No JVM API, so iOS compiles it too.
 *
 * TRUST: only a VERIFIED read ever moves the stored balance — the same bar as the
 * Query tab's green badge (the proof verifies against a beacon-attested state root).
 * An unverified read is recorded as the address's current error and changes nothing,
 * so a lying peer can neither invent a change nor hide one from the next verified
 * read. A read anchored at an OLDER block than the stored one is ignored too: the
 * engine's finalized fallback can serve state a few epochs behind the head, and
 * comparing against it would announce a change and then its reversal.
 *
 * Assets: the store is keyed by (address, asset) and every change names its asset.
 * Today the only asset is the chain's native currency ([NATIVE_ASSET]); ERC-20 tokens
 * plug in later as further assets read through `eth_call` (the Query tab's token list
 * is #639's), without a store migration.
 */

/** The chain's native currency (ETH, xDAI) — the only [WatchChange.asset] for now. */
const val NATIVE_ASSET: String = "native"

/** One address on a network's watch list. [label] may be empty; [address] is lowercase. */
data class WatchEntry(val address: String, val label: String)

/** The last VERIFIED observation of one watched balance. */
data class WatchSeen(
    /** Decimal wei; "0" for an account that does not exist yet. */
    val balanceWei: String,
    /** The account nonce — transactions it has sent; 0 for an account that does not exist yet. */
    val nonce: Long,
    /** The block the proof anchored to. */
    val blockNumber: Long,
    /** That block's proven timestamp, unix seconds; -1 when the engine did not date it. */
    val blockTimestamp: Long,
    /** Wall-clock ms of the read. */
    val checkedAtMs: Long,
)

/** One watched address's stored state: its last verified observation, and why the newest
 *  attempt found no verified answer, when it did not ([error] null = the newest read verified). */
data class WatchAddressState(
    val seen: WatchSeen? = null,
    val error: String? = null,
    val errorAtMs: Long = 0,
)

/** What a [WatchCause] did to the watched address. */
enum class WatchCauseKind {
    /** A transaction the address sent (its value excludes the fee it paid). */
    SENT,
    /** A transaction to the address. */
    RECEIVED,
    /** A transaction from the address to itself: only the fee moves the balance. */
    SELF,
    /** The address was the block's fee recipient (priority fees, no transaction). */
    FEE_RECIPIENT,
}

/** Something in a block that moved the watched balance. */
data class WatchCause(
    val kind: WatchCauseKind,
    val blockNumber: Long,
    /** The transaction's hash; null for a fee-recipient credit. */
    val txHash: String? = null,
    /** The other side: the recipient of a sent transaction (null for a contract
     *  creation), the sender of a received one. */
    val counterparty: String? = null,
    /** The amount in decimal wei: a transaction's value; null when the block alone does
     *  not tell it (a fee-recipient credit). */
    val valueWei: String? = null,
)

/** How far the search for a change's cause got. */
enum class WatchSearch {
    /** Every block between the two observations was scanned. */
    COMPLETE,
    /** Only the newest blocks were scanned: the gap was wider than the scan window. */
    PARTIAL,
    /** A block could not be read verified; the scan stopped there (what it found is kept). */
    UNAVAILABLE,
    /** Not searched (no scan window on this check). */
    NONE,
}

/** A verified balance change of a watched address. */
data class WatchChange(
    val address: String,
    val label: String,
    val oldWei: String,
    val newWei: String,
    val oldNonce: Long,
    val newNonce: Long,
    /** The block the old balance was proven at. */
    val fromBlock: Long,
    /** The block the new balance was proven at. */
    val toBlock: Long,
    /** [toBlock]'s proven timestamp, unix seconds; -1 when unknown. */
    val blockTimestamp: Long,
    val detectedAtMs: Long,
    val search: WatchSearch,
    /** The lowest block the search scanned; -1 when it scanned none. It scans down
     *  from [toBlock], so the scanned range is [scannedFrom]..[toBlock]. */
    val scannedFrom: Long,
    /** What the scan attributed the change to, newest first; empty when it found nothing. */
    val causes: List<WatchCause>,
    val asset: String = NATIVE_ASSET,
)

/** One network's stored watch state ([Settings.watchStateJson]). */
data class WatchState(
    /** Keyed by [BalanceWatch.key]. */
    val addresses: Map<String, WatchAddressState> = emptyMap(),
    /** Newest first, at most [BalanceWatch.MAX_CHANGES]. */
    val changes: List<WatchChange> = emptyList(),
    /** Wall-clock ms of the last check that verified at least one read; 0 = never. */
    val lastCheckMs: Long = 0,
    /** Wall-clock ms of the last check attempt, verified or not; 0 = never. */
    val lastAttemptMs: Long = 0,
)

/**
 * The reads a check needs, supplied by the host over its engine. Both may block for
 * the engine's own bounds (a proof is ~90 s worst case); hosts run them off the main
 * thread.
 */
interface WatchReader {
    /** The address's account at the verified head ([NodeController.requestAccount]'s
     *  read). Throws when the network cannot be read at all; an unverified answer is a
     *  result, not an exception. */
    suspend fun account(address: String): AccountResult

    /** Block [number] WITH FULL TRANSACTIONS as `eth_getBlockByNumber` JSON, verified
     *  against the beacon anchor; null (or the literal "null", or an error envelope)
     *  when there is no verified answer. */
    suspend fun block(number: Long): String?
}

/** The pure part of the balance watch: store formats, the comparison, the cause search,
 *  the texts. [BalanceWatcher] runs it against a host's [Settings] store. */
object BalanceWatch {

    /** Watched addresses per network at most: every check reads each one's proof. */
    const val MAX_ADDRESSES: Int = 20

    /** Labels are cut to this many characters. */
    const val MAX_LABEL: Int = 32

    /** Stored changes per network; older ones fall off the Watch tab's list. */
    const val MAX_CHANGES: Int = 50

    /** Blocks a change's cause search scans by default, newest first. Hosts pass less
     *  on a metered network: a mainnet block with its transactions is ~100–200 KB. */
    const val DEFAULT_SCAN_BLOCKS: Int = 64

    private val json = Json { ignoreUnknownKeys = true }

    /** The store key of [address]'s balance of [asset]. */
    @JvmStatic
    fun key(address: String, asset: String = NATIVE_ASSET): String =
        if (asset == NATIVE_ASSET) address.lowercase() else "${address.lowercase()}/${asset.lowercase()}"

    // ---- the watch list ([Settings.watchListJson]) ----

    /** [input] as a watchable address — `0x` and 40 hex digits, lowercased — or null.
     *  (Mixed-case input is not checksum-checked yet: commonMain has no Keccak-256 until
     *  #639's token work lands one; the address is stored lowercase either way.) */
    @JvmStatic
    fun normalizeAddress(input: String): String? {
        val s = input.trim()
        if (s.length != 42 || !(s.startsWith("0x") || s.startsWith("0X"))) return null
        val hex = s.substring(2)
        if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        return "0x" + hex.lowercase()
    }

    /** [input] as a stored label: control characters dropped, trimmed, at most [MAX_LABEL] chars. */
    @JvmStatic
    fun cleanLabel(input: String): String =
        input.filter { !it.isISOControl() }.trim().take(MAX_LABEL).trim()

    /** Parse [Settings.watchListJson]'s array. Tolerant like the other stores: a malformed
     *  value yields the entries that parse (worst case none); invalid addresses and
     *  duplicates (first wins) are dropped, labels re-cleaned, the list capped. */
    @JvmStatic
    fun parseList(text: String): List<WatchEntry> {
        val arr = runCatching { json.parseToJsonElement(text) as? JsonArray }.getOrNull() ?: return emptyList()
        val seen = HashSet<String>()
        val out = ArrayList<WatchEntry>()
        for (el in arr) {
            val o = el as? JsonObject ?: continue
            val addr = o.str("address")?.let(::normalizeAddress) ?: continue
            if (!seen.add(addr)) continue
            out += WatchEntry(addr, cleanLabel(o.str("label") ?: ""))
            if (out.size == MAX_ADDRESSES) break
        }
        return out
    }

    @JvmStatic
    fun serializeList(entries: List<WatchEntry>): String = buildJsonArray {
        entries.forEach { e ->
            add(buildJsonObject {
                put("address", e.address)
                put("label", e.label)
            })
        }
    }.toString()

    /** Why [address] cannot be added to [entries], or null when it can. */
    @JvmStatic
    fun addError(entries: List<WatchEntry>, address: String): String? = when {
        normalizeAddress(address) == null -> "Enter an address: 0x followed by 40 hex digits."
        normalizeAddress(address) == ZERO_ADDRESS -> "The zero address has no owner to watch."
        entries.any { it.address == normalizeAddress(address) } -> "This address is already watched."
        entries.size >= MAX_ADDRESSES -> "At most $MAX_ADDRESSES addresses per network."
        else -> null
    }

    private const val ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

    // ---- the state ([Settings.watchStateJson]) ----

    /** Parse [Settings.watchStateJson]; anything unreadable is an empty state (the next
     *  verified read becomes the baseline again — never a change). */
    @JvmStatic
    fun parseState(text: String): WatchState {
        val o = runCatching { json.parseToJsonElement(text) as? JsonObject }.getOrNull() ?: return WatchState()
        val addresses = LinkedHashMap<String, WatchAddressState>()
        (o["seen"] as? JsonObject)?.forEach { (k, v) ->
            val a = v as? JsonObject ?: return@forEach
            val seen = run {
                val wei = a.str("wei")?.takeIf(::isDecimal) ?: return@run null
                val block = a.long("block") ?: return@run null
                WatchSeen(wei, a.long("nonce") ?: 0, block, a.long("ts") ?: -1, a.long("at") ?: 0)
            }
            addresses[k] = WatchAddressState(seen, a.str("err"), a.long("errAt") ?: 0)
        }
        val changes = (o["changes"] as? JsonArray)?.mapNotNull { el ->
            val c = el as? JsonObject ?: return@mapNotNull null
            WatchChange(
                address = c.str("address") ?: return@mapNotNull null,
                label = c.str("label") ?: "",
                oldWei = c.str("old")?.takeIf(::isDecimal) ?: return@mapNotNull null,
                newWei = c.str("new")?.takeIf(::isDecimal) ?: return@mapNotNull null,
                oldNonce = c.long("oldNonce") ?: 0,
                newNonce = c.long("newNonce") ?: 0,
                fromBlock = c.long("from") ?: -1,
                toBlock = c.long("to") ?: -1,
                blockTimestamp = c.long("ts") ?: -1,
                detectedAtMs = c.long("at") ?: 0,
                search = c.str("search")?.let { s -> WatchSearch.entries.firstOrNull { it.name == s } }
                    ?: WatchSearch.NONE,
                scannedFrom = c.long("scannedFrom") ?: -1,
                causes = (c["causes"] as? JsonArray)?.mapNotNull { ce ->
                    val x = ce as? JsonObject ?: return@mapNotNull null
                    WatchCause(
                        kind = x.str("kind")?.let { s -> WatchCauseKind.entries.firstOrNull { it.name == s } }
                            ?: return@mapNotNull null,
                        blockNumber = x.long("block") ?: -1,
                        txHash = x.str("tx"),
                        counterparty = x.str("cp"),
                        valueWei = x.str("wei")?.takeIf(::isDecimal),
                    )
                } ?: emptyList(),
                asset = c.str("asset") ?: NATIVE_ASSET,
            )
        }?.take(MAX_CHANGES) ?: emptyList()
        return WatchState(addresses, changes, o.long("lastCheckMs") ?: 0, o.long("lastAttemptMs") ?: 0)
    }

    @JvmStatic
    fun serializeState(s: WatchState): String = buildJsonObject {
        put("v", 1)
        put("lastCheckMs", s.lastCheckMs)
        put("lastAttemptMs", s.lastAttemptMs)
        put("seen", buildJsonObject {
            s.addresses.forEach { (k, a) ->
                put(k, buildJsonObject {
                    a.seen?.let {
                        put("wei", it.balanceWei)
                        put("nonce", it.nonce)
                        put("block", it.blockNumber)
                        put("ts", it.blockTimestamp)
                        put("at", it.checkedAtMs)
                    }
                    a.error?.let { put("err", it) }
                    if (a.error != null) put("errAt", a.errorAtMs)
                })
            }
        })
        put("changes", buildJsonArray {
            s.changes.take(MAX_CHANGES).forEach { c ->
                add(buildJsonObject {
                    put("address", c.address)
                    put("label", c.label)
                    put("asset", c.asset)
                    put("old", c.oldWei)
                    put("new", c.newWei)
                    put("oldNonce", c.oldNonce)
                    put("newNonce", c.newNonce)
                    put("from", c.fromBlock)
                    put("to", c.toBlock)
                    put("ts", c.blockTimestamp)
                    put("at", c.detectedAtMs)
                    put("search", c.search.name)
                    put("scannedFrom", c.scannedFrom)
                    put("causes", buildJsonArray {
                        c.causes.forEach { x ->
                            add(buildJsonObject {
                                put("kind", x.kind.name)
                                put("block", x.blockNumber)
                                x.txHash?.let { put("tx", it) }
                                x.counterparty?.let { put("cp", it) }
                                x.valueWei?.let { put("wei", it) }
                            })
                        }
                    })
                })
            }
        })
    }.toString()

    /**
     * Whether a scheduled check of a network is due: the last VERIFIED check is at least
     * [intervalMs] old and the last attempt (which a failing read also stamps) at least
     * [retryMs] — so a network that cannot verify right now is retried at the slower
     * pace instead of on every host tick. A stamp in the future (written while the clock
     * ran ahead, then corrected) counts as old: otherwise no check would run until the
     * clock caught up with it.
     */
    @JvmStatic
    fun isDue(state: WatchState, nowMs: Long, intervalMs: Long, retryMs: Long): Boolean =
        elapsed(state.lastCheckMs, nowMs, intervalMs) && elapsed(state.lastAttemptMs, nowMs, retryMs)

    private fun elapsed(stampMs: Long, nowMs: Long, intervalMs: Long): Boolean =
        stampMs == 0L || nowMs < stampMs || nowMs - stampMs >= intervalMs

    // ---- the check ----

    /** [check]'s outcome: the state to store, and the changes it found (oldest last). */
    data class Outcome(val state: WatchState, val changes: List<WatchChange>)

    /**
     * Read every entry's balance through [reader] and compare it with [previous]: the
     * first verified read of an address is its baseline (no change), a later one that
     * differs is a [WatchChange] whose cause is searched in at most [maxScanBlocks]
     * blocks, newest first. State for addresses no longer in [entries] is dropped.
     *
     * [budget] bounds the whole check — a background pass has a deadline of its own
     * (WorkManager stops a worker at ~10 min). It is checked before every read: past it,
     * the cause search stops where it is (the change keeps what it found, as PARTIAL)
     * and the addresses not read yet keep their stored state untouched, for the next
     * check — which reads them first: addresses go least recently verified first. A
     * single read already running is not cut short; its own bound applies.
     */
    suspend fun check(
        entries: List<WatchEntry>,
        previous: WatchState,
        reader: WatchReader,
        nowMs: Long,
        maxScanBlocks: Int = DEFAULT_SCAN_BLOCKS,
        budget: Duration = Duration.INFINITE,
    ): Outcome {
        val started = TimeSource.Monotonic.markNow()
        val outOfTime = { started.elapsedNow() >= budget }
        val addresses = LinkedHashMap<String, WatchAddressState>()
        val found = ArrayList<WatchChange>()
        var anyVerified = false
        // Least recently verified first (never verified before all): when the budget runs
        // out, the addresses it did not reach lead the next check instead of trailing
        // every check behind the same ones.
        val order = entries.sortedBy { previous.addresses[key(it.address)]?.seen?.checkedAtMs ?: Long.MIN_VALUE }
        for (e in order) {
            val key = key(e.address)
            val prev = previous.addresses[key] ?: WatchAddressState()
            if (outOfTime()) {
                addresses[key] = prev
                continue
            }
            val r = try {
                reader.account(e.address)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                addresses[key] = prev.copy(error = t.message ?: t::class.simpleName ?: "read failed", errorAtMs = nowMs)
                continue
            }
            val balance = if (r.exists) r.balanceWei else "0"
            if (!isVerified(r) || balance == null || !isDecimal(balance)) {
                addresses[key] = prev.copy(error = r.failReason ?: "unverified", errorAtMs = nowMs)
                continue
            }
            anyVerified = true
            val nonce = if (r.exists) r.nonce.coerceAtLeast(0) else 0
            val now = WatchSeen(normalizeDecimal(balance), nonce, r.blockNumber, r.blockTimestamp, nowMs)
            val old = prev.seen
            addresses[key] = when {
                old == null -> WatchAddressState(now)
                // An older anchor than the stored one (a finalized fallback): no news, and
                // never a step back — see the file header.
                r.blockNumber < old.blockNumber -> WatchAddressState(old)
                old.balanceWei == now.balanceWei -> WatchAddressState(now)
                else -> {
                    val (search, scannedFrom, causes) =
                        findCauses(e.address, old.blockNumber, r.blockNumber, reader, maxScanBlocks, outOfTime)
                    found += WatchChange(
                        address = e.address, label = e.label,
                        oldWei = old.balanceWei, newWei = now.balanceWei,
                        oldNonce = old.nonce, newNonce = now.nonce,
                        fromBlock = old.blockNumber, toBlock = r.blockNumber,
                        blockTimestamp = r.blockTimestamp, detectedAtMs = nowMs,
                        search = search, scannedFrom = scannedFrom, causes = causes,
                    )
                    WatchAddressState(now)
                }
            }
        }
        val state = WatchState(
            addresses = addresses,
            changes = (found.asReversed() + previous.changes).take(MAX_CHANGES),
            lastCheckMs = if (anyVerified) nowMs else previous.lastCheckMs,
            lastAttemptMs = nowMs,
        )
        return Outcome(state, found)
    }

    /** The Query tab's green badge: the proof verifies against a beacon-attested root. */
    @JvmStatic
    fun isVerified(r: AccountResult): Boolean = r.beaconChainVerified && r.peerProofValid && r.failReason == null

    private data class Search(val search: WatchSearch, val scannedFrom: Long, val causes: List<WatchCause>)

    /** Scan blocks ([fromBlock], [toBlock]] newest first, at most [maxScanBlocks] of them,
     *  for what touched [address]. Stops at the first block without a verified answer, and
     *  when [outOfTime] says so (then only the blocks scanned so far count: PARTIAL, or
     *  NONE before the first). */
    private suspend fun findCauses(
        address: String,
        fromBlock: Long,
        toBlock: Long,
        reader: WatchReader,
        maxScanBlocks: Int,
        outOfTime: () -> Boolean,
    ): Search {
        if (maxScanBlocks <= 0 || toBlock <= fromBlock) return Search(WatchSearch.NONE, -1, emptyList())
        val lowest = maxOf(fromBlock + 1, toBlock - maxScanBlocks + 1)
        val causes = ArrayList<WatchCause>()
        var scannedFrom = -1L
        var b = toBlock
        while (b >= lowest) {
            if (outOfTime()) {
                return Search(if (scannedFrom < 0) WatchSearch.NONE else WatchSearch.PARTIAL, scannedFrom, causes)
            }
            val text = try {
                reader.block(b)
            } catch (c: CancellationException) {
                throw c
            } catch (_: Throwable) {
                null
            }
            val inBlock = text?.let { causesIn(it, address, b) }
                ?: return Search(WatchSearch.UNAVAILABLE, scannedFrom, causes)
            causes += inBlock
            scannedFrom = b
            b--
        }
        return Search(if (lowest == fromBlock + 1) WatchSearch.COMPLETE else WatchSearch.PARTIAL, scannedFrom, causes)
    }

    /**
     * What in block [blockNumber] — `eth_getBlockByNumber` JSON with full transactions —
     * touched [address]: transactions from or to it (verified against the header's
     * `transactionsRoot` by the engine) and the fee-recipient credit (`miner`, a header
     * field). Null when [blockJson] is no such block (the literal "null", an error
     * envelope, a hashes-only body, unparseable text): the caller must not read "nothing
     * found" into a block it could not see.
     *
     * Not withdrawals: neither engine's block JSON carries the `withdrawals` list (only
     * `withdrawalsRoot`), so a validator withdrawal is one of the things the texts name
     * as moving funds without a transaction. Should an engine add the list, it must
     * verify it against `withdrawalsRoot` before this reads it.
     */
    @JvmStatic
    fun causesIn(blockJson: String, address: String, blockNumber: Long): List<WatchCause>? {
        val o = runCatching { json.parseToJsonElement(blockJson) as? JsonObject }.getOrNull() ?: return null
        val txs = o["transactions"] as? JsonArray ?: return null
        val me = address.lowercase()
        val out = ArrayList<WatchCause>()
        for (el in txs) {
            val tx = el as? JsonObject ?: return null // hashes only: cannot tell who sent what
            val from = tx.str("from")?.lowercase()
            val to = tx.str("to")?.lowercase()
            val kind = when {
                from == me && to == me -> WatchCauseKind.SELF
                from == me -> WatchCauseKind.SENT
                to == me -> WatchCauseKind.RECEIVED
                else -> continue
            }
            out += WatchCause(
                kind = kind,
                blockNumber = blockNumber,
                txHash = tx.str("hash"),
                counterparty = when (kind) {
                    WatchCauseKind.SENT -> to
                    WatchCauseKind.RECEIVED -> from
                    else -> null
                },
                valueWei = tx.str("value")?.let(::hexToDecimal),
            )
        }
        if (o.str("miner")?.lowercase() == me) {
            out += WatchCause(WatchCauseKind.FEE_RECIPIENT, blockNumber)
        }
        return out
    }

    // ---- texts ----

    /** [network]'s native currency symbol for the texts below (ETH, xDAI), or null for a
     *  network the app does not list one for — hosts outside :ui read it here. */
    @JvmStatic
    fun currency(network: String): String? = nativeCurrencySymbol(network)

    /** "Savings" or, without a label, the shortened address. */
    @JvmStatic
    fun displayName(address: String, label: String): String = label.ifBlank { shortAddress(address) }

    /** 0x1234…cdef */
    @JvmStatic
    fun shortAddress(address: String): String =
        if (address.length > 12) address.take(6) + "…" + address.takeLast(4) else address

    /** The notification title: "Savings: +0.5 ETH". */
    @JvmStatic
    fun notificationTitle(c: WatchChange, currency: String?): String =
        "${displayName(c.address, c.label)}: ${formatDelta(c.oldWei, c.newWei)}${currency?.let { " $it" } ?: ""}"

    /** The notification body: the balance move, then what the scan attributed it to. */
    @JvmStatic
    fun notificationText(c: WatchChange, currency: String?): String = buildString {
        val unit = currency?.let { " $it" } ?: ""
        append("Balance ${formatUnits(c.oldWei)} → ${formatUnits(c.newWei)}$unit at block ${grouped(c.toBlock)}. ")
        append(causeSummary(c, currency))
    }.trim()

    /** One sentence on the cause: the transactions found, or why none is named. */
    @JvmStatic
    fun causeSummary(c: WatchChange, currency: String?): String {
        val unit = currency?.let { " $it" } ?: ""
        if (c.causes.isNotEmpty()) {
            val shown = c.causes.take(3).joinToString("; ") { causeLine(it, unit) }
            val more = if (c.causes.size > 3) "; and ${c.causes.size - 3} more" else ""
            return "$shown$more."
        }
        val range = if (c.scannedFrom >= 0) "blocks ${grouped(c.scannedFrom)}–${grouped(c.toBlock)}" else ""
        val sent = c.newNonce - c.oldNonce
        val sentNote = if (sent > 0) " The address sent $sent transaction${if (sent == 1L) "" else "s"} meanwhile." else ""
        return when (c.search) {
            WatchSearch.COMPLETE ->
                "No transaction from or to this address in $range: the balance moved without one — " +
                    "through a contract (an internal transfer), a validator withdrawal or a bridge.$sentNote"
            WatchSearch.PARTIAL ->
                "No transaction from or to this address in the newest $range; the change happened in the " +
                    "${grouped(c.toBlock - c.fromBlock)} blocks since the last check.$sentNote"
            WatchSearch.UNAVAILABLE ->
                "The blocks in between could not be read verified, so the transaction is not named.$sentNote"
            WatchSearch.NONE -> sentNote.trim()
        }
    }

    private fun causeLine(x: WatchCause, unit: String): String {
        val amount = x.valueWei?.takeIf { it != "0" }?.let { " ${formatUnits(it)}$unit" } ?: ""
        val tx = x.txHash?.let { " (tx ${shortHash(it)})" } ?: ""
        return when (x.kind) {
            WatchCauseKind.RECEIVED -> "received$amount from ${x.counterparty?.let(::shortAddress) ?: "?"}$tx"
            WatchCauseKind.SENT ->
                "sent$amount to ${x.counterparty?.let(::shortAddress) ?: "a new contract"}$tx"
            WatchCauseKind.SELF -> "a transaction to itself$tx"
            WatchCauseKind.FEE_RECIPIENT -> "fees as block ${grouped(x.blockNumber)}'s fee recipient"
        }.replaceFirstChar { it.uppercase() }
    }

    /** 0x5f3a…9e1b */
    @JvmStatic
    fun shortHash(hash: String): String = if (hash.length > 14) hash.take(6) + "…" + hash.takeLast(4) else hash

    // ---- amounts: decimal strings, no BigInteger in commonMain ----

    /** "+0.5" / "−0.012" — [formatUnits] of new − old, signed. */
    @JvmStatic
    fun formatDelta(oldWei: String, newWei: String): String {
        val cmp = compareDecimal(newWei, oldWei)
        return when {
            cmp > 0 -> "+" + formatUnits(subtractDecimal(newWei, oldWei))
            cmp < 0 -> "−" + formatUnits(subtractDecimal(oldWei, newWei))
            else -> "±0"
        }
    }

    /**
     * Decimal wei as the native unit (18 decimals on every chain the app lists — see
     * [nativeCurrencySymbol]): truncated, never rounded, to at most [maxFraction] digits,
     * trailing zeros dropped, the integer part grouped; a non-zero amount below the last
     * digit shows as "< 0.000001" rather than a zero that is not one.
     */
    @JvmStatic
    fun formatUnits(wei: String, decimals: Int = 18, maxFraction: Int = 6): String {
        if (!isDecimal(wei)) return wei
        val digits = normalizeDecimal(wei)
        if (digits == "0") return "0"
        val padded = digits.padStart(decimals + 1, '0')
        val intPart = padded.dropLast(decimals).trimStart('0').ifEmpty { "0" }
        val frac = padded.takeLast(decimals).take(maxFraction).trimEnd('0')
        if (intPart == "0" && frac.isEmpty()) return "< 0." + "0".repeat(maxFraction - 1) + "1"
        val grouped = intPart.reversed().chunked(3).joinToString(",").reversed()
        return if (frac.isEmpty()) grouped else "$grouped.$frac"
    }

    /** 21,000,123 */
    @JvmStatic
    fun grouped(n: Long): String =
        if (n < 0) "-" + grouped(-n) else n.toString().reversed().chunked(3).joinToString(",").reversed()

    internal fun isDecimal(s: String): Boolean = s.isNotEmpty() && s.all { it in '0'..'9' }

    internal fun normalizeDecimal(s: String): String = s.trimStart('0').ifEmpty { "0" }

    /** Compare two non-negative decimal strings. */
    internal fun compareDecimal(a: String, b: String): Int {
        val x = normalizeDecimal(a)
        val y = normalizeDecimal(b)
        if (x.length != y.length) return x.length.compareTo(y.length)
        return x.compareTo(y)
    }

    /** [a] − [b] for non-negative decimal strings with a ≥ b. */
    internal fun subtractDecimal(a: String, b: String): String {
        val x = normalizeDecimal(a)
        val y = normalizeDecimal(b).padStart(x.length, '0')
        val out = CharArray(x.length)
        var borrow = 0
        for (i in x.indices.reversed()) {
            var d = (x[i] - '0') - (y[i] - '0') - borrow
            borrow = if (d < 0) 1 else 0
            if (d < 0) d += 10
            out[i] = '0' + d
        }
        return normalizeDecimal(out.concatToString())
    }

    /** A 0x-hex quantity (uint256 at most) as a decimal string, or null when it is not hex. */
    @JvmStatic
    fun hexToDecimal(hex: String): String? {
        val h = hex.removePrefix("0x").removePrefix("0X")
        if (h.isEmpty() || h.length > 64 || !h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        // Little-endian base-1e9 limbs: each hex digit multiplies by 16 and adds.
        val limbs = ArrayList<Long>().apply { add(0) }
        for (ch in h) {
            var carry = ch.digitToInt(16).toLong()
            for (i in limbs.indices) {
                val v = limbs[i] * 16 + carry
                limbs[i] = v % LIMB
                carry = v / LIMB
            }
            while (carry > 0) {
                limbs += carry % LIMB
                carry /= LIMB
            }
        }
        val sb = StringBuilder(limbs.last().toString())
        for (i in limbs.size - 2 downTo 0) sb.append(limbs[i].toString().padStart(9, '0'))
        return sb.toString()
    }

    private const val LIMB = 1_000_000_000L

    private fun JsonObject.str(k: String): String? = (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content
    private fun JsonObject.long(k: String): Long? = (this[k] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
}

/**
 * Runs [BalanceWatch.check] against a host's [Settings] store: loads the list and the
 * state, checks, and stores the result. One instance per process — hosts keep it beside
 * their controller — because it is what keeps two triggers (a foreground tick and a
 * background pass, say) from checking the same network at once: the second one returns
 * null instead of reading every proof twice and racing the first one's write.
 */
class BalanceWatcher(
    private val settings: Settings,
    private val nowMs: () -> Long = ::wallClockMillis,
) {
    private val guard = Mutex()
    private val inFlight = HashSet<String>()

    /**
     * Check [network]'s watch list now. Returns the changes found — empty most of the
     * time — or null when nothing was checked: nothing is watched there, or a check of
     * [network] is already running. The state is stored either way it ran.
     */
    suspend fun check(
        network: String,
        reader: WatchReader,
        maxScanBlocks: Int = BalanceWatch.DEFAULT_SCAN_BLOCKS,
        budget: Duration = Duration.INFINITE,
    ): List<WatchChange>? {
        val entries = BalanceWatch.parseList(settings.watchListJson(network))
        if (entries.isEmpty()) return null
        if (!guard.withLock { inFlight.add(network) }) return null
        try {
            val previous = BalanceWatch.parseState(settings.watchStateJson(network))
            val out = BalanceWatch.check(entries, previous, reader, nowMs(), maxScanBlocks, budget)
            // Re-read the list for the write: an address removed while the proofs were
            // being read must not come back as stored state.
            val listed = BalanceWatch.parseList(settings.watchListJson(network)).mapTo(HashSet()) { BalanceWatch.key(it.address) }
            settings.setWatchStateJson(network, BalanceWatch.serializeState(
                out.state.copy(addresses = out.state.addresses.filterKeys { it in listed }),
            ))
            return out.changes
        } finally {
            guard.withLock { inFlight.remove(network) }
        }
    }

    /** Whether a check of [network] is running right now. */
    suspend fun isChecking(network: String): Boolean = guard.withLock { network in inFlight }

    /**
     * Drop the stored state of addresses no longer on [network]'s list — what every check
     * does on its write, for a list edit no check follows: removing the last address
     * leaves nothing to check, and without this its old balance would be the baseline of
     * a later re-add, which would then announce the whole difference as a change. A check
     * already running drops them on its own write; this one then does nothing.
     */
    suspend fun prune(network: String) {
        if (!guard.withLock { inFlight.add(network) }) return
        try {
            val state = BalanceWatch.parseState(settings.watchStateJson(network))
            val listed = BalanceWatch.parseList(settings.watchListJson(network)).mapTo(HashSet()) { BalanceWatch.key(it.address) }
            if (state.addresses.keys.all { it in listed }) return
            settings.setWatchStateJson(network, BalanceWatch.serializeState(
                state.copy(addresses = state.addresses.filterKeys { it in listed }),
            ))
        } finally {
            guard.withLock { inFlight.remove(network) }
        }
    }
}

/** The wall clock in unix ms; kotlin.time's Clock is @ExperimentalTime in the 2.2 stdlib. */
@OptIn(kotlin.time.ExperimentalTime::class)
internal fun wallClockMillis(): Long = Clock.System.now().toEpochMilliseconds()
