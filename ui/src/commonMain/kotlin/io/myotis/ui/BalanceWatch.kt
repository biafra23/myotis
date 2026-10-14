package io.myotis.ui

import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmStatic
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.TimeSource
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
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
 * Assets: the store is keyed by (address, asset) and every change names its asset: the
 * chain's native currency ([NATIVE_ASSET]), and each ERC-20 token the network lists
 * ([listedTokens]: the built-in ones and the user's own, from Settings). A token balance
 * is a verified `eth_call` to `balanceOf` ([readTokenRaw] — an empty reply is an error,
 * never a zero). The engine API does not say which block an `eth_call` ran against, so a
 * token observation is anchored to the block of the same address's verified account read
 * in the same check, seconds earlier; tokens are read only after that read verified, and
 * never on an anchor older than the stored one. A token change's cause is searched in the
 * token's `Transfer` logs (block receipts, verified against `receiptsRoot` by the engine).
 */

/** The chain's native currency (ETH, xDAI) as a [WatchChange.asset]. */
const val NATIVE_ASSET: String = "native"

/** One address on a network's watch list. [label] may be empty; [address] is lowercase. */
data class WatchEntry(val address: String, val label: String)

/** The last VERIFIED observation of one watched balance. */
data class WatchSeen(
    /** The balance in the asset's base units, decimal: wei for the native currency ("0"
     *  for an account that does not exist yet), a token's raw `balanceOf` amount. */
    val balance: String,
    /** The account nonce — transactions it has sent; 0 for an account that does not exist
     *  yet, and for a token observation. */
    val nonce: Long,
    /** The block the proof anchored to (for a token: the same check's account read's). */
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
    /** A transaction the address sent (its value excludes the fee it paid) — for a token,
     *  a `Transfer` from the address. */
    SENT,
    /** A transaction to the address — for a token, a `Transfer` to it. */
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
    /** The amount in the asset's base units, decimal: a transaction's value in wei, a
     *  `Transfer`'s value; null when the block alone does not tell it (a fee-recipient
     *  credit). */
    val amount: String? = null,
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
    /** The balances before and after, in the asset's base units (decimal). */
    val oldBalance: String,
    val newBalance: String,
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
    /** [NATIVE_ASSET], or [BalanceWatch.tokenAsset] of the token. */
    val asset: String = NATIVE_ASSET,
    /** The token's symbol; null for the native currency (the texts name the network's). */
    val symbol: String? = null,
    /** The asset's decimals: 18 for the native currency, the token's otherwise. */
    val decimals: Int = 18,
) {
    val isToken: Boolean get() = asset != NATIVE_ASSET
}

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

    /** A verified `eth_call` of [data] to the contract [to] at the verified head, from the
     *  anonymous sender ([NodeController.ethCall]'s read) — the token balances. A revert or
     *  "no verified answer" is the result's status; throws only when the network cannot be
     *  read at all. */
    suspend fun call(to: String, data: String): EthCallResult

    /** Every receipt of block [number] as `eth_getBlockReceipts` JSON (verified against the
     *  header's `receiptsRoot`); null (or "null", or an error envelope) when there is no
     *  verified answer — a token change's `Transfer` logs. */
    suspend fun receipts(number: Long): String?
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
     *  on a metered network: a mainnet block with its transactions is ~100–200 KB. A token
     *  change scans a quarter as many: its search reads the blocks' receipts, which weigh
     *  more than their bodies. */
    const val DEFAULT_SCAN_BLOCKS: Int = 64

    /** Token balances of one address read at once (the Query tab's bound too). */
    const val TOKEN_READS_IN_FLIGHT: Int = 4

    /** `Transfer(address,address,uint256)`'s event signature, the logs' topic 0. */
    const val TRANSFER_TOPIC: String = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    private val json = Json { ignoreUnknownKeys = true }

    /** The store key of [address]'s balance of [asset]. */
    @JvmStatic
    fun key(address: String, asset: String = NATIVE_ASSET): String =
        if (asset == NATIVE_ASSET) address.lowercase() else "${address.lowercase()}/${asset.lowercase()}"

    /** [token] as a [WatchChange.asset]: `erc20:` and its contract address, lowercase. */
    @JvmStatic
    fun tokenAsset(token: Token): String = "erc20:${token.key}"

    /** The store keys a check of [entries] keeps, with [tokens] listed: each address's native
     *  balance and its balance of each listed token. Anything else is dropped on the write. */
    @JvmStatic
    fun listedKeys(entries: List<WatchEntry>, tokens: List<Token>): Set<String> =
        entries.flatMapTo(HashSet()) { e -> listOf(key(e.address)) + tokens.map { key(e.address, tokenAsset(it)) } }

    // ---- the watch list ([Settings.watchListJson]) ----

    /** [input] as a watchable address — `0x` and 40 hex digits, lowercased — or null.
     *  The address is stored lowercase; [addError] checks a mixed-case one's EIP-55
     *  checksum first, so a typo in it is caught before it is stored. */
    @JvmStatic
    fun normalizeAddress(input: String): String? {
        val s = input.trim()
        if (!isHexAddress(s)) return null
        return "0x" + s.substring(2).lowercase()
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

    /** Why [address] cannot be added to [entries], or null when it can. A mixed-case address
     *  must carry a valid EIP-55 checksum (all-lower or all-upper carries none). */
    @JvmStatic
    fun addError(entries: List<WatchEntry>, address: String): String? = when {
        normalizeAddress(address) == null -> "Enter an address: 0x followed by 40 hex digits."
        !Eip55.isValid(address.trim()) -> "That address fails its checksum (EIP-55) — check it for a typo."
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
                val balance = a.str("bal")?.takeIf(::isDecimal) ?: return@run null
                val block = a.long("block") ?: return@run null
                WatchSeen(balance, a.long("nonce") ?: 0, block, a.long("ts") ?: -1, a.long("at") ?: 0)
            }
            addresses[k] = WatchAddressState(seen, a.str("err"), a.long("errAt") ?: 0)
        }
        val changes = (o["changes"] as? JsonArray)?.mapNotNull { el ->
            val c = el as? JsonObject ?: return@mapNotNull null
            WatchChange(
                address = c.str("address") ?: return@mapNotNull null,
                label = c.str("label") ?: "",
                oldBalance = c.str("old")?.takeIf(::isDecimal) ?: return@mapNotNull null,
                newBalance = c.str("new")?.takeIf(::isDecimal) ?: return@mapNotNull null,
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
                        amount = x.str("amt")?.takeIf(::isDecimal),
                    )
                } ?: emptyList(),
                asset = c.str("asset") ?: NATIVE_ASSET,
                symbol = c.str("symbol"),
                decimals = c.long("decimals")?.toInt()?.takeIf { it in 0..CustomTokens.MAX_DECIMALS } ?: 18,
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
                        put("bal", it.balance)
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
                    c.symbol?.let { put("symbol", it) }
                    put("decimals", c.decimals)
                    put("old", c.oldBalance)
                    put("new", c.newBalance)
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
                                x.amount?.let { put("amt", it) }
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
     * Read every entry's balances through [reader] and compare them with [previous]: its
     * native balance, then — once that read verified, on an anchor no older than the stored
     * one — its balance of each of [tokens]. The first verified read of a balance is its
     * baseline (no change); a later one that differs is a [WatchChange]. Its cause is
     * searched in at most [maxScanBlocks] blocks, newest first — a token's in a quarter as
     * many blocks' receipts. State for balances no longer listed is dropped.
     *
     * [budget] bounds the whole check — a background pass has a deadline of its own
     * (WorkManager stops a worker at ~10 min). It is checked before every read: past it,
     * the cause search stops where it is (the change keeps what it found, as PARTIAL)
     * and the balances not read yet keep their stored state untouched, for the next check
     * — which reads them first: addresses go least recently attempted first (by their
     * least recently attempted balance), and so do an address's tokens. A single read
     * already running is not cut short; its own bound applies.
     */
    suspend fun check(
        entries: List<WatchEntry>,
        previous: WatchState,
        reader: WatchReader,
        nowMs: Long,
        maxScanBlocks: Int = DEFAULT_SCAN_BLOCKS,
        budget: Duration = Duration.INFINITE,
        tokens: List<Token> = emptyList(),
    ): Outcome {
        val started = TimeSource.Monotonic.markNow()
        val outOfTime = { started.elapsedNow() >= budget }
        val addresses = LinkedHashMap<String, WatchAddressState>()
        val found = ArrayList<WatchChange>()
        var anyVerified = false
        fun prevOf(k: String) = previous.addresses[k] ?: WatchAddressState()
        // Least recently attempted first (never attempted before all): when the budget runs
        // out, the balances it did not reach lead the next check instead of trailing every
        // check behind the same ones — and one whose read keeps failing slowly goes to the
        // back after each attempt rather than leading, and eating, every budget.
        val order = entries.sortedBy { e ->
            (listOf(key(e.address)) + tokens.map { key(e.address, tokenAsset(it)) })
                .minOf { lastAttempt(previous.addresses[it]) }
        }
        for (e in order) {
            val nativeKey = key(e.address)
            val tokenKeys = tokens.map { key(e.address, tokenAsset(it)) }
            val prev = prevOf(nativeKey)
            // Until this address's account read verifies on a current anchor, its token
            // balances have none to be anchored to: they keep their stored state.
            fun keepTokens() = tokenKeys.forEach { addresses[it] = prevOf(it) }
            if (outOfTime()) {
                addresses[nativeKey] = prev
                keepTokens()
                continue
            }
            val r = try {
                reader.account(e.address)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                addresses[nativeKey] = prev.copy(error = t.message ?: t::class.simpleName ?: "read failed", errorAtMs = nowMs)
                keepTokens()
                continue
            }
            val balance = if (r.exists) r.balanceWei else "0"
            if (!isVerified(r) || balance == null || !isDecimal(balance)) {
                addresses[nativeKey] = prev.copy(error = r.failReason ?: "unverified", errorAtMs = nowMs)
                keepTokens()
                continue
            }
            anyVerified = true
            val nonce = if (r.exists) r.nonce.coerceAtLeast(0) else 0
            val now = WatchSeen(normalizeDecimal(balance), nonce, r.blockNumber, r.blockTimestamp, nowMs)
            val old = prev.seen
            // An older anchor than the stored one (a finalized fallback): no news, and never a
            // step back — see the file header. The tokens wait for a current anchor too.
            if (old != null && r.blockNumber < old.blockNumber) {
                addresses[nativeKey] = WatchAddressState(old)
                keepTokens()
                continue
            }
            addresses[nativeKey] = WatchAddressState(now)
            if (old != null && old.balance != now.balance) {
                val (search, scannedFrom, causes) =
                    findCauses(e.address, old.blockNumber, r.blockNumber, reader, maxScanBlocks, outOfTime)
                found += WatchChange(
                    address = e.address, label = e.label,
                    oldBalance = old.balance, newBalance = now.balance,
                    oldNonce = old.nonce, newNonce = now.nonce,
                    fromBlock = old.blockNumber, toBlock = r.blockNumber,
                    blockTimestamp = r.blockTimestamp, detectedAtMs = nowMs,
                    search = search, scannedFrom = scannedFrom, causes = causes,
                )
            }
            if (tokens.isEmpty()) continue
            // The address's tokens, least recently attempted first, a few reads at a time.
            val reads = readTokens(e.address, tokens.sortedBy { lastAttempt(previous.addresses[key(e.address, tokenAsset(it))]) }, reader, outOfTime)
            for (t in tokens) {
                val k = key(e.address, tokenAsset(t))
                val tokenPrev = prevOf(k)
                val read = reads[t.key]
                when {
                    read == null -> addresses[k] = tokenPrev // out of time before it was read
                    read.raw == null -> addresses[k] = tokenPrev.copy(error = read.error ?: "unreadable", errorAtMs = nowMs)
                    else -> {
                        anyVerified = true
                        val seen = WatchSeen(normalizeDecimal(read.raw), 0, r.blockNumber, r.blockTimestamp, nowMs)
                        val was = tokenPrev.seen
                        addresses[k] = WatchAddressState(if (was != null && r.blockNumber < was.blockNumber) was else seen)
                        if (was != null && r.blockNumber >= was.blockNumber && was.balance != seen.balance) {
                            val (search, scannedFrom, causes) = findTokenCauses(
                                e.address, t, was.blockNumber, r.blockNumber, reader, maxScanBlocks / 4, outOfTime,
                            )
                            found += WatchChange(
                                address = e.address, label = e.label,
                                oldBalance = was.balance, newBalance = seen.balance,
                                oldNonce = old?.nonce ?: nonce, newNonce = nonce,
                                fromBlock = was.blockNumber, toBlock = r.blockNumber,
                                blockTimestamp = r.blockTimestamp, detectedAtMs = nowMs,
                                search = search, scannedFrom = scannedFrom, causes = causes,
                                asset = tokenAsset(t), symbol = t.symbol, decimals = t.decimals,
                            )
                        }
                    }
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

    /** When [a] was last attempted, verified or not; never attempted sorts first. */
    private fun lastAttempt(a: WatchAddressState?): Long =
        if (a == null) Long.MIN_VALUE else maxOf(a.seen?.checkedAtMs ?: 0, if (a.error != null) a.errorAtMs else 0)

    /** [holder]'s balances of [tokens] ([readTokenRaw]), [TOKEN_READS_IN_FLIGHT] at a time,
     *  keyed by [Token.key]; a token the budget left unread is absent. */
    private suspend fun readTokens(
        holder: String,
        tokens: List<Token>,
        reader: WatchReader,
        outOfTime: () -> Boolean,
    ): Map<String, TokenBalance> {
        val permits = Semaphore(TOKEN_READS_IN_FLIGHT)
        val call: EthCall = { to, data -> reader.call(to, data) }
        return coroutineScope {
            tokens.map { t ->
                async {
                    permits.withPermit {
                        if (outOfTime()) null else t.key to readTokenRaw(call, holder, t)
                    }
                }
            }.awaitAll().filterNotNull().toMap()
        }
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
                amount = tx.str("value")?.let(::hexToDecimal),
            )
        }
        if (o.str("miner")?.lowercase() == me) {
            out += WatchCause(WatchCauseKind.FEE_RECIPIENT, blockNumber)
        }
        return out
    }

    /** [findCauses] for a token: the `Transfer` logs of [token] to or from [holder] in the
     *  receipts of blocks ([fromBlock], [toBlock]], newest first, at most [maxScanBlocks]. */
    private suspend fun findTokenCauses(
        holder: String,
        token: Token,
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
                reader.receipts(b)
            } catch (c: CancellationException) {
                throw c
            } catch (_: Throwable) {
                null
            }
            val inBlock = text?.let { transfersIn(it, holder, token, b) }
                ?: return Search(WatchSearch.UNAVAILABLE, scannedFrom, causes)
            causes += inBlock
            scannedFrom = b
            b--
        }
        return Search(if (lowest == fromBlock + 1) WatchSearch.COMPLETE else WatchSearch.PARTIAL, scannedFrom, causes)
    }

    /**
     * The `Transfer` logs of [token] that moved [holder]'s balance in block [blockNumber] —
     * `eth_getBlockReceipts` JSON, verified against the header's `receiptsRoot` by the
     * engine: from [holder] (SENT) or to it (RECEIVED), with the amount in the token's base
     * units. Null when [receiptsJson] is no receipt list (the literal "null", an error
     * envelope, unparseable text), so a block that could not be read is never "nothing
     * found". A log of another contract claiming the topic is not [token]'s and is skipped.
     */
    @JvmStatic
    fun transfersIn(receiptsJson: String, holder: String, token: Token, blockNumber: Long): List<WatchCause>? {
        val arr = runCatching { json.parseToJsonElement(receiptsJson) as? JsonArray }.getOrNull() ?: return null
        val me = holder.lowercase()
        val out = ArrayList<WatchCause>()
        for (el in arr) {
            val receipt = el as? JsonObject ?: return null
            val logs = receipt["logs"] as? JsonArray ?: continue
            for (le in logs) {
                val log = le as? JsonObject ?: continue
                if (log.str("address")?.lowercase() != token.key) continue
                val topics = (log["topics"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content?.lowercase() }
                    ?: continue
                // Transfer(address indexed from, address indexed to, uint256 value): an
                // ERC-721 Transfer indexes the id as a fourth topic and is not a balance move.
                if (topics.size != 3 || topics[0] != TRANSFER_TOPIC) continue
                val from = topicAddress(topics[1]) ?: continue
                val to = topicAddress(topics[2]) ?: continue
                val kind = when {
                    from == me && to == me -> WatchCauseKind.SELF
                    from == me -> WatchCauseKind.SENT
                    to == me -> WatchCauseKind.RECEIVED
                    else -> continue
                }
                out += WatchCause(
                    kind = kind,
                    blockNumber = blockNumber,
                    txHash = log.str("transactionHash") ?: receipt.str("transactionHash"),
                    counterparty = when (kind) {
                        WatchCauseKind.SENT -> to
                        WatchCauseKind.RECEIVED -> from
                        else -> null
                    },
                    amount = log.str("data")?.let(::hexToDecimal),
                )
            }
        }
        return out
    }

    /** An indexed address topic (32 bytes, the address in the low 20) as `0x…`, lowercase. */
    private fun topicAddress(topic: String): String? =
        topic.takeIf { it.length == 66 && it.startsWith("0x") && it.substring(2, 26).all { c -> c == '0' } }
            ?.let { "0x" + it.substring(26) }

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

    /** What [c] is counted in: the token's symbol, else the network's [currency]; "" when
     *  neither is known (a network the app lists no currency for). */
    @JvmStatic
    fun unitOf(c: WatchChange, currency: String?): String = c.symbol ?: currency ?: ""

    /** The notification title: "Savings: +0.5 ETH", "Savings: −100 USDC". */
    @JvmStatic
    fun notificationTitle(c: WatchChange, currency: String?): String =
        "${displayName(c.address, c.label)}: ${formatDelta(c.oldBalance, c.newBalance, c.decimals)}" +
            unitOf(c, currency).let { if (it.isEmpty()) "" else " $it" }

    /** The notification body: the balance move, then what the scan attributed it to. */
    @JvmStatic
    fun notificationText(c: WatchChange, currency: String?): String = buildString {
        val unit = unitOf(c, currency).let { if (it.isEmpty()) "" else " $it" }
        append("Balance ${formatUnits(c.oldBalance, c.decimals)} → ${formatUnits(c.newBalance, c.decimals)}$unit")
        append(" at block ${grouped(c.toBlock)}. ")
        append(causeSummary(c, currency))
    }.trim()

    /** One sentence on the cause: the transactions found, or why none is named. */
    @JvmStatic
    fun causeSummary(c: WatchChange, currency: String?): String {
        val unit = unitOf(c, currency).let { if (it.isEmpty()) "" else " $it" }
        if (c.causes.isNotEmpty()) {
            val shown = c.causes.take(3).joinToString("; ") { causeLine(it, unit, c.decimals) }
            val more = if (c.causes.size > 3) "; and ${c.causes.size - 3} more" else ""
            return "$shown$more."
        }
        val range = if (c.scannedFrom >= 0) "blocks ${grouped(c.scannedFrom)}–${grouped(c.toBlock)}" else ""
        if (c.isToken) {
            val symbol = c.symbol ?: "this token"
            return when (c.search) {
                WatchSearch.COMPLETE ->
                    "No Transfer of $symbol to or from this address in $range: the contract changed the " +
                        "balance without one — a rebasing token does (stETH, daily), so does one that " +
                        "takes a fee or adjusts balances itself."
                WatchSearch.PARTIAL ->
                    "No Transfer of $symbol to or from this address in the newest $range; the change " +
                        "happened in the ${grouped(c.toBlock - c.fromBlock)} blocks since the last check."
                WatchSearch.UNAVAILABLE ->
                    "The blocks' receipts could not be read verified, so the transfer is not named."
                WatchSearch.NONE -> ""
            }
        }
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

    private fun causeLine(x: WatchCause, unit: String, decimals: Int): String {
        val amount = x.amount?.takeIf { it != "0" }?.let { " ${formatUnits(it, decimals)}$unit" } ?: ""
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

    /** "+0.5" / "−0.012" — [formatUnits] of new − old in [decimals], signed. */
    @JvmStatic
    fun formatDelta(oldBalance: String, newBalance: String, decimals: Int = 18): String {
        val cmp = compareDecimal(newBalance, oldBalance)
        return when {
            cmp > 0 -> "+" + formatUnits(subtractDecimal(newBalance, oldBalance), decimals)
            cmp < 0 -> "−" + formatUnits(subtractDecimal(oldBalance, newBalance), decimals)
            else -> "±0"
        }
    }

    /**
     * A base-unit amount in whole units of an asset with [decimals] (18: the native
     * currency on every chain the app lists — see [nativeCurrencySymbol]) — the Query tab's
     * [formatTokenAmount]: truncated, never rounded, to at most [maxFraction] digits,
     * trailing zeros dropped, the integer part grouped; a non-zero amount below the last
     * digit shows as "< 0.000001" rather than a zero that is not one.
     */
    @JvmStatic
    fun formatUnits(amount: String, decimals: Int = 18, maxFraction: Int = 6): String =
        formatTokenAmount(amount, decimals, maxFraction)

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
            val out = BalanceWatch.check(
                entries, previous, reader, nowMs(), maxScanBlocks, budget, tokens = tokens(network),
            )
            // Re-read the lists for the write: an address removed while the proofs were
            // being read, or a token removed in Settings, must not come back as stored state.
            val listed = listedKeys(network)
            settings.setWatchStateJson(network, BalanceWatch.serializeState(
                out.state.copy(addresses = out.state.addresses.filterKeys { it in listed }),
            ))
            return out.changes
        } finally {
            release(network)
        }
    }

    /** Whether a check of [network] is running right now. */
    suspend fun isChecking(network: String): Boolean = guard.withLock { network in inFlight }

    /** The tokens a check of [network] reads: the ones it lists ([listedTokens]). */
    private fun tokens(network: String): List<Token> = listedTokens(network, settings.customTokensJson(network))

    private fun listedKeys(network: String): Set<String> =
        BalanceWatch.listedKeys(BalanceWatch.parseList(settings.watchListJson(network)), tokens(network))

    /**
     * Drop the stored state of balances no longer listed on [network] — addresses removed
     * from the watch list, tokens removed in Settings — what every check does on its write,
     * for an edit no check follows: removing the last address leaves nothing to check, and
     * without this its old balance would be the baseline of a later re-add, which would then
     * announce the whole difference as a change. A check already running drops them on its
     * own write; this one then does nothing.
     */
    suspend fun prune(network: String) {
        if (!guard.withLock { inFlight.add(network) }) return
        try {
            val state = BalanceWatch.parseState(settings.watchStateJson(network))
            val listed = listedKeys(network)
            if (state.addresses.keys.all { it in listed }) return
            settings.setWatchStateJson(network, BalanceWatch.serializeState(
                state.copy(addresses = state.addresses.filterKeys { it in listed }),
            ))
        } finally {
            release(network)
        }
    }

    /** Free [network]'s slot — also from a cancelled coroutine: `withLock` suspends when the
     *  guard is contended, and a cancelled caller would throw there instead, leaking the slot
     *  for the rest of the process (every later check returning null, and Android's idle
     *  controller, which asks [isChecking], never pausing that stack again). */
    private suspend fun release(network: String) {
        withContext(NonCancellable) { guard.withLock { inFlight.remove(network) } }
    }
}

/** The wall clock in unix ms; kotlin.time's Clock is @ExperimentalTime in the 2.2 stdlib. */
@OptIn(kotlin.time.ExperimentalTime::class)
internal fun wallClockMillis(): Long = Clock.System.now().toEpochMilliseconds()
