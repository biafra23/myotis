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
 * never a zero). A token observation is anchored at the block the call ran against
 * ([EthCallResult.blockNumber]; an engine that does not say falls back to the same address's
 * verified account read in the same check), and an older one than the stored never steps a
 * balance back. Tokens are read only for addresses whose account read verified in the same
 * check. A token change's cause is searched in the token's `Transfer` logs — and, for a
 * wrapped native token (WETH, WXDAI), its `Deposit`/`Withdrawal` — in the block receipts,
 * which the engine verifies against `receiptsRoot`.
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
    /** The block the proof anchored to; for a token, the block its `eth_call` ran against
     *  (or, from an engine that does not say, the same check's account read's). */
    val blockNumber: Long,
    /** That block's proven timestamp, unix seconds; -1 when the engine did not date it. */
    val blockTimestamp: Long,
    /** Wall-clock ms of the read. */
    val checkedAtMs: Long,
    /** For a custom token: what its contract's own `decimals()` answered, when it did — the
     *  scale its amounts are shown in, whatever Settings → Tokens says. Null otherwise. */
    val decimals: Int? = null,
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
    /** A wrapped native token (WETH, WXDAI) minted to the address: its `Deposit`. */
    WRAPPED,
    /** A wrapped native token burned from the address: its `Withdrawal`. */
    UNWRAPPED,
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

    /** Blocks a change's cause search scans by default, newest first — a token change's too,
     *  in the blocks' receipts, unless the host passes a window of its own. Hosts pass less on
     *  a metered network: a mainnet block with its transactions is ~100–200 KB, and its
     *  receipts weigh more. */
    const val DEFAULT_SCAN_BLOCKS: Int = 64

    /** `Transfer(address,address,uint256)`'s event signature, the logs' topic 0. */
    const val TRANSFER_TOPIC: String = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    /** WETH9's `Deposit(address,uint256)` — a wrap mints without a `Transfer` (WETH, WXDAI). */
    const val DEPOSIT_TOPIC: String = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"

    /** WETH9's `Withdrawal(address,uint256)` — an unwrap burns without a `Transfer`. */
    const val WITHDRAWAL_TOPIC: String = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"

    /** How a stored "no verified answer" token read says it is retried. */
    private const val WATCH_RETRY_HINT = " — the next check retries"

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
                // "wei" is this branch's first key for it (its test builds stored that).
                val balance = (a.str("bal") ?: a.str("wei"))?.takeIf(::isDecimal) ?: return@run null
                val block = a.long("block") ?: return@run null
                WatchSeen(
                    balance, a.long("nonce") ?: 0, block, a.long("ts") ?: -1, a.long("at") ?: 0,
                    a.long("dec")?.toInt()?.takeIf { it in 0..CustomTokens.MAX_DECIMALS },
                )
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
                        amount = (x.str("amt") ?: x.str("wei"))?.takeIf(::isDecimal),
                    )
                } ?: emptyList(),
                asset = c.str("asset") ?: NATIVE_ASSET,
                symbol = c.str("symbol"),
                decimals = c.long("decimals")?.toInt()?.takeIf { it in 0..CustomTokens.MAX_DECIMALS } ?: 18,
            )
        }?.take(MAX_CHANGES) ?: emptyList()
        return WatchState(
            addresses, changes,
            o.long("lastCheckMs") ?: 0, o.long("lastAttemptMs") ?: 0,
        )
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
                        it.decimals?.let { d -> put("dec", d) }
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
     * Read every entry's balances through [reader] and compare them with [previous]. First
     * every native balance; then the balance of each of [tokens] of every address whose
     * account read verified in this check. The first verified read of a balance is its
     * baseline (no change); a later one that differs is a [WatchChange]. Its cause is searched
     * in at most [maxScanBlocks] blocks, newest first — a token's in at most
     * [maxTokenScanBlocks] blocks' receipts. State for balances no longer listed is dropped.
     *
     * A token balance verified less than [tokenIntervalMs] ago (0, the default: never) is not
     * read again — a host on a metered network reads its many `eth_call`s less often than the
     * one proof per address. One whose newest read failed, or that was never read, is due on
     * every check.
     *
     * [budget] bounds the whole check — a background pass has a deadline of its own
     * (WorkManager stops a worker at ~10 min). It is checked before every read: past it,
     * the cause search stops where it is (the change keeps what it found, as PARTIAL)
     * and the balances not read yet keep their stored state untouched, for the next check
     * — which reads them first: the native balances go least recently attempted first, and
     * so do the (address, token) pairs. While token balances are due, the native reads stop
     * at half the budget (their cause searches may use all of it), so neither a long token
     * list nor a slow native phase keeps the other out of every check. A single read already
     * running is not cut short; its own bound applies.
     */
    suspend fun check(
        entries: List<WatchEntry>,
        previous: WatchState,
        reader: WatchReader,
        nowMs: Long,
        maxScanBlocks: Int = DEFAULT_SCAN_BLOCKS,
        budget: Duration = Duration.INFINITE,
        tokens: List<Token> = emptyList(),
        maxTokenScanBlocks: Int = maxScanBlocks,
        tokenIntervalMs: Long = 0,
    ): Outcome {
        val started = TimeSource.Monotonic.markNow()
        val outOfTime = { started.elapsedNow() >= budget }
        val addresses = LinkedHashMap<String, WatchAddressState>()
        val found = ArrayList<WatchChange>()
        var anyVerified = false
        fun prevOf(k: String) = previous.addresses[k] ?: WatchAddressState()
        fun tokenDue(e: WatchEntry, t: Token) = tokenDue(previous.addresses[key(e.address, tokenAsset(t))], nowMs, tokenIntervalMs)
        val tokensWait = entries.any { e -> tokens.any { t -> tokenDue(e, t) } }
        val nativeBudget = if (tokensWait && budget.isFinite()) budget / 2 else budget
        val nativeOutOfTime = { started.elapsedNow() >= nativeBudget }
        val watched = entries.mapTo(HashSet()) { it.address }

        // ---- the native balances: least recently attempted first (never attempted before
        // all), so what a spent budget left out leads the next check, and a read that keeps
        // failing slowly goes to the back after each attempt instead of eating every budget.
        val anchors = HashMap<String, AccountResult>() // address → its verified, current account read
        // One fetch per block for the whole check, kept as what it holds for the watched
        // addresses only: one transaction can move several of them.
        val blocks = HashMap<Long, BlockSlice?>()
        for (e in entries.sortedBy { lastAttempt(previous.addresses[key(it.address)]) }) {
            val k = key(e.address)
            val prev = prevOf(k)
            if (nativeOutOfTime()) {
                addresses[k] = prev
                continue
            }
            val r = try {
                reader.account(e.address)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                addresses[k] = prev.copy(error = t.message ?: t::class.simpleName ?: "read failed", errorAtMs = nowMs)
                continue
            }
            val balance = if (r.exists) r.balanceWei else "0"
            if (!isVerified(r) || balance == null || !isDecimal(balance)) {
                addresses[k] = prev.copy(error = r.failReason ?: "unverified", errorAtMs = nowMs)
                continue
            }
            anyVerified = true
            val nonce = if (r.exists) r.nonce.coerceAtLeast(0) else 0
            val now = WatchSeen(normalizeDecimal(balance), nonce, r.blockNumber, r.blockTimestamp, nowMs)
            val old = prev.seen
            // An older anchor than the stored one (a finalized fallback): no news, and never a
            // step back — see the file header.
            if (old != null && r.blockNumber < old.blockNumber) {
                addresses[k] = WatchAddressState(old)
                continue
            }
            addresses[k] = WatchAddressState(now)
            anchors[e.address] = r
            if (old != null && old.balance != now.balance) {
                val (search, scannedFrom, causes) = scan(old.blockNumber, r.blockNumber, maxScanBlocks, outOfTime) { b ->
                    val slice = if (b in blocks) blocks[b] else reader.block(b)?.let { blockSlice(it, watched) }.also { blocks[b] = it }
                    slice?.let { causesIn(it, e.address, b) }
                }
                found += WatchChange(
                    address = e.address, label = e.label,
                    oldBalance = old.balance, newBalance = now.balance,
                    oldNonce = old.nonce, newNonce = now.nonce,
                    fromBlock = old.blockNumber, toBlock = r.blockNumber,
                    blockTimestamp = r.blockTimestamp, detectedAtMs = nowMs,
                    search = search, scannedFrom = scannedFrom, causes = causes,
                )
            }
        }

        // ---- the token balances: every pair keeps its stored state unless read below.
        for (e in entries) for (t in tokens) key(e.address, tokenAsset(t)).let { addresses[it] = prevOf(it) }
        val pairs = entries.filter { it.address in anchors }
            .flatMap { e -> tokens.filter { tokenDue(e, it) }.map { e to it } }
            .sortedBy { (e, t) -> lastAttempt(previous.addresses[key(e.address, tokenAsset(t))]) }
        if (pairs.isNotEmpty()) {
            val call: EthCall = { to, data -> reader.call(to, data) }
            val reads = readTokens(pairs, call, outOfTime)
            // A custom token's own decimals(): the scale its amounts are shown in (a built-in
            // token's are pinned). Kept once a read stored them; asked, once per check, only
            // while none is stored — so a failed ask never drops a known scale.
            val chainDecimals = HashMap<String, Int?>()
            for (t in tokens) {
                if (!t.custom) continue
                val stored = previous.addresses.entries.firstNotNullOfOrNull { (k, a) ->
                    a.seen?.decimals?.takeIf { k.endsWith("/" + tokenAsset(t)) }
                }
                chainDecimals[t.key] = stored ?: if (
                    !outOfTime() && pairs.any { (e, p) -> p == t && reads[key(e.address, tokenAsset(t))]?.raw != null }
                ) readTokenDecimals(call, t) else null
            }
            // One fetch per block's receipts for the whole check, kept as the logs that concern
            // the listed tokens and watched addresses only: one rebase moves every holder's
            // balance, and their searches cover the same blocks.
            val tokenKeys = tokens.mapTo(HashSet()) { it.key }
            val receipts = HashMap<Long, List<TokenLog>?>()
            for ((e, t) in pairs) {
                val k = key(e.address, tokenAsset(t))
                val read = reads[k] ?: continue // out of time before it was read
                val tokenPrev = prevOf(k)
                if (read.raw == null) {
                    addresses[k] = tokenPrev.copy(error = read.error ?: "unreadable", errorAtMs = nowMs)
                    continue
                }
                anyVerified = true
                val anchor = anchors.getValue(e.address)
                // The call's own block; an engine that does not say falls back to the account
                // read's, from this check's native phase.
                val block = read.blockNumber.takeIf { it > 0 } ?: anchor.blockNumber
                val seen = WatchSeen(
                    normalizeDecimal(read.raw), 0, block,
                    if (block == anchor.blockNumber) anchor.blockTimestamp else -1, nowMs,
                    chainDecimals[t.key],
                )
                val was = tokenPrev.seen
                if (was != null && block < was.blockNumber) {
                    addresses[k] = WatchAddressState(was) // an older anchor: never a step back
                    continue
                }
                addresses[k] = WatchAddressState(seen)
                if (was == null || was.balance == seen.balance) continue
                val (search, scannedFrom, causes) = scan(was.blockNumber, block, maxTokenScanBlocks, outOfTime) { b ->
                    val logs = if (b in receipts) receipts[b]
                    else reader.receipts(b)?.let { tokenLogs(it, tokenKeys, watched) }.also { receipts[b] = it }
                    logs?.let { transfersIn(it, e.address, t, b) }
                }
                found += WatchChange(
                    address = e.address, label = e.label,
                    oldBalance = was.balance, newBalance = seen.balance,
                    oldNonce = 0, newNonce = 0,
                    fromBlock = was.blockNumber, toBlock = block,
                    blockTimestamp = seen.blockTimestamp, detectedAtMs = nowMs,
                    search = search, scannedFrom = scannedFrom, causes = causes,
                    asset = tokenAsset(t), symbol = t.symbol, decimals = seen.decimals ?: t.decimals,
                )
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

    /** Whether a token balance stored as [a] is read on a check at [nowMs]: always without an
     *  interval, when never read or its newest read failed, else once [intervalMs] passed
     *  since it was last verified. */
    private fun tokenDue(a: WatchAddressState?, nowMs: Long, intervalMs: Long): Boolean {
        val seen = a?.seen
        return intervalMs <= 0 || seen == null || a.error != null || elapsed(seen.checkedAtMs, nowMs, intervalMs)
    }

    /** When [a] was last attempted, verified or not; never attempted sorts first. */
    private fun lastAttempt(a: WatchAddressState?): Long =
        if (a == null) Long.MIN_VALUE else maxOf(a.seen?.checkedAtMs ?: 0, if (a.error != null) a.errorAtMs else 0)

    /** The balances of [pairs] ([readTokenRaw]), the Query tab's [TOKEN_READS_IN_FLIGHT] at a
     *  time, keyed by [key]; a pair the budget left unread is absent. */
    private suspend fun readTokens(
        pairs: List<Pair<WatchEntry, Token>>,
        call: EthCall,
        outOfTime: () -> Boolean,
    ): Map<String, TokenBalance> {
        val permits = Semaphore(TOKEN_READS_IN_FLIGHT)
        return coroutineScope {
            pairs.map { (e, t) ->
                async {
                    permits.withPermit {
                        if (outOfTime()) null
                        else key(e.address, tokenAsset(t)) to readTokenRaw(call, e.address, t, WATCH_RETRY_HINT)
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
     *  asking [inBlock] what each one did (null: no verified answer). Stops at the first
     *  block without one, and when [outOfTime] says so (then only the blocks scanned so far
     *  count: PARTIAL, or NONE before the first). */
    private suspend fun scan(
        fromBlock: Long,
        toBlock: Long,
        maxScanBlocks: Int,
        outOfTime: () -> Boolean,
        inBlock: suspend (Long) -> List<WatchCause>?,
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
            val got = try {
                inBlock(b)
            } catch (c: CancellationException) {
                throw c
            } catch (_: Throwable) {
                null
            } ?: return Search(WatchSearch.UNAVAILABLE, scannedFrom, causes)
            causes += got
            scannedFrom = b
            b--
        }
        return Search(if (lowest == fromBlock + 1) WatchSearch.COMPLETE else WatchSearch.PARTIAL, scannedFrom, causes)
    }

    /** One block's transaction as the native cause search reads it: who sent it, to whom
     *  (null for a contract creation), its hash and its value (hex wei). */
    internal data class BlockTx(val hash: String?, val from: String?, val to: String?, val value: String?)

    /** What a block holds for a set of addresses: its fee recipient and the transactions
     *  from or to any of them, in block order. */
    internal data class BlockSlice(val miner: String?, val txs: List<BlockTx>)

    /**
     * Block [blockJson] — `eth_getBlockByNumber` JSON with full transactions, verified
     * against the header's `transactionsRoot` by the engine — cut down to what touches
     * [addresses] (lowercase), so a check can keep it for every watched address's search.
     * Null when [blockJson] is no such block (the literal "null", an error envelope, a
     * hashes-only body, unparseable text): the caller must not read "nothing found" into a
     * block it could not see.
     */
    internal fun blockSlice(blockJson: String, addresses: Set<String>): BlockSlice? {
        val o = runCatching { json.parseToJsonElement(blockJson) as? JsonObject }.getOrNull() ?: return null
        val txs = o["transactions"] as? JsonArray ?: return null
        val out = ArrayList<BlockTx>()
        for (el in txs) {
            val tx = el as? JsonObject ?: return null // hashes only: cannot tell who sent what
            val from = tx.str("from")?.lowercase()
            val to = tx.str("to")?.lowercase()
            if (from in addresses || to in addresses) out += BlockTx(tx.str("hash"), from, to, tx.str("value"))
        }
        return BlockSlice(o.str("miner")?.lowercase(), out)
    }

    /**
     * What in block [blockNumber] — `eth_getBlockByNumber` JSON with full transactions —
     * touched [address]: transactions from or to it (verified against the header's
     * `transactionsRoot` by the engine) and the fee-recipient credit (`miner`, a header
     * field). Null when [blockJson] is no such block ([blockSlice]).
     *
     * Not withdrawals: neither engine's block JSON carries the `withdrawals` list (only
     * `withdrawalsRoot`), so a validator withdrawal is one of the things the texts name
     * as moving funds without a transaction. Should an engine add the list, it must
     * verify it against `withdrawalsRoot` before this reads it.
     */
    @JvmStatic
    fun causesIn(blockJson: String, address: String, blockNumber: Long): List<WatchCause>? =
        blockSlice(blockJson, setOf(address.lowercase()))?.let { causesIn(it, address, blockNumber) }

    internal fun causesIn(block: BlockSlice, address: String, blockNumber: Long): List<WatchCause> {
        val me = address.lowercase()
        val out = ArrayList<WatchCause>()
        for (tx in block.txs) {
            val kind = when {
                tx.from == me && tx.to == me -> WatchCauseKind.SELF
                tx.from == me -> WatchCauseKind.SENT
                tx.to == me -> WatchCauseKind.RECEIVED
                else -> continue
            }
            out += WatchCause(
                kind = kind,
                blockNumber = blockNumber,
                txHash = tx.hash,
                counterparty = when (kind) {
                    WatchCauseKind.SENT -> tx.to
                    WatchCauseKind.RECEIVED -> tx.from
                    else -> null
                },
                amount = tx.value?.let(::hexToDecimal),
            )
        }
        if (block.miner == me) out += WatchCause(WatchCauseKind.FEE_RECIPIENT, blockNumber)
        return out
    }

    /** One token log as the token cause search reads it: the emitting contract (lowercase),
     *  its topics (lowercase), its data, and its transaction's hash. */
    internal data class TokenLog(val tx: String?, val token: String, val topics: List<String>, val data: String?)

    /**
     * Block receipts [receiptsJson] — `eth_getBlockReceipts` JSON, verified against the
     * header's `receiptsRoot` by the engine — cut down to the `Transfer`, `Deposit` and
     * `Withdrawal` logs of the contracts [tokenKeys] that name one of [holders] (all
     * lowercase), so a check can keep them for every search. Null when [receiptsJson] is no
     * receipt list (the literal "null", an error envelope, unparseable text), so a block that
     * could not be read is never "nothing found".
     */
    internal fun tokenLogs(receiptsJson: String, tokenKeys: Set<String>, holders: Set<String>): List<TokenLog>? {
        val arr = runCatching { json.parseToJsonElement(receiptsJson) as? JsonArray }.getOrNull() ?: return null
        val out = ArrayList<TokenLog>()
        for (el in arr) {
            val receipt = el as? JsonObject ?: return null
            val logs = receipt["logs"] as? JsonArray ?: continue
            for (le in logs) {
                val log = le as? JsonObject ?: continue
                val token = log.str("address")?.lowercase() ?: continue
                if (token !in tokenKeys) continue
                val topics = (log["topics"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content?.lowercase() }
                    ?: continue
                val named = when (topics.firstOrNull()) {
                    TRANSFER_TOPIC -> topics.size == 3 &&
                        (topicAddress(topics[1]) in holders || topicAddress(topics[2]) in holders)
                    DEPOSIT_TOPIC, WITHDRAWAL_TOPIC -> topics.size == 2 && topicAddress(topics[1]) in holders
                    else -> false
                }
                if (named) {
                    out += TokenLog(log.str("transactionHash") ?: receipt.str("transactionHash"), token, topics, log.str("data"))
                }
            }
        }
        return out
    }

    /**
     * What [token]'s logs in block [blockNumber] — `eth_getBlockReceipts` JSON, verified
     * against the header's `receiptsRoot` by the engine — did to [holder]'s balance: a
     * `Transfer` from [holder] (SENT) or to it (RECEIVED), and a `Deposit` to it (WRAPPED) or
     * `Withdrawal` from it (UNWRAPPED) — a wrapped native token (WETH9, WXDAI) mints and
     * burns with these, without a `Transfer`; one that emits both for the same move is named
     * by its `Transfer` alone. Amounts are in the token's base units. A transfer from
     * [holder] to itself moves no balance and is not a cause; nor is an ERC-721 `Transfer`
     * (it indexes the id as a fourth topic), or a log whose address topics are not
     * addresses. Null when [receiptsJson] is no receipt list ([tokenLogs]). Logs of other
     * contracts are skipped, whatever topics they claim.
     */
    @JvmStatic
    fun transfersIn(receiptsJson: String, holder: String, token: Token, blockNumber: Long): List<WatchCause>? =
        tokenLogs(receiptsJson, setOf(token.key), setOf(holder.lowercase()))?.let { transfersIn(it, holder, token, blockNumber) }

    internal fun transfersIn(logs: List<TokenLog>, holder: String, token: Token, blockNumber: Long): List<WatchCause> {
        val me = holder.lowercase()
        val out = ArrayList<WatchCause>()
        for (log in logs) {
            if (log.token != token.key) continue
            val t = log.topics
            val amount = log.data?.let(::hexToDecimal)
            out += when {
                // Transfer(address indexed from, address indexed to, uint256 value)
                t.size == 3 && t[0] == TRANSFER_TOPIC -> {
                    val from = topicAddress(t[1]) ?: continue
                    val to = topicAddress(t[2]) ?: continue
                    when {
                        from == me && to == me -> continue
                        from == me -> WatchCause(WatchCauseKind.SENT, blockNumber, log.tx, to, amount)
                        to == me -> WatchCause(WatchCauseKind.RECEIVED, blockNumber, log.tx, from, amount)
                        else -> continue
                    }
                }
                t.size == 2 && t[0] == DEPOSIT_TOPIC && topicAddress(t[1]) == me ->
                    WatchCause(WatchCauseKind.WRAPPED, blockNumber, log.tx, null, amount)
                t.size == 2 && t[0] == WITHDRAWAL_TOPIC && topicAddress(t[1]) == me ->
                    WatchCause(WatchCauseKind.UNWRAPPED, blockNumber, log.tx, null, amount)
                else -> continue
            }
        }
        // A transaction with a Transfer of this holder is named by it: a wrapper that also
        // emits a mint or burn Transfer must not count the same move twice.
        val transferred = out.filter { it.kind == WatchCauseKind.SENT || it.kind == WatchCauseKind.RECEIVED }
            .mapTo(HashSet()) { it.txHash }
        return out.filter {
            (it.kind != WatchCauseKind.WRAPPED && it.kind != WatchCauseKind.UNWRAPPED) || it.txHash !in transferred
        }
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
            WatchCauseKind.WRAPPED -> "wrapped$amount$tx"
            WatchCauseKind.UNWRAPPED -> "unwrapped$amount$tx"
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
     *
     * The token balances are read too, each unless it was verified less than
     * [tokenIntervalMs] ago (0, the default: every check) — a host on a metered network reads
     * its many `eth_call`s less often than the one proof per address. A token change's cause
     * is searched in at most [maxTokenScanBlocks] blocks' receipts.
     */
    suspend fun check(
        network: String,
        reader: WatchReader,
        maxScanBlocks: Int = BalanceWatch.DEFAULT_SCAN_BLOCKS,
        budget: Duration = Duration.INFINITE,
        maxTokenScanBlocks: Int = maxScanBlocks,
        tokenIntervalMs: Long = 0,
    ): List<WatchChange>? {
        val entries = BalanceWatch.parseList(settings.watchListJson(network))
        if (entries.isEmpty()) return null
        if (!guard.withLock { inFlight.add(network) }) return null
        try {
            val previous = BalanceWatch.parseState(settings.watchStateJson(network))
            val now = nowMs()
            val out = BalanceWatch.check(
                entries, previous, reader, now, maxScanBlocks, budget, tokens = tokens(network),
                maxTokenScanBlocks = maxTokenScanBlocks,
                tokenIntervalMs = tokenIntervalMs,
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
