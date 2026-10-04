package io.myotis.ui

import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/**
 * The user's log-index watch list: which contracts to index, and from which
 * block. Entries are entered on the Index tab (or arrive baked into an
 * imported snapshot), persisted host-side per network as the JSON array this
 * object serializes, and turned into the engine config on every push — the
 * engine only ever sees the generic config JSON (docs/eth-getlogs-design.md §5).
 *
 * A `fromBlock` is a TRUST ASSERTION, not a hint: the engine clamps a query's
 * coverage requirement to it, so a value LATER than the contract's real
 * deployment makes the index answer without the earlier part being covered —
 * events silently vanish. Undershooting cannot lie (no logs exist below
 * deployment); the Index tab's copy says so.
 *
 * REMOVING a contract is recorded here, not just forgotten: the engine's
 * config push is additive (it unions with what the index already subscribes),
 * so an address that merely disappeared from this list would stay indexed
 * forever. A removed address stays in the store as an `unwatched` marker —
 * `{"address":"0x…","unwatched":true}`, no `fromBlock` — and the push names
 * it under the config's `unwatch`, which is what makes the engine drop the
 * entry with its coverage and its logs (engine ABI ≥ 37).
 *
 * A marker is a removal WAITING TO BE DELIVERED, not a standing ban. It
 * survives a push that never happened (the network was stopped: the removal
 * takes effect at the next start) and one the engine did not take, and it goes
 * as soon as a push that carried it was taken ([delivered]). Left in place it
 * would unwatch the address again on every later push — also after something
 * this host cannot see had subscribed it anew (a snapshot dropped into the data
 * dir), deleting what was just supplied. It also goes when the address is
 * subscribed again before delivery: added by hand ([watch]) or brought in by an
 * import ([adoptImported]).
 */
object LogIndexWatch {

    data class Entry(val address: String, val fromBlock: Long)

    // One object of the store's array, and the fields read out of it. Shared by
    // the entry parser and the marker reader so both see the store the same way.
    private val OBJECT = Regex("""\{[^{}]*\}""")
    private val ADDRESS = Regex(""""address"\s*:\s*"((?:[^"\\]|\\.)*)"""")
    private val FROM_BLOCK = Regex(""""fromBlock"\s*:\s*(\d+)""")
    private val UNWATCHED = Regex(""""unwatched"\s*:\s*true""")

    // The `unwatch` array of a config push, exactly as [configJson] writes it.
    private val PUSHED_UNWATCH = Regex(""""unwatch":\[([^\]]*)\]""")

    /** A 0x-prefixed 20-byte hex address — the only shape the engine accepts. */
    @JvmStatic
    fun isValidAddress(s: String): Boolean =
        s.length == 42 && s.startsWith("0x") && s.drop(2).all {
            it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F'
        }

    /**
     * Serialize for [Settings.setLogIndexWatchJson]: the watched [entries],
     * then one marker per removed address in [unwatched]. A marker carries no
     * `fromBlock` on purpose — that is what keeps [parse] (and an older build
     * reading this store after a downgrade) from mistaking it for a
     * subscription.
     */
    @JvmStatic
    @JvmOverloads
    fun serialize(entries: List<Entry>, unwatched: List<String> = emptyList()): String =
        (entries.map { """{"address":"${it.address}","fromBlock":${it.fromBlock}}""" } +
            unwatched.map { """{"address":"$it","unwatched":true}""" })
            .joinToString(",", "[", "]")

    /**
     * Parse [Settings.logIndexWatchJson]'s array. Tolerant the same way the
     * settings files are: a malformed or hand-edited value yields the entries
     * that do parse (worst case none) rather than an exception at boot, and
     * fields inside an object may appear in either order. Invalid addresses
     * are dropped — a typo that slipped into the store must not reach the
     * engine, where its fromBlock would extend the backfill walk. Duplicate
     * addresses (bytes-equal, so case-insensitively) keep the FIRST entry:
     * the engine rejects a config with a duplicate address OUTRIGHT — the
     * whole network's eth_getLogs would go dark over one — so dedup must
     * happen at every boundary the store passes through. Removed-address
     * markers are not entries and are skipped — [unwatched] reads those.
     */
    @JvmStatic
    fun parse(json: String): List<Entry> {
        val seen = HashSet<String>()
        return OBJECT.findAll(json)
            .mapNotNull { obj ->
                val addr = ADDRESS.find(obj.value)?.groupValues?.get(1) ?: return@mapNotNull null
                val from = FROM_BLOCK.find(obj.value)?.groupValues?.get(1)?.toLongOrNull()
                    ?: return@mapNotNull null
                if (isValidAddress(addr) && seen.add(addr.lowercase())) Entry(addr, from) else null
            }
            .toList()
    }

    /**
     * The removed addresses [json] carries (see the class doc), in store
     * order, deduplicated like [parse]. An address that ALSO parses as a
     * watched entry is not reported: the engine refuses a push naming one
     * address under both `watch` and `unwatch`, and a hand-edited store must
     * not be able to turn the whole network's eth_getLogs off that way. The
     * subscription wins: it is the one the Index tab shows, and silently
     * dropping a contract the user can see listed is the worse surprise.
     */
    @JvmStatic
    fun unwatched(json: String): List<String> {
        val watched = parse(json).mapTo(HashSet()) { it.address.lowercase() }
        val seen = HashSet<String>()
        return OBJECT.findAll(json)
            .mapNotNull { obj ->
                if (!UNWATCHED.containsMatchIn(obj.value)) return@mapNotNull null
                val addr = ADDRESS.find(obj.value)?.groupValues?.get(1) ?: return@mapNotNull null
                val key = addr.lowercase()
                if (isValidAddress(addr) && key !in watched && seen.add(key)) addr else null
            }
            .toList()
    }

    /**
     * [json] with everything that does not parse dropped, entries and removal
     * markers alike kept — what a host runs a persisted value through on load
     * so a hand-edited one degrades instead of reaching the engine raw.
     */
    @JvmStatic
    fun normalize(json: String): String = serialize(parse(json), unwatched(json))

    /**
     * The store after the user added [entry]: appended to the watched
     * entries, and no longer marked removed — subscribing again is the newer
     * statement. An address already watched keeps its existing entry (the
     * Index tab refuses the duplicate before it gets here).
     */
    @JvmStatic
    fun watch(json: String, entry: Entry): String {
        val key = entry.address.lowercase()
        val entries = parse(json)
        return serialize(
            if (entries.any { it.address.lowercase() == key }) entries else entries + entry,
            unwatched(json).filterNot { it.lowercase() == key },
        )
    }

    /**
     * The store after the user removed [address]: its entry is gone and the
     * address is marked removed, so the next config push tells the engine to
     * drop it ([delivered] takes the marker out again once one has). Marked
     * even when no entry was there — that is how a contract
     * the engine indexes but this list never held (an imported snapshot's, or
     * one removed before removal reached the engine) is unsubscribed.
     */
    @JvmStatic
    fun unwatch(json: String, address: String): String {
        val key = address.lowercase()
        val marked = unwatched(json)
        return serialize(
            parse(json).filterNot { it.address.lowercase() == key },
            if (marked.any { it.lowercase() == key }) marked else marked + address,
        )
    }

    /**
     * The store with [address] gone entirely — no entry and no removal marker.
     * For a removal with nothing to deliver: a host that never pushed a config
     * cannot have subscribed the address, so a marker would only wait for a
     * push it has no business in, and unwatch a contract that arrived by other
     * means in the meantime.
     */
    @JvmStatic
    fun forget(json: String, address: String): String {
        val key = address.lowercase()
        return serialize(
            parse(json).filterNot { it.address.lowercase() == key },
            unwatched(json).filterNot { it.lowercase() == key },
        )
    }

    /**
     * The store after a successful snapshot import: every contract the import
     * BROUGHT IN joins the watched entries, so this list keeps describing what
     * the index holds and an imported subscription is not left looking like
     * one the user never asked for. "Brought in" is the engine's entry list
     * after the import ([statusAfter] — the import result, which embeds the
     * status) minus the one before it ([statusBefore]): a contract the engine
     * already indexed without being listed here stays unlisted, since that is
     * exactly the state the Index tab offers to clean up.
     *
     * A brought-in address also loses its removal marker. Importing it is the
     * newer statement, and a marker left behind would have the very next push
     * delete what was just imported.
     *
     * A topic-restricted entry ([LogIndexStatus.Entry.restricted]) is NOT
     * listed: this store carries no topics, so the next push would name the
     * address unrestricted — a topic conflict, on which the engine replaces
     * the whole index. It stays among the contracts the Index tab shows as
     * indexed but unlisted, where it can be removed.
     *
     * [statusBefore] that is null, or is not a status at all (the probe failed
     * and returned an error object), leaves [json] untouched: with nothing to
     * subtract, every contract the engine holds would count as brought in —
     * including ones whose removal is still waiting to be delivered, which
     * would be listed again and lose their marker. The Index tab shows the
     * unlisted contracts instead, and the user decides.
     */
    @JvmStatic
    fun adoptImported(json: String, statusBefore: String?, statusAfter: String): String {
        if (statusBefore == null || !LogIndexStatus.isStatus(statusBefore)) return json
        val before = LogIndexStatus.parse(statusBefore).entries.mapTo(HashSet()) { it.address }
        val brought = LogIndexStatus.parse(statusAfter).entries.filter { it.address !in before }
        val entries = parse(json)
        val listed = entries.mapTo(HashSet()) { it.address.lowercase() }
        val broughtKeys = brought.mapTo(HashSet()) { it.address }
        return serialize(
            entries + brought.filter { it.address !in listed && !it.restricted }
                .map { Entry(it.address, it.fromBlock) },
            unwatched(json).filterNot { it.lowercase() in broughtKeys },
        )
    }

    /**
     * The store after the engine TOOK the config push [pushedConfig] (what
     * [configJson] built, and `setLogIndexConfig` answered true for): the
     * removal markers that push carried are dropped — see the class doc for
     * why a delivered marker must not stay. [json] is the store as it is NOW,
     * which may have been edited since the push was built, so only an address
     * that is still marked goes: one re-added in between is no marker any
     * more, and one removed in between was not in the push and waits for the
     * next. Returns [json] itself when there is nothing to drop, so a host can
     * skip the write.
     */
    @JvmStatic
    fun delivered(json: String, pushedConfig: String): String {
        val sent = PUSHED_UNWATCH.find(pushedConfig)?.groupValues?.get(1)
            ?.split(',')?.mapTo(HashSet()) { it.trim().trim('"').lowercase() }
            ?: return json
        val marked = unwatched(json)
        val left = marked.filterNot { it.lowercase() in sent }
        return if (left.size == marked.size) json else serialize(parse(json), left)
    }

    /**
     * The engine config JSON for a push, or null when the user has expressed
     * nothing to disable with: a disable ships ONLY when the host holds an
     * explicit persisted flag ([configured] — [Settings.logIndexConfigured]).
     * The cases:
     *
     * - Enabled: always a push (with the entries; or with `watch:[]` when an
     *   imported snapshot is the subscription — the engine's config union
     *   keeps its baked-in watch-table, and the push re-asserts
     *   enabled/maxSpeed on restart).
     * - Disabled AND configured: the DISABLE push. Skipping it would let the
     *   engine's boot-time activate-from-disk re-enable an imported index on
     *   every restart — a disabled toggle must win.
     * - Disabled, NOT configured: null, EVEN WITH ENTRIES. Entries alone are
     *   an additive act (typed on the Index tab without ever touching
     *   Collect); turning them into an `enabled:false` push would kill a
     *   dropped-in snapshot the engine activated at boot — a disable the
     *   user never expressed. On every host the enable toggle and import both
     *   persist the flag, so a real turn-off always has [configured] = true.
     *
     * No names: display names are resolved by the receiving engine (ENS
     * reverse lookup in its naming pass), never entered here.
     *
     * Removed addresses ride along as `unwatch` (see the class doc), on
     * exactly the pushes that go out anyway; a host that got `true` for the
     * push hands it to [delivered]. A null push carries none — the Index tab
     * makes sure a removal that has to reach the engine is not stuck behind
     * one (it records the engine's own state as this host's settings first).
     */
    @JvmStatic
    @JvmOverloads
    fun configJson(
        watchJson: String,
        enabled: Boolean,
        maxSpeed: Boolean = false,
        configured: Boolean = false,
        backfillPaused: Boolean = false,
    ): String? {
        if (!enabled && !configured) return null
        val entries = parse(watchJson)
        val watch = entries.joinToString(",") {
            """{"address":"${it.address}","fromBlock":${it.fromBlock}}"""
        }
        // Omitted when empty, so a store without removals pushes the exact
        // JSON it always did.
        val unwatch = unwatched(watchJson).takeIf { it.isNotEmpty() }
            ?.joinToString(",", ""","unwatch":[""", "]") { "\"$it\"" }
            .orEmpty()
        return """{"enabled":$enabled,"maxSpeed":$maxSpeed,"backfillPaused":$backfillPaused,"watch":[$watch]$unwatch}"""
    }

    /**
     * The watch list the retired built-in "Kohaku contracts" preset subscribed
     * (tornado-cash registries, the railgun proxy, privacy-pools + its sepolia
     * pools), kept ONLY as migration seed data: a user who had the preset
     * toggle on has `logIndex.<network>=true` persisted but no watch entries —
     * the preset lived in code. Hosts seed their (absent) watch store from
     * this on first read so the next config push does not silently drop the
     * user's four-plus subscriptions. Null for networks the preset never
     * covered. Labels are not carried over (the generic config has no names;
     * the engine's naming pass and imported snapshots supply display names).
     */
    @JvmStatic
    fun legacyKohakuWatchJson(network: String): String? = when (network) {
        "mainnet" -> serialize(listOf(
            Entry("0xB20c66C4DE72433F3cE747b58B86830c459CA911", 14_173_395), // tornado instance registry
            Entry("0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2", 14_173_129), // tornado relayer registry
            Entry("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9", 14_693_013), // railgun proxy
            Entry("0x6818809EefCe719E480a7526D76bD3e561526b46", 22_153_713), // privacy-pools entrypoint
        ))
        "sepolia" -> serialize(listOf(
            Entry("0x4e69fD587118dFb64957d18654E3894118E9B1BF", 5_594_611), // tornado instance registry
            Entry("0xD6663593E71e4916eCb6f6606e1A6FbfA1634ffA", 5_594_660), // tornado relayer registry
            Entry("0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea", 5_784_774), // railgun proxy
            Entry("0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB", 8_461_453), // privacy-pools entrypoint
            Entry("0x644d5A2554d36e27509254F32ccfeBe8cd58861f", 8_461_453), // privacy-pools ETH pool
            Entry("0x6709277E170DEe3E54101cDb73a450E392ADfF54", 8_461_453), // privacy-pools USDT pool
            Entry("0x0b062Fe33c4f1592D8EA63f9a0177FcA44374C0f", 8_461_453), // privacy-pools USDC pool
        ))
        else -> null
    }
}
