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
 */
object LogIndexWatch {

    data class Entry(val address: String, val fromBlock: Long)

    /** A 0x-prefixed 20-byte hex address — the only shape the engine accepts. */
    @JvmStatic
    fun isValidAddress(s: String): Boolean =
        s.length == 42 && s.startsWith("0x") && s.drop(2).all {
            it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F'
        }

    /** Serialize for [Settings.setLogIndexWatchJson]. */
    @JvmStatic
    fun serialize(entries: List<Entry>): String =
        entries.joinToString(",", "[", "]") {
            """{"address":"${it.address}","fromBlock":${it.fromBlock}}"""
        }

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
     * happen at every boundary the store passes through.
     */
    @JvmStatic
    fun parse(json: String): List<Entry> {
        val addrRe = Regex(""""address"\s*:\s*"((?:[^"\\]|\\.)*)"""")
        val fromRe = Regex(""""fromBlock"\s*:\s*(\d+)""")
        val seen = HashSet<String>()
        return Regex("""\{[^{}]*\}""").findAll(json)
            .mapNotNull { obj ->
                val addr = addrRe.find(obj.value)?.groupValues?.get(1) ?: return@mapNotNull null
                val from = fromRe.find(obj.value)?.groupValues?.get(1)?.toLongOrNull()
                    ?: return@mapNotNull null
                if (isValidAddress(addr) && seen.add(addr.lowercase())) Entry(addr, from) else null
            }
            .toList()
    }

    /**
     * The engine config JSON for a push, or null when there is nothing to say
     * (no entries, not enabled, and the network was never configured — the
     * caller then skips the push entirely, so an engine without a config keeps
     * eth_getLogs in its honest not-configured state). With entries but
     * disabled the push still goes out: that is how an active index is turned
     * off. With no entries but enabled (an imported snapshot is the
     * subscription — the engine's config union keeps its baked-in watch-table)
     * the push carries the empty list and only re-asserts enabled/maxSpeed on
     * restart.
     *
     * [configured] = the host has an explicit persisted enabled/disabled flag
     * for this network ([Settings.logIndexConfigured]). It matters for exactly
     * one case: entries empty AND disabled. On a virgin network that is
     * "nothing to say" (null) — but after an import-then-disable it is the
     * DISABLE push, and skipping it would let the engine's boot-time
     * activate-from-disk re-enable the index on every restart. A disabled
     * toggle must win, so a configured network always pushes.
     *
     * No names: display names are resolved by the receiving engine (ENS
     * reverse lookup in its naming pass), never entered here.
     */
    @JvmStatic
    @JvmOverloads
    fun configJson(
        watchJson: String,
        enabled: Boolean,
        maxSpeed: Boolean = false,
        configured: Boolean = false,
    ): String? {
        val entries = parse(watchJson)
        if (entries.isEmpty() && !enabled && !configured) return null
        val watch = entries.joinToString(",") {
            """{"address":"${it.address}","fromBlock":${it.fromBlock}}"""
        }
        return """{"enabled":$enabled,"maxSpeed":$maxSpeed,"watch":[$watch]}"""
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
