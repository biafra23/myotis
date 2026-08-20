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
     * that do parse (worst case none) rather than an exception at boot.
     * Invalid addresses are dropped — a typo that slipped into the store must
     * not reach the engine, where its fromBlock would extend the backfill walk.
     */
    @JvmStatic
    fun parse(json: String): List<Entry> =
        Regex(""""address"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*"fromBlock"\s*:\s*(\d+)""")
            .findAll(json)
            .mapNotNull { m ->
                val addr = m.groupValues[1]
                val from = m.groupValues[2].toLongOrNull() ?: return@mapNotNull null
                if (isValidAddress(addr)) Entry(addr, from) else null
            }
            .toList()

    /**
     * The engine config JSON for a push, or null when there is nothing to say
     * (no entries and not enabled — the caller then skips the push entirely,
     * so an engine without a config keeps eth_getLogs in its honest
     * not-configured state). With entries but disabled the push still goes out:
     * that is how an active index is turned off. With no entries but enabled
     * (an imported snapshot is the subscription — the engine's config union
     * keeps its baked-in watch-table) the push carries the empty list and only
     * re-asserts enabled/maxSpeed on restart.
     *
     * No names: display names are resolved by the receiving engine (ENS
     * reverse lookup in its naming pass), never entered here.
     */
    @JvmStatic
    @JvmOverloads
    fun configJson(watchJson: String, enabled: Boolean, maxSpeed: Boolean = false): String? {
        val entries = parse(watchJson)
        if (entries.isEmpty() && !enabled) return null
        val watch = entries.joinToString(",") {
            """{"address":"${it.address}","fromBlock":${it.fromBlock}}"""
        }
        return """{"enabled":$enabled,"maxSpeed":$maxSpeed,"watch":[$watch]}"""
    }
}
