package io.myotis.ui

import io.myotis.logindex.LogIndexDownloads
import io.myotis.logindex.LogIndexDownloads.Estimate
import io.myotis.logindex.LogIndexPresets
import io.myotis.logindex.LogIndexPresets.Preset

/**
 * The copy of the Index tab's "Predefined contracts" section, pure so the
 * desktop tests pin it: what one preset costs, what the selection costs, when
 * adding them together saves a re-walk, and what the metered-network setting
 * does right now. Every figure is an estimate (LogIndexDownloads' census) and
 * the copy says so with "~".
 */
object LogIndexPresetText {

    private fun b(n: Long) = LogIndexDownloads.formatBytes(n)

    /** The preset's row caption: contracts, start block, and its own cost. */
    fun presetLine(p: Preset, e: Estimate): String {
        val n = p.contracts.size
        return (if (n == 1) "1 contract" else "$n contracts") +
            " · from block ${grouped(p.fromBlock)} · ~${b(e.downloadBytes)} download · ~${b(e.storageBytes)} on disk"
    }

    /**
     * What adding the selection costs, in two lines: the download (and how far
     * the walk goes), and what stays on the device. Null for an empty selection.
     */
    fun totalLines(e: Estimate): List<String>? {
        if (e.presetIds.isEmpty()) return null
        return listOf(
            "Download: ~${b(e.downloadBytes)} — every block header from the head down " +
                "${grouped(e.blocksToWalk)} blocks, plus the receipts of the blocks that may hold " +
                "these contracts' logs, each checked against the chain before it is kept.",
            "Stored on this device: ~${b(e.storageBytes)} (~${grouped(e.logs)} logs). Keep " +
                "~${b(e.peakDiskBytes)} free: the index is saved by writing a new copy first.",
        )
    }

    /** "Together is cheaper" for a selection of several presets, or null when it is not worth saying. */
    fun togetherLine(e: Estimate): String? {
        if (!e.cheaperTogether) return null
        return "Adding these together is cheaper: one walk serves them all (~${b(e.downloadBytes)}). " +
            "Added one at a time, each walks the chain again (~${b(e.separateDownloadBytes)} in total, " +
            "~${b(e.savedBytes)} more)."
    }

    /**
     * The advice for a user who leaves some of the network's presets out, or
     * null: what adding ALL of them now would cost, against adding the rest later.
     */
    fun adviceLine(selected: List<Preset>, available: List<Preset>, headBlock: Long?): String? {
        val all = LogIndexDownloads.togetherAdvice(selected, available, headBlock) ?: return null
        return "If you will want the others too, add them now: all ${available.size} together are " +
            "~${b(all.downloadBytes)}, while adding them one at a time later costs ~${b(all.separateDownloadBytes)} — " +
            "every later addition walks the chain from the head again."
    }

    /** For an index that already watches contracts: what adding more means for it. */
    const val EXISTING_INDEX_NOTE =
        "This index already watches contracts. Adding more starts a new walk from the head for the " +
            "new ones — the download above — and the logs collected so far are kept."

    /**
     * What the metered-network setting does right now, given the host's report
     * ([networkMetering]: the API's METERED / UNMETERED / UNKNOWN name, null when
     * the host does not report it).
     */
    fun meteredLine(allowMetered: Boolean, networkMetering: String?): String = when {
        allowMetered ->
            "Downloads also run on metered connections (mobile data, hotspots) — mind your data plan."
        networkMetering == "METERED" ->
            "This device is on a metered connection now: the download waits until it is on an " +
                "unmetered one (Wi-Fi). $HEAD_NOTE"
        networkMetering == null || networkMetering == "UNKNOWN" ->
            "Unmetered only. This device does not report metered connections, so downloads are " +
                "never held here."
        else ->
            "Unmetered only: on a metered connection (mobile data, a hotspot) the download waits " +
                "for Wi-Fi. $HEAD_NOTE"
    }

    /** What still runs on a metered network: head-follow, and the catch-up after time offline. */
    private const val HEAD_NOTE =
        "New blocks at the head are still followed, including the catch-up after time offline — " +
            "for a large mainnet preset that can be hundreds of MB per day the device was off."


    /**
     * The label suffix of a preset whose contracts are all listed. "— added",
     * unless one of them is listed from a LATER block than the preset's: the
     * index then covers less history than the preset stands for, and the
     * fromBlock is a trust assertion (below it the index answers empty), so the
     * label must not claim the preset's coverage. Not re-added either way —
     * the same address under another fromBlock is another index fingerprint.
     */
    fun addedSuffix(p: Preset, listed: Map<String, Long>): String {
        val later = p.contracts.any { c -> (listed[c.address.lowercase()] ?: return@any false) > c.fromBlock }
        return if (later) " — added from a later block: earlier history not covered" else " — added"
    }

    /** The presets of [network] whose contracts are not all in the watch list yet. */
    fun addable(network: String, listed: Set<String>): List<Preset> =
        LogIndexPresets.forNetwork(network).filterNot { p -> p.contracts.all { it.address.lowercase() in listed } }

    /** Digits grouped by thousands ("14,737,691"). Pure Kotlin for Kotlin/Native. */
    internal fun grouped(n: Long): String {
        val s = n.toString()
        val neg = s.startsWith("-")
        val digits = if (neg) s.drop(1) else s
        val out = StringBuilder()
        digits.forEachIndexed { i, c ->
            if (i > 0 && (digits.length - i) % 3 == 0) out.append(',')
            out.append(c)
        }
        return (if (neg) "-" else "") + out
    }
}
