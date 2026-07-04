package io.myotis.desktop

import io.myotis.ui.QueryHistory
import io.myotis.ui.QueryHistoryEntry
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * Desktop actual of [QueryHistory]: a file-backed, most-recent-first history of Query-tab inputs,
 * mirroring Android's `AndroidQueryHistory` on-disk format (tab-separated
 * `timestampMs<TAB>input<TAB>label` lines) under the app data dir. Synchronized; capped so the
 * file and UI list can't grow unbounded.
 */
class DesktopQueryHistory(private val file: Path) : QueryHistory {
    // Most-recent-first. Guarded by `this` (read from the UI thread, written from query coroutines).
    private val entries = ArrayList<QueryHistoryEntry>()
    private var loaded = false

    @Synchronized
    override fun entries(): List<QueryHistoryEntry> {
        ensureLoaded()
        return ArrayList(entries)
    }

    @Synchronized
    override fun add(input: String, label: String) {
        ensureLoaded()
        val trimmed = sanitize(input)
        if (trimmed.isEmpty()) return
        // De-dup by input, case-insensitively (ENS names are case-insensitive; addresses in hex).
        entries.removeAll { it.input.equals(trimmed, ignoreCase = true) }
        entries.add(0, QueryHistoryEntry(trimmed, System.currentTimeMillis(), sanitize(label)))
        while (entries.size > MAX) entries.removeAt(entries.size - 1)
        rewrite()
    }

    @Synchronized
    override fun clear() {
        entries.clear()
        loaded = true
        runCatching { Files.deleteIfExists(file) }
    }

    private fun ensureLoaded() {
        if (loaded) return
        loaded = true
        if (!Files.exists(file)) return
        runCatching {
            Files.readAllLines(file, StandardCharsets.UTF_8).forEach { raw ->
                val line = raw.trim()
                if (line.isEmpty()) return@forEach
                val first = line.indexOf('\t')
                if (first < 0) return@forEach
                val second = line.indexOf('\t', first + 1)
                val ts = line.substring(0, first).toLongOrNull() ?: return@forEach
                val input: String
                val label: String
                if (second < 0) {
                    input = line.substring(first + 1); label = ""
                } else {
                    input = line.substring(first + 1, second); label = line.substring(second + 1)
                }
                if (input.isNotEmpty()) entries.add(QueryHistoryEntry(input, ts, label))
            }
        }
    }

    private fun rewrite() {
        runCatching {
            // Ensure the data dir exists — on a first-ever run the app dir may not be created yet.
            file.parent?.let { Files.createDirectories(it) }
            val sb = StringBuilder()
            entries.forEach {
                sb.append(it.timestampMillis).append('\t').append(it.input).append('\t').append(it.label).append('\n')
            }
            Files.write(file, sb.toString().toByteArray(StandardCharsets.UTF_8))
        }
    }

    private companion object {
        const val MAX = 50
        /** Trim and replace TSV-breaking chars so one free-text input can't split a record. */
        fun sanitize(s: String?): String =
            (s ?: "").trim().replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')
    }
}
