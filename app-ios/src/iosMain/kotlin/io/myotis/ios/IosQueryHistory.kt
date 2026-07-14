package io.myotis.ios

import io.myotis.ui.QueryHistory
import io.myotis.ui.QueryHistoryEntry
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import platform.Foundation.NSDate
import platform.Foundation.NSLock
import platform.Foundation.NSUserDefaults
import platform.Foundation.timeIntervalSince1970

@Serializable
private data class StoredEntry(val input: String, val timestampMillis: Long, val label: String)

/**
 * The iOS [QueryHistory]: a JSON array in NSUserDefaults (the file-backed
 * stores the other hosts use, minus the file management). Most-recent-first,
 * de-duplicated case-insensitively, capped at [MAX_ENTRIES].
 */
class IosQueryHistory : QueryHistory {

    private val defaults = NSUserDefaults.standardUserDefaults
    private val lock = NSLock()

    private inline fun <T> locked(block: () -> T): T {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }

    override fun entries(): List<QueryHistoryEntry> = locked {
        load().map { QueryHistoryEntry(it.input, it.timestampMillis, it.label) }
    }

    override fun add(input: String, label: String) = locked {
        val nowMs = (NSDate().timeIntervalSince1970 * 1000).toLong()
        val rest = load().filterNot { it.input.equals(input, ignoreCase = true) }
        val updated = (listOf(StoredEntry(input, nowMs, label)) + rest).take(MAX_ENTRIES)
        defaults.setObject(engineJson.encodeToString(updated), KEY)
    }

    override fun clear() = locked {
        defaults.removeObjectForKey(KEY)
    }

    /** Best-effort load; a malformed stored value just resets the history. */
    private fun load(): List<StoredEntry> {
        val raw = defaults.stringForKey(KEY) ?: return emptyList()
        return runCatching { engineJson.decodeFromString<List<StoredEntry>>(raw) }
            .getOrElse { emptyList() }
    }

    private companion object {
        const val KEY = "queryHistory"
        const val MAX_ENTRIES = 20
    }
}
