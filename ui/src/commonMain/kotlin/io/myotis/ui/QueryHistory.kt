package io.myotis.ui

/**
 * Persistent, most-recent-first history of Query-tab inputs (addresses / ENS names), so the user
 * can re-run a past query with one tap instead of retyping. Each platform supplies its own
 * file-backed actual: Android reuses the existing `AndroidQueryHistory` file (so previously stored
 * queries are retained), Desktop writes its own file under the app data dir.
 */
interface QueryHistory {
    /** Snapshot of history, most-recent-first. */
    fun entries(): List<QueryHistoryEntry>

    /**
     * Record [input], moving it to the front (de-duplicated case-insensitively). [label] is the
     * last thing the input resolved to (e.g. an ENS name's address, or empty for a plain address)
     * — display sugar only; re-running uses [input].
     */
    fun add(input: String, label: String)

    /** Forget all history. */
    fun clear()
}

/** One past query. [label] may be empty (never null). */
data class QueryHistoryEntry(
    val input: String,
    val timestampMillis: Long,
    val label: String,
)
