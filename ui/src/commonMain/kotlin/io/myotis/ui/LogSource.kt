package io.myotis.ui

/**
 * A live in-memory log ring the Logs tab reads. Platform-specific capture feeds it: on Android
 * the existing `LogBuffer` (which the in-tree SLF4J provider tees into); on Desktop a logback
 * appender into an in-memory ring. The UI polls [version] (cheap) and only re-[snapshot]s when
 * it changes — the same change-detection shape as [NodeController]'s snapshot flow.
 */
interface LogSource {
    /** Monotonic counter; bumped on every append and on [clear]. Cheap to read for change-polling. */
    fun version(): Long

    /** Snapshot of the ring in chronological (oldest-first) order. */
    fun snapshot(): List<LogLine>

    /** Drop all buffered lines (bumps [version]). */
    fun clear()
}

/** One captured log line. Mirrors the Android `LogBuffer.Entry` shape. */
data class LogLine(
    val sequence: Long,           // monotonic id, stable across ring rotation (used as list key)
    val timestampMillis: Long,    // wall-clock millis at capture
    val level: Char,              // 'V' / 'D' / 'I' / 'W' / 'E'
    val tag: String,              // full logger name / source tag
    val message: String,          // message (+ appended stacktrace, if any)
)
