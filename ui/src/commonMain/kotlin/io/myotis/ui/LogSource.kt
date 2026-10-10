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

    /** The current minimum level being captured into the ring. */
    fun level(): LogLevel

    /**
     * Set the minimum level captured, live — raise it to quiet the log, lower it (e.g. to DEBUG)
     * to surface the chatty wire / peer-churn lines when diagnosing. Android gates its SLF4J
     * provider; Desktop sets the logback level of the app + wire loggers so lower levels are
     * actually emitted (not merely displayed). Applies to lines captured from now on.
     */
    fun setLevel(level: LogLevel)

    /** Whether [saveLog] can write a file on this host (shows the Logs tab's Save… button).
     *  Default false: a host without a save actual (iOS, for now) hides the button. */
    val canSaveLog: Boolean get() = false

    /**
     * Write the WHOLE log — not the tab's filtered view, and not the capped clipboard copy
     * ([copyNewest]) — to a file the user picks in the host's native save dialog, offered as
     * [suggestedName]: the host's on-disk log file where it keeps one (Desktop: logback's
     * rolling file, which also holds what the ring has already dropped), else the ring as
     * [write] renders it into the sink the host opens, line by line (Android). [onResult]
     * gets one human-readable line — where the file went, "cancelled", or the error — and
     * may be invoked FROM A WORKER THREAD; callers must only touch thread-safe state in it
     * (Compose snapshot state qualifies). Returns false when this host cannot save, in which
     * case [onResult] is never called.
     */
    fun saveLog(suggestedName: String, write: (Appendable) -> Unit, onResult: (String) -> Unit): Boolean = false
}

/**
 * User-selectable minimum log level for the Logs tab. TRACE/VERBOSE is intentionally NOT selectable
 * — libp2p floods it — so the ladder starts at DEBUG. Declared in ascending severity so
 * [Enum.ordinal] ranks levels for filtering.
 */
enum class LogLevel { DEBUG, INFO, WARN, ERROR }

/** One captured log line. Mirrors the Android `LogBuffer.Entry` shape. */
data class LogLine(
    val sequence: Long,           // monotonic id, stable across ring rotation (used as list key)
    val timestampMillis: Long,    // wall-clock millis at capture
    val level: Char,              // 'V' / 'D' / 'I' / 'W' / 'E'
    val tag: String,              // full logger name / source tag
    val message: String,          // message (+ appended stacktrace, if any)
)
