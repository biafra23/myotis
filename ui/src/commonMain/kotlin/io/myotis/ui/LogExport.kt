package io.myotis.ui

import kotlin.time.Clock
import kotlin.time.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/**
 * The Logs tab's Copy keeps the NEWEST shown lines that fit this many characters. The ring
 * holds up to 50k lines — tens of MB once the DEBUG RPC bodies are on — and a copy of all of
 * it ends wherever the destination stops reading: a bug tracker or a chat keeps the FIRST
 * part of an oversized paste and drops the rest, which is exactly the newest lines a
 * diagnosis wants. Sized for a GitHub issue comment (65,536 characters) with headroom for
 * [cutNote] and whatever the reader writes around the paste. A destination with a smaller
 * limit still keeps the note, which says what the copy holds and where the rest is.
 */
internal const val LOG_COPY_BUDGET_CHARS = 60_000

/**
 * Appended to a host's "saved" line: the file is meant to be handed to other people, and at
 * the DEBUG level the RPC access log in it carries the request bodies (logback-desktop.xml:
 * addresses, signed transactions). Desktop's on-disk file keeps them from any earlier DEBUG
 * session too, so the caution does not depend on the current level.
 */
const val LOG_SAVE_CAUTION =
    "Check it before sharing: at the DEBUG level it holds the RPC request bodies (addresses, signed transactions)."

/**
 * What the Logs tab's Copy puts on the clipboard: [text] holds the newest [copiedLines] of the
 * shown lines — whole lines only — behind a one-line [cutNote] when [omittedLines] older ones
 * did not fit [budgetChars]. [canSave] says whether this host has the Save… button the hint
 * points at.
 */
internal class LogCopy(
    val text: String,
    val copiedLines: Int,
    val omittedLines: Int,
    val budgetChars: Int,
    val canSave: Boolean,
) {
    val totalLines: Int get() = copiedLines + omittedLines
    val cut: Boolean get() = omittedLines > 0

    /** The one-line status the tab shows after copying. */
    fun status(): String = when {
        totalLines == 0 -> "Nothing to copy."
        !cut -> "Copied all $copiedLines lines."
        else -> "Copied the newest $copiedLines of $totalLines lines — Copy keeps the last " +
            "${budgetChars / 1000} k characters." + if (canSave) " Save… writes the whole log." else ""
    }
}

/**
 * The newest lines of [lines] that fit [budgetChars], formatted as the tab shows them, oldest
 * first, behind [cutNote] when any had to be left out. Lines are kept whole: the walk starts
 * at the tail and stops at the first (older) line that no longer fits. The newest line is
 * always kept, even alone over the budget — an empty copy would say less than a long one.
 * Formatting stops with the walk, so a 50k-line ring costs as much as the lines copied.
 */
internal fun copyNewest(
    lines: List<LogLine>,
    tz: TimeZone,
    canSave: Boolean,
    budgetChars: Int = LOG_COPY_BUDGET_CHARS,
): LogCopy {
    if (lines.isEmpty()) return LogCopy("", 0, 0, budgetChars, canSave)
    val kept = ArrayList<String>()  // newest first
    var used = 0
    var i = lines.size - 1
    while (i >= 0) {
        val s = formatLogLine(lines[i], tz)
        if (kept.isNotEmpty() && used + s.length > budgetChars) break
        kept += s
        used += s.length
        i--
    }
    val omitted = i + 1
    val sb = StringBuilder(used + 256)
    if (omitted > 0) sb.append(cutNote(kept.size, lines.size, budgetChars, canSave)).append('\n')
    for (k in kept.indices.reversed()) sb.append(kept[k])
    return LogCopy(sb.toString(), kept.size, omitted, budgetChars, canSave)
}

/** The first line of a cut copy — what it holds, what it dropped, and (where there is a
 *  Save… button) where the rest is. */
internal fun cutNote(copied: Int, total: Int, budgetChars: Int, canSave: Boolean): String =
    "--- Myotis log: the newest $copied of $total shown lines (Copy keeps the last $budgetChars " +
        "characters); ${total - copied} older lines left out" + saveHint(canSave) + " ---"

/** The note is read wherever the copy was pasted, so it says where Save… is. */
private fun saveHint(canSave: Boolean): String =
    if (canSave) "; Save… in the Logs tab writes the whole log" else ""

/** The whole of [lines] as the tab shows them, one per line, oldest first. */
internal fun formatLogs(lines: List<LogLine>, tz: TimeZone): String =
    buildString { formatLogsTo(this, lines, tz) }

/** [formatLogs] into [sink], line by line — a host writing a file never holds the whole
 *  rendering (50k lines with the DEBUG RPC bodies run to tens of MB). */
internal fun formatLogsTo(sink: Appendable, lines: List<LogLine>, tz: TimeZone) {
    for (l in lines) sink.append(formatLogLine(l, tz))
}

/** One line as the tab shows it: `HH:mm:ss.SSS L tag: message`, newline-terminated. */
internal fun formatLogLine(l: LogLine, tz: TimeZone): String =
    "${formatLogTime(l.timestampMillis, tz)} ${l.level} ${l.tag}: ${l.message}\n"

/** The file name Save… suggests: `myotis-yyyyMMdd-HHmm.log` in [tz], at [nowMillis] — cut
 *  from the ISO-8601 form, which is stable across kotlinx-datetime's field renames. */
@OptIn(kotlin.time.ExperimentalTime::class)
internal fun logFileName(nowMillis: Long, tz: TimeZone): String {
    val iso = Instant.fromEpochMilliseconds(nowMillis).toLocalDateTime(tz).toString()  // yyyy-MM-ddTHH:mm[:ss…]
    return "myotis-${iso.substring(0, 4)}${iso.substring(5, 7)}${iso.substring(8, 10)}-" +
        "${iso.substring(11, 13)}${iso.substring(14, 16)}.log"
}

@OptIn(kotlin.time.ExperimentalTime::class)
internal fun suggestedLogFileName(tz: TimeZone): String =
    logFileName(Clock.System.now().toEpochMilliseconds(), tz)

/** HH:mm:ss.SSS in [tz] (matches the logback console/file pattern). */
// kotlin.time.Instant (used by kotlinx-datetime 0.7.x on every target) is still
// @ExperimentalTime in the 2.2 stdlib.
@OptIn(kotlin.time.ExperimentalTime::class)
internal fun formatLogTime(ms: Long, tz: TimeZone): String {
    val dt = Instant.fromEpochMilliseconds(ms).toLocalDateTime(tz)
    fun p2(n: Int) = n.toString().padStart(2, '0')
    fun p3(n: Int) = n.toString().padStart(3, '0')
    return "${p2(dt.hour)}:${p2(dt.minute)}:${p2(dt.second)}.${p3(dt.nanosecond / 1_000_000)}"
}
