package io.myotis.desktop

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.classic.spi.ThrowableProxyUtil
import ch.qos.logback.core.AppenderBase
import io.myotis.ui.LogLevel
import io.myotis.ui.LogLine
import io.myotis.ui.LOG_SAVE_CAUTION
import io.myotis.ui.LogSource
import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicLong

/**
 * Desktop actual of [LogSource]: an in-memory ring fed by [DesktopLogAppender] (wired into
 * logback-desktop.xml). A process-wide singleton because logback instantiates the appender
 * itself, so the appender and the UI must meet on the same instance. Mirrors Android's
 * `LogBuffer` (50k-line ring, monotonic version + sequence).
 */
object DesktopLogSource : LogSource {
    private const val MAX_LINES = 50_000
    private val lock = Any()
    private val buffer = ArrayDeque<LogLine>()
    private val version = AtomicLong()
    private val seq = AtomicLong()

    /** Append a captured line (called from [DesktopLogAppender]). */
    fun append(timestampMillis: Long, level: Char, tag: String, message: String) {
        synchronized(lock) {
            buffer.addLast(LogLine(seq.incrementAndGet(), timestampMillis, level, tag, message))
            while (buffer.size > MAX_LINES) buffer.removeFirst()
        }
        version.incrementAndGet()
    }

    override fun version(): Long = version.get()
    override fun snapshot(): List<LogLine> = synchronized(lock) { buffer.toList() }
    override fun clear() {
        synchronized(lock) { buffer.clear() }
        version.incrementAndGet()
    }

    override val canSaveLog: Boolean get() = true

    /**
     * Desktop's Save…: the AWT save dialog (on the EDT, like the log-index import dialog;
     * owned by the showing frame, so it is modal to the app window), then a copy of
     * logback's active log file — the rolling FILE appender of logback-desktop.xml, fed by
     * the same per-logger levels as this ring, so it normally holds everything the tab shows
     * plus what the ring has already dropped. Not right after a roll, though: the policy rolls
     * at 10 MB (quickly, with the DEBUG RPC bodies on), and then the active file holds minutes
     * while the ring still holds the span a diagnosis wants. So the file is copied only when
     * it is at least as large as the ring's own rendering — a file that holds every line the
     * ring holds is larger, its lines carry more (thread, logger) — and otherwise, as under a
     * logback config without a file appender, the ring is streamed through [write] instead.
     * The rolled `.gz` siblings are named, not copied, and the result line says which of the
     * two was written.
     */
    override fun saveLog(suggestedName: String, write: (Appendable) -> Unit, onResult: (String) -> Unit): Boolean {
        java.awt.EventQueue.invokeLater {
            val owner = java.awt.Frame.getFrames().firstOrNull { it.isShowing }
            val dialog = java.awt.FileDialog(owner, "Save the Myotis log", java.awt.FileDialog.SAVE)
            dialog.file = suggestedName
            dialog.isVisible = true
            val dir = dialog.directory
            val name = dialog.file
            if (dir == null || name == null) {
                onResult("Save cancelled.")
                return@invokeLater
            }
            val target = java.io.File(dir, name)
            // The copy (up to 10 MB) and a 50k-line render both stay off the EDT.
            Thread({
                onResult(
                    runCatching { writeLog(target, write) }
                        .getOrElse { "Save failed: ${it.message ?: it::class.java.simpleName}" },
                )
            }, "myotis-log-save").start()
        }
        return true
    }

    private fun writeLog(target: java.io.File, write: (Appendable) -> Unit): String {
        val source = logbackFile()
        val dir = source?.absoluteFile?.parentFile
        val rolled = dir?.listFiles { f -> f.name.endsWith(".log.gz") }?.size ?: 0
        val older = if (rolled > 0) "; $rolled older rolled file(s) stay in $dir" else ""
        if (source != null && source.isFile && source.length() >= ringChars()) {
            java.nio.file.Files.copy(
                source.toPath(), target.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
            return "Saved ${source.name} (${target.length() / 1024} kB) to $target$older. $LOG_SAVE_CAUTION"
        }
        target.bufferedWriter().use { write(it) }
        val why = when {
            source == null -> ""
            !source.isFile -> " — ${source.name} is not there"
            else -> " — ${source.name} rolled recently and holds less$older"
        }
        return "Saved the tab's log (${target.length() / 1024} kB) to $target$why. $LOG_SAVE_CAUTION"
    }

    /** The size of the ring as the tab renders it (see `formatLogLine`: 18 characters of
     *  stamp, level and punctuation around tag and message), summed under the lock. */
    private fun ringChars(): Long = synchronized(lock) {
        buffer.sumOf { 18L + it.tag.length + it.message.length }
    }

    /** The active file of logback's file appender (FILE in logback-desktop.xml), wherever it
     *  is attached, or null when the running config has none. */
    private fun logbackFile(): java.io.File? {
        val ctx = LoggerFactory.getILoggerFactory() as? ch.qos.logback.classic.LoggerContext ?: return null
        for (logger in ctx.loggerList) {
            for (appender in logger.iteratorForAppenders()) {
                if (appender is ch.qos.logback.core.FileAppender<*>) return java.io.File(appender.file)
            }
        }
        return null
    }

    // The app's own loggers whose level the Logs-tab control drives. Setting the wire logger too
    // is what lets the control actually reveal the (otherwise ERROR-gated) networking DEBUG lines.
    private val CONTROLLED_LOGGERS = listOf("com.jaeckel.ethp2p", "io.myotis", "com.jaeckel.ethp2p.networking")

    // Reflects the app-code logger (com.jaeckel.ethp2p). By default the wire logger starts quieter
    // (ERROR, per logback-desktop.xml) so the chip can read one notch more verbose than the wire is
    // actually capturing until the user picks a level — at which point setLevel() brings all three
    // (app, io.myotis, wire) to the selection, so the chip becomes exact.
    override fun level(): LogLevel =
        fromLogback((LoggerFactory.getLogger("com.jaeckel.ethp2p") as? Logger)?.effectiveLevel)

    override fun setLevel(level: LogLevel) {
        val lb = when (level) {
            LogLevel.DEBUG -> Level.DEBUG
            LogLevel.INFO -> Level.INFO
            LogLevel.WARN -> Level.WARN
            LogLevel.ERROR -> Level.ERROR
        }
        CONTROLLED_LOGGERS.forEach { (LoggerFactory.getLogger(it) as? Logger)?.level = lb }
        // The pinned RPC access logger doesn't inherit io.myotis: its bodies (DEBUG) follow the chip,
        // while the per-call INFO summaries stay on at WARN/ERROR as the pin intends.
        (LoggerFactory.getLogger("io.myotis.jsonrpc.access") as? Logger)?.level =
            if (level == LogLevel.DEBUG) Level.DEBUG else Level.INFO
    }

    private fun fromLogback(lvl: Level?): LogLevel = when {
        lvl == null -> LogLevel.INFO
        lvl.toInt() >= Level.ERROR_INT -> LogLevel.ERROR
        lvl.toInt() >= Level.WARN_INT -> LogLevel.WARN
        lvl.toInt() >= Level.INFO_INT -> LogLevel.INFO
        else -> LogLevel.DEBUG
    }
}

/**
 * Logback appender that tees every event into [DesktopLogSource] so the in-app Logs tab sees the
 * same lines as the console/file (subject to the per-logger levels in logback-desktop.xml).
 */
class DesktopLogAppender : AppenderBase<ILoggingEvent>() {
    override fun append(event: ILoggingEvent) {
        val level = when (event.level.toInt()) {
            Level.TRACE_INT -> 'V'
            Level.DEBUG_INT -> 'D'
            Level.INFO_INT -> 'I'
            Level.WARN_INT -> 'W'
            Level.ERROR_INT -> 'E'
            else -> 'I'
        }
        val tp = event.throwableProxy
        // formattedMessage can be null in logback; coalesce to "" to keep append non-null.
        val msg = event.formattedMessage ?: ""
        val message = if (tp != null) msg + "\n" + ThrowableProxyUtil.asString(tp) else msg
        DesktopLogSource.append(event.timeStamp, level, event.loggerName, message)
    }
}
