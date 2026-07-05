package io.myotis.desktop

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.classic.spi.ThrowableProxyUtil
import ch.qos.logback.core.AppenderBase
import io.myotis.ui.LogLevel
import io.myotis.ui.LogLine
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
