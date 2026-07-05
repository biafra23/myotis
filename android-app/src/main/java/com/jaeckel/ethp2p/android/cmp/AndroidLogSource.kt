package com.jaeckel.ethp2p.android.cmp

import com.jaeckel.ethp2p.android.log.AppSlf4jProvider
import com.jaeckel.ethp2p.android.log.LogBuffer
import io.myotis.ui.LogLevel
import io.myotis.ui.LogLine
import io.myotis.ui.LogSource
import org.slf4j.event.Level

/**
 * Android actual of [LogSource]: wraps the existing [LogBuffer] (which the in-tree SLF4J
 * provider tees consensus/networking/libp2p logs into, alongside the app's own LogBuffer
 * calls), so the shared Logs tab renders the same lines the Android UI shows today. The capture
 * level is the SLF4J provider's live threshold.
 */
class AndroidLogSource : LogSource {
    override fun version(): Long = LogBuffer.version()

    override fun snapshot(): List<LogLine> = LogBuffer.snapshot().map { e ->
        LogLine(e.sequence(), e.timestampMillis(), e.level(), e.tag(), e.message())
    }

    override fun clear() = LogBuffer.clear()

    override fun level(): LogLevel = when (AppSlf4jProvider.minLevel()) {
        Level.ERROR -> LogLevel.ERROR
        Level.WARN -> LogLevel.WARN
        Level.INFO -> LogLevel.INFO
        else -> LogLevel.DEBUG   // DEBUG/TRACE both surface as the DEBUG floor (TRACE is suppressed)
    }

    override fun setLevel(level: LogLevel) = AppSlf4jProvider.setMinLevel(
        when (level) {
            LogLevel.DEBUG -> Level.DEBUG
            LogLevel.INFO -> Level.INFO
            LogLevel.WARN -> Level.WARN
            LogLevel.ERROR -> Level.ERROR
        }
    )
}
