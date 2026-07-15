package io.myotis.ios

import io.myotis.ui.LogLevel
import io.myotis.ui.LogLine
import io.myotis.ui.LogSource
import platform.Foundation.NSDate
import platform.Foundation.NSLock
import platform.Foundation.timeIntervalSince1970

/**
 * The iOS [LogSource]: an in-memory ring fed by the Rust log pump in
 * [IosNodeController] (there is no JVM/SLF4J pipeline on this host — the
 * engine's tracing ring is the only log producer). Guarded by an [NSLock]:
 * the pump appends from a worker coroutine while the Logs tab polls
 * [version]/[snapshot] on the main thread.
 */
class IosLogSource : LogSource {

    private val lock = NSLock()
    private val lines = ArrayDeque<LogLine>()
    private var version = 0L
    private var seq = 0L
    private var minLevel = LogLevel.INFO

    private inline fun <T> locked(block: () -> T): T {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }

    override fun version(): Long = locked { version }

    override fun snapshot(): List<LogLine> = locked { lines.toList() }

    override fun clear() {
        locked {
            lines.clear()
            version++
        }
    }

    override fun level(): LogLevel = locked { minLevel }

    override fun setLevel(level: LogLevel) {
        locked { minLevel = level }
    }

    /** Append one raw tracing line from the engine's drain (capture-side level gate). */
    fun append(rawLine: String) {
        val line = rawLine.trim()
        if (line.isEmpty()) return
        val levelChar = detectLevel(line)
        val nowMs = (NSDate().timeIntervalSince1970 * 1000).toLong()
        locked {
            if (rank(levelChar) < minLevel.ordinal) return@locked
            lines.addLast(LogLine(seq++, nowMs, levelChar, TAG, line))
            while (lines.size > CAPACITY) lines.removeFirst()
            version++
        }
    }

    private fun detectLevel(line: String): Char = when {
        line.contains(" ERROR ") || line.startsWith("ERROR") -> 'E'
        line.contains(" WARN ") || line.startsWith("WARN") -> 'W'
        line.contains(" DEBUG ") || line.startsWith("DEBUG") -> 'D'
        line.contains(" TRACE ") || line.startsWith("TRACE") -> 'V'
        else -> 'I'
    }

    /** Rank against [LogLevel.ordinal] (DEBUG=0 … ERROR=3); TRACE ranks below DEBUG. */
    private fun rank(level: Char): Int = when (level) {
        'V' -> -1
        'D' -> 0
        'I' -> 1
        'W' -> 2
        'E' -> 3
        else -> 1
    }

    private companion object {
        const val CAPACITY = 2000
        const val TAG = "rust"
    }
}
