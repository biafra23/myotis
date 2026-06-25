package com.jaeckel.ethp2p.android.cmp

import com.jaeckel.ethp2p.android.log.LogBuffer
import io.myotis.ui.LogLine
import io.myotis.ui.LogSource

/**
 * Android actual of [LogSource]: wraps the existing [LogBuffer] (which the in-tree SLF4J
 * provider tees consensus/networking/libp2p logs into, alongside the app's own LogBuffer
 * calls), so the shared Logs tab renders the same lines the Android UI shows today.
 */
class AndroidLogSource : LogSource {
    override fun version(): Long = LogBuffer.version()

    override fun snapshot(): List<LogLine> = LogBuffer.snapshot().map { e ->
        LogLine(e.sequence(), e.timestampMillis(), e.level(), e.tag(), e.message())
    }

    override fun clear() = LogBuffer.clear()
}
