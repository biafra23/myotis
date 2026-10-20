package io.myotis.ui

/**
 * Data-usage wording shared by the Status screen and the Android node notification
 * (docs/data-usage.md). Pure text over the engine's figures, so every host words the
 * same numbers the same way.
 */
object DataUsageText {

    /** Today's figures — one network's, or several added up ([plus]). */
    data class Today(val bytesIn: Long, val bytesOut: Long, val meteredIn: Long, val meteredOut: Long) {
        val total: Long get() = bytesIn + bytesOut
        val metered: Long get() = meteredIn + meteredOut

        /** Everything not moved on a metered network: Wi-Fi/Ethernet, and the rare bytes
         *  moved while the host could not tell (no active network). */
        val unmetered: Long get() = (total - metered).coerceAtLeast(0)

        operator fun plus(o: Today) = Today(
            bytesIn + o.bytesIn, bytesOut + o.bytesOut, meteredIn + o.meteredIn, meteredOut + o.meteredOut,
        )

        companion object {
            @kotlin.jvm.JvmField
            val ZERO = Today(0, 0, 0, 0)
        }
    }

    /** One line for the node notification: `Data today 12.4 MB · 4.1 MB metered · 8.3 MB unmetered`. */
    fun notificationLine(t: Today): String =
        "Data today ${bytes(t.total)} · ${bytes(t.metered)} metered · ${bytes(t.unmetered)} unmetered"

    /** The notification's short form, for its collapsed header: `12.4 MB today`. */
    fun notificationShort(t: Today): String = "${bytes(t.total)} today"

    /**
     * A byte count for people: `512 B`, `3.4 KB`, `12.4 MB`, `1.2 GB` (binary units,
     * one decimal, rounded down so a figure never reads higher than what was moved).
     */
    fun bytes(b: Long): String {
        val n = b.coerceAtLeast(0)
        return when {
            n >= GB -> tenths(n, GB, "GB")
            n >= MB -> tenths(n, MB, "MB")
            n >= KB -> tenths(n, KB, "KB")
            else -> "$n B"
        }
    }

    private fun tenths(n: Long, unit: Long, name: String): String {
        val t = n * 10 / unit
        return "${t / 10}.${t % 10} $name"
    }

    private const val KB = 1024L
    private const val MB = 1024L * 1024
    private const val GB = 1024L * 1024 * 1024
}
