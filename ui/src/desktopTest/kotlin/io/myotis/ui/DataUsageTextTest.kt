package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/** The data-usage wording of the Status rows and the Android node notification. */
class DataUsageTextTest {

    @Test
    fun bytesUseBinaryUnitsWithOneDecimalRoundedDown() {
        assertEquals("0 B", DataUsageText.bytes(0))
        assertEquals("1023 B", DataUsageText.bytes(1023))
        assertEquals("1.0 KB", DataUsageText.bytes(1024))
        assertEquals("1.4 KB", DataUsageText.bytes(1535))     // 1.499 KB never reads 1.5
        assertEquals("12.4 MB", DataUsageText.bytes(13_002_344)) // exactly 12.4 MB
        assertEquals("1023.9 MB", DataUsageText.bytes(1024L * 1024 * 1024 - 1))
        assertEquals("1.0 GB", DataUsageText.bytes(1024L * 1024 * 1024))
        assertEquals("0 B", DataUsageText.bytes(-5))
    }

    @Test
    fun theNotificationSplitsTodayIntoMeteredAndUnmetered() {
        val mb = 1024L * 1024
        val t = DataUsageText.Today(bytesIn = 10 * mb, bytesOut = 2 * mb, meteredIn = 3 * mb, meteredOut = 1 * mb)
        assertEquals(12 * mb, t.total)
        assertEquals(4 * mb, t.metered)
        assertEquals(8 * mb, t.unmetered)
        assertEquals("Data today 12.0 MB · 4.0 MB metered · 8.0 MB unmetered", DataUsageText.notificationLine(t))
        assertEquals("12.0 MB today", DataUsageText.notificationShort(t))
    }

    @Test
    fun networksAddUp() {
        val mainnet = DataUsageText.Today(100, 20, 10, 2)
        val gnosis = DataUsageText.Today(50, 5, 0, 0)
        assertEquals(DataUsageText.Today(150, 25, 10, 2), DataUsageText.Today.ZERO + mainnet + gnosis)
    }

    @Test
    fun unmeteredNeverGoesNegative() {
        // A metered part above the total cannot happen engine-side; the text must still not
        // print a negative figure if a host ever adds up figures from different days.
        assertEquals(0L, DataUsageText.Today(1, 0, 5, 0).unmetered)
    }
}
