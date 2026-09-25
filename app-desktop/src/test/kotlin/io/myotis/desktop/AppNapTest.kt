package io.myotis.desktop

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class AppNapTest {
    @Test
    fun `holds an NSProcessInfo activity on macOS, idempotently`() {
        assumeTrue(AppNap.isMac, "macOS only: the Objective-C runtime is what is under test")
        assertTrue(AppNap.disable("AppNapTest"))
        assertTrue(AppNap.active)
        assertTrue(AppNap.disable("AppNapTest, again"))
    }

    @Test
    fun `is a no-op elsewhere`() {
        assumeFalse(AppNap.isMac)
        assertFalse(AppNap.disable("AppNapTest"))
        assertFalse(AppNap.active)
    }
}
