package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The Status tab's EL "Peers" value: the snap/2 share of the serving pool goes
 * in parentheses after the serving count, and only when there is one.
 */
class ElPeersValueTest {

    @Test
    fun `serving peers on snap2 are shown in parentheses after the serving count`() {
        assertEquals("12 · snap 10 · serving 8 (3)", elPeersValue(12, 10, 8, 3))
        // Every serving peer on snap/2 is still worth saying.
        assertEquals("8 · snap 8 · serving 8 (8)", elPeersValue(8, 8, 8, 8))
    }

    @Test
    fun `no parentheses while every serving peer is on snap1`() {
        assertEquals("12 · snap 10 · serving 8", elPeersValue(12, 10, 8, 0))
        assertEquals("0 · snap 0 · serving 0", elPeersValue(0, 0, 0, 0))
    }
}
