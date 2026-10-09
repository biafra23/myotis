package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The Status tab's peer-group headers: the layer, the group's own live-peer
 * phrase, and the cache total — the number its Cache row starts with.
 */
class PeerGroupTitleTest {

    @Test
    fun `EL header counts connected peers, CL header counts servers per minute`() {
        assertEquals("EL · 12 peers · 96 cache", peerGroupTitle("EL", "12 peers", 96))
        assertEquals("CL · served 2/min · 3 cache", peerGroupTitle("CL", "served 2/min", 3))
    }

    @Test
    fun `a fresh install reads as zeros, not as a missing header`() {
        assertEquals("EL · 0 peers · 0 cache", peerGroupTitle("EL", "0 peers", 0))
        assertEquals("CL · served 0/min · 0 cache", peerGroupTitle("CL", "served 0/min", 0))
    }
}
