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
    fun `one ready peer is a peer, not peers`() {
        assertEquals("1 peer", elPeersPhrase(1))
        assertEquals("0 peers", elPeersPhrase(0))
        assertEquals("2 peers", elPeersPhrase(2))
        assertEquals("EL · 1 peer · 5 cache", peerGroupTitle("EL", elPeersPhrase(1), 5))
    }

    @Test
    fun `a fresh install reads as zeros, not as a missing header`() {
        assertEquals("EL · 0 peers · 0 cache", peerGroupTitle("EL", "0 peers", 0))
        assertEquals("CL · served 0/min · 0 cache", peerGroupTitle("CL", "served 0/min", 0))
    }
}
