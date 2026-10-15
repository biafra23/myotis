package io.myotis.jsonrpc.policy

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The block-selector serving window (#366), next to its one definition: head
 * tags and `finalized` are always servable, `safe` and `earliest` never, and a
 * number pin only within [RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE] below to
 * [RpcBlockWindow.BLOCK_NUM_TOLERANCE] above the anchored head. The engine-side
 * twin (`RustBlockWindowTest`) pins the two tolerances against host.rs; this one
 * pins the decision.
 */
class RpcBlockWindowTest {

    private val head = 25_000_000L

    @Test
    fun tagsNeedNoHead() {
        for (tag in listOf("latest", "pending", "finalized", "LATEST", " latest ", null, "")) {
            assertTrue(RpcBlockWindow.blockInWindow(tag) { error("a tag must not read the head") }, "'$tag'")
        }
        for (tag in listOf("safe", "earliest")) {
            assertFalse(RpcBlockWindow.blockInWindow(tag) { head }, "'$tag' is never servable")
        }
    }

    @Test
    fun numberPinsAreServedOnlyInsideTheWindow() {
        val low = head - RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE
        val high = head + RpcBlockWindow.BLOCK_NUM_TOLERANCE
        assertTrue(RpcBlockWindow.blockInWindow("0x" + head.toString(16)) { head })
        assertTrue(RpcBlockWindow.blockInWindow(head.toString()) { head }, "decimal pins are accepted too")
        assertTrue(RpcBlockWindow.blockInWindow("0x" + low.toString(16)) { head }, "lower edge inclusive")
        assertTrue(RpcBlockWindow.blockInWindow("0x" + high.toString(16)) { head }, "upper edge inclusive")
        assertFalse(RpcBlockWindow.blockInWindow("0x" + (low - 1).toString(16)) { head }, "one below the window")
        assertFalse(RpcBlockWindow.blockInWindow("0x" + (high + 1).toString(16)) { head }, "one above the window")
    }

    @Test
    fun malformedPinsAndAnUnknownHeadAreRefused() {
        assertFalse(RpcBlockWindow.blockInWindow("0xzz") { head })
        assertFalse(RpcBlockWindow.blockInWindow("-5") { head })
        assertFalse(RpcBlockWindow.blockInWindow("0x" + head.toString(16)) { null }, "no head = not synced enough to validate a pin")
    }
}
