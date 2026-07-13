package io.myotis.node;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the EL-hunt trigger ({@link ChainStack#elHuntDue}) — the mirror of the
 * Rust pool's {@code el_hunt_due} test, so both engines enter emergency
 * snap-peer re-dial mode in the same state: the SERVING pool empty past the
 * stall window. Below-target-but-nonzero never hunts (that stays the polite
 * maintainer's job — on snap-scarce chains the target is simply unreachable
 * and a target-based trigger would hunt forever).
 */
class ElHuntTriggerTest {

    @Test
    void anyServingPeerNeverHunts() {
        long now = 1_000_000L;
        assertFalse(ChainStack.elHuntDue(1, true, now - 10 * ChainStack.EL_HUNT_STALL_MS, now),
                "one serving peer must suppress the hunt regardless of history");
        assertFalse(ChainStack.elHuntDue(5, false, 0L, now));
    }

    @Test
    void emptyPoolHuntsOnlyPastTheStallWindow() {
        long now = 1_000_000L;
        assertFalse(ChainStack.elHuntDue(0, false, 0L, now), "no stall clock yet (fresh start)");
        assertFalse(ChainStack.elHuntDue(0, true, now - ChainStack.EL_HUNT_STALL_MS + 1, now),
                "brief outage inside the window must not trip emergency mode");
        assertTrue(ChainStack.elHuntDue(0, true, now - ChainStack.EL_HUNT_STALL_MS, now),
                "empty past the window must hunt");
        // nanoTime's origin is arbitrary: a NEGATIVE since-stamp must still hunt
        // once the elapsed window passes (the flag, not the value, marks validity).
        assertTrue(ChainStack.elHuntDue(0, true, -ChainStack.EL_HUNT_STALL_MS, ChainStack.EL_HUNT_STALL_MS),
                "negative nanoTime-derived stamps must not suppress the hunt");
    }
}
