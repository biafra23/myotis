package io.myotis.node;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The anchored header-backfill plan — kept case-identical with the Rust
 *  {@code pool::backfill_plan} tests (same inputs, same expected values). */
class BackfillRangeTest {

    private static final Bytes32 HH = Bytes32.rightPad(Bytes.fromHexString("0x07")); // head hash
    private static final Bytes32 PP = Bytes32.rightPad(Bytes.fromHexString("0x09")); // earliest parent

    @Test
    void planIsAlwaysAnchored() {
        assertNull(ChainStack.backfillPlan(0, HH, 32, -1, -1, null), "no head yet");
        // Empty window: restart at the head window, anchored by the head hash.
        assertEquals(new ChainStack.BackfillPlan(999_969, 32, new ChainStack.BatchAnchor(HH)),
                ChainStack.backfillPlan(1_000_000, HH, 32, -1, -1, null));
        assertEquals(new ChainStack.BackfillPlan(999_809, 192, new ChainStack.BatchAnchor(HH)),
                ChainStack.backfillPlan(1_000_000, HH, 4096, -1, -1, null));
        // Run below the head within one batch: extend UP to and including the head.
        assertEquals(new ChainStack.BackfillPlan(999_981, 20, new ChainStack.BatchAnchor(HH)),
                ChainStack.backfillPlan(1_000_000, HH, 4096, 999_000, 999_980, PP));
        // Run too far behind: restart near the head (still head-anchored).
        assertEquals(new ChainStack.BackfillPlan(999_809, 192, new ChainStack.BatchAnchor(HH)),
                ChainStack.backfillPlan(1_000_000, HH, 4096, 900_000, 900_010, PP));
        // Run includes the head, floor not reached: fill DOWN, parent-anchored.
        assertEquals(new ChainStack.BackfillPlan(999_708, 192, new ChainStack.BatchAnchor(PP)),
                ChainStack.backfillPlan(1_000_000, HH, 4096, 999_900, 1_000_000, PP));
        // Down-fill without a known earliest parent → no plan.
        assertNull(ChainStack.backfillPlan(1_000_000, HH, 4096, 999_900, 1_000_000, null));
        // Window full → done.
        assertNull(ChainStack.backfillPlan(1_000_000, HH, 32, 999_969, 1_000_000, PP));
        // cap=1: only the head itself.
        assertEquals(new ChainStack.BackfillPlan(1_000_000, 1, new ChainStack.BatchAnchor(HH)),
                ChainStack.backfillPlan(1_000_000, HH, 1, -1, -1, null));
    }
}
