package io.myotis.node;

import io.myotis.api.SendResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * #360: bytes that are no transaction are refused on the bytes alone, before the
 * wait for a ready backend — so a paused or starting stack (here: none at all)
 * answers the permanent refusal, never the retryable "stack not ready".
 */
class GatedSendRefusalTest {

    @Test
    void bytesThatAreNoTransactionAreRefusedWithoutTouchingTheStack() {
        GatedVerifiedReads reads = new GatedVerifiedReads(null);
        SendResult junk = reads.sendRawTransactionDetailed(new byte[] {0x00});
        assertEquals(SendResult.Status.REFUSED, junk.status());
        assertEquals("invalid raw transaction: transaction type not supported (0x0)", junk.detail());
        assertEquals(SendResult.Status.REFUSED, reads.sendRawTransactionDetailed(new byte[0]).status());
        assertEquals(SendResult.Status.REFUSED, reads.sendRawTransactionDetailed(null).status());
    }
}
