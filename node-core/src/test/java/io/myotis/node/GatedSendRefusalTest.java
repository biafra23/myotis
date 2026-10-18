package io.myotis.node;

import io.myotis.api.SendResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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

    static {
        // Sender recovery (EthTxDecoder) runs on BouncyCastle, as the hosts register it.
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /** The EIP-155 spec example: a legacy transaction signed for chain 1. */
    private static final byte[] SPEC_TX = org.apache.tuweni.bytes.Bytes.fromHexString(
            "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7"
            + "6400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a0"
            + "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83").toArrayUnsafe();

    @Test
    void aTransactionSignedForAnotherChainIsRefusedBeforeTheWait() {
        // #665: judged on the bytes and the static network config, so a paused or
        // starting stack answers it with the permanent refusal too.
        assertEquals("invalid sender: invalid chain id for signer: have 1 want 11155111",
                GatedVerifiedReads.sendRefusal(SPEC_TX, () -> 11_155_111L));
        assertNull(GatedVerifiedReads.sendRefusal(SPEC_TX, () -> 1L));
        // Bytes that are no transaction are refused without reading the chain.
        assertEquals("invalid raw transaction: transaction type not supported (0x0)",
                GatedVerifiedReads.sendRefusal(new byte[] {0x00}, () -> {
                    throw new AssertionError("chain read for bytes that are no transaction");
                }));
    }
}
