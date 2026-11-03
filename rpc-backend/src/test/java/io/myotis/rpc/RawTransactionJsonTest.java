package io.myotis.rpc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** The JSON value {@link VerifiedRpcBackend}'s raw transaction reads answer (#715): the
 *  Rust {@code eljson::raw_tx_json} twin — the bytes as a 0x-hex JSON string. */
class RawTransactionJsonTest {

    @Test
    void rawBytesAreAQuotedLowercaseHexString() {
        assertEquals("\"0x02f86c\"", VerifiedRpcBackend.rawTxJson(new byte[] {0x02, (byte) 0xf8, 0x6c}));
        assertEquals("\"0xc0\"", VerifiedRpcBackend.rawTxJson(new byte[] {(byte) 0xc0}));
    }
}
