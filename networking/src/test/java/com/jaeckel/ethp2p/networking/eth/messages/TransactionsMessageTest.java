package com.jaeckel.ethp2p.networking.eth.messages;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Wire-format tests for the eth Transactions (0x12) encoder. Assertions are
 * against the raw RLP bytes so they pin the legacy-vs-typed distinction the
 * codec hinges on, independent of any decoder.
 */
class TransactionsMessageTest {

    @Test
    void legacyTxEmbeddedVerbatimAsNestedList() {
        // A legacy tx is itself an RLP list (here a 2-element fake [1, 2] = 0xc2 01 02);
        // it must nest into the outer list unchanged, not be re-wrapped as a string.
        byte[] legacy = {(byte) 0xc2, 0x01, 0x02};
        byte[] msg = TransactionsMessage.encode(legacy);
        // outer list of 3 payload bytes: 0xc3 || c2 01 02
        assertArrayEquals(new byte[]{(byte) 0xc3, (byte) 0xc2, 0x01, 0x02}, msg);
    }

    @Test
    void typedTxWrappedAsRlpByteString() {
        // EIP-2718 typed tx: 0x02 || 100 bytes (101 total, first byte <= 0x7f).
        byte[] typed = new byte[101];
        typed[0] = 0x02;
        Arrays.fill(typed, 1, 101, (byte) 0xAB);
        byte[] msg = TransactionsMessage.encode(typed);
        // outer list (0xf8, len=103) -> RLP string (0xb8, len=101) -> 0x02 ...
        assertEquals((byte) 0xf8, msg[0]);
        assertEquals((byte) 0x67, msg[1]);   // list payload length = 103
        assertEquals((byte) 0xb8, msg[2]);   // string, 1 length byte
        assertEquals((byte) 0x65, msg[3]);   // string length = 101
        assertEquals((byte) 0x02, msg[4]);   // tx type byte
        assertEquals(105, msg.length);
    }

    @Test
    void multipleTxsKeepOrderAndPerTxForm() {
        byte[] legacy = {(byte) 0xc2, 0x01, 0x02};   // nested list
        byte[] typed = {0x02, 0x7f};                 // typed -> 2-byte string 0x82 02 7f
        byte[] msg = TransactionsMessage.encode(legacy, typed);
        // outer list of 6 payload bytes: 0xc6 || (c2 01 02) || (82 02 7f)
        assertArrayEquals(
                new byte[]{(byte) 0xc6, (byte) 0xc2, 0x01, 0x02, (byte) 0x82, 0x02, 0x7f}, msg);
    }
}
