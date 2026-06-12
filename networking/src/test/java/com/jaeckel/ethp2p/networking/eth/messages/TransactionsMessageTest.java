package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wire-format tests for the eth Transactions (0x12) encoder. Assertions are
 * against the raw RLP bytes so they pin the legacy-vs-typed distinction the
 * codec hinges on, independent of any decoder.
 */
class TransactionsMessageTest {

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

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
    void skipsNullAndEmptyElementsAndNullVararg() {
        byte[] emptyList = {(byte) 0xc0};   // RLP encoding of an empty list
        assertArrayEquals(emptyList, TransactionsMessage.encode());                 // no args
        assertArrayEquals(emptyList, TransactionsMessage.encode((byte[][]) null));   // null vararg
        assertArrayEquals(emptyList, TransactionsMessage.encode(null, new byte[0])); // null + empty skipped
        // A null/empty element next to a real one is dropped, leaving just the real one.
        byte[] legacy = {(byte) 0xc2, 0x01, 0x02};
        assertArrayEquals(TransactionsMessage.encode(legacy),
                TransactionsMessage.encode(null, legacy, new byte[0]));
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

    @Test
    void hashesAreKeccakOfEachTxsCanonicalBytes() {
        // legacy tx = its own RLP list; typed tx = type||payload byte string. The hash
        // is keccak over those canonical bytes — exactly what eth_sendRawTransaction
        // returns and what a block's transactionsRoot is built from.
        byte[] legacy = {(byte) 0xc2, 0x01, 0x02};
        byte[] typed = {0x02, 0x7f};
        byte[] msg = TransactionsMessage.encode(legacy, typed);
        List<Bytes32> hashes = TransactionsMessage.hashes(msg, 256);
        assertEquals(2, hashes.size());
        assertEquals(Bytes32.wrap(Hash.keccak256(Bytes.wrap(legacy))), hashes.get(0));
        assertEquals(Bytes32.wrap(Hash.keccak256(Bytes.wrap(typed))), hashes.get(1));
    }

    @Test
    void hashesCapsAtMaxAndToleratesGarbage() {
        // null / not-a-list / empty all yield no hashes — never throw on the event loop.
        assertTrue(TransactionsMessage.hashes(null, 256).isEmpty());
        assertTrue(TransactionsMessage.hashes(new byte[0], 256).isEmpty());
        assertTrue(TransactionsMessage.hashes(new byte[]{0x01, 0x02, 0x03}, 256).isEmpty());
        // the cap bounds event-loop work even for a large batch.
        byte[] two = TransactionsMessage.encode(new byte[]{0x02, 0x7f}, new byte[]{0x02, 0x7e});
        assertEquals(1, TransactionsMessage.hashes(two, 1).size());
    }
}
