package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReceiptTest {

    @Test
    void decodesLegacyReceiptWithLog() {
        Bytes addr = Bytes.repeat((byte) 0xab, 20);
        Bytes topic = Bytes.repeat((byte) 0xcd, 32);
        Bytes bloom = Bytes.repeat((byte) 0x00, 256);
        Bytes raw = RLP.encodeList(r -> {
            r.writeValue(Bytes.fromHexString("0x01"));   // status = 1 (success)
            r.writeValue(Bytes.fromHexString("0x5208")); // cumulativeGasUsed = 21000
            r.writeValue(bloom);
            r.writeList(logs -> logs.writeList(oneLog -> {
                oneLog.writeValue(addr);
                oneLog.writeList(topics -> topics.writeValue(topic));
                oneLog.writeValue(Bytes.fromHexString("0xdeadbeef"));
            }));
        });

        Receipt rcpt = Receipt.decode(raw);
        assertEquals(0, rcpt.type());
        assertTrue(rcpt.hasStatus());
        assertTrue(rcpt.success());
        assertEquals(21000L, rcpt.cumulativeGasUsed());
        assertEquals(bloom, rcpt.logsBloom());
        assertEquals(1, rcpt.logs().size());
        Receipt.Log log = rcpt.logs().get(0);
        assertEquals(addr, log.address());
        assertEquals(1, log.topics().size());
        assertEquals(topic, log.topics().get(0));
        assertEquals(Bytes.fromHexString("0xdeadbeef"), log.data());
    }

    @Test
    void decodesTypedFailedReceiptNoLogs() {
        Bytes inner = RLP.encodeList(r -> {
            r.writeValue(Bytes.EMPTY);                   // status = 0 (failed) → RLP 0x80
            r.writeValue(Bytes.fromHexString("0x9c40")); // cumulativeGasUsed
            r.writeValue(Bytes.repeat((byte) 0x00, 256));
            r.writeList(logs -> { });
        });
        Bytes raw = Bytes.concatenate(Bytes.fromHexString("0x02"), inner); // type-2 envelope

        Receipt rcpt = Receipt.decode(raw);
        assertEquals(2, rcpt.type());
        assertTrue(rcpt.hasStatus());
        assertFalse(rcpt.success());
        assertEquals(40000L, rcpt.cumulativeGasUsed());
        assertTrue(rcpt.logs().isEmpty());
    }
}
