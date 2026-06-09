package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReceiptsMessageTest {

    /** A legacy receipt RLP list [status, cumGas, bloom, [ [addr, [topic], data] ]] —
     *  with the nested logs that make receipt re-encoding harder than transactions. */
    private static Bytes legacyReceipt() {
        Bytes addr = Bytes.repeat((byte) 0xab, 20);
        Bytes topic = Bytes.repeat((byte) 0xcd, 32);
        Bytes bloom = Bytes.repeat((byte) 0x00, 256);
        return RLP.encodeList(r -> {
            r.writeValue(Bytes.fromHexString("0x01")); // status = 1
            r.writeValue(Bytes.fromHexString("0x5208")); // cumulativeGasUsed
            r.writeValue(bloom);
            r.writeList(logs -> logs.writeList(oneLog -> {       // logs: [ [addr,[topic],data] ]
                oneLog.writeValue(addr);
                oneLog.writeList(topics -> topics.writeValue(topic));
                oneLog.writeValue(Bytes.fromHexString("0xdeadbeef")); // data
            }));
        });
    }

    /** A typed (EIP-2718) receipt envelope: type(0x02) || rlp([...]) as raw bytes. */
    private static Bytes typedReceipt() {
        Bytes inner = RLP.encodeList(r -> {
            r.writeValue(Bytes.fromHexString("0x01"));
            r.writeValue(Bytes.fromHexString("0x9c40"));
            r.writeValue(Bytes.repeat((byte) 0x00, 256));
            r.writeList(logs -> { /* no logs */ });
        });
        return Bytes.concatenate(Bytes.fromHexString("0x02"), inner);
    }

    @Test
    void decodesRawReceiptBytesForTypedAndLegacy() {
        Bytes typed = typedReceipt();
        Bytes legacy = legacyReceipt();

        // Receipts payload: [requestId, [ [typed, legacy] ]]  (one block, two receipts)
        byte[] payload = RLP.encodeList(w -> {
            w.writeLong(42L);
            w.writeList(blocks -> blocks.writeList(receipts -> {
                receipts.writeValue(typed);  // typed → byte-string envelope
                receipts.writeRLP(legacy);   // legacy → RLP list, inlined raw
            }));
        }).toArrayUnsafe();

        ReceiptsMessage.DecodeResult result = ReceiptsMessage.decode(payload);

        assertEquals(42L, result.requestId());
        assertEquals(1, result.perBlockReceipts().size());
        List<Bytes> block0 = result.perBlockReceipts().get(0);
        assertEquals(2, block0.size());
        // Raw consensus bytes must round-trip exactly — these are the receipts-trie values.
        assertEquals(typed, block0.get(0));
        assertEquals(legacy, block0.get(1));
    }
}
