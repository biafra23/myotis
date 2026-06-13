package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Decodes NewPooledTransactionHashes (0x18) in both wire layouts: the flat
 * {@code [hash, ...]} of eth/66–67 and the {@code [types, sizes, hashes]} of eth/68+
 * (EIP-5793). We only ever decode this to match our own broadcast hashes, so the
 * decoder must be version-correct, capped, and unfazed by malformed peer input.
 */
class NewPooledTransactionHashesMessageTest {

    private static final Bytes32 H1 = Bytes32.fromHexString(
            "0x1111111111111111111111111111111111111111111111111111111111111111");
    private static final Bytes32 H2 = Bytes32.fromHexString(
            "0x2222222222222222222222222222222222222222222222222222222222222222");

    private static byte[] flat(Bytes32... hashes) {
        return RLP.encodeList(w -> {
            for (Bytes32 h : hashes) w.writeValue(h);
        }).toArrayUnsafe();
    }

    private static byte[] eth68(Bytes types, List<Integer> sizes, Bytes32... hashes) {
        Bytes sizeList = RLP.encodeList(w -> sizes.forEach(w::writeInt));
        Bytes hashList = RLP.encodeList(w -> {
            for (Bytes32 h : hashes) w.writeValue(h);
        });
        return RLP.encodeList(w -> {
            w.writeValue(types);
            w.writeRLP(sizeList);
            w.writeRLP(hashList);
        }).toArrayUnsafe();
    }

    @Test
    void decodesFlatListForEth66And67() {
        byte[] msg = flat(H1, H2);
        assertEquals(List.of(H1, H2), NewPooledTransactionHashesMessage.hashes(msg, 66, 256));
        assertEquals(List.of(H1, H2), NewPooledTransactionHashesMessage.hashes(msg, 67, 256));
    }

    @Test
    void decodesTypesSizesHashesForEth68Plus() {
        byte[] msg = eth68(Bytes.of(0x00, 0x02), List.of(100, 120), H1, H2);
        assertEquals(List.of(H1, H2), NewPooledTransactionHashesMessage.hashes(msg, 68, 256));
        assertEquals(List.of(H1, H2), NewPooledTransactionHashesMessage.hashes(msg, 69, 256));
    }

    @Test
    void capsAtMax() {
        assertEquals(1, NewPooledTransactionHashesMessage.hashes(flat(H1, H2), 66, 1).size());
        byte[] v68 = eth68(Bytes.of(0x02, 0x02), List.of(1, 1), H1, H2);
        assertEquals(1, NewPooledTransactionHashesMessage.hashes(v68, 68, 1).size());
    }

    @Test
    void toleratesGarbageAndWrongSizedHashes() {
        assertTrue(NewPooledTransactionHashesMessage.hashes(null, 68, 256).isEmpty());
        assertTrue(NewPooledTransactionHashesMessage.hashes(new byte[0], 68, 256).isEmpty());
        // a non-list payload must not throw.
        assertTrue(NewPooledTransactionHashesMessage.hashes(new byte[]{0x01, 0x02}, 66, 256).isEmpty());
        // a 31-byte "hash" in the flat list is skipped, not accepted.
        byte[] shortHash = RLP.encodeList(w -> w.writeValue(Bytes.repeat((byte) 0xAB, 31))).toArrayUnsafe();
        assertTrue(NewPooledTransactionHashesMessage.hashes(shortHash, 66, 256).isEmpty());
    }
}
