package com.jaeckel.ethp2p.networking.eth;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The snap messages only ONE version has, as {@code EthHandler} dispatches
 * them: {@code GetTrieNodes}/{@code TrieNodes} (0x06/0x07) exist on snap/1,
 * {@code GetBlockAccessLists}/{@code BlockAccessLists} (0x08/0x09, EIP-8189) on
 * snap/2 — and the empty answer the latter gets. Twin of the Rust engine's
 * {@code empty_answer_follows_the_negotiated_snap_version}.
 *
 * <p>No snap/2 peer had been seen live when this was written, so these pins are
 * what stands between a wrong offset or a mangled request id and a release.
 */
class SnapVersionDispatchTest {

    private static final int[] ETH_VERSIONS = {66, 67, 68, 69};

    @Test
    void snapBaseFollowsTheEthProtocolLength() {
        assertEquals(0x21, EthHandler.snapBaseFor(66));
        assertEquals(0x21, EthHandler.snapBaseFor(68));
        assertEquals(0x22, EthHandler.snapBaseFor(69)); // eth/69 adds BlockRangeUpdate
    }

    @Test
    void getBlockAccessListsIsARequestOnSnap2Only() {
        for (int eth : ETH_VERSIONS) {
            int base = EthHandler.snapBaseFor(eth);
            int code = base + 8;
            assertTrue(EthHandler.isSnapGetBlockAccessLists(code, base, 2));
            assertFalse(EthHandler.isSnapGetBlockAccessLists(code, base, 1), "not a snap/1 message");
            assertFalse(EthHandler.isSnapGetBlockAccessLists(code, base, 0), "no snap negotiated");
            // Its neighbours are not the request: 0x07 (retired) and 0x09 (the response).
            assertFalse(EthHandler.isSnapGetBlockAccessLists(base + 7, base, 2));
            assertFalse(EthHandler.isSnapGetBlockAccessLists(base + 9, base, 2));
        }
        // The answer goes out one above the request.
        assertEquals(EthHandler.SNAP_GET_BLOCK_ACCESS_LISTS + 1, EthHandler.SNAP_BLOCK_ACCESS_LISTS);
        // On eth/68 the absolute codes are 0x29/0x2a, on eth/69 0x2a/0x2b.
        assertEquals(0x29, EthHandler.snapBaseFor(68) + EthHandler.SNAP_GET_BLOCK_ACCESS_LISTS);
        assertEquals(0x2b, EthHandler.snapBaseFor(69) + EthHandler.SNAP_BLOCK_ACCESS_LISTS);
    }

    @Test
    void theTrieNodePairExistsOnSnap1Only() {
        for (int eth : ETH_VERSIONS) {
            int base = EthHandler.snapBaseFor(eth);
            assertTrue(EthHandler.isSnapGetTrieNodes(base + 6, base, 1));
            assertTrue(EthHandler.isSnapTrieNodes(base + 7, base, 1));
            for (int version : new int[] {0, 2}) {
                assertFalse(EthHandler.isSnapGetTrieNodes(base + 6, base, version));
                assertFalse(EthHandler.isSnapTrieNodes(base + 7, base, version));
            }
        }
    }

    /** {@code GetBlockAccessLists: [reqId, [blockHash…], responseBytes]} with a raw request id. */
    private static byte[] getBlockAccessLists(Bytes reqId) {
        return RLP.encodeList(w -> {
            w.writeValue(reqId);
            w.writeList(l -> {
                l.writeValue(Bytes32.repeat((byte) 0xaa));
                l.writeValue(Bytes32.repeat((byte) 0xbb));
            });
            w.writeInt(2 * 1024 * 1024);
        }).toArrayUnsafe();
    }

    @Test
    void theEmptyAnswerIsReqIdAndAnEmptyList() {
        // [9, []] — the bytes the Rust engine's encode_empty_codes(9) produces.
        assertArrayEquals(Bytes.fromHexString("0xc209c0").toArrayUnsafe(),
                EthHandler.emptyBlockAccessLists(getBlockAccessLists(Bytes.of(9))));
    }

    @Test
    void aRequestIdWithBit63SetIsEchoedVerbatim() {
        // A uint64 id a long cannot hold as a positive number: readLong/writeLong
        // would mangle it and the peer would drop the answer as unsolicited.
        Bytes highBit = Bytes.fromHexString("0xfedcba9876543210");
        assertArrayEquals(Bytes.fromHexString("0xca88fedcba9876543210c0").toArrayUnsafe(),
                EthHandler.emptyBlockAccessLists(getBlockAccessLists(highBit)));
    }

    @Test
    void aRequestIdThatIsNotAUint64GetsNoAnswer() {
        assertNull(EthHandler.emptyBlockAccessLists(getBlockAccessLists(Bytes.repeat((byte) 0x01, 9))));
        // Not an RLP list at all: thrown, and the handler's catch logs and drops it.
        assertThrows(RuntimeException.class,
                () -> EthHandler.emptyBlockAccessLists(new byte[] {(byte) 0x83, 0x01, 0x02, 0x03}));
    }
}
