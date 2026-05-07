package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RLP roundtrip tests for the four snap/1 wire types Phase 1 introduces.
 *
 * <p>The tests exercise encode → decode with hand-built fixtures plus a few
 * edge cases (empty lists, single-account vs multi-storage path sets) so the
 * decoder is verified before it has to face peer-supplied bytes.
 */
class SnapMessagesRoundTripTest {

    private static final Bytes32 STATE_ROOT = Bytes32.fromHexString(
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    private static final Bytes32 ACCOUNT_HASH = Bytes32.fromHexString(
            "0x1111111111111111111111111111111111111111111111111111111111111111");
    private static final Bytes32 SLOT_HASH = Bytes32.fromHexString(
            "0x2222222222222222222222222222222222222222222222222222222222222222");
    private static final Bytes32 CODE_HASH_A = Bytes32.fromHexString(
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    private static final Bytes32 CODE_HASH_B = Bytes32.fromHexString(
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    // ---- GetByteCodes ------------------------------------------------------

    @Test
    void getByteCodesRoundTrip() {
        byte[] enc = GetByteCodesMessage.encode(42L, List.of(CODE_HASH_A, CODE_HASH_B), 1024L);
        GetByteCodesMessage.DecodeResult d = GetByteCodesMessage.decode(enc);
        assertEquals(42L, d.requestId());
        assertEquals(2, d.hashes().size());
        assertEquals(CODE_HASH_A, d.hashes().get(0));
        assertEquals(CODE_HASH_B, d.hashes().get(1));
        assertEquals(1024L, d.responseBytes());
    }

    @Test
    void getByteCodesEmptyList() {
        byte[] enc = GetByteCodesMessage.encode(7L, List.of(), 0L);
        GetByteCodesMessage.DecodeResult d = GetByteCodesMessage.decode(enc);
        assertEquals(7L, d.requestId());
        assertTrue(d.hashes().isEmpty());
        assertEquals(0L, d.responseBytes());
    }

    // ---- ByteCodes ---------------------------------------------------------

    @Test
    void byteCodesRoundTrip() {
        Bytes code1 = Bytes.fromHexString("0x600160005260206000f3");
        Bytes code2 = Bytes.fromHexString("0xfe");
        byte[] enc = ByteCodesMessage.encode(42L, List.of(code1, code2));
        ByteCodesMessage.DecodeResult d = ByteCodesMessage.decode(enc);
        assertEquals(42L, d.requestId());
        assertEquals(2, d.codes().size());
        assertEquals(code1, d.codes().get(0));
        assertEquals(code2, d.codes().get(1));
    }

    @Test
    void byteCodesEmptyResponse() {
        byte[] enc = ByteCodesMessage.encodeEmpty(99L);
        ByteCodesMessage.DecodeResult d = ByteCodesMessage.decode(enc);
        assertEquals(99L, d.requestId());
        assertTrue(d.codes().isEmpty());
    }

    @Test
    void byteCodesExtractRequestId() {
        byte[] enc = ByteCodesMessage.encode(123L, List.of(Bytes.fromHexString("0xab")));
        assertEquals(123L, ByteCodesMessage.extractRequestId(enc));
    }

    // ---- GetTrieNodes ------------------------------------------------------

    @Test
    void getTrieNodesAccountOnlyRoundTrip() {
        var paths = List.of(GetTrieNodesMessage.PathSet.account(ACCOUNT_HASH));
        byte[] enc = GetTrieNodesMessage.encode(11L, STATE_ROOT, paths, 65536L);
        GetTrieNodesMessage.DecodeResult d = GetTrieNodesMessage.decode(enc);
        assertEquals(11L, d.requestId());
        assertEquals(STATE_ROOT, d.stateRoot());
        assertEquals(1, d.paths().size());
        assertEquals(ACCOUNT_HASH, d.paths().get(0).accountPath());
        assertTrue(d.paths().get(0).storagePaths().isEmpty());
        assertEquals(65536L, d.responseBytes());
    }

    @Test
    void getTrieNodesStorageSlotRoundTrip() {
        var paths = List.of(GetTrieNodesMessage.PathSet.storageSlot(ACCOUNT_HASH, SLOT_HASH));
        byte[] enc = GetTrieNodesMessage.encode(12L, STATE_ROOT, paths, 65536L);
        GetTrieNodesMessage.DecodeResult d = GetTrieNodesMessage.decode(enc);
        assertEquals(12L, d.requestId());
        assertEquals(1, d.paths().size());
        var set = d.paths().get(0);
        assertEquals(ACCOUNT_HASH, set.accountPath());
        assertEquals(1, set.storagePaths().size());
        assertEquals(SLOT_HASH, Bytes32.wrap(set.storagePaths().get(0)));
    }

    @Test
    void getTrieNodesMultiSetRoundTrip() {
        Bytes32 accountB = Bytes32.fromHexString(
                "0x3333333333333333333333333333333333333333333333333333333333333333");
        Bytes32 slot1 = Bytes32.fromHexString(
                "0x4444444444444444444444444444444444444444444444444444444444444444");
        Bytes32 slot2 = Bytes32.fromHexString(
                "0x5555555555555555555555555555555555555555555555555555555555555555");
        var paths = List.of(
                GetTrieNodesMessage.PathSet.account(ACCOUNT_HASH),
                new GetTrieNodesMessage.PathSet(accountB, List.of(slot1, slot2)));
        byte[] enc = GetTrieNodesMessage.encode(13L, STATE_ROOT, paths, 131072L);
        GetTrieNodesMessage.DecodeResult d = GetTrieNodesMessage.decode(enc);
        assertEquals(2, d.paths().size());
        assertEquals(ACCOUNT_HASH, d.paths().get(0).accountPath());
        assertEquals(accountB, d.paths().get(1).accountPath());
        assertEquals(2, d.paths().get(1).storagePaths().size());
    }

    // ---- TrieNodes ---------------------------------------------------------

    @Test
    void trieNodesRoundTrip() {
        // Realistic-looking branch and leaf nodes; the codec doesn't care about
        // structure, only that it preserves the bytes.
        Bytes branch = Bytes.fromHexString("0xf85180a0" + "11".repeat(32) + "808080808080808080808080808080");
        Bytes leaf = Bytes.fromHexString("0xc220ab");
        byte[] enc = TrieNodesMessage.encode(21L, List.of(branch, leaf));
        TrieNodesMessage.DecodeResult d = TrieNodesMessage.decode(enc);
        assertEquals(21L, d.requestId());
        assertEquals(2, d.nodes().size());
        assertEquals(branch, d.nodes().get(0));
        assertEquals(leaf, d.nodes().get(1));
    }

    @Test
    void trieNodesEmptyResponse() {
        byte[] enc = TrieNodesMessage.encodeEmpty(99L);
        TrieNodesMessage.DecodeResult d = TrieNodesMessage.decode(enc);
        assertEquals(99L, d.requestId());
        assertTrue(d.nodes().isEmpty());
    }

    @Test
    void trieNodesExtractRequestId() {
        byte[] enc = TrieNodesMessage.encode(456L, List.of(Bytes.fromHexString("0xab")));
        assertEquals(456L, TrieNodesMessage.extractRequestId(enc));
    }
}
