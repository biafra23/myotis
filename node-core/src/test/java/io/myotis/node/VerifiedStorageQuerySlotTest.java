package io.myotis.node;

import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Locks {@link VerifiedStorageQuery#verifySlot}: the daemon's {@code get-storage} reports the
 * value its PROOF shows, never the peer's slot list. Before this, the list's value was reported
 * next to a proof that merely verified — so an honest proof plus a forged list value came out
 * as a "verified" slot — and a proven-absent (zero) slot read as an invalid proof.
 */
class VerifiedStorageQuerySlotTest {

    @BeforeAll
    static void setUpProvider() {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final Bytes32 KEY = Hash.keccak256(Bytes32.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000009"));
    private static final Bytes32 OTHER_KEY = Hash.keccak256(Bytes32.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000003"));
    private static final BigInteger VALUE = new BigInteger("123456789000000000000");

    @Test
    void anHonestSlotReportsTheProvenValue() {
        Bytes leaf = storageLeaf(KEY, VALUE);
        StorageRangesMessage.DecodeResult response = response(List.of(entry(KEY, VALUE)), leaf);

        VerifiedStorageQuery.SlotProof p = VerifiedStorageQuery.verifySlot(Hash.keccak256(leaf), KEY, response);

        assertTrue(p.valid());
        assertTrue(p.exists());
        assertEquals(VALUE, p.value());
    }

    @Test
    void aForgedListValueNextToAnHonestProofIsRefused() {
        Bytes leaf = storageLeaf(KEY, VALUE);
        StorageRangesMessage.DecodeResult response =
                response(List.of(entry(KEY, VALUE.multiply(BigInteger.TEN))), leaf);

        assertSame(VerifiedStorageQuery.SlotProof.INVALID,
                VerifiedStorageQuery.verifySlot(Hash.keccak256(leaf), KEY, response));
    }

    @Test
    void aSlotTheListOmitsIsStillAnsweredByTheProof() {
        Bytes leaf = storageLeaf(KEY, VALUE);

        VerifiedStorageQuery.SlotProof p =
                VerifiedStorageQuery.verifySlot(Hash.keccak256(leaf), KEY, response(List.of(), leaf));

        assertTrue(p.valid());
        assertTrue(p.exists());
        assertEquals(VALUE, p.value());
    }

    @Test
    void aProvenAbsentSlotIsAValidZero() {
        // A one-leaf storage trie holding OTHER_KEY: an exclusion proof for KEY.
        Bytes leaf = storageLeaf(OTHER_KEY, VALUE);

        VerifiedStorageQuery.SlotProof p =
                VerifiedStorageQuery.verifySlot(Hash.keccak256(leaf), KEY, response(List.of(), leaf));

        assertTrue(p.valid(), "a zero slot used to read as an invalid proof");
        assertFalse(p.exists());
        assertEquals(BigInteger.ZERO, p.value());
    }

    @Test
    void aLeafHoldingZeroDoesNotExist() {
        // rlp(0) is the empty string: a well-formed leaf whose value is zero reads like an
        // absent slot (found=false in the Rust engine, ZERO in the EVM oracle).
        Bytes leaf = storageLeaf(KEY, BigInteger.ZERO);

        VerifiedStorageQuery.SlotProof p =
                VerifiedStorageQuery.verifySlot(Hash.keccak256(leaf), KEY, response(List.of(), leaf));

        assertTrue(p.valid());
        assertFalse(p.exists());
        assertEquals(BigInteger.ZERO, p.value());
    }

    @Test
    void aValueClaimedForAProvenAbsentSlotIsRefused() {
        Bytes leaf = storageLeaf(OTHER_KEY, VALUE);
        StorageRangesMessage.DecodeResult response = response(List.of(entry(KEY, VALUE)), leaf);

        assertSame(VerifiedStorageQuery.SlotProof.INVALID,
                VerifiedStorageQuery.verifySlot(Hash.keccak256(leaf), KEY, response));
    }

    @Test
    void anEmptyStorageTrieIsZeroWithoutAProof() {
        VerifiedStorageQuery.SlotProof p = VerifiedStorageQuery.verifySlot(
                MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT, KEY,
                new StorageRangesMessage.DecodeResult(1, List.of(), List.of()));

        assertTrue(p.valid());
        assertFalse(p.exists());
    }

    @Test
    void aGarbageProofIsInvalid() {
        Bytes32 root = Bytes32.fromHexString(
                "0x6666666666666666666666666666666666666666666666666666666666666666");
        StorageRangesMessage.DecodeResult response = new StorageRangesMessage.DecodeResult(
                1, List.of(entry(KEY, VALUE)), List.of(Bytes.fromHexString("0xdeadbeef")));

        assertSame(VerifiedStorageQuery.SlotProof.INVALID,
                VerifiedStorageQuery.verifySlot(root, KEY, response));
    }

    @Test
    void theListIsComparedByValueNotByEncoding() {
        // A leading zero byte in the list changes the bytes, not the number.
        Bytes leaf = storageLeaf(KEY, VALUE);
        Bytes padded = Bytes.concatenate(Bytes.of(0), Bytes.wrap(VALUE.toByteArray()).trimLeadingZeros());
        StorageRangesMessage.DecodeResult response = new StorageRangesMessage.DecodeResult(
                1, List.of(new StorageRangesMessage.StorageData(KEY, padded)), List.of(leaf));

        assertTrue(VerifiedStorageQuery.verifySlot(Hash.keccak256(leaf), KEY, response).valid());
    }

    private static StorageRangesMessage.StorageData entry(Bytes32 key, BigInteger value) {
        return new StorageRangesMessage.StorageData(key, Bytes.wrap(value.toByteArray()).trimLeadingZeros());
    }

    private static StorageRangesMessage.DecodeResult response(
            List<StorageRangesMessage.StorageData> slots, Bytes proofNode) {
        return new StorageRangesMessage.DecodeResult(1, slots, List.of(proofNode));
    }

    /**
     * A one-leaf storage trie's root node: {@code [hexPrefix(leaf, keyHash), rlp(value)]} — the
     * leaf value is the RLP of the trimmed integer, as in the real storage trie.
     */
    private static Bytes storageLeaf(Bytes32 keyHash, BigInteger value) {
        Bytes encodedValue = RLP.encode(w -> w.writeBigInteger(value));
        Bytes path = Bytes.concatenate(Bytes.of(0x20), keyHash); // leaf flag, even length
        return RLP.encodeList(w -> {
            w.writeValue(path);
            w.writeValue(encodedValue);
        });
    }
}
