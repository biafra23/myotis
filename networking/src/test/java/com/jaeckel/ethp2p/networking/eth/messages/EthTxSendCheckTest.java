package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.MutableBytes;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPReader;
import org.apache.tuweni.rlp.RLPWriter;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The eth_sendRawTransaction gate, {@link EthTxDecoder#checkSendable} (#360): only a
 * transaction is relayed. The Rust twin ({@code tx::decode_sendable}, myotis-net's
 * el/tx.rs tests) checks the same cases and must refuse them in the same words.
 */
class EthTxSendCheckTest {

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /** The throwaway key the Rust twin signs with: 0x42 × 32. */
    private static final SECP256K1.KeyPair KP = SECP256K1.KeyPair.fromSecretKey(
            SECP256K1.SecretKey.fromBytes(Bytes32.wrap(Bytes.repeat((byte) 0x42, 32))));
    private static final Bytes FROM = Hash.keccak256(KP.publicKey().bytes()).slice(12, 20);

    /** The EIP-155 spec example: sender 0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f. */
    private static final Bytes SPEC_TX = Bytes.fromHexString(
            "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7"
            + "6400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a0"
            + "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");

    private static final BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private static final String INVALID_SIG = "invalid transaction v, r, s values";

    // ---- RLP items: Bytes is a value, a List of items a list ----

    private static Bytes be(long v) {
        return Bytes.minimalBytes(v);
    }

    private static Bytes be(BigInteger v) {
        return Bytes.wrap(v.toByteArray()).trimLeadingZeros();
    }

    private static void write(RLPWriter w, Object item) {
        if (item instanceof Bytes b) {
            w.writeValue(b);
        } else {
            w.writeList(lw -> ((List<?>) item).forEach(i -> write(lw, i)));
        }
    }

    private static Bytes encode(List<Object> items) {
        return RLP.encodeList(w -> items.forEach(i -> write(w, i)));
    }

    private static List<Object> items(RLPReader r) {
        List<Object> out = new ArrayList<>();
        while (!r.isComplete()) out.add(r.nextIsList() ? r.readList(EthTxSendCheckTest::items) : r.readValue());
        return out;
    }

    /** The unsigned fields of a type-{@code ty} (1, 2 or 4) transfer on chain 1. */
    private static List<Object> unsignedFields(int ty) {
        List<Object> f = new ArrayList<>(List.of(be(1), be(7)));                // chainId, nonce
        if (ty == 1) {
            f.add(be(30_000_000_000L));                                          // gasPrice
        } else {
            f.add(be(2_000_000_000L));                                           // maxPriorityFeePerGas
            f.add(be(30_000_000_000L));                                          // maxFeePerGas
        }
        f.addAll(List.of(be(21_000), Bytes.repeat((byte) 0x11, 20), be(1), Bytes.EMPTY, List.of()));
        if (ty == 4) {
            // One authorization; the gate does not read its contents.
            f.add(List.of(List.of(be(1), Bytes.repeat((byte) 0xde, 20), Bytes.EMPTY, be(1),
                    Bytes.repeat((byte) 1, 32), Bytes.repeat((byte) 2, 32))));
        }
        return f;
    }

    /** {@code ty || rlp([..unsigned, yParity, r, s])} signed by {@link #KP}. */
    private static Bytes signTyped(int ty, List<Object> unsigned) {
        Bytes preimage = Bytes.concatenate(Bytes.of(ty), encode(unsigned));
        SECP256K1.Signature sig = SECP256K1.signHashed(Hash.keccak256(preimage), KP);
        List<Object> fields = new ArrayList<>(unsigned);
        fields.add(be(sig.v()));
        fields.add(be(sig.r()));
        fields.add(be(sig.s()));
        return Bytes.concatenate(Bytes.of(ty), encode(fields));
    }

    private static Bytes signTyped(int ty, Consumer<List<Object>> edit) {
        List<Object> f = unsignedFields(ty);
        edit.accept(f);
        return signTyped(ty, f);
    }

    /** {@code levels} lists, each holding the next: the outermost is a transaction field
     *  (depth 1), so the innermost, empty, sits at depth {@code levels}. */
    private static Object nested(int levels) {
        Object item = List.of();
        for (int i = 1; i < levels; i++) item = List.of(item);
        return item;
    }

    /** A typed {@code raw} with its fields edited and its signature left as it was. */
    private static Bytes edited(Bytes raw, Consumer<List<Object>> edit) {
        List<Object> fields = RLP.decodeList(raw.slice(1), EthTxSendCheckTest::items);
        edit.accept(fields);
        return Bytes.concatenate(raw.slice(0, 1), encode(fields));
    }

    private static String refusal(Bytes raw) {
        EthTxDecoder.SendCheck c = EthTxDecoder.checkSendable(raw);
        assertNull(c.tx(), "refused, so no transaction");
        assertNotNull(c.refusal(), "refused");
        return c.refusal();
    }

    private static EthTxDecoder.DecodedTx sendable(Bytes raw) {
        EthTxDecoder.SendCheck c = EthTxDecoder.checkSendable(raw);
        assertNull(c.refusal(), () -> "refused: " + c.refusal());
        return c.tx();
    }

    @Test
    void aSignedTransactionOfEveryRelayedTypePasses() {
        assertEquals(Bytes.fromHexString("0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"), sendable(SPEC_TX).from());
        for (int ty : new int[] {1, 2, 4}) {
            EthTxDecoder.DecodedTx tx = sendable(signTyped(ty, unsignedFields(ty)));
            assertEquals(ty, tx.type());
            assertEquals(FROM, tx.from(), "type " + ty);
        }
        // A creation is a transaction like any other — except for type 0x4.
        assertEquals(Bytes.EMPTY, sendable(signTyped(2, f -> f.set(5, Bytes.EMPTY))).to());
    }

    @Test
    void bytesThatAreNoTransactionAreRefused() {
        // The issue's reproduction: one 0x00 byte.
        assertEquals("invalid raw transaction: transaction type not supported (0x0)",
                refusal(Bytes.fromHexString("0x00")));
        assertEquals("invalid raw transaction: empty", refusal(Bytes.EMPTY));
        assertEquals("invalid raw transaction: empty", refusal(null));
        assertEquals("invalid raw transaction: transaction type not supported (0x5)",
                refusal(Bytes.fromHexString("0x05c0")));
        assertEquals("invalid raw transaction: transaction type not supported (0x7f)",
                refusal(Bytes.fromHexString("0x7f")));
        assertEquals("invalid raw transaction: neither an RLP list nor an EIP-2718 typed transaction",
                refusal(Bytes.fromHexString("0x83646f67")));
        assertEquals("invalid raw transaction: malformed legacy transaction", refusal(Bytes.fromHexString("0xc0")));
        assertEquals("invalid raw transaction: malformed type 0x2 transaction", refusal(Bytes.fromHexString("0x02")));
        assertEquals("invalid raw transaction: malformed type 0x2 transaction", refusal(Bytes.fromHexString("0x02c0")));
        // Truncated by one byte.
        assertEquals("invalid raw transaction: malformed legacy transaction",
                refusal(SPEC_TX.slice(0, SPEC_TX.size() - 1)));
    }

    @Test
    void aBlobTransactionIsRefusedInEitherForm() {
        // The network form (0x03 || rlp([tx, blobs, commitments, proofs])) and the bare
        // one alike: neither may be pushed in a Transactions message.
        Bytes bare = signTyped(2, unsignedFields(2));
        assertEquals(EthTxDecoder.BLOB_SEND_REFUSAL, refusal(Bytes.concatenate(Bytes.of(3), bare.slice(1))));
        List<Object> network = List.of(RLP.decodeList(bare.slice(1), EthTxSendCheckTest::items),
                List.of(), List.of(), List.of());
        assertEquals(EthTxDecoder.BLOB_SEND_REFUSAL, refusal(Bytes.concatenate(Bytes.of(3), encode(network))));
    }

    @Test
    void onlyAStrictEncodingPassesSoTheHashIsTheTransactionsOwn() {
        String malformed = "invalid raw transaction: malformed type 0x2 transaction";
        Bytes raw = signTyped(2, unsignedFields(2));
        // Anything trailing the transaction.
        assertEquals(malformed, refusal(Bytes.concatenate(raw, Bytes.of(0))));
        assertEquals("invalid raw transaction: malformed legacy transaction",
                refusal(Bytes.concatenate(SPEC_TX, Bytes.of(0x80))));
        // A field too many, or too few.
        assertEquals(malformed, refusal(edited(raw, f -> f.add(Bytes.EMPTY))));
        assertEquals(malformed, refusal(edited(raw, f -> f.remove(7))));
        // An integer with a leading zero byte, even one the signature covers.
        assertEquals(malformed, refusal(signTyped(2, f -> f.set(1, Bytes.fromHexString("0x0007")))));
        assertEquals(malformed, refusal(edited(raw, f -> f.set(11, Bytes.concatenate(Bytes.of(0), (Bytes) f.get(11))))));
        // The access list as bytes, or `to` as a list.
        assertEquals(malformed, refusal(signTyped(2, f -> f.set(8, Bytes.EMPTY))));
        assertEquals(malformed, refusal(edited(raw, f -> f.set(5, List.of()))));
        // A `to` that is neither empty nor an address; a fee wider than 16 bytes.
        assertEquals(malformed, refusal(edited(raw, f -> f.set(5, Bytes.repeat((byte) 0x11, 5)))));
        assertEquals(malformed, refusal(edited(raw, f -> f.set(3, Bytes.repeat((byte) 0x01, 17)))));
        // Nesting: an access list whose innermost list sits 32 deep (the top-level list
        // at 0) is still RLP the Rust decoder reads; one level more is not.
        sendable(signTyped(2, f -> f.set(8, nested(32))));
        assertEquals(malformed, refusal(signTyped(2, f -> f.set(8, nested(33)))));
        // Non-canonical RLP: the nonce 0x07 spelled 0x81 0x07, where a byte below 0x80
        // must stand for itself.
        assertEquals(Bytes.fromHexString("0x02f8"), raw.slice(0, 2));
        assertEquals(Bytes.fromHexString("0x0107"), raw.slice(3, 2)); // chainId 1, nonce 7
        MutableBytes longForm = Bytes.concatenate(raw.slice(0, 4), Bytes.of(0x81), raw.slice(4)).mutableCopy();
        longForm.set(2, (byte) (longForm.get(2) + 1)); // the list's length byte
        assertEquals(malformed, refusal(longForm));
    }

    @Test
    void aSetCodeTransactionMustNameItsTarget() {
        assertEquals("invalid raw transaction: a type 0x4 transaction cannot create a contract",
                refusal(signTyped(4, f -> f.set(5, Bytes.EMPTY))));
    }

    @Test
    void aSignatureAPeerWouldRefuseIsRefused() {
        // A legacy v that is neither 27/28 nor EIP-155.
        int at = SPEC_TX.size() - 67; // v = 0x25 sits before the r (0xa0 || 32) and s items
        assertEquals(0x25, SPEC_TX.get(at));
        MutableBytes v29 = SPEC_TX.mutableCopy();
        v29.set(at, (byte) 29);
        assertEquals(INVALID_SIG, refusal(v29));
        Bytes raw = signTyped(2, unsignedFields(2));
        // A typed yParity above 1 — 2, or one past 32 bits (decode() reads it as an
        // int; it must still be a signature value here, as in the Rust twin).
        assertEquals(INVALID_SIG, refusal(edited(raw, f -> f.set(9, be(2)))));
        assertEquals(INVALID_SIG, refusal(edited(raw, f -> f.set(9, be(1L << 40)))));
        // r or s zero, r at or past n.
        assertEquals(INVALID_SIG, refusal(edited(raw, f -> f.set(10, Bytes.EMPTY))));
        assertEquals(INVALID_SIG, refusal(edited(raw, f -> f.set(11, Bytes.EMPTY))));
        assertEquals(INVALID_SIG, refusal(edited(raw, f -> f.set(10, be(N)))));
        // The malleated twin of a valid signature — s' = n - s, the parity flipped —
        // would name the same sender, but it is high-s: EIP-2 refuses it.
        Bytes malleated = edited(raw, f -> {
            BigInteger s = ((Bytes) f.get(11)).toUnsignedBigInteger();
            long parity = ((Bytes) f.get(9)).isEmpty() ? 0 : ((Bytes) f.get(9)).toLong();
            f.set(9, be(1 - parity));
            f.set(11, be(N.subtract(s)));
        });
        assertEquals(INVALID_SIG, refusal(malleated));
        assertEquals(FROM, sendable(raw).from());
        // An r in range that is no curve point's x: nothing recovers.
        Bytes senderless = null;
        for (int x = 1; x <= 255 && senderless == null; x++) {
            final int r = x;
            Bytes candidate = edited(raw, f -> f.set(10, be(r)));
            EthTxDecoder.DecodedTx t = EthTxDecoder.decode(candidate);
            if (t != null && t.from() == null) senderless = candidate;
        }
        assertNotNull(senderless, "some small r is no x-coordinate");
        assertEquals("invalid sender: the signature recovers no address", refusal(senderless));
    }
}
