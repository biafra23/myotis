package com.jaeckel.ethp2p.core.types;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.math.BigInteger;
import java.security.Security;
import java.util.function.Consumer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPWriter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * A.3: an Amsterdam header (EIP-7928 blockAccessListHash, then EIP-7843
 * slotNumber, after requestsHash) decodes and hashes like any other — twin of
 * the Rust {@code amsterdam_header_round_trips_through_decode_and_hash}. This
 * decoder reads nothing past requestsHash; what matters is that the two new
 * trailing fields are not rejected, shift none of the fields before them, and
 * stay covered by the block hash, which is keccak256 of the RAW encoding.
 */
class BlockHeaderAmsterdamTest {

    /** Sepolia's first Amsterdam slot (ethereum/pm#2205). */
    private static final long SLOT = 11_296_768L;

    private static final Bytes32 STATE_ROOT = Bytes32.repeat((byte) 0x04);
    private static final Bytes32 PARENT_BEACON_ROOT = Bytes32.repeat((byte) 0x09);

    @BeforeAll
    static void registerBouncyCastle() {
        // Tuweni's keccak256 is a JCA digest (see MerklePatriciaProofVerifierTest).
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** A Prague-shaped header (21 fields, requestsHash last) plus {@code tail}. */
    private static Bytes header(Consumer<RLPWriter> tail) {
        return RLP.encodeList(w -> {
            w.writeValue(Bytes32.repeat((byte) 0x01));          // parentHash
            w.writeValue(Bytes32.repeat((byte) 0x02));          // ommersHash
            w.writeValue(Bytes.repeat((byte) 0x03, 20));        // beneficiary
            w.writeValue(STATE_ROOT);                           // stateRoot
            w.writeValue(Bytes32.repeat((byte) 0x05));          // transactionsRoot
            w.writeValue(Bytes32.repeat((byte) 0x06));          // receiptsRoot
            w.writeValue(Bytes.wrap(new byte[256]));            // logsBloom
            w.writeBigInteger(BigInteger.ZERO);                 // difficulty
            w.writeLong(10_000_000L);                           // number
            w.writeLong(60_000_000L);                           // gasLimit
            w.writeLong(21_000L);                               // gasUsed
            w.writeLong(1_791_294_816L);                        // timestamp
            w.writeValue(Bytes.wrap("myotis-amsterdam".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
            w.writeValue(Bytes32.repeat((byte) 0x07));          // mixHash / prevRandao
            w.writeValue(Bytes.wrap(new byte[8]));              // nonce
            w.writeBigInteger(BigInteger.valueOf(7));           // baseFeePerGas
            w.writeValue(Bytes32.repeat((byte) 0x08));          // withdrawalsRoot
            w.writeLong(0);                                     // blobGasUsed
            w.writeLong(0);                                     // excessBlobGas
            w.writeValue(PARENT_BEACON_ROOT);                   // parentBeaconBlockRoot
            w.writeValue(Bytes32.repeat((byte) 0x0a));          // requestsHash
            tail.accept(w);
        });
    }

    private static Bytes amsterdam(long slot) {
        return header(w -> {
            w.writeValue(Bytes32.repeat((byte) 0x0b));          // blockAccessListHash
            w.writeLong(slot);                                  // slotNumber
        });
    }

    @Test
    void amsterdamHeaderDecodesAndHashesOverTheRawBytes() {
        Bytes raw = amsterdam(SLOT);
        BlockHeader h = BlockHeader.decode(raw);
        assertEquals(10_000_000L, h.number);
        assertEquals(STATE_ROOT, h.stateRoot);
        assertEquals(1_791_294_816L, h.timestamp);
        assertEquals(PARENT_BEACON_ROOT, h.parentBeaconBlockRoot);
        assertEquals(Hash.keccak256(raw), BlockHeader.hash(raw));
        // The trailing fields are covered by the hash: the same header without
        // them is a different block.
        assertNotEquals(BlockHeader.hash(header(w -> { })), BlockHeader.hash(raw));
    }

    @Test
    void slotZeroAndLaterForkFieldsAreNotRejected() {
        assertEquals(10_000_000L, BlockHeader.decode(amsterdam(0)).number); // slot 0 = empty string
        Bytes later = header(w -> {
            w.writeValue(Bytes32.repeat((byte) 0x0b));
            w.writeLong(SLOT);
            w.writeValue(Bytes.wrap("a-later-fork".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        });
        assertEquals(STATE_ROOT, BlockHeader.decode(later).stateRoot);
    }
}
