package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Round-trips a tx through sign → decode and asserts the recovered sender matches the
 * signing key's address — the load-bearing part (per-type signing-hash reconstruction).
 */
class EthTxDecoderTest {

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final SECP256K1.KeyPair KP = SECP256K1.KeyPair.random();
    private static final Bytes EXPECTED_FROM = Hash.keccak256(KP.publicKey().bytes()).slice(12, 20);
    private static final Bytes TO = Bytes.fromHexString("0x00000000219ab540356cBB839Cbe05303d7705Fa");

    /** 0x02 || rlp([chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList, yParity, r, s]) */
    @Test
    void recoversSenderFrom1559() {
        Bytes signing = Bytes.concatenate(Bytes.of(2), RLP.encodeList(w -> {
            w.writeLong(1);                                   // chainId
            w.writeLong(42);                                  // nonce
            w.writeBigInteger(BigInteger.valueOf(1_000_000_000L));     // maxPriority
            w.writeBigInteger(BigInteger.valueOf(30_000_000_000L));    // maxFee
            w.writeLong(21000);                               // gas
            w.writeValue(TO);
            w.writeBigInteger(BigInteger.valueOf(1_000_000));  // value
            w.writeValue(Bytes.EMPTY);                         // data
            w.writeList(al -> {});                             // accessList
        }));
        SECP256K1.Signature sig = SECP256K1.signHashed(Hash.keccak256(signing), KP);

        Bytes raw = Bytes.concatenate(Bytes.of(2), RLP.encodeList(w -> {
            w.writeLong(1); w.writeLong(42);
            w.writeBigInteger(BigInteger.valueOf(1_000_000_000L));
            w.writeBigInteger(BigInteger.valueOf(30_000_000_000L));
            w.writeLong(21000); w.writeValue(TO);
            w.writeBigInteger(BigInteger.valueOf(1_000_000)); w.writeValue(Bytes.EMPTY);
            w.writeList(al -> {});
            w.writeInt(sig.v());
            w.writeBigInteger(sig.r()); w.writeBigInteger(sig.s());
        }));

        EthTxDecoder.DecodedTx t = EthTxDecoder.decode(raw);
        assertNotNull(t);
        assertEquals(2, t.type());
        assertEquals(42, t.nonce());
        assertEquals(1L, t.chainId());
        assertEquals(BigInteger.valueOf(30_000_000_000L), t.maxFeePerGas());
        assertArrayEquals(TO.toArray(), t.to().toArray());
        assertNotNull(t.from(), "sender must be recovered");
        assertArrayEquals(EXPECTED_FROM.toArray(), t.from().toArray());
    }

    /** legacy EIP-155: rlp([nonce, gasPrice, gas, to, value, data, v, r, s]), v = chainId*2+35+yParity */
    @Test
    void recoversSenderFromLegacyEip155() {
        long chainId = 1;
        Bytes signing = RLP.encodeList(w -> {
            w.writeLong(7);                                    // nonce
            w.writeBigInteger(BigInteger.valueOf(20_000_000_000L));  // gasPrice
            w.writeLong(21000);                                // gas
            w.writeValue(TO);
            w.writeBigInteger(BigInteger.valueOf(5_000_000));   // value
            w.writeValue(Bytes.EMPTY);                          // data
            w.writeLong(chainId); w.writeInt(0); w.writeInt(0); // EIP-155 trailer
        });
        SECP256K1.Signature sig = SECP256K1.signHashed(Hash.keccak256(signing), KP);
        long v = chainId * 2 + 35 + sig.v();

        Bytes raw = RLP.encodeList(w -> {
            w.writeLong(7); w.writeBigInteger(BigInteger.valueOf(20_000_000_000L));
            w.writeLong(21000); w.writeValue(TO);
            w.writeBigInteger(BigInteger.valueOf(5_000_000)); w.writeValue(Bytes.EMPTY);
            w.writeLong(v); w.writeBigInteger(sig.r()); w.writeBigInteger(sig.s());
        });

        EthTxDecoder.DecodedTx t = EthTxDecoder.decode(raw);
        assertNotNull(t);
        assertEquals(0, t.type());
        assertEquals(1L, t.chainId());
        assertEquals(BigInteger.valueOf(20_000_000_000L), t.gasPrice());
        assertArrayEquals(EXPECTED_FROM.toArray(), t.from().toArray());
    }

    @Test
    void unknownTypeReturnsNull() {
        assertNull(EthTxDecoder.decode(Bytes.fromHexString("0x7fabcdef")));
        assertNull(EthTxDecoder.decode(Bytes.EMPTY));
        assertNull(EthTxDecoder.decode(null));
    }
}
