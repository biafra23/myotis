package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Fee-field decoding for legacy and typed transactions, plus effectiveTip math. */
class TxFeeFieldsTest {

    private static final BigInteger GWEI = BigInteger.valueOf(1_000_000_000L);

    /** Legacy tx: rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s]) */
    private static Bytes legacyTx(BigInteger gasPrice) {
        return RLP.encodeList(w -> {
            w.writeLong(7);                              // nonce
            w.writeBigInteger(gasPrice);
            w.writeLong(21000);                          // gasLimit
            w.writeByteArray(new byte[20]);              // to
            w.writeBigInteger(BigInteger.ONE);           // value
            w.writeByteArray(new byte[0]);               // data
            w.writeLong(27); w.writeLong(1); w.writeLong(1); // v, r, s
        });
    }

    /** EIP-1559 tx: 0x02 || rlp([chainId, nonce, maxPriority, maxFee, gasLimit, to, value, data, accessList, yParity, r, s]) */
    private static Bytes eip1559Tx(BigInteger maxPriority, BigInteger maxFee) {
        Bytes payload = RLP.encodeList(w -> {
            w.writeLong(1);                              // chainId
            w.writeLong(7);                              // nonce
            w.writeBigInteger(maxPriority);
            w.writeBigInteger(maxFee);
            w.writeLong(21000);
            w.writeByteArray(new byte[20]);
            w.writeBigInteger(BigInteger.ONE);
            w.writeByteArray(new byte[0]);
            w.writeList(lw -> {});                       // accessList
            w.writeLong(0); w.writeLong(1); w.writeLong(1);
        });
        return Bytes.concatenate(Bytes.of(0x02), payload);
    }

    @Test
    void decodesLegacyGasPrice() {
        TxFeeFields f = TxFeeFields.decode(legacyTx(GWEI.multiply(BigInteger.valueOf(20))));
        assertEquals(0, f.type());
        assertEquals(GWEI.multiply(BigInteger.valueOf(20)), f.gasPrice());
        // effective tip = gasPrice - baseFee
        assertEquals(GWEI.multiply(BigInteger.valueOf(5)),
                f.effectiveTip(GWEI.multiply(BigInteger.valueOf(15))));
    }

    @Test
    void decodes1559FeeCaps() {
        TxFeeFields f = TxFeeFields.decode(eip1559Tx(GWEI, GWEI.multiply(BigInteger.valueOf(30))));
        assertEquals(2, f.type());
        assertEquals(GWEI, f.maxPriorityFeePerGas());
        assertEquals(GWEI.multiply(BigInteger.valueOf(30)), f.maxFeePerGas());
        // baseFee leaves more headroom than the tip cap → tip cap wins
        assertEquals(GWEI, f.effectiveTip(GWEI.multiply(BigInteger.valueOf(10))));
        // baseFee squeezes headroom below the tip cap → maxFee - baseFee wins
        assertEquals(GWEI.divide(BigInteger.TWO),
                f.effectiveTip(GWEI.multiply(BigInteger.valueOf(30)).subtract(GWEI.divide(BigInteger.TWO))));
    }

    @Test
    void effectiveTipFlooredAtZero() {
        // legacy gasPrice below baseFee (can't actually be included) → 0, never negative
        TxFeeFields f = TxFeeFields.decode(legacyTx(GWEI));
        assertEquals(BigInteger.ZERO, f.effectiveTip(GWEI.multiply(BigInteger.TEN)));
    }

    @Test
    void unknownTypeAndGarbageReturnNull() {
        assertNull(TxFeeFields.decode(Bytes.concatenate(Bytes.of(0x7f), Bytes.of(1, 2, 3))));
        assertNull(TxFeeFields.decode(Bytes.of(0x01, 0x02)));   // truncated typed payload
        assertNull(TxFeeFields.decode(Bytes.EMPTY));
        assertNull(TxFeeFields.decode(null));
    }
}
