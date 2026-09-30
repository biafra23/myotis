package io.myotis.evm;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Unsigned transaction parameters used as input to gas estimation.
 *
 * <p>Mirrors the relevant fields of an EIP-1559 transaction; legacy and
 * access-list shapes are projected to this for estimation purposes. This is a
 * Phase 5 input — earlier phases only call {@link EvmExecutor#callView}.
 *
 * <p>The fee fields follow geth's {@code eth_estimateGas} (#509): a legacy
 * {@code gasPrice} is both the fee cap and the tip; the effective price the
 * GASPRICE opcode reads is {@code min(gasFeeCap, baseFee + gasTipCap)}, zero
 * when neither is set; and a non-zero fee cap bounds the estimate by what the
 * sender can pay for.
 *
 * @param from       sender address
 * @param to         target address; null for contract creation
 * @param value      wei to transfer
 * @param data       calldata
 * @param gasLimit   optional cap; null lets the executor pick the ceiling. Below
 *                   21000 it is no cap at all — geth's reading, which a
 *                   {@code "gas": "0x0"} from a wallet relies on.
 * @param gasFeeCap  {@code maxFeePerGas} (or a legacy {@code gasPrice}), or null
 * @param gasTipCap  {@code maxPriorityFeePerGas} (or a legacy {@code gasPrice}), or null
 */
public record UnsignedTransaction(
        Address from,
        Address to,
        BigInteger value,
        byte[] data,
        Long gasLimit,
        BigInteger gasFeeCap,
        BigInteger gasTipCap) {

    public UnsignedTransaction {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(data, "data");
    }

    /** An unpriced transaction: no fee field set (GASPRICE reads zero). */
    public UnsignedTransaction(Address from, Address to, BigInteger value, byte[] data, Long gasLimit) {
        this(from, to, value, data, gasLimit, null, null);
    }

    /** The fee cap geth's affordability rule divides by; zero when unset. */
    public BigInteger feeCapOrZero() {
        return gasFeeCap == null ? BigInteger.ZERO : gasFeeCap;
    }

    /** The price GASPRICE reads at {@code baseFee}: {@code min(feeCap, baseFee + tip)}, zero when unpriced. */
    public BigInteger effectiveGasPrice(BigInteger baseFee) {
        BigInteger cap = feeCapOrZero();
        BigInteger tip = gasTipCap == null ? BigInteger.ZERO : gasTipCap;
        if (cap.signum() == 0 && tip.signum() == 0) return BigInteger.ZERO;
        BigInteger price = (baseFee == null ? BigInteger.ZERO : baseFee).add(tip);
        return price.min(cap);
    }
}
