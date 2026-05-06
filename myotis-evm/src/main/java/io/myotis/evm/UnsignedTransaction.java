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
 * @param from      sender address
 * @param to        target address; null for contract creation
 * @param value     wei to transfer
 * @param data      calldata
 * @param gasLimit  optional cap; null lets the executor pick the ceiling
 */
public record UnsignedTransaction(
        Address from,
        Address to,
        BigInteger value,
        byte[] data,
        Long gasLimit) {

    public UnsignedTransaction {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(data, "data");
    }
}
