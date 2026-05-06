package io.myotis.evm.world;

import io.myotis.evm.Address;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Snapshot of an account's state at a particular {@code stateRoot}.
 *
 * <p>This is the data structure SNAP returns and the fixture loader emits.
 * Storage values are not embedded here — they are fetched separately, slot
 * by slot, via {@link SnapStateOracle#fetchStorage}. Bytecode is referenced
 * by {@code codeHash}; the actual bytecode is resolved through
 * {@link io.myotis.evm.world.BytecodeCache}.
 */
public record AccountState(
        Address address,
        long nonce,
        BigInteger balance,
        byte[] codeHash) {

    public AccountState {
        Objects.requireNonNull(address, "address");
        Objects.requireNonNull(balance, "balance");
        Objects.requireNonNull(codeHash, "codeHash");
        if (codeHash.length != 32) {
            throw new IllegalArgumentException("codeHash must be 32 bytes");
        }
        if (balance.signum() < 0) {
            throw new IllegalArgumentException("balance cannot be negative");
        }
    }
}
