package io.myotis.evm.world;

import io.myotis.evm.Address;
import io.myotis.evm.EvmExecutionError;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;

/**
 * Source of state for the EVM, served on demand and verified against a
 * trusted {@code stateRoot}.
 *
 * <p>The contract is strict: every successful return value must be backed by
 * a SNAP proof that verifies against the {@code stateRoot} the caller supplied,
 * or by a Keccak-256 hash check for bytecode. Implementations must reject
 * unverifiable responses and surface {@link EvmExecutionError.InvalidProof}.
 *
 * <p>Phase 1 wires this to {@code networking/snap}. Phase 0 uses
 * {@link FixtureSnapStateOracle}.
 */
public interface SnapStateOracle {

    /**
     * Fetch the account record at {@code address} under {@code stateRoot}.
     *
     * <p>An absent account (no record in the trie) returns the empty default:
     * nonce=0, balance=0, codeHash=keccak256(empty).
     */
    CompletableFuture<AccountState> fetchAccount(byte[] stateRoot, Address address);

    /**
     * Fetch storage slot {@code slot} of {@code address} under {@code stateRoot}.
     * Missing slots return {@link BigInteger#ZERO}.
     */
    CompletableFuture<BigInteger> fetchStorage(byte[] stateRoot, Address address, BigInteger slot);

    /** Fetch bytecode by its keccak256 hash. */
    CompletableFuture<byte[]> fetchBytecode(byte[] codeHash);
}
