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

    /**
     * Best-effort batch WARM of {@code request} (account &rarr; the storage slots
     * wanted under it) into the oracle's proof cache, coalesced into a few
     * {@code GetTrieNodes} round-trips (one path-set per account, chunked) instead of
     * one round-trip per item. Verification is identical to {@link #fetchAccount} /
     * {@link #fetchStorage} — each account/slot proof is independently checked against
     * its (state / storage) root; only the REQUESTS coalesce. Callers must treat it as
     * a pure cache warmer: read the actual values back via fetchAccount/fetchStorage
     * (which hit the warmed cache), so an item the batch couldn't verify simply
     * becomes a normal per-item fetch. Default no-op for oracles without a proof cache.
     */
    default CompletableFuture<Void> fetchBatch(
            byte[] stateRoot,
            java.util.Map<Address, ? extends java.util.Set<BigInteger>> request) {
        return CompletableFuture.completedFuture(null);
    }
}
