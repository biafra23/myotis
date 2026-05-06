package io.myotis.evm.world;

import io.myotis.evm.Address;
import io.myotis.evm.CryptoProviders;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * In-memory {@link SnapStateOracle} backed by hand-supplied fixture data.
 *
 * <p>Phase 0 spike harness. Lets us drive the EVM end-to-end against known
 * state without standing up a real SNAP peer. Phase 1 replaces this with the
 * actual SNAP-backed implementation.
 *
 * <p>Construct via {@link Builder} so the fixture is immutable once handed to
 * the executor:
 * <pre>{@code
 * var oracle = FixtureSnapStateOracle.builder()
 *     .account(usdc, AccountState.eoa(...))
 *     .bytecode(usdc, USDC_BYTECODE)
 *     .storage(usdc, slot, value)
 *     .build();
 * }</pre>
 */
public final class FixtureSnapStateOracle implements SnapStateOracle {

    private final Map<Address, AccountState> accounts;
    private final Map<Bytes, byte[]> bytecodeByHash;
    private final Map<Address, Map<BigInteger, BigInteger>> storage;

    private FixtureSnapStateOracle(Builder b) {
        this.accounts = Map.copyOf(b.accounts);
        this.bytecodeByHash = Map.copyOf(b.bytecodeByHash);
        Map<Address, Map<BigInteger, BigInteger>> copy = new HashMap<>();
        for (var e : b.storage.entrySet()) copy.put(e.getKey(), Map.copyOf(e.getValue()));
        this.storage = Map.copyOf(copy);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public CompletableFuture<AccountState> fetchAccount(byte[] stateRoot, Address address) {
        AccountState a = accounts.get(address);
        if (a == null) {
            // Absent accounts surface as a default empty record. Mirrors the SNAP
            // protocol contract: a missing trie node for an address means EOA-of-zero.
            CryptoProviders.ensureRegistered();
            byte[] emptyCodeHash = Hash.keccak256(Bytes.EMPTY).toArrayUnsafe();
            return CompletableFuture.completedFuture(
                    new AccountState(address, 0L, BigInteger.ZERO, emptyCodeHash));
        }
        return CompletableFuture.completedFuture(a);
    }

    @Override
    public CompletableFuture<BigInteger> fetchStorage(byte[] stateRoot, Address address, BigInteger slot) {
        Map<BigInteger, BigInteger> slots = storage.get(address);
        if (slots == null) return CompletableFuture.completedFuture(BigInteger.ZERO);
        return CompletableFuture.completedFuture(slots.getOrDefault(slot, BigInteger.ZERO));
    }

    @Override
    public CompletableFuture<byte[]> fetchBytecode(byte[] codeHash) {
        byte[] code = bytecodeByHash.get(Bytes.wrap(codeHash));
        if (code == null) {
            return CompletableFuture.failedFuture(new EvmExecutionException(
                    new EvmExecutionError.BytecodeUnavailable(codeHash.clone())));
        }
        return CompletableFuture.completedFuture(code.clone());
    }

    public static final class Builder {
        private final Map<Address, AccountState> accounts = new HashMap<>();
        private final Map<Bytes, byte[]> bytecodeByHash = new HashMap<>();
        private final Map<Address, Map<BigInteger, BigInteger>> storage = new HashMap<>();

        public Builder account(AccountState state) {
            accounts.put(state.address(), state);
            return this;
        }

        /**
         * Register {@code bytecode} for an account. The fixture stores it
         * keyed by the keccak256 hash, so callers do not need to compute the
         * hash themselves; the corresponding {@link AccountState} should
         * carry the same hash, which can also be obtained from {@link #codeHashOf}.
         */
        public Builder bytecode(byte[] bytecode) {
            byte[] hash = codeHashOf(bytecode);
            bytecodeByHash.put(Bytes.wrap(hash), bytecode.clone());
            return this;
        }

        public Builder storage(Address address, BigInteger slot, BigInteger value) {
            storage.computeIfAbsent(address, k -> new HashMap<>()).put(slot, value);
            return this;
        }

        public FixtureSnapStateOracle build() {
            return new FixtureSnapStateOracle(this);
        }
    }

    /** Convenience helper for fixture builders. */
    public static byte[] codeHashOf(byte[] bytecode) {
        CryptoProviders.ensureRegistered();
        return Hash.keccak256(Bytes.wrap(bytecode)).toArrayUnsafe();
    }
}
