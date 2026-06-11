package io.myotis.evm.world;

import java.math.BigInteger;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Cross-call cache of proof-<em>verified</em> state, keyed by world {@code stateRoot}.
 *
 * <p><b>Why this exists.</b> A wallet confirm screen fires huge {@code eth_call}s —
 * a ~1000-token balance sweep (MetaMask's BalanceChecker) and Multicall3
 * simulations — and, when they exceed the per-call timeout, MetaMask <em>retries
 * the identical call</em> many times. {@link SnapBackedStateOracle}'s account
 * memo is per-instance (rebuilt with each head context) and storage slots were
 * not cached across calls at all, so every retry re-fetched hundreds of storage
 * proofs from scratch — a retry-storm that saturated the few snap peers, starved
 * cheap reads, and never converged. Caching the verified results at the node
 * level lets each retry reuse what the last one fetched, so the call converges in
 * a couple of attempts instead of looping forever.
 *
 * <p><b>Why it's safe.</b> Entries are keyed by {@code stateRoot} and stored only
 * after the MPT proof has been verified against that root (see
 * {@code verifyAndDecode*} in {@link SnapBackedStateOracle}). State at a fixed
 * {@code stateRoot} is immutable, so a cached {@code (stateRoot, address, slot) ->
 * value} mapping is a cryptographic fact, not peer-trusted data — reusing it
 * across any call pinned to that root is sound. MetaMask number-pins its confirm
 * reads to a block, so the retries share a {@code stateRoot} and hit the cache.
 *
 * <p>Bounded (LRU, per kind) so a long-lived node doesn't grow without limit as
 * the head advances and old roots fall out of use.
 */
public interface StateProofCache {

    /** Verified value of {@code slot} for {@code address} at {@code stateRoot}, if cached. */
    Optional<BigInteger> getStorage(byte[] stateRoot, byte[] address, BigInteger slot);

    /** Cache a verified storage value. */
    void putStorage(byte[] stateRoot, byte[] address, BigInteger slot, BigInteger value);

    /** Verified account record (+ storage root) for {@code address} at {@code stateRoot}, if cached. */
    Optional<AccountEntry> getAccount(byte[] stateRoot, byte[] address);

    /** Cache a verified account record. */
    void putAccount(byte[] stateRoot, byte[] address, AccountEntry entry);

    /** A verified account record plus its storage trie root (the latter is needed to
     *  anchor subsequent storage-slot proofs and isn't exposed on {@link AccountState}). */
    record AccountEntry(AccountState account, byte[] storageRoot) {
        public AccountEntry(AccountState account, byte[] storageRoot) {
            this.account = account;
            this.storageRoot = storageRoot.clone();
        }
        @Override public byte[] storageRoot() { return storageRoot.clone(); }
    }

    /** No-op cache; the default so existing callers/tests are unaffected. */
    static StateProofCache noop() {
        return Noop.INSTANCE;
    }

    /** Bounded in-memory cache; {@code maxEntriesPerKind} caps storage and account
     *  entries separately (LRU eviction). */
    static StateProofCache inMemory(int maxEntriesPerKind) {
        return new InMemory(maxEntriesPerKind);
    }

    enum Noop implements StateProofCache {
        INSTANCE;
        @Override public Optional<BigInteger> getStorage(byte[] r, byte[] a, BigInteger s) { return Optional.empty(); }
        @Override public void putStorage(byte[] r, byte[] a, BigInteger s, BigInteger v) {}
        @Override public Optional<AccountEntry> getAccount(byte[] r, byte[] a) { return Optional.empty(); }
        @Override public void putAccount(byte[] r, byte[] a, AccountEntry e) {}
    }

    final class InMemory implements StateProofCache {
        private final Map<String, BigInteger> storage;
        private final Map<String, AccountEntry> accounts;

        InMemory(int maxEntriesPerKind) {
            this.storage = boundedLru(maxEntriesPerKind);
            this.accounts = boundedLru(maxEntriesPerKind);
        }

        private static <V> Map<String, V> boundedLru(int cap) {
            return Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, V> eldest) {
                    return size() > cap;
                }
            });
        }

        private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

        private static String accountKey(byte[] root, byte[] addr) {
            return hex(root) + ':' + hex(addr);
        }

        private static String storageKey(byte[] root, byte[] addr, BigInteger slot) {
            return hex(root) + ':' + hex(addr) + ':' + slot.toString(16);
        }

        @Override public Optional<BigInteger> getStorage(byte[] root, byte[] addr, BigInteger slot) {
            return Optional.ofNullable(storage.get(storageKey(root, addr, slot)));
        }

        @Override public void putStorage(byte[] root, byte[] addr, BigInteger slot, BigInteger value) {
            storage.put(storageKey(root, addr, slot), value);   // BigInteger is immutable
        }

        @Override public Optional<AccountEntry> getAccount(byte[] root, byte[] addr) {
            return Optional.ofNullable(accounts.get(accountKey(root, addr)));
        }

        @Override public void putAccount(byte[] root, byte[] addr, AccountEntry entry) {
            accounts.put(accountKey(root, addr), entry);
        }
    }
}
