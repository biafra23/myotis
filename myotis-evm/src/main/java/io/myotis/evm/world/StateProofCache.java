package io.myotis.evm.world;

import com.jaeckel.ethp2p.core.encoding.Hex;

import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Cross-call cache of proof-<em>verified</em> state.
 *
 * <p><b>Why this exists.</b> A wallet fires huge {@code eth_call}s —
 * ~1000-token balance sweeps (MetaMask's BalanceChecker), 67KB Multicall3
 * batches (Kohaku's per-poll state sync) — and re-issues them every poll
 * cycle. {@link SnapBackedStateOracle}'s account memo is per-instance
 * (rebuilt with each head context), so without a node-level cache every
 * poll re-fetched hundreds of storage proofs from scratch — a storm that
 * saturated the few snap peers, starved cheap reads, and never converged.
 *
 * <p><b>Keying.</b> The two kinds are keyed by what their proofs anchor to:
 * <ul>
 *   <li><b>Accounts</b> are keyed by world {@code stateRoot}: the account
 *       leaf is proven against the world trie, and a new block means a new
 *       world root, so the (cheap, one-proof) account record must be
 *       re-proven per block.
 *   <li><b>Storage slots</b> are keyed by the account's {@code storageRoot}:
 *       a slot proof anchors at the storage trie root, not the world root,
 *       so a verified {@code (storageRoot, slot) -> value} mapping is a
 *       cryptographic fact independent of which block it was fetched at.
 *       Since most contracts' storage doesn't change every block, this lets
 *       a per-poll sweep reuse all slots of every unchanged contract across
 *       head advances — the per-block account proof (whose leaf carries the
 *       storageRoot) is exactly the freshness check that makes reuse sound.
 * </ul>
 *
 * <p><b>Why it's safe.</b> Entries are stored only after the MPT proof has
 * been verified against the respective root (see {@code verifyAndDecode*} in
 * {@link SnapBackedStateOracle}). State under a fixed root is immutable, so a
 * cached mapping is a cryptographic fact, not peer-trusted data — reusing it
 * for any call whose account resolves to that root is sound.
 *
 * <p>Bounded (LRU, per kind) so a long-lived node doesn't grow without limit
 * as the head advances and old roots fall out of use.
 */
public interface StateProofCache {

    /** Verified value of {@code slot} in the storage trie rooted at
     *  {@code storageRoot}, if cached. NOTE: keyed by the account's storage
     *  trie root (from its proven account leaf), NOT the world stateRoot. */
    Optional<BigInteger> getStorage(byte[] storageRoot, BigInteger slot);

    /** Cache a verified storage value under its storage trie root. */
    void putStorage(byte[] storageRoot, BigInteger slot, BigInteger value);

    /** Verified account record (+ storage root) for {@code address} at world
     *  {@code stateRoot}, if cached. */
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
        @Override public Optional<BigInteger> getStorage(byte[] r, BigInteger s) { return Optional.empty(); }
        @Override public void putStorage(byte[] r, BigInteger s, BigInteger v) {}
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

        private static String hex(byte[] b) { return Hex.formatHex(b); }

        private static String accountKey(byte[] root, byte[] addr) {
            return hex(root) + ':' + hex(addr);
        }

        private static String storageKey(byte[] storageRoot, BigInteger slot) {
            return hex(storageRoot) + ':' + slot.toString(16);
        }

        @Override public Optional<BigInteger> getStorage(byte[] storageRoot, BigInteger slot) {
            return Optional.ofNullable(storage.get(storageKey(storageRoot, slot)));
        }

        @Override public void putStorage(byte[] storageRoot, BigInteger slot, BigInteger value) {
            storage.put(storageKey(storageRoot, slot), value);   // BigInteger is immutable
        }

        @Override public Optional<AccountEntry> getAccount(byte[] root, byte[] addr) {
            return Optional.ofNullable(accounts.get(accountKey(root, addr)));
        }

        @Override public void putAccount(byte[] root, byte[] addr, AccountEntry entry) {
            accounts.put(accountKey(root, addr), entry);
        }
    }
}
