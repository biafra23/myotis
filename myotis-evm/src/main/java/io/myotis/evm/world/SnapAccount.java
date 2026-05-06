package io.myotis.evm.world;

import io.myotis.evm.Address;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.account.AccountStorageEntry;
import org.hyperledger.besu.evm.account.MutableAccount;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * {@link MutableAccount} backed by a {@link SyncStateView} for misses and an
 * in-memory journal for writes performed during execution.
 *
 * <p>Code is loaded lazily on first {@link #getCode} call. Storage values are
 * loaded on first {@link #getStorageValue} call and journalled in a separate
 * map; subsequent {@link #setStorageValue} writes shadow the loaded value
 * without invalidating it (the original is preserved for
 * {@link #getOriginalStorageValue}, which the EVM's gas refund logic uses).
 */
final class SnapAccount implements MutableAccount {

    private final org.hyperledger.besu.datatypes.Address besuAddress;
    private final SyncStateView view;

    private long nonce;
    private Wei balance;
    /**
     * Snapshot of the {@code codeHash} read at construction time. Becomes
     * stale after {@link #setCode} so {@code getCodeHash} recomputes lazily
     * if {@code dirtyCode} is set.
     */
    private byte[] codeHash;
    private Bytes loadedCode;
    private boolean dirtyCode;

    private final Map<UInt256, UInt256> originalStorage = new HashMap<>();
    private final Map<UInt256, UInt256> updatedStorage = new HashMap<>();

    private boolean immutable;

    private SnapAccount(org.hyperledger.besu.datatypes.Address besuAddress, SyncStateView view) {
        this.besuAddress = besuAddress;
        this.view = view;
    }

    SnapAccount(org.hyperledger.besu.datatypes.Address besuAddress, SyncStateView view, AccountState s) {
        this(besuAddress, view);
        this.nonce = s.nonce();
        this.balance = Wei.of(s.balance());
        this.codeHash = s.codeHash();
    }

    static SnapAccount fromState(AccountState s, SyncStateView view) {
        org.hyperledger.besu.datatypes.Address bAddr =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(s.address().toByteArray()));
        return new SnapAccount(bAddr, view, s);
    }

    /** For the EVM-call internal {@code WorldUpdater} new-account ctor. */
    SnapAccount(org.hyperledger.besu.datatypes.Address besuAddress, SyncStateView view, boolean fresh) {
        this(besuAddress, view);
        this.nonce = 0L;
        this.balance = Wei.ZERO;
        this.codeHash = Hash.EMPTY.toArrayUnsafe();
        this.loadedCode = Bytes.EMPTY;
    }

    static SnapAccount fromMutable(MutableAccount src, SyncStateView view) {
        SnapAccount a = new SnapAccount(src.getAddress(), view);
        a.nonce = src.getNonce();
        a.balance = src.getBalance();
        a.codeHash = src.getCodeHash().toArrayUnsafe();
        a.loadedCode = src.getCode();
        // Inherit storage journals from the parent so writes performed
        // earlier in the same transaction are visible inside nested calls.
        // Without this, a child frame's SLOAD would re-read from the oracle
        // and miss the in-flight SSTORE's effect.
        if (src instanceof SnapAccount s) {
            a.originalStorage.putAll(s.originalStorage);
            a.updatedStorage.putAll(s.updatedStorage);
        }
        return a;
    }

    // ---- AccountState ------------------------------------------------------

    @Override
    public org.hyperledger.besu.datatypes.Address getAddress() {
        return besuAddress;
    }

    @Override
    public Hash getAddressHash() {
        return Hash.hash(besuAddress);
    }

    @Override
    public long getNonce() { return nonce; }

    @Override
    public Wei getBalance() { return balance; }

    @Override
    public Bytes getCode() {
        if (loadedCode != null) return loadedCode;
        if (codeHashIsEmpty()) {
            loadedCode = Bytes.EMPTY;
            return loadedCode;
        }
        loadedCode = Bytes.wrap(view.bytecode(codeHash));
        return loadedCode;
    }

    @Override
    public Hash getCodeHash() {
        if (dirtyCode) {
            // setCode was called; recompute from the new bytes.
            return Hash.hash(loadedCode);
        }
        return Hash.wrap(Bytes32.wrap(codeHash));
    }

    @Override
    public boolean isStorageEmpty() {
        // We cannot prove emptiness under SNAP without enumerating the entire
        // storage trie of the account. Returning false is always safe — at
        // worst the EVM does a redundant SLOAD for a slot that turns out to
        // be zero. Returning true incorrectly is *not* safe: SELFDESTRUCT and
        // EIP-161 empty-account cleanup would skip work that is required for
        // correct gas accounting.
        return false;
    }

    @Override
    public UInt256 getStorageValue(UInt256 slot) {
        UInt256 v = updatedStorage.get(slot);
        if (v != null) return v;
        UInt256 orig = originalStorage.get(slot);
        if (orig != null) return orig;
        UInt256 fetched = view.storage(Address.of(besuAddress.toArrayUnsafe()), slot);
        originalStorage.put(slot, fetched);
        return fetched;
    }

    @Override
    public UInt256 getOriginalStorageValue(UInt256 slot) {
        UInt256 cached = originalStorage.get(slot);
        if (cached != null) return cached;
        UInt256 fetched = view.storage(Address.of(besuAddress.toArrayUnsafe()), slot);
        originalStorage.put(slot, fetched);
        return fetched;
    }

    @Override
    public NavigableMap<Bytes32, AccountStorageEntry> storageEntriesFrom(Bytes32 startKeyHash, int limit) {
        // Used by debug/trace pathways we don't exercise during view calls.
        // Returning empty is correct under the SNAP model: enumerating the
        // full storage trie would be a separate (expensive) protocol call.
        return Collections.emptyNavigableMap();
    }

    // ---- MutableAccount ----------------------------------------------------

    @Override
    public void setNonce(long value) {
        ensureMutable();
        this.nonce = value;
    }

    @Override
    public void setBalance(Wei value) {
        ensureMutable();
        this.balance = value;
    }

    @Override
    public void setCode(Bytes code) {
        ensureMutable();
        this.loadedCode = code;
        this.dirtyCode = true;
    }

    @Override
    public void setStorageValue(UInt256 key, UInt256 value) {
        ensureMutable();
        // Lazily seed the original-value cache so a subsequent getOriginalStorageValue
        // returns the pre-write value rather than the journalled write.
        originalStorage.computeIfAbsent(key,
                k -> view.storage(Address.of(besuAddress.toArrayUnsafe()), k));
        updatedStorage.put(key, value);
    }

    @Override
    public void clearStorage() {
        ensureMutable();
        // EVM contract: subsequent SLOADs see zero. Wiping the original cache
        // and writing zeros into the journal both work; the cleaner approach
        // is to mark every previously-loaded slot as zeroed.
        Map<UInt256, UInt256> zeros = new HashMap<>();
        for (UInt256 k : originalStorage.keySet()) zeros.put(k, UInt256.ZERO);
        for (UInt256 k : updatedStorage.keySet()) zeros.put(k, UInt256.ZERO);
        updatedStorage.putAll(zeros);
    }

    @Override
    public Map<UInt256, UInt256> getUpdatedStorage() {
        return Collections.unmodifiableMap(new TreeMap<>(updatedStorage));
    }

    @Override
    public void becomeImmutable() {
        immutable = true;
    }

    private void ensureMutable() {
        if (immutable) throw new IllegalStateException("account is immutable");
    }

    private boolean codeHashIsEmpty() {
        return java.util.Arrays.equals(codeHash, Hash.EMPTY.toArrayUnsafe());
    }
}
