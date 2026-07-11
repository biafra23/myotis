package io.myotis.evm.world;

import io.myotis.evm.Address;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.account.MutableAccount;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * {@link WorldUpdater} that reads state from a {@link SyncStateView} on cache
 * miss and journals all writes in memory until {@link #commit()} or
 * {@link #revert()}.
 *
 * <p>For view-only callers ({@code callView}) the journal exists purely so
 * that intra-transaction {@code SSTORE}/{@code SLOAD} sequences see
 * each other's writes; nothing is ever written back to the network. The
 * journal is discarded along with the updater after each call.
 *
 * <p>Nested updaters (created via {@link #updater()}) are supported because
 * Besu's EVM expects them for {@code STATICCALL}/{@code DELEGATECALL} frames.
 * Their commit propagates dirty accounts up to the parent.
 */
public final class SnapWorldUpdater implements WorldUpdater {

    private final SyncStateView baseView;
    private final SnapWorldUpdater parent;

    /** Accounts touched in this updater's scope, indexed by address. */
    private final Map<org.hyperledger.besu.datatypes.Address, SnapAccount> touched = new HashMap<>();

    /**
     * Accounts explicitly deleted in this scope. {@code SELFDESTRUCT} adds
     * here; subsequent reads must see the account as gone.
     */
    private final Set<org.hyperledger.besu.datatypes.Address> deleted = new HashSet<>();

    public SnapWorldUpdater(SyncStateView baseView) {
        this(baseView, null);
    }

    private SnapWorldUpdater(SyncStateView baseView, SnapWorldUpdater parent) {
        this.baseView = baseView;
        this.parent = parent;
    }

    // ---- WorldView ---------------------------------------------------------

    @Override
    public Account get(org.hyperledger.besu.datatypes.Address address) {
        return getAccount(address);
    }

    // ---- WorldUpdater ------------------------------------------------------

    @Override
    public MutableAccount createAccount(
            org.hyperledger.besu.datatypes.Address address, long nonce, Wei balance) {
        SnapAccount a = new SnapAccount(address, baseView, true);
        a.setNonce(nonce);
        a.setBalance(balance);
        touched.put(address, a);
        deleted.remove(address);
        return a;
    }

    @Override
    public MutableAccount getAccount(org.hyperledger.besu.datatypes.Address address) {
        if (deleted.contains(address)) return null;
        SnapAccount cached = touched.get(address);
        if (cached != null) return cached;
        if (parent != null) {
            // A nested updater inherits its parent's view. Promote a snapshot
            // into the local map so subsequent writes in this scope diverge
            // without leaking back until commit().
            MutableAccount parentAccount = parent.getAccount(address);
            if (parentAccount == null) return null;
            SnapAccount nested = SnapAccount.fromMutable(parentAccount, baseView);
            touched.put(address, nested);
            return nested;
        }
        // Fall through to SNAP/fixture state. We always materialise an
        // EVM-side account record — the EVM treats absent accounts as
        // empty (nonce=0, balance=0, no code) and the AccountState the
        // oracle returns for a miss already encodes that.
        Address own = Address.of(address.getBytes().toArrayUnsafe());
        AccountState state = baseView.account(own);
        SnapAccount a = SnapAccount.fromState(state, baseView);
        touched.put(address, a);
        return a;
    }

    @Override
    public void deleteAccount(org.hyperledger.besu.datatypes.Address address) {
        deleted.add(address);
        touched.remove(address);
    }

    @Override
    public Collection<? extends Account> getTouchedAccounts() {
        // Returning live references is intentional: Besu inspects them after
        // execution to determine which accounts to persist. View-only callers
        // ignore this set.
        return new ArrayList<>(touched.values());
    }

    @Override
    public Collection<org.hyperledger.besu.datatypes.Address> getDeletedAccountAddresses() {
        return new ArrayList<>(deleted);
    }

    @Override
    public void revert() {
        touched.clear();
        deleted.clear();
    }

    @Override
    public void commit() {
        if (parent == null) {
            // Top-level commit. For view-only execution this is a no-op:
            // the journal is discarded along with the updater itself.
            return;
        }
        for (Map.Entry<org.hyperledger.besu.datatypes.Address, SnapAccount> e : touched.entrySet()) {
            parent.touched.put(e.getKey(), e.getValue());
            parent.deleted.remove(e.getKey());
        }
        for (org.hyperledger.besu.datatypes.Address a : deleted) {
            parent.deleted.add(a);
            parent.touched.remove(a);
        }
    }

    @Override
    public Optional<WorldUpdater> parentUpdater() {
        return Optional.ofNullable(parent);
    }

    @Override
    public WorldUpdater updater() {
        return new SnapWorldUpdater(baseView, this);
    }
}
