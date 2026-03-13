package com.jaeckel.ethp2p.consensus;

import java.util.Arrays;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe holder for beacon chain sync state.
 *
 * <p>Provides atomic access to the latest beacon-verified execution state root,
 * finalized slot, and optimistic slot. Uses a single {@link AtomicReference} to
 * an immutable record for lock-free reads.
 *
 * <p>Also maintains a rolling window of recently seen execution state roots from
 * beacon block headers (both finalized and attested). This allows verifying that
 * a peer's claimed state root corresponds to an actual beacon chain block, even
 * if it doesn't match the current finalized state root.
 */
public class BeaconSyncState {

    private record State(long finalizedSlot, byte[] executionStateRoot, long optimisticSlot,
                          long executionBlockNumber) {}

    /** A beacon-attested (slot, executionStateRoot) pair with verification status. */
    public record SlottedStateRoot(long slot, byte[] stateRoot, boolean blsVerified) {}

    private static final int MAX_KNOWN_ROOTS = 8192;

    private final AtomicReference<State> state = new AtomicReference<>(new State(0, null, 0, 0));

    /** Rolling window of recently seen execution state roots from beacon headers. */
    private final ConcurrentLinkedDeque<SlottedStateRoot> knownStateRoots = new ConcurrentLinkedDeque<>();

    /**
     * Update the beacon sync state atomically.
     *
     * @param finalizedSlot       the latest finalized beacon slot
     * @param executionStateRoot  the execution state root from the finalized execution payload header
     * @param optimisticSlot      the latest optimistic (attested) slot
     */
    public void update(long finalizedSlot, byte[] executionStateRoot, long optimisticSlot) {
        state.set(new State(finalizedSlot, executionStateRoot, optimisticSlot, 0));
    }

    /**
     * Update the beacon sync state atomically, including the execution block number.
     */
    public void update(long finalizedSlot, byte[] executionStateRoot, long optimisticSlot,
                       long executionBlockNumber) {
        state.set(new State(finalizedSlot, executionStateRoot, optimisticSlot, executionBlockNumber));
    }

    /**
     * Returns the beacon-verified execution state root, or null if not yet synced.
     */
    public byte[] getVerifiedExecutionStateRoot() {
        return state.get().executionStateRoot();
    }

    /**
     * Returns the latest finalized beacon slot, or 0 if not yet synced.
     */
    public long getFinalizedSlot() {
        return state.get().finalizedSlot();
    }

    /**
     * Returns the latest optimistic (attested) slot, or 0 if not yet synced.
     */
    public long getOptimisticSlot() {
        return state.get().optimisticSlot();
    }

    /**
     * Returns the execution-layer block number of the finalized execution payload, or 0.
     */
    public long getExecutionBlockNumber() {
        return state.get().executionBlockNumber();
    }

    /**
     * Returns true if the beacon sync state has been populated with at least one update.
     */
    public boolean isSynced() {
        return state.get().executionStateRoot() != null;
    }

    /**
     * Returns the number of state roots currently in the rolling window.
     */
    public int getKnownStateRootCount() {
        return knownStateRoots.size();
    }

    /**
     * Record an execution state root seen in a beacon block header.
     * Duplicate (slot, root) pairs are ignored; however, an unverified entry
     * will be upgraded to verified if the same root is seen with BLS verification.
     * The window is capped at {@link #MAX_KNOWN_ROOTS}.
     *
     * @param slot        the beacon slot of the block
     * @param stateRoot   the 32-byte execution state root from the block's execution payload
     * @param blsVerified true if this root was validated via sync committee BLS signature
     */
    public void recordStateRoot(long slot, byte[] stateRoot, boolean blsVerified) {
        if (stateRoot == null || stateRoot.length != 32) return;
        // Check for duplicates; upgrade unverified → verified if applicable
        for (SlottedStateRoot entry : knownStateRoots) {
            if (entry.slot() == slot && Arrays.equals(entry.stateRoot(), stateRoot)) {
                if (blsVerified && !entry.blsVerified()) {
                    knownStateRoots.remove(entry);
                    break; // re-add as verified below
                }
                return; // already present with same or better verification
            }
        }
        knownStateRoots.addLast(new SlottedStateRoot(slot, stateRoot.clone(), blsVerified));
        // Evict oldest entries if window is full
        while (knownStateRoots.size() > MAX_KNOWN_ROOTS) {
            knownStateRoots.pollFirst();
        }
    }

    /**
     * Look up a state root in the rolling window of beacon-attested execution state roots.
     *
     * @param stateRoot the 32-byte execution state root to search for
     * @return the matching entry, or null if not found
     */
    public SlottedStateRoot findStateRoot(byte[] stateRoot) {
        if (stateRoot == null || stateRoot.length != 32) return null;
        // Search newest-first for best match
        var it = knownStateRoots.descendingIterator();
        while (it.hasNext()) {
            SlottedStateRoot entry = it.next();
            if (Arrays.equals(entry.stateRoot(), stateRoot)) {
                return entry;
            }
        }
        return null;
    }
}
