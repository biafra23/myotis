package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
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

    /**
     * Minimum number of BLS-verified execution state roots in the rolling window before
     * we consider the node {@link State#SYNCED}. In the best case {@code fillChainStateRoots}
     * records 40-80 roots per invocation (2 epochs of blocks); in practice many peers reject
     * {@code beacon_blocks_by_range/2} with protocol negotiation failures and the window only
     * grows via {@code updateSyncState} (2 roots per finality poll, mostly deduplicated).
     *
     * <p>A threshold of 4 means "at least two successful finality polls have landed" — enough
     * to confirm the catch-up rotation is real and headers are advancing, without waiting on
     * a fill path that may never succeed in a given peer set.
     */
    public static final int FILL_THRESHOLD = 4;

    /**
     * Coarse-grained sync state for the beacon light client, exposed via {@code beacon-status}.
     * <ul>
     *   <li>{@link #SYNCING} — no trust anchor yet; verification queries fail with
     *       {@code beaconNotSynced}.</li>
     *   <li>{@link #CATCHING_UP} — trust anchor present but verification isn't dependable yet,
     *       either because the state-root window is still sparse or because wall-clock has
     *       crossed into a sync-committee period we don't hold.</li>
     *   <li>{@link #SYNCED} — verification-ready: window populated and committee current.
     *       Can regress back to {@link #CATCHING_UP} if we fall behind; not latched.</li>
     * </ul>
     */
    public enum State { SYNCING, CATCHING_UP, SYNCED }

    private record InnerState(long finalizedSlot, byte[] executionStateRoot, long optimisticSlot,
                          long executionBlockNumber, byte[] executionBlockHash,
                          long optimisticBlockNumber, byte[] optimisticBlockHash,
                          byte[] optimisticStateRoot) {}

    /** A beacon-attested (slot, executionStateRoot) pair with verification status. */
    public record SlottedStateRoot(long slot, byte[] stateRoot, boolean blsVerified) {}

    private static final int MAX_KNOWN_ROOTS = 8192;

    private final AtomicReference<InnerState> state = new AtomicReference<>(
            new InnerState(0, null, 0, 0, null, 0, null, null));

    /** Period of the committee currently held by the light-client store. Separate from the
     *  InnerState record because it's written by rotation events (not by the finalized update
     *  path) and isn't transactional with the other execution-payload fields. */
    private volatile long currentSyncCommitteePeriod = 0L;

    /** The first committee period observed once bootstrap completes — i.e. where catch-up
     *  begins. Captured on the first {@link #setCurrentSyncCommitteePeriod} call and never
     *  moved, so {@code (current - start) / (target - start)} is a stable progress fraction.
     *  -1 until the first rotation is recorded. */
    private volatile long catchUpStartPeriod = -1L;

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
        InnerState prev = state.get();
        state.set(new InnerState(finalizedSlot, executionStateRoot, optimisticSlot, 0, null,
                prev.optimisticBlockNumber(), prev.optimisticBlockHash(), prev.optimisticStateRoot()));
    }

    /**
     * Update the beacon sync state atomically, including the execution block number.
     */
    public void update(long finalizedSlot, byte[] executionStateRoot, long optimisticSlot,
                       long executionBlockNumber) {
        InnerState prev = state.get();
        state.set(new InnerState(finalizedSlot, executionStateRoot, optimisticSlot, executionBlockNumber, null,
                prev.optimisticBlockNumber(), prev.optimisticBlockHash(), prev.optimisticStateRoot()));
    }

    /**
     * Update the beacon sync state atomically, including execution block number and block hash.
     */
    public void update(long finalizedSlot, byte[] executionStateRoot, long optimisticSlot,
                       long executionBlockNumber, byte[] executionBlockHash) {
        InnerState prev = state.get();
        state.set(new InnerState(finalizedSlot, executionStateRoot, optimisticSlot,
                executionBlockNumber, executionBlockHash != null ? executionBlockHash.clone() : null,
                prev.optimisticBlockNumber(), prev.optimisticBlockHash(), prev.optimisticStateRoot()));
    }

    /**
     * Record the optimistic (attested) header's execution payload fields. Separate from the
     * finalized {@code update()} path because the two headers advance on different cadences:
     * finalized lags by ~2 epochs between finality events (~12 min), while the attested header
     * refreshes every slot. Verification code can prefer the attested anchor when the finalized
     * block is too far behind the snap peer's head.
     */
    public void updateOptimisticExecution(long optimisticBlockNumber, byte[] optimisticBlockHash,
                                          byte[] optimisticStateRoot) {
        InnerState prev = state.get();
        state.set(new InnerState(prev.finalizedSlot(), prev.executionStateRoot(), prev.optimisticSlot(),
                prev.executionBlockNumber(), prev.executionBlockHash(),
                optimisticBlockNumber,
                optimisticBlockHash != null ? optimisticBlockHash.clone() : null,
                optimisticStateRoot != null ? optimisticStateRoot.clone() : null));
    }

    /**
     * Returns the beacon-verified execution state root, or null if not yet synced.
     */
    public byte[] getVerifiedExecutionStateRoot() {
        return state.get().executionStateRoot();
    }

    /**
     * The finalized execution payload's (block number, state root) read from a single
     * atomic snapshot. {@code stateRoot} is null if not yet synced.
     */
    public record FinalizedExecution(long blockNumber, byte[] stateRoot) {}

    /**
     * Returns the finalized execution block number and state root from one atomic read.
     * <p>Callers that need both (e.g. header-chain verification anchors the chain at
     * {@code blockNumber} and requires its state root to equal {@code stateRoot}) MUST use
     * this rather than {@link #getExecutionBlockNumber()} + {@link #getVerifiedExecutionStateRoot()}
     * separately: the underlying {@code InnerState} can be replaced between two reads, pairing a
     * block number with a state root from a different payload.
     */
    public FinalizedExecution getFinalizedExecution() {
        InnerState s = state.get();
        return new FinalizedExecution(s.executionBlockNumber(), s.executionStateRoot());
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
     * Returns the beacon-verified execution block hash of the finalized payload, or null.
     */
    public byte[] getExecutionBlockHash() {
        return state.get().executionBlockHash();
    }

    /**
     * Returns the execution-layer block number of the optimistic (attested) payload, or 0.
     * <p>The attested header's BLS sync-committee signature is the same trust anchor as the
     * finalized header, but the attested slot is typically 1-2 slots behind wall-clock, vs.
     * ~2 epochs for finalized. Useful as a verification anchor when finalized is too stale.
     */
    public long getOptimisticBlockNumber() {
        return state.get().optimisticBlockNumber();
    }

    /**
     * Returns the execution-layer block hash of the optimistic (attested) payload, or null.
     */
    public byte[] getOptimisticBlockHash() {
        return state.get().optimisticBlockHash();
    }

    /**
     * Returns the execution-layer state root of the optimistic (attested) payload, or null.
     */
    public byte[] getOptimisticStateRoot() {
        return state.get().optimisticStateRoot();
    }

    /**
     * Returns true if the beacon sync state has been populated with at least one update.
     * <p>Note: this is true as soon as bootstrap completes. It does <em>not</em> imply the
     * sync committee is current; use {@link #getFinalizedPeriod()} and compare against
     * {@link BeaconChainSpec#currentMainnetPeriod()} to detect stale catch-up.
     */
    public boolean isSynced() {
        return state.get().executionStateRoot() != null;
    }

    /**
     * Push the light-client store's current sync-committee period into observable state.
     * Called from {@code BeaconLightClient.updateSyncState()} on every rotation event
     * (rotations happen inside {@code processUpdate}/{@code processFinalityUpdate} and
     * {@code forceRotateIfPastPeriod}).
     */
    public void setCurrentSyncCommitteePeriod(long period) {
        // Record where catch-up started the first time we learn a period (bootstrap
        // completes), so a progress bar can compute a stable fraction. Use the lower of
        // the two if called out of order, so the start can only move backwards.
        if (catchUpStartPeriod < 0 || period < catchUpStartPeriod) {
            catchUpStartPeriod = period;
        }
        this.currentSyncCommitteePeriod = period;
    }

    /**
     * The committee period catch-up started from (first observed period), or -1 if
     * bootstrap hasn't recorded a period yet. With {@link #getCurrentSyncCommitteePeriod()}
     * and {@link BeaconChainSpec#currentPeriod(long)} this gives a catch-up progress
     * fraction: {@code (current - start) / (target - start)}.
     */
    public long getCatchUpStartPeriod() {
        return catchUpStartPeriod;
    }

    /**
     * Returns the period of the committee the store is currently using to verify sync
     * aggregates. When this lags wall-clock, we can't verify incoming finality updates
     * until defensive catch-up rotates us forward.
     */
    public long getCurrentSyncCommitteePeriod() {
        return currentSyncCommitteePeriod;
    }

    /**
     * Compute the coarse-grained sync state. Intended for {@code beacon-status} output
     * and for clients deciding whether to issue verification queries.
     *
     * @param clGenesisTime CL genesis time (seconds since epoch) for the active network
     * @param secondsPerSlot network slot time (mainnet 12, Gnosis 5) for wall-clock period estimation
     */
    public State getSyncState(long clGenesisTime, int secondsPerSlot) {
        if (!isSynced()) {
            return State.SYNCING;
        }
        if (getKnownStateRootCount() < FILL_THRESHOLD) {
            return State.CATCHING_UP;
        }
        long wallPeriod = BeaconChainSpec.currentPeriod(clGenesisTime, secondsPerSlot);
        if (currentSyncCommitteePeriod < wallPeriod) {
            return State.CATCHING_UP;
        }
        return State.SYNCED;
    }

    /**
     * Returns the sync committee period of the latest finalized slot, or 0 if not synced.
     */
    public long getFinalizedPeriod() {
        return BeaconChainSpec.computeSyncCommitteePeriod(getFinalizedSlot());
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
     * Snapshot the rolling window (oldest→newest) so it can be persisted across
     * restarts. The entries were validated via finality-update BLS signatures; see
     * {@link #importKnownStateRoots}.
     */
    public List<SlottedStateRoot> exportKnownStateRoots() {
        return new ArrayList<>(knownStateRoots);
    }

    /**
     * Re-import persisted window entries (e.g. from a snapshot sidecar) using the same
     * dedup/cap path as live recording. Lets a warm restart reach SYNCED without first
     * re-observing {@link #FILL_THRESHOLD} live finality polls. Soundness: this only
     * pre-fills the "have we seen enough finality" counter — {@code getSyncState} still
     * gates SYNCED on {@link #isSynced()} (a fresh post-restart update) and on the sync
     * committee period being current, so a long-offline restart can't report SYNCED on
     * stale roots alone.
     */
    public void importKnownStateRoots(Collection<SlottedStateRoot> roots) {
        if (roots == null) return;
        for (SlottedStateRoot r : roots) {
            if (r != null) recordStateRoot(r.slot(), r.stateRoot(), r.blsVerified());
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
