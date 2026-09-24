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
     * SYNCED also needs the finalized header within this many epochs of the wall clock.
     * Finality trails the head by ~2 epochs, so a live feed stays well inside it; a frozen
     * one — a withheld or stalled light-client feed, a fork this build cannot follow, or
     * a chain that has stopped finalizing — drops out within 5 epochs of its last
     * finality, instead of staying SYNCED until the wall clock leaves the held
     * committee's period (up to ~27.3 h on mainnet, ~11.4 h on Gnosis). Twin of the
     * Rust engine's {@code SYNCED_SLOT_SLACK_EPOCHS}
     * ({@code rust/myotis-net/src/sync.rs}, {@code sync_state_at}); keep the two equal.
     * {@code BeaconLightClient.HUNT_SLACK_EPOCHS} is this value, so the LC hunt engages at
     * the same staleness that ends SYNCED.
     */
    public static final int SYNCED_SLOT_SLACK_EPOCHS = 5;

    /**
     * Coarse-grained sync state for the beacon light client, exposed via {@code beacon-status}.
     * <ul>
     *   <li>{@link #SYNCING} — no trust anchor yet; verification queries fail with
     *       {@code beaconNotSynced}.</li>
     *   <li>{@link #CATCHING_UP} — trust anchor present but verification isn't dependable: the
     *       state-root window is still sparse, wall-clock has crossed into a sync-committee
     *       period we don't hold, or the finalized head is more than
     *       {@link #SYNCED_SLOT_SLACK_EPOCHS} epochs behind the wall clock.</li>
     *   <li>{@link #SYNCED} — verification-ready: window populated, committee current, finality
     *       recent. Can regress back to {@link #CATCHING_UP} if we fall behind; not latched.</li>
     *   <li>{@link #STALE_ANCHOR} — syncing is REFUSED: the best available trust anchor
     *       (embedded checkpoint or persisted snapshot, whichever is newer) is older than
     *       the weak-subjectivity bound, so an attacker holding keys of since-exited sync
     *       committee members could in principle serve a validly signed forged
     *       continuation. Waits for the user to raise the bound or explicitly accept the
     *       risk; verified queries fail closed meanwhile.</li>
     * </ul>
     */
    public enum State { SYNCING, CATCHING_UP, SYNCED, STALE_ANCHOR }

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

    /** Period of the trust anchor a stale-anchor park is refusing to sync from, or -1
     *  when not parked. Set/cleared by {@code BeaconLightClient.awaitAnchorFreshness}. */
    private volatile long staleAnchorPeriod = -1L;

    /** The weak-subjectivity bound (periods) currently enforced — host override if set,
     *  else the network default. Published for status surfaces; 0 until the light
     *  client records it at sync start. */
    private volatile long wsBoundPeriods = 0L;

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
    public record FinalizedExecution(long blockNumber, byte[] stateRoot, byte[] blockHash) {}

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
        return new FinalizedExecution(
                s.executionBlockNumber(), s.executionStateRoot(), s.executionBlockHash());
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
     * <p>Note: this is true as soon as bootstrap completes, and it latches — it does
     * <em>not</em> imply the sync committee is current or finality recent. The SYNCED gate
     * for both is {@link #getSyncState}.
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
     * Compute the coarse-grained sync state at the wall clock. Intended for
     * {@code beacon-status} output and for clients deciding whether to issue verification
     * queries.
     *
     * @param clGenesisTime  CL genesis time (seconds since epoch) for the active network
     * @param secondsPerSlot network slot time (mainnet 12, Gnosis 5) for the wall-clock slot
     * @param slotsPerEpoch  network epoch length (mainnet 32, Gnosis 16) for the finality
     *                       freshness slack — the network's own, not the mainnet preset's
     */
    public State getSyncState(long clGenesisTime, int secondsPerSlot, int slotsPerEpoch) {
        return syncStateAt(BeaconChainSpec.wallClockSlot(clGenesisTime, secondsPerSlot),
                slotsPerEpoch);
    }

    /**
     * {@link #getSyncState} at a given wall-clock slot: the SYNCED gate itself, pure in the
     * clock so it is unit-testable (the Rust twin is {@code sync_state_at} in
     * {@code rust/myotis-net/src/sync.rs}). SYNCED needs a finalized execution state root,
     * {@link #FILL_THRESHOLD} known state roots, a committee period not behind the wall
     * clock's, and a finalized slot at most {@link #SYNCED_SLOT_SLACK_EPOCHS} epochs behind
     * {@code wallSlot}; a stale-anchor park overrides all of it.
     */
    State syncStateAt(long wallSlot, int slotsPerEpoch) {
        if (staleAnchorPeriod >= 0) {
            return State.STALE_ANCHOR;
        }
        // One read, so the root and the finalized slot come from the same update.
        InnerState s = state.get();
        if (s.executionStateRoot() == null) {
            return State.SYNCING;
        }
        if (getKnownStateRootCount() < FILL_THRESHOLD) {
            return State.CATCHING_UP;
        }
        if (currentSyncCommitteePeriod < BeaconChainSpec.computeSyncCommitteePeriod(wallSlot)) {
            return State.CATCHING_UP;
        }
        if (s.finalizedSlot() + (long) SYNCED_SLOT_SLACK_EPOCHS * slotsPerEpoch < wallSlot) {
            return State.CATCHING_UP;
        }
        return State.SYNCED;
    }

    /** Enter the stale-anchor park: report {@link State#STALE_ANCHOR} and remember which
     *  anchor period was refused (status surfaces show it as the current period). */
    public void markStaleAnchor(long anchorPeriod) {
        this.staleAnchorPeriod = Math.max(0L, anchorPeriod);
    }

    /** Leave the stale-anchor park (bound raised, risk accepted, or anchor fresh). */
    public void clearStaleAnchor() {
        this.staleAnchorPeriod = -1L;
    }

    /** Anchor period a stale-anchor park is refusing, or -1 when not parked. */
    public long getStaleAnchorPeriod() {
        return staleAnchorPeriod;
    }

    /** Record the effective weak-subjectivity bound for status surfaces. */
    public void setWsBoundPeriods(long periods) {
        this.wsBoundPeriods = Math.max(0L, periods);
    }

    /** The weak-subjectivity bound (periods) currently enforced; 0 until recorded. */
    public long getWsBoundPeriods() {
        return wsBoundPeriods;
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
     * gates SYNCED on the sync committee period being current and on the finalized slot
     * being within {@link #SYNCED_SLOT_SLACK_EPOCHS} epochs of the wall clock. The
     * snapshot's own finality counts only while it is that recent, so a restart after any
     * longer downtime reports SYNCED once a fresh finality update lands, never on stale
     * roots alone.
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
