package io.myotis.api;

/**
 * {@link SyncState} plus the pre-bootstrap phase, for status displays:
 * {@code STARTING} until the beacon client has produced its first state.
 *
 * <p>{@code STALE_ANCHOR}: the best available trust anchor (embedded checkpoint
 * or persisted snapshot, whichever is newer) is older than the network's
 * weak-subjectivity bound, so the engine refuses to sync forward from it until
 * the user either raises the bound ({@link ChainHandle#setWsBoundPeriods}) or
 * explicitly accepts the risk ({@link ChainHandle#acceptStaleAnchor}). While in
 * this state no verification happens and verified queries fail closed.
 */
public enum BeaconState { STARTING, SYNCING, CATCHING_UP, SYNCED, STALE_ANCHOR }
