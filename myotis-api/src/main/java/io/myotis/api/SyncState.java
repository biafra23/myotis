package io.myotis.api;

/**
 * The beacon light client's sync state. Not latched — a node can regress from
 * {@code SYNCED} (e.g. losing CL peers).
 *
 * <p>{@code STALE_ANCHOR}: syncing is refused because the best available trust
 * anchor is older than the weak-subjectivity bound (see
 * {@link BeaconState#STALE_ANCHOR}); waiting for the user to raise the bound or
 * accept the risk.
 */
public enum SyncState { SYNCING, CATCHING_UP, SYNCED, STALE_ANCHOR }
