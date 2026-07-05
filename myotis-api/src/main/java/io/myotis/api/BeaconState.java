package io.myotis.api;

/**
 * {@link SyncState} plus the pre-bootstrap phase, for status displays:
 * {@code STARTING} until the beacon client has produced its first state.
 */
public enum BeaconState { STARTING, SYNCING, CATCHING_UP, SYNCED }
