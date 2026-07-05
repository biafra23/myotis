package io.myotis.api;

/**
 * The beacon light client's sync state. Not latched — a node can regress from
 * {@code SYNCED} (e.g. losing CL peers).
 */
public enum SyncState { SYNCING, CATCHING_UP, SYNCED }
