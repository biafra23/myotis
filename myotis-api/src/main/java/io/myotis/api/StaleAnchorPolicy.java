package io.myotis.api;

/**
 * The user's remembered answer to a {@link BeaconState#STALE_ANCHOR} park, applied by
 * the engine itself at every park so it works with no UI open
 * ({@link ChainHandle#setStaleAnchorPolicy}). Engine codes are the ordinals.
 */
public enum StaleAnchorPolicy {
    /** Wait for the user (the default). */
    ASK,
    /** Re-anchor on a checkpoint every answering checkpoint-sync server names. */
    CHECKPOINT,
    /** Sync forward from the stale anchor (consent given in advance). */
    CONTINUE
}
