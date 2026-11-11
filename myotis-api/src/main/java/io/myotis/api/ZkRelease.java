package io.myotis.api;

/**
 * Outcome of {@link ChainHandle#fetchZkProofForStaleAnchor()}: Colibri's ZK proof
 * of the current sync-committee period, fetched and verified, and handed to a
 * stack parked in {@link BeaconState#STALE_ANCHOR}.
 *
 * <p>Not {@code applied} means no usable proof is available right now; a host then
 * offers the remaining choices (a fresh checkpoint, or continuing from the stale
 * anchor). When applied, the stack leaves the park once a peer serves a finality
 * update the proven committee signed.
 *
 * @param applied the verified proof was handed to the parked stack
 * @param period  the proven committee's sync-committee period; 0 unless applied
 * @param error   null when applied; otherwise why no proof is available
 */
public record ZkRelease(boolean applied, long period, String error) {
    /** Not applied, for {@code reason}. */
    public static ZkRelease refused(String reason) {
        return new ZkRelease(false, 0, reason);
    }
}
