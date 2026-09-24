package io.myotis.api;

/**
 * The network has scheduled — or activated — a fork this build does not implement: the
 * library/app must be updated. Derived from the EIP-2124 fork ids peers present in their
 * eth Status (an announced {@code forkNext}, or a fork hash provably the successor of
 * ours), which nothing in verification reads — so it is ADVISORY ONLY: a lying peer can
 * cause a false warning, never a wrong answer.
 *
 * <p>Null on {@link StatusSnapshot#upgradeAdvisory()} when nothing is detected, or when
 * the watch is not enabled for the network (staged rollout: Sepolia first).
 *
 * @param phase          {@code SCHEDULED} (activation ahead) or {@code ACTIVE} (passed)
 * @param activationTime unix seconds at which the fork activates / activated
 * @param forkId         EIP-2124 fork hash upgraded peers use once it is active,
 *                       {@code 0x} + 8 lowercase hex digits
 * @param observedPeers  distinct peers corroborating it (at least the detector's threshold)
 */
public record UpgradeAdvisory(UpgradePhase phase, long activationTime, String forkId, int observedPeers) {
}
