package io.myotis.api;

/**
 * Peers report that the network has scheduled — or activated — a fork this build does not
 * implement: the library/app should be updated. Derived from what peers advertise and
 * nothing in verification reads — so it is ADVISORY ONLY and UNVERIFIED: lying peers can
 * cause a false warning, never a wrong answer. Hosts should claim the node "can no longer
 * verify" only when its own verified state agrees (beacon state not SYNCED, or a stale
 * verified head). Two detectors feed it, merged into one advisory (ACTIVE over SCHEDULED,
 * then a known activation time, then more peers):
 * <ul>
 *   <li>the execution layer's EIP-2124 fork ids in peers' eth Status (an announced
 *       {@code forkNext}, or a fork hash that places as the successor of ours) — enabled
 *       per network (staged rollout: Sepolia first);</li>
 *   <li>the consensus layer's discv5 ENR {@code eth2} fields (an announced
 *       {@code next_fork_epoch}, or a fork digest that reproduces from a newer fork
 *       version) and peers' libp2p Status fork digests — every network.</li>
 * </ul>
 *
 * <p>Null on {@link StatusSnapshot#upgradeAdvisory()} when nothing is detected.
 *
 * @param phase          {@code SCHEDULED} (activation ahead) or {@code ACTIVE} (passed)
 * @param activationTime unix seconds at which the fork activates / activated; {@code 0}
 *                       when unknown — peers are seen on the fork but nobody announced
 *                       its epoch (a consensus fork digest does not encode it)
 * @param forkId         the fork identifier upgraded peers use once it is active —
 *                       the EIP-2124 fork hash, or the consensus fork digest —
 *                       {@code 0x} + 8 lowercase hex digits
 * @param observedPeers  distinct peer networks (IPv4 /24, IPv6 /48) backing it — at least
 *                       the detector's threshold, and more than the peers contradicting it
 */
public record UpgradeAdvisory(UpgradePhase phase, long activationTime, String forkId, int observedPeers) {
}
