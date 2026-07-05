package io.myotis.api;

import java.util.List;

/**
 * One coherent point-in-time view of a network's stack — the superset of what the
 * hosts' status surfaces render (UI status tabs, the daemon's {@code status} /
 * {@code beacon-status} / {@code peers} IPC commands).
 *
 * @param running               whether the stack is running
 * @param network               canonical network name
 * @param beaconState           beacon light-client state (STARTING before first state)
 * @param connectedPeers        EL peers with an open RLPx session (incl. still handshaking)
 * @param readyPeers            EL peers past the eth handshake
 * @param snapPeers             peers that negotiated snap/1
 * @param snapServingPeers      peers currently in the snap serving pool (drives readiness)
 * @param discoveredPeers       discv4 Kademlia table size
 * @param backedOffPeers        active (non-expired) dial-backoff entries, pruned on read
 * @param blacklistedPeers      peers blacklisted this session (wrong chain)
 * @param attemptedDials        in-flight / recently-attempted dials
 * @param discv5TableSize       live nodes in the CL discv5 routing table
 * @param executionBlockNumber  finalized execution block number (0 if none yet)
 * @param optimisticBlockNumber optimistic-head execution block number (0 if none yet)
 * @param finalizedSlot         finalized beacon slot (0 if none yet)
 * @param finalizedBlockNumber  execution block number of the finalized payload (0 if none)
 * @param syncStartPeriod       sync-committee catch-up start period (-1 if unknown)
 * @param syncCurrentPeriod     current sync-committee period the client holds
 * @param syncTargetPeriod      wall-clock sync-committee period (catch-up target)
 * @param finalizedPeriod       period of the finalized slot
 * @param wallClockPeriod       wall-clock period (== syncTargetPeriod; kept for
 *                              diagnostics parity with the daemon's beacon-status)
 * @param verifiedHeadAgeMs     age of the last verified RPC head context;
 *                              {@code Long.MAX_VALUE} = none built yet
 * @param readyPeerList         per-peer detail for the READY peers, snap-capable first
 */
public record StatusSnapshot(
        boolean running,
        String network,
        BeaconState beaconState,
        int connectedPeers,
        int readyPeers,
        int snapPeers,
        int snapServingPeers,
        int discoveredPeers,
        int backedOffPeers,
        int blacklistedPeers,
        int attemptedDials,
        int discv5TableSize,
        long executionBlockNumber,
        long optimisticBlockNumber,
        long finalizedSlot,
        long finalizedBlockNumber,
        long syncStartPeriod,
        long syncCurrentPeriod,
        long syncTargetPeriod,
        long finalizedPeriod,
        long wallClockPeriod,
        long verifiedHeadAgeMs,
        List<PeerInfo> readyPeerList) {
}
