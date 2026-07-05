package io.myotis.api;

import java.util.List;

/**
 * Deep beacon/CL status — the superset behind operator surfaces like the daemon's
 * {@code beacon-status} command (the EL-side counterpart lives in {@link StatusSnapshot}).
 *
 * @param state                 beacon light-client state
 * @param currentPeriod         sync-committee period the client holds (0 before bootstrap)
 * @param targetPeriod          wall-clock period being caught up to
 * @param discv5TableSize       live nodes in the CL discv5 routing table
 * @param connectedPeers        connected CL libp2p peers
 * @param lightClientPeers      of those, peers serving the light_client protocols
 * @param finalizedSlot         finalized beacon slot (0 while SYNCING)
 * @param optimisticSlot        optimistic beacon slot (0 while SYNCING)
 * @param finalizedPeriod       period of the finalized slot
 * @param executionStateRootHex latest verified execution state root (0x-hex), null while SYNCING
 * @param executionBlockNumber  finalized execution block number
 * @param knownStateRoots       beacon-attested state roots currently held
 * @param fillThreshold         the engine's known-roots threshold for serving verified reads
 * @param peers                 per-peer CL detail
 */
public record BeaconStatus(
        BeaconState state,
        long currentPeriod,
        long targetPeriod,
        int discv5TableSize,
        int connectedPeers,
        long lightClientPeers,
        long finalizedSlot,
        long optimisticSlot,
        long finalizedPeriod,
        String executionStateRootHex,
        long executionBlockNumber,
        int knownStateRoots,
        int fillThreshold,
        List<ClPeerInfo> peers) {
}
