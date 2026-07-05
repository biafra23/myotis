package io.myotis.api;

import java.util.List;

/**
 * A verified account query's full result — the account data, the proof material,
 * and the verification verdict, plus the beacon diagnostics operator surfaces
 * emit. Everything the daemon's {@code get-account} IPC JSON contains is
 * reproducible from this record alone.
 *
 * <p>Verification failures set {@link #failReason} (and the relevant booleans);
 * they are never exceptions.
 *
 * @param address               the queried address (0x-hex, as given)
 * @param exists                whether the account exists in the peer's response
 * @param nonce                 account nonce; -1 when {@code !exists}
 * @param balanceWei            decimal wei string, or null when {@code !exists}
 * @param storageRootHex        from the proof-verified leaf when available (never
 *                              the peer's slim body in that case), else peer-claimed
 * @param codeHashHex           same provenance rule as {@code storageRootHex}
 * @param blockNumber           peer-reported block the proof anchors to
 * @param peerStateRootHex      the peer's state root the proof was checked against
 * @param peerProofValid        the MPT proof verifies against {@code peerStateRoot}
 * @param beaconChainVerified   {@code peerStateRoot} ties to a beacon-attested root
 * @param blsVerified           the beacon match was BLS-signed
 * @param matchedBeaconSlot     slot of the matching beacon attestation; -1 if none
 * @param verifyMethod          "stateRootMatch" / "headerChain" / null
 * @param failReason            null when verified; otherwise a stable reason token
 *                              (e.g. "beaconNotSynced", "headerChainGapTooLarge")
 * @param accountHashHex        keccak256(address) — the snap trie key
 * @param proofNodesHex         the MPT proof nodes (0x-hex), peer-served
 * @param beaconSynced          beacon client was SYNCED at query time
 * @param finalizedPeriod       sync-committee period of the finalized slot
 * @param wallClockPeriod       wall-clock sync-committee period
 * @param finalizedBlockNumber  finalized execution block number (0 if none)
 * @param optimisticBlockNumber optimistic-head execution block number (0 if none)
 */
public record AccountProofResult(
        String address,
        boolean exists,
        long nonce,
        String balanceWei,
        String storageRootHex,
        String codeHashHex,
        long blockNumber,
        String peerStateRootHex,
        boolean peerProofValid,
        boolean beaconChainVerified,
        boolean blsVerified,
        long matchedBeaconSlot,
        String verifyMethod,
        String failReason,
        String accountHashHex,
        List<String> proofNodesHex,
        boolean beaconSynced,
        long finalizedPeriod,
        long wallClockPeriod,
        long finalizedBlockNumber,
        long optimisticBlockNumber) {
}
