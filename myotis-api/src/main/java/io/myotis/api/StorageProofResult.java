package io.myotis.api;

import java.util.List;

/**
 * A verified storage-slot query's full result. The storage proof is verified
 * against the account's proof-verified {@code storageRoot} (never the world state
 * root directly), and the anchoring account state root is then tied to the beacon
 * chain exactly like {@link AccountProofResult}.
 *
 * @param addressHex            the contract address queried (0x-hex)
 * @param slot                  the requested slot number
 * @param holderHex             the mapping holder address, or null for a plain slot
 * @param storageKeyHex         the actual storage key queried (0x-hex; for a holder,
 *                              keccak256(holder ‖ slot))
 * @param storageKeyHashHex     keccak256(storageKey) — the snap trie key
 * @param exists                whether the slot was present in the peer's response
 * @param valueHex              slot value (0x-hex), or null when {@code !exists}
 * @param valueDecimal          slot value as a decimal string, or null
 * @param slotsReturned         slots the peer returned (diagnostic when {@code !exists})
 * @param storageRootHex        the account's proof-verified storage root
 * @param proofNodesHex         the storage MPT proof nodes (0x-hex)
 * @param storageProofValid     the storage proof verifies against {@code storageRoot}
 * @param beaconSynced          beacon client was SYNCED at query time
 * @param beaconChainVerified   the anchoring state root ties to a beacon-attested root
 * @param blsVerified           the beacon match was BLS-signed
 * @param matchedBeaconSlot     slot of the matching beacon attestation; -1 if none
 * @param verifyMethod          "stateRootMatch" / "headerChain" / null
 * @param failReason            null when verified; otherwise a stable reason token
 * @param peerBlockNumber       peer-reported block the account proof anchors to
 * @param finalizedBlockNumber  finalized execution block number (0 if none)
 * @param optimisticBlockNumber optimistic-head execution block number (0 if none)
 * @param finalizedSlot         finalized beacon slot (0 if none)
 * @param optimisticSlot        optimistic beacon slot (0 if none)
 * @param maxHeaderChainGap     the engine's header-chain walk bound (currently 8192)
 */
public record StorageProofResult(
        String addressHex,
        long slot,
        String holderHex,
        String storageKeyHex,
        String storageKeyHashHex,
        boolean exists,
        String valueHex,
        String valueDecimal,
        int slotsReturned,
        String storageRootHex,
        List<String> proofNodesHex,
        boolean storageProofValid,
        boolean beaconSynced,
        boolean beaconChainVerified,
        boolean blsVerified,
        long matchedBeaconSlot,
        String verifyMethod,
        String failReason,
        long peerBlockNumber,
        long finalizedBlockNumber,
        long optimisticBlockNumber,
        long finalizedSlot,
        long optimisticSlot,
        int maxHeaderChainGap) {
}
