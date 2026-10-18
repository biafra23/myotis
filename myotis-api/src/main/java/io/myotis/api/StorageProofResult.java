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
 * @param exists                the storage proof shows the slot holding a non-zero value.
 *                              A zero slot is pruned from the trie, so a proven-absent slot
 *                              reads {@code exists=false} with {@code storageProofValid=true}
 *                              — the Rust engine's {@code found}. When the proof fails,
 *                              {@code exists=false} with {@code storageProofValid=false}:
 *                              nothing was proven, and {@code failReason} says so
 * @param valueHex              the PROVEN slot value (0x-hex) — never the peer's slot list —
 *                              or null when {@code !exists}
 * @param valueDecimal          slot value as a decimal string, or null
 * @param slotsReturned         slots the peer returned (diagnostic when {@code !exists})
 * @param storageRootHex        the account's proof-verified storage root
 * @param proofNodesHex         the storage MPT proof nodes (0x-hex)
 * @param storageProofValid     the storage proof verifies against {@code storageRoot}
 * @param beaconSynced          beacon client was SYNCED at query time
 * @param beaconChainVerified   the anchoring state root ties to a beacon-attested root
 * @param blsVerified           the beacon match was BLS-signed
 * @param matchedBeaconSlot     beacon slot of the block the anchoring state root was matched
 *                              to — the attested block whose root it is (stateRootMatch) or
 *                              whose hash the header walk ended at (headerChain); -1 if
 *                              none. Like the two slots below, a BLOCK's own slot (#658): a
 *                              read proven at the current head reports {@code optimisticSlot},
 *                              one proven at the finality {@code finalizedSlot} (unless that
 *                              head or finality moved on during the read), one matched to an
 *                              earlier root still in the window a slot below the head
 * @param verifyMethod          "stateRootMatch" / "headerChain" / null
 * @param failReason            null when verified; otherwise a stable reason token
 * @param peerBlockNumber       block the account proof anchors to. Java engine (and
 *                              the Rust engine's Tor path): the serving peer's
 *                              reported head. Rust engine clearnet path: the beacon
 *                              anchor's optimistic head when the query ran against
 *                              the anchored root (preferred since the #355 fix),
 *                              the peer's head only on its fallback
 * @param finalizedBlockNumber  finalized execution block number (0 if none)
 * @param optimisticBlockNumber optimistic-head execution block number (0 if none). The block
 *                              numbers and the two slots below are sampled at different
 *                              moments of the read, so while the head (or the finality) moves
 *                              on during it a number and its slot can name different blocks:
 *                              compare {@code matchedBeaconSlot} with the slots, and do not
 *                              label a block number with a slot from here
 * @param finalizedSlot         beacon slot of the finalized block the reads prove against
 *                              (0 if none)
 * @param optimisticSlot        beacon slot of the optimistic head block the reads prove
 *                              against: the attested header's own slot, not the later
 *                              signature slot of the sync aggregate that attested it (#658);
 *                              0 if none. Read once the proof is in, so a head that moved on
 *                              during the read leaves {@code matchedBeaconSlot} below it. Like
 *                              {@code finalizedSlot} it is the head the reads have RESOLVED:
 *                              from Gloas on, a newer head waits for its execution header, and
 *                              meanwhile this can trail {@code finalizedSlot}
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
