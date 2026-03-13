package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * Parses SSZ-encoded {@code SignedBeaconBlock} payloads from the
 * {@code beacon_blocks_by_range/2} P2P protocol and computes each block's
 * header hash ({@code hash_tree_root(BeaconBlockHeader)}).
 *
 * <p>Computing the header hash requires {@code body_root = hash_tree_root(BeaconBlockBody)},
 * which in turn requires hashing every field of the block body — including the
 * full transactions list, attestations, and (for Electra) execution requests.
 *
 * <p>Supports both Deneb (12-field body) and Electra (13-field body) forks.
 * Each nested SSZ type is defined in its own class with {@code decode()} and
 * {@code hashTreeRoot()} methods.
 */
public final class BeaconBlockParser {

    private BeaconBlockParser() {}

    /** Result of parsing a SignedBeaconBlock. */
    public record ParsedBlock(
            long slot,
            long proposerIndex,
            byte[] parentRoot,
            byte[] stateRoot,
            byte[] bodyRoot,
            byte[] executionStateRoot,
            byte[] blockHeaderRoot
    ) {}

    /**
     * Parse a SSZ-encoded {@code SignedBeaconBlock} and compute its header hash.
     *
     * @param ssz the full SSZ bytes of the SignedBeaconBlock
     * @return parsed block with slot, roots, and computed header hash
     * @throws IllegalArgumentException if the SSZ is malformed
     */
    public static ParsedBlock parse(byte[] ssz) {
        // SignedBeaconBlock: [message_offset(4)] [signature(96)] [message...]
        if (ssz.length < 100) throw new IllegalArgumentException("SignedBeaconBlock too short: " + ssz.length);
        int messageOffset = SszUtil.readUint32(ssz, 0);
        if (messageOffset < 100 || messageOffset > ssz.length) {
            throw new IllegalArgumentException("Invalid message offset: " + messageOffset);
        }
        byte[] blockBytes = Arrays.copyOfRange(ssz, messageOffset, ssz.length);

        // BeaconBlock: [slot(8)] [proposer_index(8)] [parent_root(32)] [state_root(32)] [body_offset(4)]
        if (blockBytes.length < 84) throw new IllegalArgumentException("BeaconBlock too short: " + blockBytes.length);
        long slot = SszUtil.readUint64(blockBytes, 0);
        long proposerIndex = SszUtil.readUint64(blockBytes, 8);
        byte[] parentRoot = Arrays.copyOfRange(blockBytes, 16, 48);
        byte[] stateRoot = Arrays.copyOfRange(blockBytes, 48, 80);
        int bodyOffset = SszUtil.readUint32(blockBytes, 80);
        if (bodyOffset < 84 || bodyOffset > blockBytes.length) {
            throw new IllegalArgumentException("Invalid body offset: " + bodyOffset);
        }

        // Decode body and compute roots
        BeaconBlockBody body = BeaconBlockBody.decode(blockBytes, bodyOffset, blockBytes.length);
        byte[] bodyRoot = body.hashTreeRoot();
        byte[] executionStateRoot = body.executionPayload().stateRoot();
        byte[] blockHeaderRoot = new BeaconBlockHeader(
                slot, proposerIndex, parentRoot, stateRoot, bodyRoot
        ).hashTreeRoot();

        return new ParsedBlock(slot, proposerIndex, parentRoot, stateRoot,
                bodyRoot, executionStateRoot, blockHeaderRoot);
    }
}
