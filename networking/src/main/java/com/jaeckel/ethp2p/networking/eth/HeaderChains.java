package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;

import java.util.Arrays;
import java.util.List;

/**
 * The gate that turns peer-supplied headers into proven ones, shared by the verified
 * account/storage/block reads in {@code :node-core} and the JSON-RPC backend's head and header
 * windows. ({@code ChainStack}'s served-header backfill keeps its own top-anchored check.)
 *
 * <p>A header window proves itself only DOWNWARD from a block hash the light client attested.
 * A header's parent hash commits it to its parent, never to its children: the attested block
 * pins its parent, which pins its own, and so on down the window — while nothing pins a header
 * ABOVE an attested block, since anyone can write a header naming it as the parent. So the
 * attested hash must be the window's TOP. (These walks once anchored the window's bottom
 * instead — the finalized block — and accepted any header a peer made up above it.)
 *
 * <p>Twin of the Rust {@code el::verify::verify_header_chain} and {@code fetch_anchored_window}.
 */
public final class HeaderChains {

    private HeaderChains() {}

    /**
     * True iff {@code window} is non-empty, its LAST header hashes to {@code topHash}, and every
     * header's hash equals the next one's parent hash. Each hash is keccak256 of the header's
     * own RLP, computed locally at decode, so then every header in the window is the canonical
     * block at its height, whole: a caller may trust any of its fields.
     */
    public static boolean anchoredAtTop(List<BlockHeadersMessage.VerifiedHeader> window,
                                        byte[] topHash) {
        if (window == null || window.isEmpty() || topHash == null) return false;
        byte[] top = window.get(window.size() - 1).hash().toArrayUnsafe();
        if (!Arrays.equals(top, topHash)) return false;
        for (int i = 0; i < window.size() - 1; i++) {
            if (!window.get(i).hash().equals(window.get(i + 1).header().parentHash)) return false;
        }
        return true;
    }
}
