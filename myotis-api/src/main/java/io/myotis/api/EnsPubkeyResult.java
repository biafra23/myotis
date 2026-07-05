package io.myotis.api;

/**
 * An ENS pubkey record lookup.
 *
 * @param name        the ENS name
 * @param pubkeyXHex  the secp256k1 x coordinate (0x-hex), null when absent
 * @param pubkeyYHex  the secp256k1 y coordinate (0x-hex), null when absent
 * @param blockNumber block the resolution state anchors to; -1 when none
 * @param verified    true iff resolved against beacon-finalized state
 * @param error       null on success
 */
public record EnsPubkeyResult(
        String name,
        String pubkeyXHex,
        String pubkeyYHex,
        long blockNumber,
        boolean verified,
        String error) {
}
