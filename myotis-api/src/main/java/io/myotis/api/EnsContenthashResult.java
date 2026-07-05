package io.myotis.api;

/**
 * An ENS contenthash lookup (ENSIP-7).
 *
 * @param name           the ENS name
 * @param contenthashHex the raw contenthash bytes (0x-hex), null when absent
 * @param blockNumber    block the resolution state anchors to; -1 when none
 * @param verified       true iff resolved against beacon-finalized state
 * @param error          null on success
 */
public record EnsContenthashResult(
        String name,
        String contenthashHex,
        long blockNumber,
        boolean verified,
        String error) {
}
