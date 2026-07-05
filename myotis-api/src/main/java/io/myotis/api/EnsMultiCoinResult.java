package io.myotis.api;

/**
 * An ENS multi-coin address lookup (ENSIP-9 / SLIP-44).
 *
 * @param name        the ENS name
 * @param coinType    the SLIP-44 coin type queried
 * @param addressHex  the coin address bytes (0x-hex), null when absent
 * @param blockNumber block the resolution state anchors to; -1 when none
 * @param verified    true iff resolved against beacon-finalized state
 * @param error       null on success
 */
public record EnsMultiCoinResult(
        String name,
        long coinType,
        String addressHex,
        long blockNumber,
        boolean verified,
        String error) {
}
