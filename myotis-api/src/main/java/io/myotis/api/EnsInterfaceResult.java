package io.myotis.api;

/**
 * An ENS interface-implementer record lookup (ERC-165).
 *
 * @param name           the ENS name
 * @param interfaceIdHex the queried 4-byte interface id (0x-hex)
 * @param implementerHex the implementer address (0x-hex), null when absent
 * @param blockNumber    block the resolution state anchors to; -1 when none
 * @param verified       true iff resolved against beacon-finalized state
 * @param error          null on success
 */
public record EnsInterfaceResult(
        String name,
        String interfaceIdHex,
        String implementerHex,
        long blockNumber,
        boolean verified,
        String error) {
}
