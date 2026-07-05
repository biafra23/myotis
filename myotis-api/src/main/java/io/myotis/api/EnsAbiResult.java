package io.myotis.api;

/**
 * An ENS ABI record lookup (ENSIP-4).
 *
 * @param name         the ENS name
 * @param contentType  the returned encoding (bit from the request mask); 0 when absent
 * @param dataHex      the ABI payload bytes (0x-hex), null when absent
 * @param blockNumber  block the resolution state anchors to; -1 when none
 * @param verified     true iff resolved against beacon-finalized state
 * @param error        null on success
 */
public record EnsAbiResult(
        String name,
        long contentType,
        String dataHex,
        long blockNumber,
        boolean verified,
        String error) {
}
