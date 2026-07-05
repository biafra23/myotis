package io.myotis.api;

/**
 * An ENS-stored DNS record lookup (ENSIP-6).
 *
 * @param name        the ENS name
 * @param dnsName     the DNS name queried
 * @param recordType  the DNS record type (e.g. 1 = A, 16 = TXT)
 * @param dataHex     the raw DNS record bytes (0x-hex), null when absent
 * @param blockNumber block the resolution state anchors to; -1 when none
 * @param verified    true iff resolved against beacon-finalized state
 * @param error       null on success
 */
public record EnsDnsRecordResult(
        String name,
        String dnsName,
        int recordType,
        String dataHex,
        long blockNumber,
        boolean verified,
        String error) {
}
