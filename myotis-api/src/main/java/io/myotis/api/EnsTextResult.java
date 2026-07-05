package io.myotis.api;

/**
 * An ENS text-record lookup.
 *
 * @param name        the ENS name
 * @param key         the queried text key
 * @param value       the record value, null when absent
 * @param blockNumber block the resolution state anchors to; -1 when none
 * @param verified    true iff resolved against beacon-finalized state
 * @param error       null on success
 */
public record EnsTextResult(
        String name,
        String key,
        String value,
        long blockNumber,
        boolean verified,
        String error) {
}
