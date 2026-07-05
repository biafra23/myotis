package io.myotis.api;

/**
 * Result of a forward or reverse ENS name↔address resolution.
 *
 * <p>Convention (same as every ENS record lookup): {@code addressHex == null} with
 * {@code error == null} is a <em>successful</em> "name has no record";
 * {@code error != null} is a resolution failure.
 *
 * @param name        the ENS name (queried, or reverse-resolved)
 * @param addressHex  the resolved / queried address (0x-hex), null when unresolved
 * @param blockNumber block the resolution state anchors to; -1 when none
 * @param verified    true iff resolved against beacon-finalized state
 * @param error       null on success or no-record; otherwise why resolution failed
 */
public record EnsResolutionResult(
        String name,
        String addressHex,
        long blockNumber,
        boolean verified,
        String error) {
}
