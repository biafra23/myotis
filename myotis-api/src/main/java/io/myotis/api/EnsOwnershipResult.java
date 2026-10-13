package io.myotis.api;

/**
 * Who holds an ENS name and for how long — the registry and, for a {@code .eth}
 * second-level name, the BaseRegistrar, read directly (no resolver involved), each
 * seen through the chain's NameWrapper where it is the holder.
 *
 * <p>The record convention of every ENS read: a successful "nothing on chain for this
 * name" is every address null and both times -1 with {@code error == null}; a read
 * that failed carries its error. Whether a {@code .eth} name is taken is a question
 * of TIME against {@code expiresAt} and {@code gracePeriodSeconds}, which the caller
 * answers with its own clock: the registry keeps the old owner and the registrar the
 * old expiry long after the name became free to register.
 *
 * @param name               the ENS name as asked
 * @param registrantHex      the {@code .eth} registrant (the registrar's token owner,
 *                           unwrapped); null for a subname, an unregistered name or
 *                           an expired one — the registrar's {@code ownerOf} reverts
 *                           from the expiry on, grace period included
 * @param managerHex         the registry owner (unwrapped) — who sets records and
 *                           subnames; null when the registry holds no owner
 * @param wrapped            the registry owner is the chain's NameWrapper
 * @param resolverHex        the registry's resolver for the exact name, null when none
 * @param expiresAt          {@code nameExpires}, unix seconds; -1 for a subname or an
 *                           unregistered name
 * @param gracePeriodSeconds the registrar's {@code GRACE_PERIOD} (only the registrant
 *                           may renew within it past {@code expiresAt}); -1 when
 *                           {@code expiresAt} is -1
 * @param blockNumber        block the resolution state anchors to; -1 when none
 * @param blockTimestamp     the timestamp (unix seconds) of block {@code blockNumber},
 *                           from the verified header the read ran against; -1 when
 *                           none (a failed read, or an engine that does not report it)
 * @param verified           true iff resolved against beacon-finalized state
 * @param error              null on success
 */
public record EnsOwnershipResult(
        String name,
        String registrantHex,
        String managerHex,
        boolean wrapped,
        String resolverHex,
        long expiresAt,
        long gracePeriodSeconds,
        long blockNumber,
        long blockTimestamp,
        boolean verified,
        String error) {
}
