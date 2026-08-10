package io.myotis.api;

/**
 * Narrow status source the JSON-RPC server consumes to answer the local
 * {@code myotis_status} / {@code myotis_beaconStatus} introspection methods — the
 * JSON-RPC counterpart of the daemon's {@code status} / {@code beacon-status} IPC
 * commands.
 *
 * <p>Kept separate from {@link ChainHandle} so the RPC layer depends only on the two
 * status shapes plus uptime, not the full engine surface. Both engine hosts already
 * assemble {@link StatusSnapshot} / {@link BeaconStatus}; this just adds node uptime
 * so the RPC result mirrors the IPC command's {@code uptimeSeconds} field.
 *
 * <p>Like the IPC commands, these are pure introspection: implementations must answer
 * even when the node is not synced / has no peers — that is precisely when a client
 * wants to poll progress. FFI-portable: flat records + a primitive only.
 */
public interface NodeStatusReads {

    /** EL/networking + lifecycle view (the {@code status} command's source). */
    StatusSnapshot status();

    /** CL light-client view (the {@code beacon-status} command's source). */
    BeaconStatus beaconStatus();

    /** Node uptime in seconds, anchored to when the start was REQUESTED (so the boot
     *  itself counts); {@code 0} until the first start succeeds. */
    long uptimeSeconds();
}
