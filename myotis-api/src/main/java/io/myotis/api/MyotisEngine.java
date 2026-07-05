package io.myotis.api;

import io.myotis.api.ports.EnginePorts;

import java.util.List;

/**
 * The engine's root object: knows the embedded network catalog and hosts one
 * {@link ChainHandle} per enabled network. One process can host several networks
 * side by side (mainnet + Gnosis + …), each on its own ports; a failure in one is
 * isolated to that network.
 *
 * <p>Hosts construct exactly one implementation at their composition root (the
 * single line naming a concrete engine class) and use only this API from there on.
 */
public interface MyotisEngine {

    /** The networks compiled into this engine, in display order. */
    List<NetworkInfo> availableNetworks();

    /**
     * Resolve a user-supplied network name or alias (case-insensitive; e.g.
     * {@code xdai}/{@code gbc} → {@code gnosis}) to the canonical name used
     * everywhere else in this API.
     *
     * @throws EngineException on an unknown network
     */
    String canonicalNetworkName(String nameOrAlias);

    /**
     * Construct and register one network's stack with the host's injected ports.
     * Does NOT start it — call {@link ChainHandle#start()}. Creating a network
     * that is already hosted throws.
     *
     * @throws EngineException on an unknown network or one already hosted
     */
    ChainHandle create(EngineConfig config, EnginePorts ports);

    /** The handle for {@code networkName}, or {@code null} if not hosted. */
    ChainHandle get(String networkName);

    /** Canonical names of the networks currently hosted. */
    List<String> hostedNetworks();

    /** Stop and unregister one network (no-op if absent). */
    void stop(String networkName);

    /** Stop and unregister every hosted network. */
    void shutdownAll();
}
