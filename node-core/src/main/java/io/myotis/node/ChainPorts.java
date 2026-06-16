package io.myotis.node;

import com.jaeckel.ethp2p.networking.NetworkConfig;

/**
 * The three ports a single network's {@code ChainStack} owns: the EL (RLPx TCP +
 * discv4 UDP) port, the CL discv5 UDP port, and the verified JSON-RPC HTTP port.
 *
 * <p>Defaults come from {@link NetworkConfig} (pinned per network so several stacks
 * can run in one process without colliding); a host may override any of them (e.g.
 * the Android app persists a user-chosen RPC port per network).
 */
public record ChainPorts(int elPort, int discv5Port, int rpcPort) {

    /** The per-network default ports for {@code network}. */
    public static ChainPorts defaultsFor(NetworkConfig network) {
        return new ChainPorts(
                network.defaultElPort(),
                network.defaultDiscv5Port(),
                network.defaultRpcPort());
    }

    /** Same EL/discv5 defaults, but with the RPC port overridden (host-configurable). */
    public ChainPorts withRpcPort(int overriddenRpcPort) {
        return new ChainPorts(elPort, discv5Port, overriddenRpcPort);
    }
}
