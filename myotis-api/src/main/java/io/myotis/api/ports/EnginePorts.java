package io.myotis.api.ports;

/**
 * The bundle of host-implemented seams injected into one network's stack.
 *
 * @param keyStore    node-identity storage (required)
 * @param peerCache   EL peer cache (required)
 * @param clPeerCache CL (beacon libp2p) peer cache (required)
 * @param dnsServers  DNS servers for EIP-1459 lookups; null → the resolver's
 *                    default (mobile hosts must supply the active network's DNS —
 *                    their resolvers have no system config)
 * @param httpGateway CCIP-Read (ERC-3668) HTTP transport (required where ENS/EVM
 *                    features are used; null disables off-chain resolution)
 * @param logger      engine log sink; null → the engine's default logger
 * @param clock       monotonic clock; null → the engine's monotonic default
 */
public record EnginePorts(
        NodeKeyStore keyStore,
        EnginePeerCache peerCache,
        EngineClPeerCache clPeerCache,
        DnsServers dnsServers,
        HttpGateway httpGateway,
        EngineLogger logger,
        EngineClock clock) {
}
