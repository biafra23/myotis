package io.myotis.api;

/**
 * Host-tunable configuration for one network's stack. Networks are referenced by
 * canonical name; all protocol constants (genesis, fork IDs, checkpoints,
 * bootnodes) are embedded in the engine.
 *
 * @param networkName          canonical network name (see {@link MyotisEngine#canonicalNetworkName})
 * @param elPort               RLPx TCP + discv4 UDP port; 0 → the network's default
 * @param discv5Port           CL discv5 UDP port; 0 → the network's default
 * @param rpcPort              verified JSON-RPC HTTP port (loopback); 0 → the network's default
 * @param syncSnapshotPath     file path for the light-client sync snapshot (a private
 *                             cache, not a trust anchor); null → no snapshot persistence
 * @param gossipsubEnabled     subscribe to CL gossipsub (live finality updates) in
 *                             addition to polling
 * @param targetSnapPeers      snap-peer maintainer target; 0 → maintainer disabled
 *                             (bare daemons rely on continuous discv4; NAT'd/mobile
 *                             hosts should enable it)
 * @param strictStateFreshness true → strict 2-minute state freshness (production);
 *                             false → relaxed (experimental)
 * @param dataDir              directory for engine-owned private state (peer caches,
 *                             working files) for engines that persist their own — the
 *                             Rust engine requires it; the Java engine ignores it (its
 *                             caches come in through the {@code EnginePorts} cache
 *                             ports instead). Nullable while only the Java engine runs.
 */
public record EngineConfig(
        String networkName,
        int elPort,
        int discv5Port,
        int rpcPort,
        String syncSnapshotPath,
        boolean gossipsubEnabled,
        int targetSnapPeers,
        boolean strictStateFreshness,
        String dataDir) {
}
