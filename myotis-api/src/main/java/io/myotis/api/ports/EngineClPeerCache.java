package io.myotis.api.ports;

import java.util.List;

/**
 * The CL (beacon libp2p) peer cache — multiaddrs, failure counts, and the
 * proven-capability records that let the light client front-load peers that have
 * actually served bootstraps / catch-up ranges / light-client protocols before.
 */
public interface EngineClPeerCache {

    /** Cached CL peer multiaddrs to seed the light client, in stored order. */
    List<String> load();

    /** Record a responsive CL peer multiaddr (idempotent). */
    void add(String multiaddr);

    /** Record that a CL peer failed (for deprioritization). */
    void markFailure(String multiaddr);

    /** Proven catch-up service ranges. */
    List<ServedRange> servedRanges();

    /** Record that {@code multiaddr} served catch-up across [low, high]. */
    void recordServed(String multiaddr, long low, long high);

    /** Peers that have served bootstraps, with the period served. */
    List<BootstrapPeer> bootstrapPeers();

    /** Record that {@code multiaddr} served a bootstrap for {@code period}. */
    void recordBootstrap(String multiaddr, long period);

    /** Peers confirmed to serve the light_client req/resp protocols. */
    List<String> lightClientConfirmed();

    /** Peers proven NOT to serve the light_client protocols. */
    List<String> lightClientDenied();

    /** Persist a batch of light-client capability verdicts. */
    void markLightClientBatch(List<String> confirmed, List<String> denied);

    /** Flush queued writes and release resources. */
    void close();
}
