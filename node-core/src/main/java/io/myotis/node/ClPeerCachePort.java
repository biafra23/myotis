package io.myotis.node;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The CL (beacon libp2p) peer-cache operations a {@code ChainStack} needs, abstracted
 * so the daemon ({@code CLPeerCache}) and Android ({@code AndroidCLPeerCache}) can each
 * supply their own file-backed implementation via a thin adapter. Method shapes mirror
 * what {@code BeaconLightClient}'s seed/listener setters consume, so they wire as direct
 * method references.
 */
public interface ClPeerCachePort {

    /** Cached CL peer multiaddrs to seed the light client, in stored order. */
    List<String> load();

    /** Record a responsive CL peer multiaddr (idempotent). */
    void add(String multiaddr);

    /** Record that a CL peer failed (for deprioritization). */
    void markFailure(String multiaddr);

    /** Peer → [low, high] sync-committee period range it has served (for catch-up seeding). */
    Map<String, long[]> servedRanges();

    /** Record that {@code multiaddr} served catch-up across [low, high]. */
    void recordServed(String multiaddr, long low, long high);

    /** Peer → period it served a bootstrap from (front-loads proven LC servers on restart). */
    Map<String, Long> bootstrapPeers();

    /** Record that {@code multiaddr} served a bootstrap for {@code period}. */
    void recordBootstrap(String multiaddr, long period);

    /** Peers confirmed to serve light_client protocols. */
    Set<String> lightClientConfirmed();

    /** Peers proven NOT to serve light_client protocols. */
    Set<String> lightClientDenied();

    /** Persist a batch of light-client capability verdicts (confirmed + denied). */
    void markLightClientBatch(Collection<String> confirmed, Collection<String> denied);

    /** Flush queued writes and release resources. */
    void close();
}
