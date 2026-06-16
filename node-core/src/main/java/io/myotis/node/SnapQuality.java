package io.myotis.node;

/**
 * Learned snap-serving verdict for an EL peer, persisted across restarts and used
 * to order dial priority (CONFIRMED first, DENIED last). Shared by the daemon and
 * Android peer caches via {@link PeerCachePort}.
 */
public enum SnapQuality { CONFIRMED, UNKNOWN, DENIED }
