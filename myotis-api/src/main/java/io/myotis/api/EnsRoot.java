package io.myotis.api;

/**
 * Which state root ENS resolution runs against.
 * <ul>
 *   <li>{@code FINALIZED} — beacon-finalized state (fully verified; ~2 epochs
 *       stale; needs a snap peer retaining that state).</li>
 *   <li>{@code PEER_HEAD} — the peer's latest head (freshest; peer-claimed for
 *       the resolution itself).</li>
 *   <li>{@code AUTO} — try FINALIZED, fall back to PEER_HEAD on no-record/error.</li>
 * </ul>
 */
public enum EnsRoot { FINALIZED, PEER_HEAD, AUTO }
