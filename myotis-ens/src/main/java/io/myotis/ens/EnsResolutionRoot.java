package io.myotis.ens;

/**
 * Which Ethereum state the ENS contracts are executed against when resolving a
 * name. This is a trust/freshness trade-off:
 *
 * <ul>
 *   <li>{@link #AUTO} (default) — try {@link #FINALIZED} first; if it yields no
 *       address (the record didn't exist yet at the finalized block — e.g. a name
 *       registered or an {@code addr()} first set in the last ~12 min) or errors
 *       (a snap peer doesn't retain that block's state), fall back to
 *       {@link #PEER_HEAD}. So you get a beacon-verified mapping whenever one
 *       exists, and still resolve brand-new names (marked peer-claimed). Note: a
 *       record that <i>changed</i> in the last ~12 min resolves to its
 *       verified-but-stale finalized value, not the new one — staleness, not a
 *       failure; ENS records change rarely.</li>
 *   <li>{@link #FINALIZED} — run resolution against the light client's
 *       beacon-verified <b>finalized</b> execution state root. The name→address
 *       mapping is then cryptographically verified end-to-end (snap proofs anchor
 *       to a beacon-attested root), with no peer-head probe. Cost: the state is
 *       ~12 minutes old (the finality lag), and a snap peer must still retain
 *       that block's state. No fallback: brand-new names return "does not
 *       resolve."</li>
 *   <li>{@link #PEER_HEAD} — run resolution against a snap peer's latest
 *       <b>head</b> state. Freshest possible data, but the head root is the peer's
 *       claim and is NOT beacon-verified, so the resolved address is peer-claimed.
 *       Use only when you need the very latest ENS state and accept that the
 *       mapping isn't independently verified.</li>
 * </ul>
 *
 * <p>The account lookup that follows resolution is beacon-verified regardless of
 * this setting; this only governs the name→address resolution step.
 */
public enum EnsResolutionRoot {
    /** Finalized first, falling back to head when finalized has no verified answer. Default. */
    AUTO,
    /** Beacon-verified finalized state root only (verified mapping, ~12 min stale). */
    FINALIZED,
    /** A snap peer's head state (freshest, but peer-claimed / unverified mapping). */
    PEER_HEAD
}
