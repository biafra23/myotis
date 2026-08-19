package com.jaeckel.ethp2p.consensus.lightclient;

/**
 * The weak-subjectivity age bound for sync anchors, in sync-committee periods.
 *
 * <p><b>Why:</b> the light client's forward walk is only as trustworthy as the anchor
 * it starts from (embedded checkpoint or persisted snapshot). Validators exit over
 * time; once enough of the anchor-era sync committee has exited and withdrawn, an
 * attacker who acquired those keys could sign a validly-verifying forged
 * continuation (a long-range attack), and BLS verification alone cannot tell it
 * from the honest chain. The weak-subjectivity period is how long an anchor stays
 * safe; syncing forward from anything older must be an explicit, informed user
 * decision — never silent.
 *
 * <p><b>The bound:</b> {@code wallClockPeriod - anchorPeriod > bound} → the anchor is
 * refused and the client parks in {@code STALE_ANCHOR} until the user raises the
 * bound or accepts the risk ({@code BeaconLightClient.acceptStaleAnchor}).
 *
 * <p><b>Default derivation (mainnet preset):</b> the consensus-spec formula
 * (weak-subjectivity.md, {@code SAFETY_DECAY = 10}) plateaus at
 * {@code 3532 epochs ≈ 15.7 days} for any validator count ≥ 262 144 (pre-Electra
 * churn; Electra's 256-ETH exit-churn cap only lengthens it, so the pre-Electra
 * figure is the conservative floor). 3532 / 256 epochs-per-period = 13.8 →
 * <b>13 periods (~14.7 days)</b>, rounded down so the bound never exceeds the spec
 * window. Per-network defaults live in {@code NetworkConfig.wsBoundPeriods()}
 * (gnosis has different churn parameters and a much shorter window); this constant
 * is the fallback for clients constructed without one.
 */
public final class WeakSubjectivity {

    /** Mainnet-preset fallback: 13 periods (~14.7 days). See class doc for derivation. */
    public static final long DEFAULT_BOUND_PERIODS = 13L;

    private WeakSubjectivity() {}

    /** The bound actually enforced: the host override when set (&gt; 0), else the
     *  network default when set, else {@link #DEFAULT_BOUND_PERIODS}. */
    public static long effectiveBound(long overridePeriods, long networkDefaultPeriods) {
        if (overridePeriods > 0) return overridePeriods;
        if (networkDefaultPeriods > 0) return networkDefaultPeriods;
        return DEFAULT_BOUND_PERIODS;
    }

    /**
     * Whether an anchor at {@code anchorPeriod} is beyond the bound at
     * {@code wallClockPeriod}. A wall clock behind the anchor (negative age — clock
     * skew) is treated as fresh: a backwards clock can only make the check
     * <i>more</i> permissive, and defending the device clock is outside this
     * threat model (documented in docs/readiness-and-verified-head-age.md).
     */
    public static boolean isStale(long anchorPeriod, long wallClockPeriod, long boundPeriods) {
        return wallClockPeriod - anchorPeriod > boundPeriods;
    }
}
