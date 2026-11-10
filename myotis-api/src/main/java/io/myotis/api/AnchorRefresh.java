package io.myotis.api;

import java.util.List;

/**
 * Outcome of {@link ChainHandle#refreshAnchorFromCheckpointz()}: a fresh
 * finalized checkpoint that checkpoint-sync servers of at least two independent
 * operators agree on, handed to a stack parked in {@link BeaconState#STALE_ANCHOR}.
 *
 * <p>The root is those operators' word — no engine can verify an anchor — so a
 * host shows {@code operators} with it. Everything synced from it is verified as
 * usual (the bootstrap is pinned to it, every later update BLS-verified).
 *
 * @param applied   the stack took the anchor and is bootstrapping from it
 * @param root      the finalized block root, 0x-hex; null unless applied
 * @param slot      the finalized epoch's first slot; 0 unless applied
 * @param epoch     the finalized epoch; 0 unless applied
 * @param operators the agreeing operators (registrable domains); empty unless applied
 * @param error     null when applied; otherwise why not
 */
public record AnchorRefresh(boolean applied, String root, long slot, long epoch,
                            List<String> operators, String error) {
    public AnchorRefresh {
        operators = operators == null ? List.of() : List.copyOf(operators);
    }

    /** Not applied, for {@code reason}. */
    public static AnchorRefresh refused(String reason) {
        return new AnchorRefresh(false, null, 0, 0, List.of(), reason);
    }
}
