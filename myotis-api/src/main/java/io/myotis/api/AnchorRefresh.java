package io.myotis.api;

import java.util.List;

/**
 * Outcome of {@link ChainHandle#refreshAnchorFromCheckpointz(boolean)}: a fresh
 * finalized checkpoint that every answering checkpoint-sync server names (at
 * least two independent operators among them) and that long-known peers confirm,
 * handed to a stack parked in {@link BeaconState#STALE_ANCHOR}. A single
 * differing server, or a long-known peer naming another root for that epoch,
 * refuses it, and {@code error} then names the outlier.
 *
 * <p>The root is those operators' word — no engine can verify an anchor — so a
 * host shows {@code operators} with it. The long-known peers (pinned in the
 * release, or known to this device for a week) are the eclipse guard: an
 * attacker who controls this device's network cannot answer as a peer whose
 * identity it already knew. Everything synced from the root is verified as usual
 * (the bootstrap is pinned to it, every later update BLS-verified).
 *
 * @param applied     the stack took the anchor and is bootstrapping from it
 * @param root        the finalized block root, 0x-hex; null unless applied
 * @param slot        the finalized epoch's first slot; 0 unless applied
 * @param epoch       the finalized epoch; 0 unless applied
 * @param operators   the agreeing operators (registrable domains); empty unless applied
 * @param confirmedBy the long-known peers that named the same root; empty unless
 *                    applied, and empty when applied only on the user's "use it anyway"
 * @param unconfirmed no long-known peer confirmed it: when not applied, the host
 *                    flags it ("an eclipse cannot be ruled out") and may offer
 *                    "use it anyway"; when applied, it was that explicit choice
 * @param error       null when applied; otherwise why not
 */
public record AnchorRefresh(boolean applied, String root, long slot, long epoch,
                            List<String> operators, List<String> confirmedBy,
                            boolean unconfirmed, String error) {
    public AnchorRefresh {
        operators = operators == null ? List.of() : List.copyOf(operators);
        confirmedBy = confirmedBy == null ? List.of() : List.copyOf(confirmedBy);
    }

    /** Not applied, for {@code reason}. */
    public static AnchorRefresh refused(String reason) {
        return new AnchorRefresh(false, null, 0, 0, List.of(), List.of(), false, reason);
    }
}
