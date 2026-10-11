package io.myotis.api;

/**
 * The outcome of a verified {@code eth_createAccessList} — the EIP-2930 access
 * list a transaction touches, built as geth builds it (traced with geth's
 * exclusions, then confirmed with the list applied until it stops changing) —
 * the sibling of {@link CallResult} and {@link EstimateResult}:
 *
 * <ul>
 *   <li>{@link Status#OK} — {@code accessListJson} is the list exactly as the
 *       JSON-RPC result carries it ({@code [{"address", "storageKeys": [...]}]},
 *       sorted by address and key), {@code gasUsed} what the run made with the
 *       list used (after refunds, geth's {@code UsedGas}). {@code vmError} is
 *       that run's OWN failure, if any — geth reports a revert or a halt in the
 *       result's {@code error} field NEXT TO the list, never instead of it, so a
 *       wallet still gets the list for a transaction it is about to learn
 *       fails: {@code "execution reverted"} (then {@code revertData} carries the
 *       raw payload, for the decoded reason hosts append as they do for a
 *       code-3 revert) or the halt ({@code "out of gas"}, …). Null when the run
 *       succeeded.</li>
 *   <li>{@link Status#UNAVAILABLE} — no verified answer right now (retryable);
 *       {@code detail} may carry a diagnostic reason.</li>
 *   <li>{@link Status#REFUSED} — permanently unanswerable on this build (an
 *       engine that builds no access lists, a contradictory transaction
 *       object, an EVM fork the engine cannot price); {@code detail} says why.
 *       Hosts serve the permanent -32602, as for {@link CallResult.Status#REFUSED}.</li>
 *   <li>{@link Status#INFEASIBLE} — the request cannot run within the caller's
 *       own limits — its {@code gas} below the intrinsic cost, a fee cap below
 *       the base fee, funds the fee needs — exactly as {@link CallResult.Status#INFEASIBLE}
 *       for {@link VerifiedReads#callTx}, whose checks this shares. An answer,
 *       not a failure to answer; {@code detail} is geth's message, served
 *       verbatim under geth's -32000.</li>
 * </ul>
 *
 * <p>Flat record over FFI-portable types per the engine-contract rules; the
 * list crosses as JSON, as every compound value does. {@code gasUsed} is
 * meaningful only for OK; the other fields are null when not applicable.
 */
public record AccessListResult(
        Status status,
        String accessListJson,
        long gasUsed,
        String vmError,
        byte[] revertData,
        String detail) {

    public AccessListResult {
        java.util.Objects.requireNonNull(status, "status");
    }

    public enum Status { OK, UNAVAILABLE, REFUSED, INFEASIBLE }

    /**
     * @param accessListJson the list as the JSON-RPC result carries it
     * @param gasUsed        what the run made with the list used
     * @param vmError        that run's own failure as geth words it, or null
     * @param revertData     the raw revert payload when {@code vmError} is a revert, else null
     */
    public static AccessListResult ok(String accessListJson, long gasUsed, String vmError, byte[] revertData) {
        return new AccessListResult(Status.OK,
                java.util.Objects.requireNonNull(accessListJson, "accessListJson"),
                gasUsed, vmError, revertData, null);
    }

    public static AccessListResult unavailable(String detail) {
        return new AccessListResult(Status.UNAVAILABLE, null, 0L, null, null, detail);
    }

    public static AccessListResult refused(String detail) {
        return new AccessListResult(Status.REFUSED, null, 0L, null, null,
                java.util.Objects.requireNonNull(detail, "detail"));
    }

    public static AccessListResult infeasible(String detail) {
        return new AccessListResult(Status.INFEASIBLE, null, 0L, null, null,
                java.util.Objects.requireNonNull(detail, "detail"));
    }
}
