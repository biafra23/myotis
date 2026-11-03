package io.myotis.api;

/**
 * The outcome of a {@code debug_traceCall} (#716; {@link VerifiedReads#traceCall}): the
 * trace — geth's {@code callTracer} or {@code prestateTracer} answer, as the JSON-RPC
 * result carries it — or why there is none. A run that reverts or halts is still
 * {@link Status#OK}: the trace carries the failure, as geth's does.
 *
 * @param status    the outcome
 * @param traceJson the trace as JSON, for {@link Status#OK}; else null
 * @param detail    the reason, for every other status (geth's words for
 *                  {@link Status#INFEASIBLE}); may be null for {@link Status#UNAVAILABLE}
 */
public record TraceResult(Status status, String traceJson, String detail) {

    public TraceResult {
        java.util.Objects.requireNonNull(status, "status");
    }

    /** OK: traced; UNAVAILABLE: retryable; REFUSED: never on this engine (-32602);
     *  INFEASIBLE: the request cannot run within the caller's own limits (geth's -32000). */
    public enum Status { OK, UNAVAILABLE, REFUSED, INFEASIBLE }

    public static TraceResult ok(String traceJson) {
        return new TraceResult(Status.OK, java.util.Objects.requireNonNull(traceJson, "traceJson"), null);
    }

    public static TraceResult unavailable(String detail) {
        return new TraceResult(Status.UNAVAILABLE, null, detail);
    }

    public static TraceResult refused(String detail) {
        return new TraceResult(Status.REFUSED, null, java.util.Objects.requireNonNull(detail, "detail"));
    }

    public static TraceResult infeasible(String detail) {
        return new TraceResult(Status.INFEASIBLE, null, java.util.Objects.requireNonNull(detail, "detail"));
    }
}
