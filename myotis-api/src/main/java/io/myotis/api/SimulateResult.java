package io.myotis.api;

/**
 * The outcome of an {@code eth_simulateV1} (#716; {@link VerifiedReads#simulateV1}): geth's
 * result — the simulated blocks with their calls, as the JSON-RPC result carries them — or
 * why there is none. A call that reverts or halts is still {@link Status#OK}: its result
 * carries the failure, as geth's does.
 *
 * @param status     the outcome
 * @param resultJson the JSON-RPC result (an array of blocks), for {@link Status#OK}; else null
 * @param code       geth's error code, for {@link Status#FAILED} (-38010 to -38026, -32602,
 *                   -32603); else 0
 * @param detail     the reason, for every other status (geth's words for
 *                   {@link Status#FAILED}); may be null for {@link Status#UNAVAILABLE}
 */
public record SimulateResult(Status status, String resultJson, int code, String detail) {

    public SimulateResult {
        java.util.Objects.requireNonNull(status, "status");
    }

    /** OK: simulated; FAILED: geth's own simulation error, with its code; UNAVAILABLE:
     *  retryable; REFUSED: never on this engine (-32602). */
    public enum Status { OK, FAILED, UNAVAILABLE, REFUSED }

    public static SimulateResult ok(String resultJson) {
        return new SimulateResult(Status.OK, java.util.Objects.requireNonNull(resultJson, "resultJson"), 0, null);
    }

    public static SimulateResult failed(int code, String message) {
        return new SimulateResult(Status.FAILED, null, code, java.util.Objects.requireNonNull(message, "message"));
    }

    public static SimulateResult unavailable(String detail) {
        return new SimulateResult(Status.UNAVAILABLE, null, 0, detail);
    }

    public static SimulateResult refused(String detail) {
        return new SimulateResult(Status.REFUSED, null, 0, java.util.Objects.requireNonNull(detail, "detail"));
    }
}
