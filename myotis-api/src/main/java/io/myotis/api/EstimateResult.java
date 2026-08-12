package io.myotis.api;

/**
 * The detailed outcome of a verified {@code eth_estimateGas} — the estimate
 * sibling of {@link CallResult}, distinguishing the three cases the single
 * nullable {@code Long} of {@link VerifiedReads#estimateGas} cannot:
 *
 * <ul>
 *   <li>{@link Status#OK} — {@code gas} is the buffered gas-limit estimate.</li>
 *   <li>{@link Status#REVERTED} — the estimated transaction reverted;
 *       {@code revertData} is the raw payload (possibly empty). A verified
 *       chain answer: hosts serve the standard JSON-RPC
 *       {@code {code: 3, "execution reverted…", data}} instead of the
 *       retryable -32000 a wallet misreads as a node outage.</li>
 *   <li>{@link Status#UNAVAILABLE} — no verified answer right now (retryable);
 *       {@code detail} may carry a diagnostic reason.</li>
 * </ul>
 *
 * <p>Flat record over FFI-portable types per the engine-contract rules;
 * {@code gas} is meaningful only for OK, {@code revertData}/{@code detail}
 * null when not applicable.
 */
public record EstimateResult(Status status, long gas, byte[] revertData, String detail) {

    public EstimateResult {
        java.util.Objects.requireNonNull(status, "status");
    }

    public enum Status { OK, REVERTED, UNAVAILABLE }

    public static EstimateResult ok(long gas) {
        return new EstimateResult(Status.OK, gas, null, null);
    }

    public static EstimateResult reverted(byte[] revertData) {
        return new EstimateResult(Status.REVERTED, 0L,
                revertData == null ? new byte[0] : revertData, null);
    }

    public static EstimateResult unavailable(String detail) {
        return new EstimateResult(Status.UNAVAILABLE, 0L, null, detail);
    }
}
