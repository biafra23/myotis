package io.myotis.api;

/**
 * The detailed outcome of a verified {@code eth_call} — distinguishes the three
 * cases the single nullable {@code byte[]} of {@link VerifiedReads#call} cannot:
 *
 * <ul>
 *   <li>{@link Status#OK} — executed, {@code data} is the ABI return bytes
 *       (possibly empty).</li>
 *   <li>{@link Status#REVERTED} — executed <em>successfully as a verification
 *       matter</em> and the contract reverted; {@code data} is the raw revert
 *       payload (possibly empty). This is a verified chain answer, not a
 *       failure: hosts map it to the standard JSON-RPC
 *       {@code {code: 3, message: "execution reverted…", data: 0x…}} that
 *       wallets parse. Reporting it as "cannot answer" makes wallets treat a
 *       normal negative answer (e.g. an ERC-165 probe on a plain ERC-20) as a
 *       node outage.</li>
 *   <li>{@link Status#UNAVAILABLE} — no verified answer right now (not synced /
 *       no peer / out-of-window block); retryable, hosts keep the existing
 *       -32000 mapping. {@code detail} may carry a diagnostic reason.</li>
 * </ul>
 *
 * <p>Flat record over FFI-portable types (enum, {@code byte[]}, {@code String})
 * per the engine-contract rules; {@code data}/{@code detail} are null when not
 * applicable to the status.
 */
public record CallResult(Status status, byte[] data, String detail) {

    public CallResult {
        java.util.Objects.requireNonNull(status, "status");
    }

    public enum Status { OK, REVERTED, UNAVAILABLE }

    public static CallResult ok(byte[] data) {
        return new CallResult(Status.OK, data == null ? new byte[0] : data, null);
    }

    public static CallResult reverted(byte[] revertData) {
        return new CallResult(Status.REVERTED, revertData == null ? new byte[0] : revertData, null);
    }

    public static CallResult unavailable(String detail) {
        return new CallResult(Status.UNAVAILABLE, null, detail);
    }
}
