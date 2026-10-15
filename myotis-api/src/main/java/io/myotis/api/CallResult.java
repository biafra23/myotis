package io.myotis.api;

/**
 * The detailed outcome of a verified {@code eth_call} — distinguishes the
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
 *   <li>{@link Status#REFUSED} — this engine will not answer this request on
 *       this build, and no retry changes that (e.g. the Java engine past an EVM
 *       fork its Besu cannot price). {@code detail} says why. Hosts serve the
 *       PERMANENT JSON-RPC -32602, never the retryable -32000 a client would
 *       spin on (CLAUDE.md: a refusal is permanent).</li>
 *   <li>{@link Status#INFEASIBLE} — the call cannot succeed within the
 *       caller's own limits (#509): it ran out of the {@code gas} the caller
 *       gave it, that limit is below the intrinsic cost, the fee cap is below
 *       the block's base fee, or the sender cannot afford {@code gas × fee cap
 *       + value}. {@link VerifiedReads#callTx} answers it; a plain call only
 *       on the Rust engine, when its calldata alone costs more than the call
 *       budget (the Java engine's plain call charges no intrinsic gas). An
 *       answer, not a failure to answer; {@code detail} carries geth's message
 *       ("out of gas", "err: intrinsic gas too low: have N, want M (supplied
 *       gas N)", …), which hosts serve verbatim as geth does (JSON-RPC -32000)
 *       — never as return data.</li>
 * </ul>
 *
 * <p>{@code blockNumber} is the block whose state the call ran against, when
 * the producer says ({@code -1} otherwise): a {@code latest} call runs against
 * whatever verified head the engine holds at that moment — the optimistic head,
 * or a finalized fallback some epochs older — so a caller comparing answers over
 * time (the apps' balance watch) needs the block to order them. It is set on an
 * answered call ({@link Status#OK}, {@link Status#REVERTED}) by the Rust engine
 * and by the Java engine's plain call ({@code callDetailed} without state
 * overrides, and {@code callTx}); the Java engine's state-override path and the
 * default {@link VerifiedReads#callDetailed} keep {@code -1}. So a caller must
 * handle {@code -1} on any status — it is additive, never a guarantee.
 *
 * <p>Flat record over FFI-portable types (enum, {@code byte[]}, {@code String},
 * {@code long}) per the engine-contract rules; {@code data}/{@code detail} are
 * null when not applicable to the status.
 */
public record CallResult(Status status, byte[] data, String detail, long blockNumber) {

    public CallResult {
        java.util.Objects.requireNonNull(status, "status");
    }

    /** A result whose block is not known ({@code blockNumber} {@code -1}). */
    public CallResult(Status status, byte[] data, String detail) {
        this(status, data, detail, -1L);
    }

    /** This result, stating that the call ran against block {@code block}. */
    public CallResult atBlock(long block) {
        return new CallResult(status, data, detail, block);
    }

    public enum Status { OK, REVERTED, UNAVAILABLE, REFUSED, INFEASIBLE }

    public static CallResult ok(byte[] data) {
        return new CallResult(Status.OK, data == null ? new byte[0] : data, null);
    }

    public static CallResult reverted(byte[] revertData) {
        return new CallResult(Status.REVERTED, revertData == null ? new byte[0] : revertData, null);
    }

    public static CallResult unavailable(String detail) {
        return new CallResult(Status.UNAVAILABLE, null, detail);
    }

    public static CallResult refused(String detail) {
        return new CallResult(Status.REFUSED, null, detail);
    }

    public static CallResult infeasible(String detail) {
        return new CallResult(Status.INFEASIBLE, null, java.util.Objects.requireNonNull(detail, "detail"));
    }
}
