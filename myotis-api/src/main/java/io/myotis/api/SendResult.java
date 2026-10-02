package io.myotis.api;

/**
 * The detailed outcome of {@code eth_sendRawTransaction} (#531) — distinguishes
 * the cases the single nullable hash of {@link VerifiedReads#sendRawTransaction}
 * cannot:
 * <ul>
 *   <li>{@link Status#SENT} — broadcast to at least one peer; {@code txHash} is
 *       keccak256 of the raw transaction.</li>
 *   <li>{@link Status#REJECTED} — refused before broadcast: judged on fresh,
 *       verified state, the transaction can never be mined as sent (its sender
 *       cannot pay {@code value + gas × fee}, or its nonce is used), and no
 *       peer would say so. Nothing was broadcast. An answer, not a failure to
 *       answer: {@code detail} is geth's txpool verdict in geth's words
 *       ("insufficient funds for gas * price + value: …", "nonce too low: …"),
 *       which hosts serve verbatim under geth's JSON-RPC -32000 so that wallets
 *       classify it (ethers v6 and viem: {@code INSUFFICIENT_FUNDS},
 *       {@code NONCE_EXPIRED}).</li>
 *   <li>{@link Status#UNAVAILABLE} — not sent now (not a transaction, no peer,
 *       the broadcast cut); retryable, hosts keep the existing -32000 mapping.
 *       {@code detail} may carry a diagnostic reason.</li>
 * </ul>
 * <p>Flat record over FFI-portable types ({@code byte[]}, {@code String}, an
 * enum) per the engine-contract rules; {@code txHash}/{@code detail} are null
 * when not applicable to the status.
 */
public record SendResult(Status status, byte[] txHash, String detail) {

    public SendResult {
        java.util.Objects.requireNonNull(status, "status");
    }

    public enum Status { SENT, REJECTED, UNAVAILABLE }

    public static SendResult sent(byte[] txHash) {
        return new SendResult(Status.SENT, java.util.Objects.requireNonNull(txHash, "txHash"), null);
    }

    public static SendResult rejected(String detail) {
        return new SendResult(Status.REJECTED, null, java.util.Objects.requireNonNull(detail, "detail"));
    }

    public static SendResult unavailable(String detail) {
        return new SendResult(Status.UNAVAILABLE, null, detail);
    }
}
