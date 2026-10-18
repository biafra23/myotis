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
 *   <li>{@link Status#REFUSED} — the bytes are no transaction this node relays
 *       (#360): they do not decode as one under a strict reading of their type,
 *       their signature names no sender (or carries values a peer refuses), or
 *       it is a blob transaction — or it was signed for another chain (#665;
 *       "invalid sender: invalid chain id for signer: have X want Y", geth's
 *       words). Nothing was broadcast, and no retry changes
 *       the bytes: hosts serve the PERMANENT JSON-RPC -32602 with
 *       {@code detail}, never the retryable -32000 a client would spin on
 *       (CLAUDE.md: a refusal is permanent).</li>
 *   <li>{@link Status#UNAVAILABLE} — not sent now (no peer, the broadcast
 *       cut); retryable, hosts keep the existing -32000 mapping. {@code detail}
 *       may carry a diagnostic reason.</li>
 * </ul>
 * <p>Flat record over FFI-portable types ({@code byte[]}, {@code String}, an
 * enum) per the engine-contract rules; {@code txHash}/{@code detail} are null
 * when not applicable to the status.
 */
public record SendResult(Status status, byte[] txHash, String detail) {

    public SendResult {
        java.util.Objects.requireNonNull(status, "status");
        // The fields the status promises: a SENT result without its hash, or a
        // refusal without its reason, would reach the router as a crash.
        if (status == Status.SENT) java.util.Objects.requireNonNull(txHash, "txHash");
        if (status == Status.REJECTED || status == Status.REFUSED) {
            java.util.Objects.requireNonNull(detail, "detail");
        }
    }

    public enum Status { SENT, REJECTED, REFUSED, UNAVAILABLE }

    public static SendResult sent(byte[] txHash) {
        return new SendResult(Status.SENT, txHash, null);
    }

    public static SendResult rejected(String detail) {
        return new SendResult(Status.REJECTED, null, detail);
    }

    public static SendResult refused(String detail) {
        return new SendResult(Status.REFUSED, null, detail);
    }

    public static SendResult unavailable(String detail) {
        return new SendResult(Status.UNAVAILABLE, null, detail);
    }
}
