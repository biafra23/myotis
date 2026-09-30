package io.myotis.api;

/**
 * The JSON-RPC transaction object of an {@code eth_estimateGas} or
 * {@code eth_call} request (geth's {@code TransactionArgs}), as the host
 * validated it (#509).
 *
 * <p>Every field changes the answer, so an engine APPLIES each one or the
 * request is REFUSED — never answered with a field dropped. The failure this
 * exists for: a type-4 estimate whose {@code authorizationList} was ignored ran
 * the call against an EOA with no code, answered a fraction of the gas the
 * delegated execution needs, and the wallet's transaction ran out of gas on
 * chain.
 *
 * <p>Two views of ONE object, built together by the host:
 * <ul>
 *   <li>{@link #json} — the canonical full object ({@code from}, {@code to},
 *       {@code input}, {@code value}, {@code gas}, the fee fields,
 *       {@code nonce}, {@code chainId}, {@code type}, {@code accessList},
 *       {@code authorizationList}), for an engine that applies every field
 *       (the Rust engine parses it).</li>
 *   <li>the typed fields — what an engine can apply without parsing JSON.
 *       {@code chainId} and {@code type} are in {@link #json} only: the host
 *       checks {@code chainId} against the node and {@code type} against the
 *       other fields. Only an EIP-7702 authorization or a contract creation can
 *       observe {@code nonce}. The two lists are
 *       summarised by {@link #hasAccessList} / {@link #hasAuthorizationList};
 *       an engine that does not apply them reports
 *       {@link VerifiedReads#supportsTransactionLists()} false and the host
 *       refuses them before dispatch.</li>
 * </ul>
 *
 * <p>Flat record over FFI-portable types per the engine-contract rules.
 *
 * @param from                     the sender, or null for an anonymous one
 * @param to                       the recipient, or null for contract creation
 * @param data                     calldata (init code for a creation); never null
 * @param valueWei                 value in decimal wei, or null for zero
 * @param gas                      the caller's gas limit, or null
 * @param gasPriceWei              legacy {@code gasPrice} in decimal wei, or null
 * @param maxFeePerGasWei          EIP-1559 {@code maxFeePerGas} in decimal wei, or null
 * @param maxPriorityFeePerGasWei  EIP-1559 {@code maxPriorityFeePerGas} in decimal wei, or null
 * @param nonce                    the transaction nonce, or null
 * @param hasAccessList            a NON-EMPTY {@code accessList} is present (an empty one changes nothing)
 * @param hasAuthorizationList     an {@code authorizationList} is present
 * @param json                     the canonical object, geth's {@code TransactionArgs} shape
 */
public record TransactionArgs(
        byte[] from,
        byte[] to,
        byte[] data,
        String valueWei,
        Long gas,
        String gasPriceWei,
        String maxFeePerGasWei,
        String maxPriorityFeePerGasWei,
        Long nonce,
        boolean hasAccessList,
        boolean hasAuthorizationList,
        String json) {

    public TransactionArgs {
        java.util.Objects.requireNonNull(data, "data");
        java.util.Objects.requireNonNull(json, "json");
    }

    /**
     * Whether the object carries anything beyond {@code from}/{@code to}/
     * {@code data}/{@code value} that an engine could APPLY: {@code gas}, a fee
     * field, either list — or a {@code nonce} on a contract creation, whose
     * address it decides. ({@code chainId} and {@code type} are the host's to
     * check — see the class docs.)
     */
    public boolean hasExtendedFields() {
        return gas != null || gasPriceWei != null || maxFeePerGasWei != null
                || maxPriorityFeePerGasWei != null || hasAccessList || hasAuthorizationList
                || (to == null && nonce != null);
    }
}
