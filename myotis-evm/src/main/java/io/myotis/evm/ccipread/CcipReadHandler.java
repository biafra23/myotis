package io.myotis.evm.ccipread;

import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ERC-3668 (CCIP-Read) gateway handler.
 *
 * <p>When the EVM reverts with the {@code OffchainLookup} selector, the
 * executor calls {@link #handle} with the parsed revert; this class
 * iterates the listed URLs, performs the gateway request via the supplied
 * {@link CcipGateway} transport (URL template substitution, GET/POST
 * routing per spec), and returns the response bytes for the executor to
 * pass into the contract's callback function.
 *
 * <p>Execution path per ERC-3668 §6:
 * <ol>
 *   <li>EVM reverts with {@link OffchainLookupRevert#SELECTOR}.
 *   <li>For each URL in {@code urls}, attempt the gateway request:
 *       GET if the URL contains both {@code {sender}} and {@code {data}}
 *       placeholders, POST otherwise.
 *   <li>Parse the JSON {@code {"data": "0x..."}} response.
 *   <li>The first URL that returns a parseable body wins; on all-failure,
 *       throw {@link EvmExecutionError.CcipGatewayFailed}.
 *   <li>The executor re-enters the EVM with
 *       {@code callbackFunction(response, extraData)} targeted at
 *       {@code sender}. Recursion is capped at depth 1 (plan-mandated).
 * </ol>
 *
 * <p><strong>Privacy note.</strong> Gateway calls necessarily reveal:
 * the user's IP address, the queried name (encoded in {@code callData}),
 * and approximate request timing. Tor or Mixnet routing of these requests
 * is a future privacy improvement tracked separately.
 */
public final class CcipReadHandler {

    /** Plan-mandated cap. The spec allows nesting; real resolvers don't need it. */
    public static final int MAX_RECURSION_DEPTH = 1;

    private static final Pattern SENDER_PLACEHOLDER = Pattern.compile("\\{sender\\}");
    private static final Pattern DATA_PLACEHOLDER   = Pattern.compile("\\{data\\}");
    private static final Pattern DATA_FIELD_RE      = Pattern.compile("\"data\"\\s*:\\s*\"(0x[0-9a-fA-F]*)\"");

    private final CcipGateway gateway;

    public CcipReadHandler(CcipGateway gateway) {
        this.gateway = gateway;
    }

    /**
     * Try each URL in order. Returns the {@code data} bytes from the first
     * gateway that responds with a parseable body. Throws
     * {@link EvmExecutionException} wrapping
     * {@link EvmExecutionError.CcipGatewayFailed} if every URL fails.
     */
    public byte[] handle(OffchainLookupRevert lookup) {
        List<String> reasons = new ArrayList<>(lookup.urls().size());
        for (String urlTemplate : lookup.urls()) {
            try {
                byte[] response = tryUrl(urlTemplate, lookup);
                if (response != null) return response;
                reasons.add("non-200 or unparseable response from " + urlTemplate);
            } catch (Exception e) {
                Throwable cause = e instanceof CompletionException && e.getCause() != null
                        ? e.getCause() : e;
                reasons.add(urlTemplate + ": " + cause.getClass().getSimpleName()
                        + ": " + cause.getMessage());
            }
        }
        throw new EvmExecutionException(
                new EvmExecutionError.CcipGatewayFailed(
                        List.copyOf(lookup.urls()), List.copyOf(reasons)));
    }

    private byte[] tryUrl(String urlTemplate, OffchainLookupRevert lookup) {
        String senderHex = lookup.sender().toHex();
        String dataHex = "0x" + HexFormat.of().formatHex(lookup.callData());

        // ERC-3668 §6.1: route is GET if the URL template contains {data}
        // (so the entire request fits in the path/query), POST otherwise.
        // Detection happens BEFORE substitution because once substituted
        // the placeholder is gone.
        boolean hasDataPlaceholder = DATA_PLACEHOLDER.matcher(urlTemplate).find();

        String substituted = SENDER_PLACEHOLDER.matcher(urlTemplate)
                .replaceAll(Matcher.quoteReplacement(senderHex));
        substituted = DATA_PLACEHOLDER.matcher(substituted)
                .replaceAll(Matcher.quoteReplacement(dataHex));

        CcipGateway.Method method = hasDataPlaceholder
                ? CcipGateway.Method.GET : CcipGateway.Method.POST;
        String body = method == CcipGateway.Method.POST
                ? "{\"sender\":\"" + senderHex + "\",\"data\":\"" + dataHex + "\"}"
                : null;

        String responseBody = gateway.request(method, substituted, body).join();
        if (responseBody == null) return null;
        return parseDataField(responseBody);
    }

    /** Returns the bytes hex-encoded under {@code data}, or null if absent. */
    static byte[] parseDataField(String json) {
        if (json == null) return null;
        Matcher m = DATA_FIELD_RE.matcher(json);
        if (!m.find()) return null;
        String hex = m.group(1);
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.isEmpty()) return new byte[0];
        return HexFormat.of().parseHex(hex);
    }
}
