package io.myotis.evm.ccipread;

import com.jaeckel.ethp2p.core.concurrent.Futures;
import com.jaeckel.ethp2p.core.encoding.Hex;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ERC-3668 (CCIP-Read) gateway handler.
 *
 * <p>When the EVM reverts with the {@code OffchainLookup} selector, the
 * executor calls {@link #handle} with the parsed revert; this class
 * iterates the listed URLs <strong>serially</strong> and asynchronously,
 * performing each gateway request via the supplied {@link CcipGateway}
 * transport (URL template substitution, GET/POST routing per spec) until
 * one succeeds, then completes the returned future with the response
 * bytes for the executor to pass into the contract's callback function.
 *
 * <p>Execution path per ERC-3668 §6:
 * <ol>
 *   <li>EVM reverts with {@link OffchainLookupRevert#SELECTOR}.
 *   <li>For each URL in {@code urls}, attempt the gateway request:
 *       GET if the URL template contains a {@code {data}} placeholder
 *       (so the call fits in the URL), POST otherwise. Per ERC-3668 §6.1.
 *   <li>Parse the JSON {@code {"data": "0x..."}} response.
 *   <li>The first URL that returns a parseable body wins; on all-failure,
 *       the future fails with {@link EvmExecutionError.CcipGatewayFailed}.
 *   <li>The executor re-enters the EVM with
 *       {@code callbackFunction(response, extraData)} targeted at
 *       {@code sender}. Recursion is capped at depth 1 (plan-mandated).
 * </ol>
 *
 * <p><strong>Async by contract.</strong> {@link #handle} returns a
 * {@link CompletableFuture} so the caller (the {@code CcipReadEvmExecutor}
 * decorator) can chain via {@code thenCompose} without blocking the EVM
 * thread on network IO. Earlier drafts used {@code .join()} which tied up
 * the executor thread pool and risked deadlock if the gateway impl
 * completed on the same pool.
 *
 * <p>URLs are tried <strong>serially</strong>, not in parallel, because the
 * spec wants the first listed URL to win when it can — failing over only
 * if it actually fails. Parallel fan-out would mask diagnostic information
 * about specific gateway problems and increase peer load.
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
     * Try each URL serially until one returns a parseable body. The
     * returned future completes with that body's {@code data} bytes, or
     * fails with {@link EvmExecutionException} wrapping
     * {@link EvmExecutionError.CcipGatewayFailed} if every URL fails.
     */
    public CompletableFuture<byte[]> handle(OffchainLookupRevert lookup) {
        return tryUrlsSerially(lookup, 0, new ArrayList<>(lookup.urls().size()));
    }

    private CompletableFuture<byte[]> tryUrlsSerially(
            OffchainLookupRevert lookup, int idx, List<String> reasons) {
        if (idx >= lookup.urls().size()) {
            return Futures.failedFuture(new EvmExecutionException(
                    new EvmExecutionError.CcipGatewayFailed(
                            List.copyOf(lookup.urls()), List.copyOf(reasons))));
        }
        String urlTemplate = lookup.urls().get(idx);
        // One decision point on THIS url's outcome, with the fallback recursion
        // outside it: wrapping the recursion in the failure handler (the previous
        // shape) replayed the remaining url list once per level — up to 2^n gateway
        // requests on an all-failing list instead of n.
        return tryUrlAsync(urlTemplate, lookup).handle((response, t) -> {
            if (t != null) {
                Throwable cause = unwrap(t);
                reasons.add(urlTemplate + ": " + cause.getClass().getSimpleName()
                        + ": " + cause.getMessage());
                return tryUrlsSerially(lookup, idx + 1, reasons);
            }
            if (response != null) {
                return CompletableFuture.completedFuture(response);
            }
            reasons.add("non-200 or unparseable response from " + urlTemplate);
            return tryUrlsSerially(lookup, idx + 1, reasons);
        }).thenCompose(Function.identity());
    }

    private CompletableFuture<byte[]> tryUrlAsync(String urlTemplate, OffchainLookupRevert lookup) {
        String senderHex = lookup.sender().toHex();
        String dataHex = Hex.formatHexPrefixed(lookup.callData());

        // ERC-3668 §6.1: route is GET if the URL template contains {data}
        // (so the entire request fits in the path/query), POST otherwise.
        // Detection happens BEFORE substitution because once substituted the
        // placeholder is gone.
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

        return gateway.request(method, substituted, body)
                .thenApply(CcipReadHandler::parseDataField)
                .thenApply(CcipReadHandler::rejectGatewayHttpError);
    }

    /** ERC-7884 {@code HttpError(uint16,string)} selector — gateways wrap upstream
     *  HTTP failures (rate limits, 5xx) in this even when the transport returns
     *  200. Treat it as a gateway failure, not a valid "no record" answer. */
    private static final byte[] HTTP_ERROR_SELECTOR = {(byte) 0xca, (byte) 0x7a, (byte) 0x4e, (byte) 0x75};

    /**
     * If the gateway body encodes an {@code HttpError} (e.g. a proxied 429 "Too
     * Many Requests" or a 5xx), throw so {@link #tryUrlsSerially} records it and
     * fails over / surfaces a transient gateway error — rather than passing the
     * error blob to the resolver callback, which would silently decode it to an
     * empty record and look like "name does not resolve". Otherwise pass the
     * response through unchanged.
     */
    private static byte[] rejectGatewayHttpError(byte[] data) {
        if (data == null || indexOf(data, HTTP_ERROR_SELECTOR) < 0) return data;
        // The HttpError carries a uint16 status and a string, but both are nested
        // inside the gateway's batch wrapper at offsets that are awkward to parse
        // robustly; the human-readable message ("Too Many Requests", "Bad
        // Gateway", …) is the reliable signal, so surface that.
        String message = scanAsciiMessage(data);
        throw new java.util.concurrent.CompletionException(new java.io.IOException(
                "gateway HttpError" + (message.isEmpty() ? "" : ": " + message)));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    /** Longest run of printable ASCII (>= 4 chars) in the blob — the error text. */
    private static String scanAsciiMessage(byte[] data) {
        String best = "";
        StringBuilder cur = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xff;
            if (c >= 0x20 && c <= 0x7e) {
                cur.append((char) c);
            } else {
                if (cur.length() > best.length()) best = cur.toString();
                cur.setLength(0);
            }
        }
        if (cur.length() > best.length()) best = cur.toString();
        return best.length() >= 4 ? best.trim() : "";
    }

    /** Returns the bytes hex-encoded under {@code data}, or null if absent. */
    static byte[] parseDataField(String json) {
        if (json == null) return null;
        Matcher m = DATA_FIELD_RE.matcher(json);
        if (!m.find()) return null;
        String hex = m.group(1);
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.isEmpty()) return new byte[0];
        return Hex.parseHex(hex);
    }

    private static Throwable unwrap(Throwable t) {
        while (t instanceof CompletionException && t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }
}
