package io.myotis.evm.ccipread;

import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ERC-3668 (CCIP-Read) gateway handler.
 *
 * <p><strong>Phase 4 deliverable.</strong> The class is implemented as a
 * standalone unit so the OffchainLookup parser is exercised under tests; the
 * wiring into {@link io.myotis.evm.DefaultEvmExecutor#callView} happens in
 * Phase 4 once the recursion and re-entry semantics are settled.
 *
 * <p><strong>HTTP client TODO (Android compat).</strong> This class currently
 * uses {@code java.net.http.HttpClient} for the JVM Phase-4 prototype. That
 * package is API 33+ on Android and is <em>not</em> in the
 * {@code coreLibraryDesugaring} set, so it would crash at runtime on
 * {@code minSdk = 29} devices. Per {@code CLAUDE.md}'s "Platform & language
 * direction" section, the production HTTP client must be Ktor (works on
 * Android and is Compose-Multiplatform-ready). Swap before Phase 4 lands or
 * before this module is wired into {@code :android-app}.
 *
 * <p>Execution path per spec:
 * <ol>
 *   <li>EVM reverts with {@link OffchainLookupRevert#SELECTOR}.
 *   <li>For each URL in {@code urls}, attempt the gateway request:
 *       GET if the URL contains a {@code {data}} placeholder body, POST otherwise.
 *   <li>Parse the JSON {@code {"data": "0x..."}} response.
 *   <li>The first URL that returns 200 wins; on all-failure, propagate
 *       {@link EvmExecutionError.CcipGatewayFailed}.
 *   <li>Re-enter the EVM with {@code callbackFunction(response, extraData)}
 *       targeted at {@code sender}. Recursion is capped at depth 1 (plan-mandated).
 * </ol>
 *
 * <p>Privacy note: gateway calls leak the user's IP and the queried name to
 * the gateway operator. Tor routing is a future TODO.
 */
public final class CcipReadHandler {

    /** Plan-mandated cap. Spec allows nesting; real resolvers don't need it. */
    public static final int MAX_RECURSION_DEPTH = 1;

    private static final Pattern SENDER_PLACEHOLDER = Pattern.compile("\\{sender\\}");
    private static final Pattern DATA_PLACEHOLDER   = Pattern.compile("\\{data\\}");
    private static final Pattern DATA_FIELD_RE      = Pattern.compile("\"data\"\\s*:\\s*\"(0x[0-9a-fA-F]*)\"");

    private final HttpClient client;
    private final Duration perGatewayTimeout;

    public CcipReadHandler(HttpClient client, Duration perGatewayTimeout) {
        this.client = client;
        this.perGatewayTimeout = perGatewayTimeout;
    }

    public CcipReadHandler() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
                Duration.ofSeconds(10));
    }

    /**
     * Try each URL in order. Returns the {@code data} bytes from the first
     * gateway that responds with a 200 and a parseable body. Throws
     * {@link EvmExecutionException} wrapping {@link EvmExecutionError.CcipGatewayFailed}
     * if every URL fails.
     */
    public byte[] handle(OffchainLookupRevert lookup) {
        List<String> reasons = new ArrayList<>(lookup.urls().size());
        for (String urlTemplate : lookup.urls()) {
            try {
                byte[] response = tryUrl(urlTemplate, lookup);
                if (response != null) return response;
                reasons.add("non-200 or unparseable response from " + urlTemplate);
            } catch (Exception e) {
                reasons.add(urlTemplate + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
        throw new EvmExecutionException(
                new EvmExecutionError.CcipGatewayFailed(List.copyOf(lookup.urls()), List.copyOf(reasons)));
    }

    private byte[] tryUrl(String urlTemplate, OffchainLookupRevert lookup) throws IOException, InterruptedException {
        String senderHex = lookup.sender().toHex();
        String dataHex = "0x" + HexFormat.of().formatHex(lookup.callData());
        String substituted = SENDER_PLACEHOLDER.matcher(urlTemplate).replaceAll(Matcher.quoteReplacement(senderHex));
        boolean hasDataPlaceholder = DATA_PLACEHOLDER.matcher(substituted).find();
        substituted = DATA_PLACEHOLDER.matcher(substituted).replaceAll(Matcher.quoteReplacement(dataHex));

        HttpRequest request;
        if (hasDataPlaceholder) {
            // GET — both placeholders were embedded directly in the URL.
            request = HttpRequest.newBuilder(URI.create(substituted))
                    .timeout(perGatewayTimeout)
                    .header("Accept", "application/json")
                    .GET().build();
        } else {
            // POST — the gateway expects a JSON body with sender/data.
            String body = "{\"sender\":\"" + senderHex + "\",\"data\":\"" + dataHex + "\"}";
            request = HttpRequest.newBuilder(URI.create(substituted))
                    .timeout(perGatewayTimeout)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
        }

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) return null;
        return parseDataField(response.body());
    }

    /** Returns the bytes hex-encoded under {@code data}, or null if absent. */
    static byte[] parseDataField(String json) {
        Matcher m = DATA_FIELD_RE.matcher(json);
        if (!m.find()) return null;
        String hex = m.group(1);
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.isEmpty()) return new byte[0];
        return HexFormat.of().parseHex(hex);
    }
}
