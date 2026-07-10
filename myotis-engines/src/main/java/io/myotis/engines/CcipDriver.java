package io.myotis.engines;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import io.myotis.api.EngineException;
import io.myotis.api.ports.HttpGateway;
import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The host half of CCIP-Read (ERC-3668) for the Rust engine (EL-C-5-3): the
 * native resolver reports {@code status:"offchain"} with the decoded
 * OffchainLookup tuple; this drives the HTTP gateway round (the engine's ONLY
 * HTTP, via the {@link HttpGateway} port) and re-enters the native resolver
 * with {@code method:"ccipCallback"} so the callback runs as a verified
 * eth_call and the answer is decoded with the original record semantics.
 *
 * <p>Java-engine parity ({@code CcipReadHandler}/{@code CcipReadEvmExecutor}):
 * URLs tried SERIALLY, first parseable body wins; GET iff the template contains
 * {@code {data}} (detected before substitution), else POST with
 * {@code {"sender":"0x..","data":"0x.."}}; the response's {@code data} field is
 * extracted with a lenient regex, not a JSON parser; response data containing
 * the {@code HttpError} selector {@code 0xca7a4e75} at any offset counts as
 * that gateway failing; ONE round only ({@code MAX_RECURSION_DEPTH = 1}) — a
 * second OffchainLookup from the callback is an error.
 *
 * <p>Failures throw {@link EngineException}; {@link RustEnsApi} folds them into
 * the result's error field (it never throws).
 */
final class CcipDriver {

    /** Java {@code CcipReadHandler.MAX_RECURSION_DEPTH} twin. */
    static final int MAX_ROUNDS = 1;

    /** Lenient {@code "data":"0x…"} extraction — Java parity (not a JSON parser). */
    private static final Pattern DATA_FIELD =
            Pattern.compile("\"data\"\\s*:\\s*\"(0x[0-9a-fA-F]*)\"");

    private CcipDriver() {
    }

    /**
     * Drive CCIP rounds until the record JSON is not an offchain-with-tuple
     * marker. Returns the final record JSON (which may still be a plain
     * {@code offchain} without tuple fields — the parsers report that as the
     * descriptive offchain error). {@code nativeCall} is the ccipCallback
     * transport seam (the real one calls {@code nativeEnsRecordJson}).
     */
    static String drive(JsonObject originalParams, String json, HttpGateway gateway,
            UnaryOperator<String> nativeCall) {
        for (int round = 0; ; round++) {
            JsonValue parsed;
            try {
                parsed = Json.parse(json);
            } catch (RuntimeException e) {
                return json; // let the record parsers fail closed on it
            }
            if (!parsed.isObject()) {
                return json;
            }
            JsonObject o = parsed.asObject();
            var status = o.get("status");
            var sender = o.get("senderHex");
            if (o.get("error") != null || status == null || !status.isString()
                    || !"offchain".equals(status.asString())
                    || sender == null || !sender.isString()) {
                // Not an actionable offchain marker (includes the unparseable-
                // tuple case: offchain without senderHex) — hand it back.
                return json;
            }
            if (gateway == null) {
                throw new EngineException(
                        "name resolves offchain (ERC-3668) and no CCIP-Read HTTP gateway"
                        + " is configured on this host");
            }
            if (round >= MAX_ROUNDS) {
                // Java parity message shape (CcipReadEvmExecutor's cap).
                throw new EngineException(
                        "CCIP-Read recursion depth " + MAX_ROUNDS + " exceeds cap " + MAX_ROUNDS);
            }
            String senderHex = sender.asString();
            String callDataHex = requireString(o, "callDataHex");
            String callbackHex = requireString(o, "callbackFunctionHex");
            String extraDataHex = requireString(o, "extraDataHex");
            List<String> urls = new ArrayList<>();
            var urlsVal = o.get("urls");
            if (urlsVal != null && urlsVal.isArray()) {
                urlsVal.asArray().forEach(u -> {
                    if (u.isString()) {
                        urls.add(u.asString());
                    }
                });
            }
            String responseHex = fetch(gateway, senderHex, callDataHex, urls);

            JsonObject cb = Json.object();
            for (String name : originalParams.names()) {
                cb.add(name, originalParams.get(name));
            }
            cb.set("method", "ccipCallback");
            cb.add("queryMethod", originalParams.getString("method", ""));
            cb.add("senderHex", senderHex);
            cb.add("callbackFunctionHex", callbackHex);
            cb.add("responseHex", responseHex);
            cb.add("extraDataHex", extraDataHex);
            cb.add("wrapped", o.getBoolean("wrapped", false));
            // The callback must run against the same root kind the offchain
            // attempt did (verified == finalized in the record envelope).
            cb.add("finalized", o.getBoolean("verified", false));
            json = nativeCall.apply(cb.toString());
        }
    }

    /**
     * Try the gateway URLs serially; return the first parseable {@code data}
     * payload. Throws {@link EngineException} with per-URL reasons when all
     * fail (Java {@code CcipGatewayFailed} shape).
     */
    private static String fetch(HttpGateway gateway, String senderHex, String callDataHex,
            List<String> urls) {
        if (urls.isEmpty()) {
            throw new EngineException("CCIP-Read gateway failed: OffchainLookup carried no URLs");
        }
        List<String> reasons = new ArrayList<>();
        for (String template : urls) {
            try {
                // GET iff the template consumes the data inline — decided
                // BEFORE substitution (Java parity).
                boolean get = template.contains("{data}");
                String url = template.replace("{sender}", senderHex)
                        .replace("{data}", callDataHex);
                String body = get ? null
                        : "{\"sender\":\"" + senderHex + "\",\"data\":\"" + callDataHex + "\"}";
                String response = gateway.request(
                        get ? HttpGateway.Method.GET : HttpGateway.Method.POST, url, body);
                Matcher m = response == null ? null : DATA_FIELD.matcher(response);
                if (m == null || !m.find()) {
                    reasons.add("non-200 or unparseable response from " + template);
                    continue;
                }
                String dataHex = m.group(1);
                if (containsHttpError(dataHex)) {
                    reasons.add("gateway HttpError from " + template);
                    continue;
                }
                return dataHex;
            } catch (RuntimeException e) {
                reasons.add(template + ": " + e.getClass().getSimpleName()
                        + (e.getMessage() != null ? ": " + e.getMessage() : ""));
            }
        }
        throw new EngineException("CCIP-Read gateway failed: " + String.join("; ", reasons));
    }

    /**
     * The batch-gateway {@code HttpError} selector {@code 0xca7a4e75} at ANY
     * even hex offset in the response data (Java's substring scan over the
     * decoded bytes — scanning the hex at even offsets is byte-equivalent).
     */
    private static boolean containsHttpError(String dataHex) {
        String bare = dataHex.startsWith("0x") ? dataHex.substring(2) : dataHex;
        String needle = "ca7a4e75";
        String lower = bare.toLowerCase(java.util.Locale.ROOT);
        for (int i = 0; i + needle.length() <= lower.length(); i += 2) {
            if (lower.startsWith(needle, i)) {
                return true;
            }
        }
        return false;
    }

    private static String requireString(JsonObject o, String key) {
        var v = o.get(key);
        if (v == null || !v.isString()) {
            throw new EngineException("offchain JSON: missing " + key);
        }
        return v.asString();
    }
}
