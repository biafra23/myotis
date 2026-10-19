package io.myotis.engines.rust;

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
 * that gateway failing; ONE round per resolution step
 * ({@code MAX_RECURSION_DEPTH = 1}) — a second OffchainLookup from a step's own
 * callback is an error.
 *
 * <p>A reverse lookup has two steps, each a call of its own on the Java engine
 * (its depth counter is per callView): reading the claimed name, and
 * forward-verifying it. Either may resolve off chain. An envelope whose round
 * is the FORWARD check carries {@code reverseClaim} (ABI 49), which this
 * driver echoes into the callback so the native side reads the answer as the
 * claimed name's address rather than as a claim — without it, an on-chain
 * claim with an off-chain forward record (a {@code *.cb.id} primary name)
 * decoded the address as a name and reported no primary name. The forward
 * check gets a round of its own, so an off-chain claim forward-verified off
 * chain takes two rounds, as on the Java engine; it is entered once, and a
 * further OffchainLookup in it hits the cap.
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
        // Rounds driven in the current step; the forward check of a reverse
        // claim is a step of its own, entered at most once.
        int round = 0;
        boolean forwardCheck = false;
        while (true) {
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
            // Echoed, never dropped: without it the callback reads the forward
            // check's answer as the claim.
            String reverseClaim = o.get("reverseClaim") == null ? null
                    : requireString(o, "reverseClaim");
            if (reverseClaim != null && !forwardCheck) {
                forwardCheck = true;
                round = 0;
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
            if (reverseClaim != null) {
                cb.add("reverseClaim", reverseClaim);
            }
            round++;
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
                // Odd-length hex can never decode (Java parity: parseHex throws
                // inside the per-URL loop) — record and try the NEXT url rather
                // than letting the native reject it after failover is gone.
                if (dataHex.length() % 2 != 0) {
                    reasons.add("odd-length data hex from " + template);
                    continue;
                }
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
        // regionMatches(ignoreCase) scans in place — no lowercase copy of a
        // potentially multi-MB L2-proof response.
        for (int i = 0; i + needle.length() <= bare.length(); i += 2) {
            if (bare.regionMatches(true, i, needle, 0, needle.length())) {
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
