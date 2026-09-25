package io.myotis.engines;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import io.myotis.api.EngineException;
import io.myotis.api.EnsAbiResult;
import io.myotis.api.EnsApi;
import io.myotis.api.EnsContenthashResult;
import io.myotis.api.EnsDnsRecordResult;
import io.myotis.api.EnsInterfaceResult;
import io.myotis.api.EnsMultiCoinResult;
import io.myotis.api.EnsPubkeyResult;
import io.myotis.api.EnsResolutionResult;
import io.myotis.api.EnsRoot;
import io.myotis.api.EnsTextResult;

/**
 * The Rust engine's {@link EnsApi}: every record type is served by the native
 * resolver (registry walk + ENSIP-10 dispatch over verified eth_calls) through
 * ONE generic dispatch native ({@code nativeEnsRecordJson}) — forward address,
 * text, contenthash, multi-coin, pubkey, ABI, dnsRecord, interfaceImplementer,
 * and reverse resolution with mandatory forward-verify (EL-C-5-2). CCIP-Read
 * (ERC-3668, EL-C-5-3) is driven host-side: the native resolver surfaces the
 * OffchainLookup tuple, {@link CcipDriver} performs the gateway round over the
 * {@link io.myotis.api.ports.HttpGateway} port, and the callback re-enters the
 * native resolver as a verified eth_call. Without a configured gateway (or on
 * an unparseable tuple) an offchain name reports a descriptive error,
 * distinguishable from "no record".
 *
 * <p>Roots: {@code resolveAddress} honors the caller's {@link EnsRoot} —
 * FINALIZED resolves against the beacon-FINALIZED execution root and fails
 * closed; AUTO tries finalized first and falls back to the beacon-anchored
 * optimistic head; PEER_HEAD maps to the optimistic head (this engine has no
 * peer-claimed-head mode — its fallback is beacon-anchored, strictly stronger).
 * All other record lookups and reverse hardcode AUTO, mirroring JavaEnsApi.
 * {@code verified} in results = "resolved against the finalized root".
 *
 * <p>Deliberate divergence from {@code JavaEnsApi}: that impl throws
 * {@link EngineException} for not-running / malformed-input states (per the
 * EnsApi javadoc), while this one folds EVERY failure — including not-running
 * and bad arguments — into the record's {@code error}. The native layer reports
 * not-running as an error JSON, and distinguishing it by message string would
 * be brittle; IPC consumers handle both shapes identically.
 */
final class RustEnsApi implements EnsApi {

    /**
     * The error for an offchain name that CCIP could NOT be driven for: the
     * OffchainLookup tuple didn't parse (the driver only acts on a full tuple)
     * — or a stale native returned offchain without one.
     */
    private static final String OFFCHAIN =
            "name resolves offchain (ERC-3668) but the OffchainLookup was not actionable";

    private final RustChainHandle handle;

    RustEnsApi(RustChainHandle handle) {
        this.handle = handle;
    }

    // ---- forward address (root-aware) ----

    @Override
    public EnsResolutionResult resolveAddress(String name, EnsRoot root) {
        if (name == null || name.isBlank()) {
            return new EnsResolutionResult(name, null, -1, false, "empty ENS name");
        }
        try {
            JsonObject params = params("addr").add("name", name).add("root", rootParam(root));
            return addressFromJson(name, exec(params));
        } catch (RuntimeException e) {
            return new EnsResolutionResult(name, null, -1, false, why(e));
        }
    }

    /** Package-private JSON seam: record JSON → forward-resolution result. */
    static EnsResolutionResult addressFromJson(String name, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            case "ok" -> new EnsResolutionResult(
                    name, p.requireString("addressHex"), p.block, p.verified, null);
            case "noRecord" -> new EnsResolutionResult(name, null, p.block, p.verified, null);
            case "offchain" -> new EnsResolutionResult(name, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    // ---- reverse (forward-verified by the native side) ----

    @Override
    public EnsResolutionResult reverseResolve(String hexAddress) {
        String bare = normalizeAddress(hexAddress);
        if (bare == null) {
            // JavaEnsApi throws this message; this impl folds it (class javadoc).
            return new EnsResolutionResult(null, hexAddress, -1, false,
                    "address must be a 20-byte hex string (40 hex chars)");
        }
        String canonical = "0x" + bare;
        try {
            JsonObject params = params("reverse").add("addressHex", canonical);
            return reverseFromJson(canonical, exec(params));
        } catch (RuntimeException e) {
            return new EnsResolutionResult(null, canonical, -1, false, why(e));
        }
    }

    /** Package-private JSON seam: record JSON → reverse-resolution result. */
    static EnsResolutionResult reverseFromJson(String addressHex, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            // The name is forward-verified on the native side; an empty record,
            // no reverse resolver, and a failed verify are all "noRecord"
            // (Java parity — indistinguishable, no special error token).
            case "ok" -> new EnsResolutionResult(
                    p.requireString("name"), addressHex, p.block, p.verified, null);
            case "noRecord" -> new EnsResolutionResult(null, addressHex, p.block, p.verified, null);
            case "offchain" -> new EnsResolutionResult(null, addressHex, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    // ---- record types (AUTO root, JavaEnsApi parity) ----

    @Override
    public EnsTextResult resolveText(String name, String key) {
        if (name == null || name.isBlank()) {
            return new EnsTextResult(name, key, null, -1, false, "empty ENS name");
        }
        if (key == null || key.isBlank()) {
            return new EnsTextResult(name, key, null, -1, false, "empty text key");
        }
        try {
            JsonObject params = params("text").add("name", name).add("key", key);
            return textFromJson(name, key, exec(params));
        } catch (RuntimeException e) {
            return new EnsTextResult(name, key, null, -1, false, why(e));
        }
    }

    static EnsTextResult textFromJson(String name, String key, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            case "ok" -> new EnsTextResult(
                    name, key, p.requireString("value"), p.block, p.verified, null);
            case "noRecord" -> new EnsTextResult(name, key, null, p.block, p.verified, null);
            case "offchain" -> new EnsTextResult(name, key, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    @Override
    public EnsContenthashResult resolveContenthash(String name) {
        if (name == null || name.isBlank()) {
            return new EnsContenthashResult(name, null, -1, false, "empty ENS name");
        }
        try {
            JsonObject params = params("contenthash").add("name", name);
            return contenthashFromJson(name, exec(params));
        } catch (RuntimeException e) {
            return new EnsContenthashResult(name, null, -1, false, why(e));
        }
    }

    static EnsContenthashResult contenthashFromJson(String name, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            case "ok" -> new EnsContenthashResult(
                    name, p.requireString("dataHex"), p.block, p.verified, null);
            case "noRecord" -> new EnsContenthashResult(name, null, p.block, p.verified, null);
            case "offchain" -> new EnsContenthashResult(name, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    @Override
    public EnsMultiCoinResult resolveMultiCoinAddr(String name, long coinType) {
        if (name == null || name.isBlank()) {
            return new EnsMultiCoinResult(name, coinType, null, -1, false, "empty ENS name");
        }
        if (coinType < 0) {
            return new EnsMultiCoinResult(name, coinType, null, -1, false, "negative coinType");
        }
        try {
            JsonObject params = params("multicoin").add("name", name).add("coinType", coinType);
            return multiCoinFromJson(name, coinType, exec(params));
        } catch (RuntimeException e) {
            return new EnsMultiCoinResult(name, coinType, null, -1, false, why(e));
        }
    }

    static EnsMultiCoinResult multiCoinFromJson(String name, long coinType, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            case "ok" -> new EnsMultiCoinResult(
                    name, coinType, p.requireString("dataHex"), p.block, p.verified, null);
            case "noRecord" -> new EnsMultiCoinResult(name, coinType, null, p.block, p.verified, null);
            case "offchain" -> new EnsMultiCoinResult(
                    name, coinType, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    @Override
    public EnsPubkeyResult resolvePubkey(String name) {
        if (name == null || name.isBlank()) {
            return new EnsPubkeyResult(name, null, null, -1, false, "empty ENS name");
        }
        try {
            JsonObject params = params("pubkey").add("name", name);
            return pubkeyFromJson(name, exec(params));
        } catch (RuntimeException e) {
            return new EnsPubkeyResult(name, null, null, -1, false, why(e));
        }
    }

    static EnsPubkeyResult pubkeyFromJson(String name, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            case "ok" -> new EnsPubkeyResult(name, p.requireString("pubkeyXHex"),
                    p.requireString("pubkeyYHex"), p.block, p.verified, null);
            case "noRecord" -> new EnsPubkeyResult(name, null, null, p.block, p.verified, null);
            case "offchain" -> new EnsPubkeyResult(name, null, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    @Override
    public EnsAbiResult resolveAbi(String name, long contentTypes) {
        if (name == null || name.isBlank()) {
            return new EnsAbiResult(name, 0, null, -1, false, "empty ENS name");
        }
        if (contentTypes < 0) {
            return new EnsAbiResult(name, 0, null, -1, false, "negative contentTypes mask");
        }
        try {
            JsonObject params = params("abi").add("name", name).add("contentTypes", contentTypes);
            return abiFromJson(name, exec(params));
        } catch (RuntimeException e) {
            return new EnsAbiResult(name, 0, null, -1, false, why(e));
        }
    }

    static EnsAbiResult abiFromJson(String name, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            // contentType=0 when absent — JavaEnsApi parity.
            case "ok" -> new EnsAbiResult(name, p.requireLong("contentType"),
                    p.requireString("dataHex"), p.block, p.verified, null);
            case "noRecord" -> new EnsAbiResult(name, 0, null, p.block, p.verified, null);
            case "offchain" -> new EnsAbiResult(name, 0, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    @Override
    public EnsDnsRecordResult resolveDnsRecord(String name, String dnsName, int recordType) {
        if (name == null || name.isBlank()) {
            return new EnsDnsRecordResult(
                    name, dnsName, recordType, null, -1, false, "empty ENS name");
        }
        if (dnsName == null || dnsName.isBlank()) {
            return new EnsDnsRecordResult(
                    name, dnsName, recordType, null, -1, false, "empty DNS name");
        }
        if (recordType < 0 || recordType > 0xFFFF) {
            return new EnsDnsRecordResult(name, dnsName, recordType, null, -1, false,
                    "recordType out of range (uint16)");
        }
        try {
            JsonObject params = params("dnsRecord")
                    .add("name", name).add("dnsName", dnsName).add("resource", recordType);
            return dnsRecordFromJson(
                    name, dnsName, recordType, exec(params));
        } catch (RuntimeException e) {
            return new EnsDnsRecordResult(name, dnsName, recordType, null, -1, false, why(e));
        }
    }

    static EnsDnsRecordResult dnsRecordFromJson(
            String name, String dnsName, int recordType, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            case "ok" -> new EnsDnsRecordResult(
                    name, dnsName, recordType, p.requireString("dataHex"), p.block, p.verified, null);
            case "noRecord" -> new EnsDnsRecordResult(
                    name, dnsName, recordType, null, p.block, p.verified, null);
            case "offchain" -> new EnsDnsRecordResult(
                    name, dnsName, recordType, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    @Override
    public EnsInterfaceResult resolveInterfaceImplementer(String name, byte[] interfaceId4) {
        // Echo the queried id like JavaEnsApi does; a malformed id is its own error
        // result (this impl never throws).
        if (interfaceId4 == null || interfaceId4.length != 4) {
            return new EnsInterfaceResult(name, null, null, -1, false,
                    "interfaceId must be exactly 4 bytes");
        }
        String idHex = com.jaeckel.ethp2p.core.encoding.Hex.formatHexPrefixed(interfaceId4);
        if (name == null || name.isBlank()) {
            return new EnsInterfaceResult(name, idHex, null, -1, false, "empty ENS name");
        }
        try {
            JsonObject params = params("interfaceImplementer")
                    .add("name", name).add("interfaceIdHex", idHex);
            return interfaceFromJson(name, idHex, exec(params));
        } catch (RuntimeException e) {
            return new EnsInterfaceResult(name, idHex, null, -1, false, why(e));
        }
    }

    static EnsInterfaceResult interfaceFromJson(String name, String idHex, String json) {
        Parsed p = Parsed.of(json);
        return switch (p.status) {
            case "ok" -> new EnsInterfaceResult(
                    name, idHex, p.requireString("addressHex"), p.block, p.verified, null);
            case "noRecord" -> new EnsInterfaceResult(name, idHex, null, p.block, p.verified, null);
            case "offchain" -> new EnsInterfaceResult(name, idHex, null, p.block, p.verified, OFFCHAIN);
            default -> throw p.unknownStatus();
        };
    }

    // ---- plumbing ----

    /**
     * One native record query + any CCIP-Read rounds it demands (EL-C-5-3):
     * an offchain answer with a parsed tuple drives the HttpGateway via
     * {@link CcipDriver} and re-enters the native callback path; everything
     * else passes straight through to the record parsers.
     */
    private String exec(JsonObject params) {
        String json = handle.ensRecordJson(params.toString());
        return CcipDriver.drive(params, json, handle.httpGateway(),
                p -> handle.ensRecordJson(p));
    }

    private static JsonObject params(String method) {
        return Json.object().add("method", method);
    }

    private static String rootParam(EnsRoot root) {
        if (root == null) {
            return "auto";
        }
        return switch (root) {
            case AUTO -> "auto";
            case FINALIZED -> "finalized";
            // This engine has no peer-claimed-head mode; PEER_HEAD maps to the
            // beacon-anchored optimistic head (strictly stronger, same "don't
            // wait for finality" intent).
            case PEER_HEAD -> "optimistic";
        };
    }

    /** Lowercase bare 40-hex form of an address input, or null when malformed. */
    private static String normalizeAddress(String hexAddress) {
        if (hexAddress == null) {
            return null;
        }
        String bare = hexAddress.startsWith("0x") || hexAddress.startsWith("0X")
                ? hexAddress.substring(2) : hexAddress;
        if (bare.length() != 40 || !bare.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
            return null;
        }
        return bare.toLowerCase(java.util.Locale.ROOT);
    }

    private static String why(RuntimeException e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }

    /**
     * The pinned envelope of every record JSON: status + blockNumber + verified
     * (all mandatory — a missing one is native shape drift and fails closed as
     * an {@link EngineException}, which the public methods fold into the
     * result's error).
     */
    private record Parsed(JsonObject o, String status, long block, boolean verified) {
        static Parsed of(String json) {
            if (json == null || json.isBlank()) {
                throw new EngineException((json == null ? "null" : "blank")
                        + " ens-record JSON from the Rust engine (native failure?)");
            }
            JsonObject o;
            try {
                o = Json.parse(json).asObject();
            } catch (RuntimeException e) {
                throw new EngineException(
                        "malformed ens-record JSON from the Rust engine: " + e.getMessage(), e);
            }
            var error = o.get("error");
            if (error != null && !error.isNull()) {
                throw new EngineException(error.isString() ? error.asString() : error.toString());
            }
            try {
                var status = o.get("status");
                var bn = o.get("blockNumber");
                var verified = o.get("verified");
                if (status == null || bn == null || bn.isNull() || verified == null) {
                    throw new EngineException(
                            "ens-record JSON: missing status/blockNumber/verified");
                }
                return new Parsed(o, status.asString(), bn.asLong(), verified.asBoolean());
            } catch (EngineException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new EngineException(
                        "malformed ens-record JSON from the Rust engine: " + e.getMessage(), e);
            }
        }

        /**
         * A mandatory string value field — absence is shape drift, fail closed.
         * Only EMPTINESS is drift (the Rust side never emits an empty value):
         * a whitespace-only text record is legitimate on-chain data and must
         * pass through, so no isBlank() here.
         */
        String requireString(String key) {
            var v = o.get(key);
            if (v == null || v.isNull() || !v.isString() || v.asString().isEmpty()) {
                throw new EngineException("ens-record JSON: status=ok without " + key);
            }
            return v.asString();
        }

        /** A mandatory numeric value field — absence is shape drift, fail closed. */
        long requireLong(String key) {
            var v = o.get(key);
            if (v == null || v.isNull()) {
                throw new EngineException("ens-record JSON: status=ok without " + key);
            }
            try {
                return v.asLong();
            } catch (RuntimeException e) {
                throw new EngineException("ens-record JSON: non-numeric " + key, e);
            }
        }

        EngineException unknownStatus() {
            return new EngineException("ens-record JSON: unknown status '" + status + "'");
        }
    }
}
