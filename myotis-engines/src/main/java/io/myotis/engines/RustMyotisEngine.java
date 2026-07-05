package io.myotis.engines;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.api.NetworkInfo;
import io.myotis.api.ports.EnginePorts;

import java.util.ArrayList;
import java.util.List;

/**
 * The Rust engine behind the {@link MyotisEngine} contract, via {@link RustEngineNative}.
 *
 * <p>R0 (current stage): the network CATALOG is answered from Rust —
 * {@link #availableNetworks()} and {@link #canonicalNetworkName} are real; hosting is not
 * implemented yet, so {@link #create} fails with a named {@link EngineException} (the
 * selector's {@code auto} mode falls back to the Java engine on that failure). Hosting
 * arrives with the Rust consensus crate (plan PRs 4–6).
 */
public final class RustMyotisEngine implements MyotisEngine {

    /** True when libmyotis_engine loaded and passed the ABI handshake. */
    public static boolean isAvailable() {
        return RustEngineNative.isAvailable();
    }

    RustMyotisEngine() {
        if (!RustEngineNative.isAvailable()) {
            throw new EngineException("libmyotis_engine is not available on this host");
        }
    }

    @Override
    public List<NetworkInfo> availableNetworks() {
        String json = RustEngineNative.nativeAvailableNetworksJson();
        if (json == null) throw new EngineException("Rust engine returned no network catalog");
        return parseNetworks(json);
    }

    /**
     * Parse the catalog JSON (a JSON array of camelCase NetworkInfo objects — the schema
     * pinned by rust/testdata/networks_catalog.json and the golden tests on both sides).
     */
    static List<NetworkInfo> parseNetworks(String json) {
        try {
            JsonArray arr = Json.parse(json).asArray();
            List<NetworkInfo> out = new ArrayList<>(arr.size());
            for (JsonValue v : arr) {
                JsonObject o = v.asObject();
                out.add(new NetworkInfo(
                        o.get("name").asString(),
                        o.get("displayName").asString(),
                        o.get("chainId").asLong(),
                        o.get("hasEns").asBoolean(),
                        o.get("defaultElPort").asInt(),
                        o.get("defaultDiscv5Port").asInt(),
                        o.get("defaultRpcPort").asInt(),
                        o.get("clGenesisTime").asLong(),
                        o.get("secondsPerSlot").asInt()));
            }
            return out;
        } catch (RuntimeException e) {
            throw new EngineException("malformed network catalog JSON from the Rust engine: "
                    + e.getMessage(), e);
        }
    }

    @Override
    public String canonicalNetworkName(String nameOrAlias) {
        if (nameOrAlias == null) throw new EngineException("network name is required");
        String canonical = RustEngineNative.nativeCanonicalNetworkName(nameOrAlias);
        if (canonical == null) {
            // Mirrors the Java engine's message shape (NetworkConfig.byName).
            throw new EngineException("Unknown network: " + nameOrAlias
                    + ". Supported: mainnet, sepolia, gnosis");
        }
        return canonical;
    }

    @Override
    public ChainHandle create(EngineConfig config, EnginePorts ports) {
        throw new EngineException("the Rust engine cannot host networks yet (R0: catalog only)"
                + " — use myotis.engine=java, or auto to fall back automatically");
    }

    @Override
    public ChainHandle get(String networkName) {
        return null;
    }

    @Override
    public List<String> hostedNetworks() {
        return List.of();
    }

    @Override
    public void stop(String networkName) {
        // nothing hosted in R0
    }

    @Override
    public void shutdownAll() {
        // nothing hosted in R0
    }
}
