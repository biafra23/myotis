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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The Rust engine behind the {@link MyotisEngine} contract, via {@link RustEngineNative}.
 *
 * <p>R1 (current stage): the network CATALOG is answered from Rust
 * ({@link #availableNetworks()}, {@link #canonicalNetworkName}) AND the engine can HOST
 * mainnet — {@link #create} returns a {@link RustChainHandle} driving the Rust
 * light-client sync loop. R1 is CL-only + mainnet-only: any other (still-canonical)
 * network is rejected with a named {@link EngineException}, on which the selector's
 * {@code auto} mode falls back to the Java engine. The EL surface (verified reads,
 * proofs) lands later.
 */
public final class RustMyotisEngine implements MyotisEngine {

    /** Networks this engine currently hosts, keyed by canonical name. */
    private final Map<String, RustChainHandle> hosted = new ConcurrentHashMap<>();

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

    // create/stop/shutdownAll are synchronized so lifecycle transitions are mutually
    // exclusive: without it, a create() racing shutdownAll() could publish a fresh
    // native handle AFTER shutdownAll finished iterating, orphaning a running tokio/
    // libp2p host. The ConcurrentHashMap ops are individually atomic, but the
    // multi-step create (nativeCreate → putIfAbsent) and teardown are not. These are
    // cold lifecycle paths, so the coarse lock costs nothing. (synchronized is
    // reentrant, so shutdownAll → stop() on the same thread is fine.)
    @Override
    public synchronized ChainHandle create(EngineConfig config, EnginePorts ports) {
        if (config == null) throw new EngineException("engine config is required");
        String canonical = canonicalNetworkName(config.networkName());
        if (!"mainnet".equals(canonical)) {
            // R1 hosts mainnet only; auto mode falls back to Java on this.
            throw new EngineException("the R1 Rust engine hosts mainnet only (got: "
                    + canonical + ")");
        }
        long id = RustEngineNative.nativeCreate(canonical, config.dataDir());
        if (id < 0) {
            // On this path the network is always mainnet (checked above), so id < 0
            // means the Rust runtime could not initialize. Named so auto mode falls back.
            throw new EngineException("the Rust engine could not initialize the runtime for "
                    + canonical);
        }
        // Mirror JavaMyotisEngine: honour a host-supplied RPC port, else the
        // mainnet default (8545). The Rust engine hosts mainnet only, so the
        // per-network default is a constant here.
        int rpcPort = config.rpcPort() > 0 ? config.rpcPort() : 8545;
        RustChainHandle handle = new RustChainHandle(id, canonical, 1L, rpcPort);
        // Atomic claim (mirrors JavaMyotisEngine.putIfAbsent): reject a re-create rather
        // than orphaning the previous handle's native entry. On a lost race, release the
        // native handle we just allocated so it doesn't leak a tokio/libp2p host.
        if (hosted.putIfAbsent(canonical, handle) != null) {
            RustEngineNative.nativeStop(id);
            throw new EngineException("network already hosted: " + canonical);
        }
        return handle;
    }

    @Override
    public ChainHandle get(String networkName) {
        return hosted.get(networkName);
    }

    @Override
    public List<String> hostedNetworks() {
        return new ArrayList<>(hosted.keySet());
    }

    @Override
    public synchronized void stop(String networkName) {
        RustChainHandle handle = hosted.remove(networkName);
        if (handle != null) handle.stop();
    }

    @Override
    public synchronized void shutdownAll() {
        for (String name : new ArrayList<>(hosted.keySet())) {
            stop(name);
        }
    }
}
