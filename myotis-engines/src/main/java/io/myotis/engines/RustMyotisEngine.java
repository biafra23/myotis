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
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Rust engine behind the {@link MyotisEngine} contract, via {@link RustEngineNative}.
 *
 * <p>The network CATALOG is answered from Rust ({@link #availableNetworks()},
 * {@link #canonicalNetworkName}) and the engine HOSTS mainnet, Sepolia and Gnosis —
 * {@link #create} returns a {@link RustChainHandle} driving the Rust light-client sync
 * loop and EL reader, with the verified reads, the EVM, ENS, the log index and the
 * rest of the engine surface behind it. A network the Rust catalog does not know is
 * rejected with a named {@link EngineException}, on which the selector's {@code auto}
 * mode falls back to the Java engine; the one thing this engine refuses by design is
 * resuming a data dir bound to a caller-supplied checkpoint ({@link AnchorMismatchException}).
 */
public final class RustMyotisEngine implements MyotisEngine {
    private static final Logger log = LoggerFactory.getLogger(RustMyotisEngine.class);

    /** The DNS-discovery value the last {@code create} pushed: -1 none yet, 0 off, 1 on. */
    private static final AtomicInteger DNS_DISCOVERY = new AtomicInteger(-1);


    /** A create() refused because the dataDir belongs to a caller-supplied checkpoint
     *  generation (native {@code ANCHOR_MISMATCH}). Distinct from a generic
     *  {@link EngineException} so {@link SelectorEngine}'s auto mode rethrows it instead
     *  of falling back to the Java engine on the same directory. */
    static final class AnchorMismatchException extends EngineException {
        AnchorMismatchException(String message) { super(message); }
    }

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
    /** The catalog entry for a canonical name, or null when unknown. */
    private NetworkInfo networkInfo(String canonical) {
        if (canonical == null) return null;
        for (NetworkInfo n : availableNetworks()) {
            if (canonical.equals(n.name())) return n;
        }
        return null;
    }

    @Override
    public synchronized ChainHandle create(EngineConfig config, EnginePorts ports) {
        if (config == null) throw new EngineException("engine config is required");
        String canonical = canonicalNetworkName(config.networkName());
        NetworkInfo net = networkInfo(canonical);
        if (net == null) {
            throw new EngineException("unknown network: " + config.networkName());
        }
        // The native side is the single source of truth for which networks it
        // hosts: nativeCreate returns UNSUPPORTED_NETWORK for a canonical network
        // whose Rust config hasn't landed yet, and auto mode falls back to Java
        // on the exception.
        long id = RustEngineNative.nativeCreate(canonical, config.dataDir());
        if (id == RustEngineNative.UNSUPPORTED_NETWORK) {
            throw new EngineException(
                    "the Rust engine does not host " + canonical + " yet");
        }
        if (id == RustEngineNative.ANCHOR_MISMATCH) {
            // Not a fallback signal: the directory holds verified state that descends
            // from a checkpoint the host supplied to the plain-C/Node engine, and the
            // Java engine would resume that snapshot under the embedded anchor —
            // exactly the silent trust-anchor swap -3 exists to refuse.
            throw new AnchorMismatchException(
                    "dataDir " + config.dataDir() + " is bound to a caller-supplied checkpoint"
                    + " (sync-anchor" + ("mainnet".equals(canonical) ? "" : "-" + canonical)
                    + ".json); the JVM hosts cannot resume it — use a fresh dataDir, or the"
                    + " Node/C-ABI host that created it");
        }
        if (id < 0) {
            throw new EngineException("the Rust engine could not initialize the runtime"
                    + " or create the dataDir for " + canonical);
        }
        // EIP-1459 DNS discovery (#539, part 3). The DnsServers port's contract is
        // "no port → the resolver's default", and the system resolver is what the
        // Rust walk uses, so a host without the port (desktop, daemon) gets DNS
        // discovery. A host that supplies servers (Android, the active network's)
        // wants THOSE used, and the Rust engine has no port for them yet — it
        // stays off there, as on iOS, which never calls this. The engine skips the
        // walk under Tor on its own. The switch is PROCESS-GLOBAL and the last
        // create wins for every network already running, so a host must hand the
        // same kind of ports to each network it hosts (today's hosts do); a create
        // that flips an already-set value is logged rather than guessed about.
        boolean dnsDiscovery = ports == null || ports.dnsServers() == null;
        int previous = DNS_DISCOVERY.getAndSet(dnsDiscovery ? 1 : 0);
        if (previous >= 0 && (previous == 1) != dnsDiscovery) {
            log.warn("[engines] the create of {} switched EIP-1459 DNS discovery {} for every"
                    + " hosted network: the switch is process-global and the last create wins",
                    canonical, dnsDiscovery ? "on" : "off");
        }
        RustEngineNative.nativeSetDnsDiscovery(dnsDiscovery);
        // Mirror JavaMyotisEngine: honour a host-supplied RPC port, else the
        // network's catalog default (mainnet 8545, sepolia 8547, ...).
        int rpcPort = config.rpcPort() > 0 ? config.rpcPort() : net.defaultRpcPort();
        RustChainHandle handle = new RustChainHandle(id, canonical, net.chainId(), rpcPort,
                net.hasEns(), ports != null ? ports.httpGateway() : null);
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
