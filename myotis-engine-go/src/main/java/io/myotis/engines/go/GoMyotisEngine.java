package io.myotis.engines.go;

import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.api.NetworkInfo;
import io.myotis.api.NetworkMetering;
import io.myotis.api.ports.EnginePorts;
import io.myotis.engines.common.LoopbackRpc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The GO engine behind the {@link MyotisEngine} contract, via {@link GoEngineNative}
 * — step 1 of the owner's program (embed the Go engine in the desktop host,
 * 2026-11). Selectable via {@code myotis.engine=go}; {@code auto} never picks it
 * (the Rust engine stays the auto choice until the engine-parity step).
 *
 * <p>The network CATALOG is answered from the Go binary, and it lists only what
 * the Go build can RUN — MAINNET for now; the multichain step lands Gnosis (the
 * Bee direction). The entry itself equals the golden's
 * ({@code rust/testdata/networks_catalog.json}, pinned both sides by
 * {@code TestCatalogMatchesGolden} here and {@code GoCatalogParityTest} on the
 * JVM side), and the canonical NAME table still knows all four catalog names +
 * the gbc/xdai aliases exactly like the Rust one — so a create for gnosis
 * canonicalizes cleanly and is then refused as not-runnable with a named
 * {@link EngineException}, rather than silently serving the wrong chain.
 *
 * <p>The twin of {@code RustMyotisEngine} in structure: catalog + create/get/stop/
 * shutdownAll + process-global metering and DNS-discovery switches, and each
 * handle gets its loopback listener from the host's {@link LoopbackRpc.Factory}
 * (the selector passes the Ktor one; the listener port lives in
 * :myotis-engine-common so this module never depends on :myotis-engine-rust).
 */
public final class GoMyotisEngine implements MyotisEngine {
    private static final Logger log = LoggerFactory.getLogger(GoMyotisEngine.class);

    /** The DNS-discovery value the last {@code create} pushed: -1 none yet, 0 off, 1 on. */
    private static final AtomicInteger DNS_DISCOVERY = new AtomicInteger(-1);

    /** Networks this engine currently hosts, keyed by canonical name. */
    private final Map<String, GoChainHandle> hosted = new ConcurrentHashMap<>();

    /** Builds each handle's loopback listener, or null: no listener. */
    private final LoopbackRpc.Factory rpcFactory;

    /** True when libmyotis_engine_go loaded and passed the ABI handshake. */
    public static boolean isAvailable() {
        return GoEngineNative.isAvailable();
    }

    /**
     * Drain up to {@code max} buffered Go-engine tracing lines (oldest first,
     * newline-joined; empty when idle or when the library is not available). The
     * observability seam hosts pump into their own log pipeline (via
     * {@code Engines.drainRustLogs}, which drains both native rings); never throws.
     */
    public static String drainLogs(int max) {
        if (!GoEngineNative.isAvailable()) return "";
        try {
            String batch = GoEngineNative.nativeDrainLogs(max);
            return batch != null ? normalizeForHostPumps(batch) : "";
        } catch (Throwable t) {
            return ""; // observability must never take the host down
        }
    }

    /**
     * Rewrite the Go ring's slog lines into the level-first shape the hosts'
     * log pumps classify by ({@code startsWith("ERROR")}/{@code "WARN")} in
     * {@code app}'s Main and the desktop's DesktopNode — the Rust tracing
     * format's shape (PR #832 review). A raw slog line starts with
     * {@code time=… level=WARN msg=…}, so every Go WARN and ERROR used to fall
     * through the pumps' else-branch to INFO — dropping exactly the refusal and
     * stall lines of the engine under test from a level-filtered view.
     *
     * <p>{@code "<LEVEL> go <original line>"}: level first for the classifier,
     * a {@code go} marker because the pumps print their own {@code rust} label
     * (their wording predates this engine and the hosts are not touched here),
     * and the original line intact after it — the slog fields stay greppable.
     * A line with no parsable level gets INFO (the slog default) rather than
     * being dropped.
     */
    static String normalizeForHostPumps(String batch) {
        StringBuilder out = new StringBuilder(batch.length() + 32);
        for (String line : batch.split("\n", -1)) {
            if (!line.isEmpty()) {
                out.append(levelFirst(line)).append('\n');
            }
        }
        if (out.length() > 0) out.setLength(out.length() - 1); // no trailing newline
        return out.toString();
    }

    private static String levelFirst(String line) {
        // slog TextHandler writes `time=<RFC3339> level=<lvl> msg=… k=v …`;
        // the RFC3339 timestamp carries no spaces, so a token scan is exact.
        String level = "INFO";
        for (String tok : line.split(" ")) {
            if (tok.startsWith("level=")) {
                level = tok.substring("level=".length()).toUpperCase(java.util.Locale.ROOT);
                break;
            }
        }
        return level + " go " + line;
    }

    /** @throws EngineException when libmyotis_engine_go is not available on this host */
    public GoMyotisEngine() {
        this(null);
    }

    /**
     * Public because the selector ({@code :myotis-engines}) constructs it from
     * another module — same standing as {@code RustMyotisEngine}. Host composition
     * roots still go through {@code Engines.engine()} (CLAUDE.md).
     *
     * @param rpcFactory builds the loopback JSON-RPC listener each {@link #create}
     *        attaches to its handle; null attaches none
     * @throws EngineException when libmyotis_engine_go is not available on this host
     */
    public GoMyotisEngine(LoopbackRpc.Factory rpcFactory) {
        this.rpcFactory = rpcFactory;
        if (!GoEngineNative.isAvailable()) {
            throw new EngineException("libmyotis_engine_go is not available on this host");
        }
    }

    @Override
    public List<NetworkInfo> availableNetworks() {
        String json = GoEngineNative.nativeAvailableNetworksJson();
        if (json == null) throw new EngineException("Go engine returned no network catalog");
        return parseNetworks(json);
    }

    /** Parse the catalog JSON — the same 9-key NetworkInfo schema as the Rust
     *  engine's (golden {@code rust/testdata/networks_catalog.json}, shared). */
    static List<NetworkInfo> parseNetworks(String json) {
        try {
            com.eclipsesource.json.JsonArray arr = com.eclipsesource.json.Json.parse(json).asArray();
            List<NetworkInfo> out = new ArrayList<>(arr.size());
            for (com.eclipsesource.json.JsonValue v : arr) {
                com.eclipsesource.json.JsonObject o = v.asObject();
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
            throw new EngineException("malformed network catalog JSON from the Go engine: "
                    + e.getMessage(), e);
        }
    }

    @Override
    public String canonicalNetworkName(String nameOrAlias) {
        if (nameOrAlias == null) throw new EngineException("network name is required");
        String canonical = GoEngineNative.nativeCanonicalNetworkName(nameOrAlias);
        if (canonical == null) {
            // Same message shape as the Java/Rust engines (the Go catalog table
            // mirrors catalog.rs: these four names + the gbc/xdai aliases).
            throw new EngineException("Unknown network: " + nameOrAlias
                    + ". Supported: mainnet, sepolia, gnosis, chiado");
        }
        return canonical;
    }

    /** The catalog entry for a canonical name, or null when unknown. */
    private NetworkInfo networkInfo(String canonical) {
        if (canonical == null) return null;
        for (NetworkInfo n : availableNetworks()) {
            if (canonical.equals(n.name())) return n;
        }
        return null;
    }

    // create/stop/shutdownAll synchronized for the same reason as the Rust twin:
    // the multi-step create (nativeCreate → putIfAbsent) and teardown must be
    // mutually exclusive with shutdownAll, or a racing create orphans a running
    // native host.
    @Override
    public synchronized ChainHandle create(EngineConfig config, EnginePorts ports) {
        if (config == null) throw new EngineException("engine config is required");
        String canonical = canonicalNetworkName(config.networkName());
        NetworkInfo net = networkInfo(canonical);
        if (net == null) {
            // canonicalNetworkName succeeded but the catalog (which lists only
            // what the Go build can RUN — mainnet for now) lacks it: this is the
            // known-but-not-runnable refusal the class doc promises, NOT an
            // unknown name (the canonical table knows all four).
            throw new EngineException("the Go engine does not host " + canonical
                    + " yet (mainnet-only until the multichain step)");
        }
        // The host's listener BEFORE the native handle: a throwing factory must not
        // leak a running Go network host (goroutines + UDP listeners).
        LoopbackRpc rpc = rpcFactory != null ? rpcFactory.create() : null;
        long id = GoEngineNative.nativeCreate(canonical, config.dataDir());
        if (id == GoEngineNative.UNSUPPORTED_NETWORK) {
            // The same refusal as above: by construction the catalog-only
            // create makes this unreachable today (the catalog is what Go's
            // Create can run); it stays as the drift guard for the multichain
            // step, when a catalog entry could out-land its Create pins.
            throw new EngineException("the Go engine does not host " + canonical
                    + " yet (mainnet-only until the multichain step)");
        }
        if (id < 0) {
            throw new EngineException("the Go engine could not initialize the runtime"
                    + " or create the dataDir for " + canonical
                    + " (empty dataDir and a dataDir held by another live handle are refused)");
        }
        // EIP-1459 DNS discovery: same process-global switch as the Rust engine,
        // but the Go build's walk has NO off-switch yet (go/internal/capi pins
        // system-resolver discovery and reports the state IN FORCE in the
        // return value, precisely so this call site can see the refusal). So the
        // EFFECTIVE state — never the requested one — is what gets recorded and
        // an `off` request is surfaced, not silently stored (apply-or-refuse,
        // #314). Today's routing (desktop, always `on`) never hits the refusal;
        // a host that brings a DnsServers port must not believe its servers are
        // consulted on this engine.
        boolean requested = ports == null || ports.dnsServers() == null;
        boolean effective = GoEngineNative.nativeSetDnsDiscovery(requested);
        if (effective != requested) {
            log.warn("[engines] the Go engine keeps EIP-1459 DNS discovery {} (its walk has no"
                    + " switch yet): a host expecting system-resolver discovery to be off does"
                    + " NOT get that on this engine", effective ? "on" : "off");
        }
        int previous = DNS_DISCOVERY.getAndSet(effective ? 1 : 0);
        if (previous >= 0 && (previous == 1) != effective) {
            log.warn("[engines] the create of {} switched EIP-1459 DNS discovery {} for every"
                    + " hosted network: the switch is process-global and the last create wins",
                    canonical, effective ? "on" : "off");
        }
        // Honour a host-supplied RPC port, else the network's catalog default.
        int rpcPort = config.rpcPort() > 0 ? config.rpcPort() : net.defaultRpcPort();
        // The catalog's CL slot clock rides along: it is what makes the status's
        // verifiedHeadAgeMs the anchor's TRUE age, not the age of the last tick
        // (PR #832 review; see GoChainHandle's slot-clock comment).
        GoChainHandle handle = new GoChainHandle(id, canonical, net.chainId(), rpcPort, rpc,
                net.clGenesisTime(), net.secondsPerSlot());
        // Atomic claim (Rust-twin parity): reject a re-create rather than orphan the
        // previous handle's native entry; release ours on a lost race.
        if (hosted.putIfAbsent(canonical, handle) != null) {
            GoEngineNative.nativeStop(id);
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
        GoChainHandle handle = hosted.remove(networkName);
        if (handle != null) handle.stop();
    }

    @Override
    public synchronized void shutdownAll() {
        for (String name : new ArrayList<>(hosted.keySet())) {
            stop(name);
        }
    }

    /** Process-global in the native engine (it is the device's network); the codes
     *  are the Go capi's Metering values, identical to the Rust usage::Metering. */
    @Override
    public void setNetworkMetering(NetworkMetering metering) {
        if (metering == null) throw new EngineException("metering is required");
        int code = switch (metering) {
            case UNKNOWN -> 0;
            case UNMETERED -> 1;
            case METERED -> 2;
        };
        if (!GoEngineNative.nativeSetNetworkMetering(code)) {
            throw new EngineException("the Go engine refused network metering " + metering);
        }
    }

    @Override
    public NetworkMetering networkMetering() {
        return meteringOf(GoEngineNative.nativeNetworkMetering());
    }

    /** A native metering code → the API enum; unknown reads as UNKNOWN (display-only). */
    static NetworkMetering meteringOf(int code) {
        return switch (code) {
            case 1 -> NetworkMetering.UNMETERED;
            case 2 -> NetworkMetering.METERED;
            default -> NetworkMetering.UNKNOWN;
        };
    }
}
