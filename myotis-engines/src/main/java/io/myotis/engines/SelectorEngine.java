package io.myotis.engines;

import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.api.NetworkInfo;
import io.myotis.api.NetworkMetering;
import io.myotis.api.ports.EnginePorts;
import io.myotis.engines.go.GoMyotisEngine;
import io.myotis.engines.rust.RustMyotisEngine;
import io.myotis.node.api.JavaMyotisEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link MyotisEngine} that routes to the Java, Rust, or Go engine per the
 * current {@link Engines} choice: {@code create()} goes to the engine the choice resolves to
 * <em>at that moment</em>; {@code get}/{@code stop} go to whichever engine owns the
 * network (recorded at create); {@code shutdownAll} fans out to all three.
 * The Go engine is reachable only through the explicit {@code go} choice —
 * {@code auto} resolves between Rust and Java alone (the Go engine is
 * desktop-only until it reaches parity).
 *
 * <p>{@code auto} semantics: prefer Rust, and fall back to Java WITH A LOG when the
 * Rust engine is unavailable or its {@code create} fails (in R0 it always does — the
 * Rust engine is catalog-only until the consensus crate lands). An explicit
 * {@code rust} choice never falls back: failures propagate as {@link EngineException}
 * so a user who forced Rust sees why it didn't run.
 */
public final class SelectorEngine implements MyotisEngine {

    private static final Logger log = LoggerFactory.getLogger(SelectorEngine.class);

    private final JavaMyotisEngine java = new JavaMyotisEngine();
    /** Lazily built: constructing it requires the native library to be loadable. */
    private volatile RustMyotisEngine rust;
    /** Lazily built, same reason; the Go engine is only ever reached via the
     *  explicit {@code go} choice (auto never routes to it — Rust stays the
     *  auto engine until the Go engine reaches parity). */
    private volatile GoMyotisEngine go;
    /** Which engine owns each hosted network (recorded when create() succeeds). */
    private final Map<String, MyotisEngine> owners = new ConcurrentHashMap<>();

    SelectorEngine() {}

    /**
     * The underlying Java engine, for hosts' DOCUMENTED debug exemptions only (the
     * daemon's {@code get-transactions} stream takes {@code JavaMyotisEngine.debugStack}
     * at the composition root). Not part of {@link MyotisEngine} — features built on
     * this do not survive an engine swap.
     */
    public JavaMyotisEngine javaDelegate() {
        return java;
    }

    private RustMyotisEngine rustEngine() {
        RustMyotisEngine r = rust;
        if (r == null) {
            synchronized (this) {
                // The JVM hosts' loopback JSON-RPC listener rides with the selector: the
                // engine module itself ships none (LoopbackRpc).
                if (rust == null) rust = new RustMyotisEngine(KtorLoopbackRpc::new);
                r = rust;
            }
        }
        return r;
    }

    private GoMyotisEngine goEngine() {
        GoMyotisEngine g = go;
        if (g == null) {
            synchronized (this) {
                // The same host-side listener the Rust handles get — LoopbackRpc
                // is the shared port (it lives in :myotis-engine-common precisely
                // so the Go engine needs no dependency on the Rust module).
                if (go == null) {
                    go = new GoMyotisEngine(KtorLoopbackRpc::new);
                    // Built LATE (a metering push never builds it — see
                    // setNetworkMetering): seed the device's current metering
                    // before this engine's first network counts a byte, or the
                    // first Go-hosted network would run under the default.
                    try {
                        go.setNetworkMetering(java.networkMetering());
                    } catch (RuntimeException | LinkageError e) {
                        log.warn("[engines] could not seed the Go engine's metering "
                                + "({}); it keeps the library default", e.toString());
                    }
                }
                g = go;
            }
        }
        return g;
    }

    /**
     * The {@link Engines#drainRustLogs} routing decision, kept here because it
     * needs the lazy engine fields: touch a native ring ONLY where this
     * selector actually runs that engine. Probing {@code GoMyotisEngine.drainLogs}
     * class-loads the Go binding and maps its library, so under auto/rust/java
     * (where auto never routes to Go) the Go ring is drained only once a Go
     * engine exists here — i.e. a Go network was or is hosted (PR #832 review).
     */
    String drainNativeLogs(int max) {
        // The java choice has no native ring (unchanged rule); rust keeps its
        // existing semantics, incl. a rust network surviving a later flip.
        String rust = "java".equals(Engines.choice()) ? "" : RustMyotisEngine.drainLogs(max);
        GoMyotisEngine g = go;
        String go = (g != null || "go".equals(Engines.choice()))
                ? GoMyotisEngine.drainLogs(max) : "";
        if (rust.isEmpty()) return go;
        if (go.isEmpty()) return rust;
        return rust + "\n" + go;
    }

    /** The engine that should answer catalog queries / receive create() right now. */
    private MyotisEngine resolve() {
        return resolveFor(Engines.choice());
    }

    private MyotisEngine resolveFor(String choice) {
        return switch (choice) {
            case "rust" -> {
                if (!RustMyotisEngine.isAvailable()) {
                    throw new EngineException("myotis.engine=rust but libmyotis_engine is not "
                            + "available on this host (not built, not on java.library.path, or "
                            + "failed the ABI handshake)");
                }
                yield rustEngine();
            }
            case "go" -> {
                if (!GoMyotisEngine.isAvailable()) {
                    throw new EngineException("myotis.engine=go but libmyotis_engine_go is not "
                            + "available on this host (not built via goBuildCShared, not on "
                            + "java.library.path, or failed the ABI handshake)");
                }
                yield goEngine();
            }
            case "auto" -> {
                if (RustMyotisEngine.isAvailable()) yield rustEngine();
                log.info("[engines] auto: Rust engine unavailable, using the Java engine");
                yield java;
            }
            default -> java;
        };
    }

    @Override
    public List<NetworkInfo> availableNetworks() {
        return resolve().availableNetworks();
    }

    @Override
    public String canonicalNetworkName(String nameOrAlias) {
        return resolve().canonicalNetworkName(nameOrAlias);
    }

    @Override
    public synchronized ChainHandle create(EngineConfig config, EnginePorts ports) {
        // synchronized: the cross-engine duplicate check below is check-then-act —
        // without the lock, two concurrent creates racing a settings flip could
        // host the same network on BOTH engines (each engine's own putIfAbsent
        // guard only covers its own registry). Creates are rare and fast (start()
        // is the slow part), so the coarse lock costs nothing.
        // Read the choice ONCE: a concurrent select() between resolving the target and
        // deciding fallback behavior must not turn an in-flight auto-create into a hard
        // failure (or vice versa).
        String choice = Engines.choice();
        if (!"rust".equals(choice) && !"go".equals(choice)) return createFor(choice, config, ports);
        // An explicit native choice (rust or go): never a fallback, and every
        // failure must arrive as the EngineException this class promises.
        // Resolving the engine, canonicalizing the name and creating the network
        // all cross the native boundary, so a LinkageError from any of them is
        // wrapped here instead of taking the host process down. Android below
        // API 33 runs on the rust path by default (no Java engine there).
        try {
            return createFor(choice, config, ports);
        } catch (LinkageError e) {
            throw new EngineException(choice + " engine failed to link while creating "
                    + config.networkName() + ": " + e, e);
        }
    }

    /** The create path for one already-read {@code choice}; runs under {@link #create}'s lock. */
    private ChainHandle createFor(String choice, EngineConfig config, EnginePorts ports) {
        MyotisEngine target = resolveFor(choice);
        // Cross-engine duplicate guard, BEFORE any create attempt: each engine
        // self-checks only its OWN registry, so without this a choice flip between two
        // creates could host the same network on both engines — the older stack would
        // leak, unreachable via get/stop. Checked here (not inside the try) so an
        // already-hosted error propagates instead of triggering a pointless fallback
        // that would fail the same way. (Canonical names are parity-tested identical
        // across engines, so the name survives a fallback target switch.)
        String canonical = target.canonicalNetworkName(config.networkName());
        if (get(canonical) != null) {
            throw new EngineException("network already hosted: " + canonical);
        }
        if (target != java && "auto".equals(choice)) {
            // auto: a Rust create() failure is a fallback signal, not an error. This
            // double-create is only safe while a failed Rust create() has no side
            // effects — the Rust engine must keep create() all-or-nothing (R0 throws
            // before doing anything; the real implementation must preserve that).
            // LinkageError too (UnsatisfiedLinkError / stale-.so symbol drift): the
            // candidate engine must never take hosting down with it. Deliberately NOT
            // Throwable — OOM/StackOverflow should not be masked as a fallback.
            try {
                return createOn(target, canonical, config, ports);
            } catch (RustMyotisEngine.AnchorMismatchException e) {
                // The dataDir is bound to a checkpoint the host supplied to the
                // Rust engine (Node/C-ABI path). Falling back would let the Java
                // engine resume that snapshot under the EMBEDDED anchor — the
                // silent trust-anchor swap the refusal exists to prevent.
                throw e;
            } catch (EngineException | LinkageError e) {
                log.warn("[engines] auto: Rust engine create({}) failed ({}); "
                        + "falling back to the Java engine", config.networkName(), e.getMessage());
                target = java;
            }
        }
        return createOn(target, canonical, config, ports);
    }

    private ChainHandle createOn(MyotisEngine target, String canonical,
                                 EngineConfig config, EnginePorts ports) {
        ChainHandle handle = target.create(config, ports);
        // Record ownership under the canonical name so get/stop (which hosts call with
        // canonical names) route to the right engine.
        owners.put(canonical, target);
        return handle;
    }

    /**
     * Which engine hosts {@code networkName} right now: {@code "java"}, {@code "rust"},
     * {@code "go"}, or {@code null} when the network isn't hosted. Display-only (the
     * Status screen's engine badge) — routing stays on {@link #owners} via get/stop.
     */
    String ownerKind(String networkName) {
        if (networkName == null) return null;
        MyotisEngine owner = owners.get(networkName);
        if (owner == null) {
            // Callers pass canonical names (host snapshots carry them), but tolerate
            // an alias. Best-effort only: canonicalNetworkName throws on unknown
            // names, and a display accessor must never throw.
            try {
                owner = owners.get(java.canonicalNetworkName(networkName));
            } catch (EngineException e) {
                return null;
            }
        }
        if (owner == null) return null;
        if (owner instanceof RustMyotisEngine) return "rust";
        if (owner instanceof GoMyotisEngine) return "go";
        return "java";
    }

    @Override
    public ChainHandle get(String networkName) {
        MyotisEngine owner = owners.get(networkName);
        return owner != null ? owner.get(networkName) : null;
    }

    @Override
    public List<String> hostedNetworks() {
        // Owners map can momentarily lead/lag the engines during create/stop; ask the
        // engines themselves for the authoritative list.
        List<String> out = new ArrayList<>(java.hostedNetworks());
        RustMyotisEngine r = rust;
        if (r != null) {
            for (String n : r.hostedNetworks()) {
                if (!out.contains(n)) out.add(n);
            }
        }
        GoMyotisEngine g = go;
        if (g != null) {
            for (String n : g.hostedNetworks()) {
                if (!out.contains(n)) out.add(n);
            }
        }
        return out;
    }

    @Override
    public void stop(String networkName) {
        MyotisEngine owner = owners.remove(networkName);
        if (owner != null) {
            owner.stop(networkName);
        } else {
            // Unknown owner (e.g. stop() raced create()): fan out — stop() is a no-op
            // on an engine that doesn't host the network.
            java.stop(networkName);
            RustMyotisEngine r = rust;
            if (r != null) r.stop(networkName);
            GoMyotisEngine g = go;
            if (g != null) g.stop(networkName);
        }
    }

    @Override
    public void shutdownAll() {
        owners.clear();
        java.shutdownAll();
        RustMyotisEngine r = rust;
        if (r != null) r.shutdownAll();
        GoMyotisEngine g = go;
        if (g != null) g.shutdownAll();
    }

    /** Every engine that RUNS here hears it (Java, Rust, and Go once a Go
     *  engine exists): a network created later on any one must count
     *  under the device's current metering from its first byte. The native
     *  engines first: {@link #networkMetering()} reads the Java one, so a Rust
     *  or Go failure leaves it reporting the OLD value and a host that pushes
     *  only on a change retries. Go is pushed only when ALREADY built —
     *  probing/building it here would map libmyotis_engine_go on hosts whose
     *  choice never routes to it (PR #832 review); a Go engine built later is
     *  seeded with this value by {@link #goEngine()}. */
    @Override
    public void setNetworkMetering(NetworkMetering metering) {
        if (metering == null) throw new EngineException("metering is required");
        if (RustMyotisEngine.isAvailable()) rustEngine().setNetworkMetering(metering);
        GoMyotisEngine g = go;
        if (g != null) g.setNetworkMetering(metering);
        java.setNetworkMetering(metering);
    }

    @Override
    public NetworkMetering networkMetering() {
        return java.networkMetering();
    }
}
