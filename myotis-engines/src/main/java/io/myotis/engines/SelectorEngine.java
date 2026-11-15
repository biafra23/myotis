package io.myotis.engines;

import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.api.NetworkInfo;
import io.myotis.api.NetworkMetering;
import io.myotis.api.ports.EnginePorts;
import io.myotis.engines.rust.RustMyotisEngine;
import io.myotis.node.api.JavaMyotisEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link MyotisEngine} that routes to the Java or Rust engine per the current
 * {@link Engines} choice: {@code create()} goes to the engine the choice resolves to
 * <em>at that moment</em>; {@code get}/{@code stop} go to whichever engine owns the
 * network (recorded at create); {@code shutdownAll} fans out to both.
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
        if (!"rust".equals(choice)) return createFor(choice, config, ports);
        // Explicit rust: never a fallback, and every failure must arrive as the
        // EngineException this class promises. Resolving the engine, canonicalizing the
        // name and creating the network all cross the native boundary, so a LinkageError
        // from any of them is wrapped here instead of taking the host process down.
        // Android below API 33 runs on this path by default (no Java engine there).
        try {
            return createFor(choice, config, ports);
        } catch (LinkageError e) {
            throw new EngineException("Rust engine failed to link while creating "
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
     * or {@code null} when the network isn't hosted. Display-only (the Status screen's
     * engine badge) — routing stays on {@link #owners} via get/stop.
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
        return owner instanceof RustMyotisEngine ? "rust" : "java";
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
        }
    }

    @Override
    public void shutdownAll() {
        owners.clear();
        java.shutdownAll();
        RustMyotisEngine r = rust;
        if (r != null) r.shutdownAll();
    }

    /** Both engines hear it: a network created later on either one must count
     *  under the device's current metering from its first byte. The Rust engine
     *  first: {@link #networkMetering()} reads the Java one, so a Rust failure
     *  leaves it reporting the OLD value and a host that pushes only on a change
     *  retries.
     *
     *  <p>The Rust-read/write and the Java-write run under {@code this} monitor
     *  (the same one {@link #rustEngine} initializes under and {@link #create}
     *  holds) so a push is one ATOMIC step for both engines. Without it, two
     *  overlapping pushes could interleave their Rust and Java writes and leave
     *  the two engines on DIFFERENT values — e.g. Rust on push A's reading,
     *  Java (and so {@link #networkMetering()}) on push B's — with neither
     *  corrected, because {@link #networkMetering()} reports Java and a
     *  push-on-change host sees Java already matching the device and never
     *  re-pushes to fix Rust. On Android this is not theoretical:
     *  {@code NodeService.pushNetworkMetering} fires from three connectivity
     *  callbacks on the shared {@code QUERY_POOL}, so concurrent pushes are the
     *  normal case, and Rust is the engine Android runs by default. The lock
     *  makes the two engines agree; it does not order two racing pushes by how
     *  fresh their reading is (the host reads the device state before arriving),
     *  but the disagree state it prevents was the one nothing healed, whereas a
     *  stale-but-agreeing pair self-heals at the next callback. */
    @Override
    public void setNetworkMetering(NetworkMetering metering) {
        if (metering == null) throw new EngineException("metering is required");
        synchronized (this) { // the monitor rustEngine() initializes under and create() holds
            if (RustMyotisEngine.isAvailable()) rustEngine().setNetworkMetering(metering);
            java.setNetworkMetering(metering);
        }
    }

    @Override
    public NetworkMetering networkMetering() {
        return java.networkMetering();
    }
}
