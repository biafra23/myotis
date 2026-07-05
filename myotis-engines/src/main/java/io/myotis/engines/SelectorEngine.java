package io.myotis.engines;

import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.api.NetworkInfo;
import io.myotis.api.ports.EnginePorts;
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
                if (rust == null) rust = new RustMyotisEngine();
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
    public ChainHandle create(EngineConfig config, EnginePorts ports) {
        // Read the choice ONCE: a concurrent select() between resolving the target and
        // deciding fallback behavior must not turn an in-flight auto-create into a hard
        // failure (or vice versa).
        String choice = Engines.choice();
        MyotisEngine target = resolveFor(choice);
        if (target != java && "auto".equals(choice)) {
            // auto: a Rust create() failure is a fallback signal, not an error. This
            // double-create is only safe while a failed Rust create() has no side
            // effects — the Rust engine must keep create() all-or-nothing (R0 throws
            // before doing anything; the real implementation must preserve that).
            try {
                return createOn(target, config, ports);
            } catch (EngineException e) {
                log.warn("[engines] auto: Rust engine create({}) failed ({}); "
                        + "falling back to the Java engine", config.networkName(), e.getMessage());
                target = java;
            }
        }
        return createOn(target, config, ports);
    }

    private ChainHandle createOn(MyotisEngine target, EngineConfig config, EnginePorts ports) {
        String canonical = target.canonicalNetworkName(config.networkName());
        // Cross-engine duplicate guard: each engine self-checks only its OWN registry,
        // so without this a choice flip between two creates could host the same network
        // on both engines — the older stack would leak, unreachable via get/stop.
        // (Upholds the MyotisEngine.create contract: already hosted anywhere → throw.)
        if (get(canonical) != null) {
            throw new EngineException("network already hosted: " + canonical);
        }
        ChainHandle handle = target.create(config, ports);
        // Record ownership under the canonical name so get/stop (which hosts call with
        // canonical names) route to the right engine.
        owners.put(canonical, target);
        return handle;
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
}
