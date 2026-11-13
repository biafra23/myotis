package io.myotis.engines;

import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.engines.go.GoMyotisEngine;
import io.myotis.engines.rust.RustMyotisEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;

/**
 * Process-wide engine selection, cloning the {@code BlsBackends} pattern. The choice
 * (system property {@code myotis.engine}, default {@code auto}) decides which engine a
 * NEW {@code create()} goes to; networks already hosted keep the engine that created
 * them — a runtime switch means "flip the choice, then (re)start the network".
 *
 * <ul>
 *   <li>{@code auto} — the Rust engine when it's available AND can serve the call,
 *       else the Java engine (logged fallback). The default: the Rust engine is the
 *       primary engine (it alone serves the log index and Tor routing), and the
 *       availability probe keeps hosts without the native library on Java.</li>
 *   <li>{@code java} — the JVM engine (node-core), unconditionally.</li>
 *   <li>{@code rust} — the Rust engine, hard: unavailable → {@link EngineException}.</li>
 *   <li>{@code go} — the Go engine (libmyotis_engine_go), hard, desktop-only
 *       (owner's brief, 2026-11): the Bee-integration engine, selectable only —
 *       {@code auto} never picks it, it stays the explicit choice until the
 *       engine-parity step. Unavailable → {@link EngineException}.</li>
 * </ul>
 */
public final class Engines {

    private static final Logger log = LoggerFactory.getLogger(Engines.class);
    public static final String PROP = "myotis.engine";

    private static final SelectorEngine ENGINE = new SelectorEngine();
    private static volatile String choice = normalize(System.getProperty(PROP, "auto"));

    private Engines() {}

    /**
     * Drain up to {@code max} buffered native-engine tracing lines (oldest first,
     * newline-joined; empty string when idle or when no native engine is
     * available). Covers BOTH native rings — the Rust engine's and the Go
     * engine's — so one host pump feeds its log pipeline whichever engine is
     * routed (Android: LogBuffer -> Logs tab + logcat; desktop: slf4j); the
     * ring of an engine that never ran is empty by construction — but the pump
     * must not PROBE one that never ran either: touching {@code GoMyotisEngine}
     * class-loads the Go binding and maps its library (PR #832 review), so the
     * routing decision lives in {@link SelectorEngine#drainNativeLogs}, which
     * only touches a ring the selector itself has built or routes to. An
     * internal observability seam, deliberately not on the engine API (like the
     * BLS backend toggle). The name predates the Go engine and stays (CLAUDE.md
     * documents it under this name).
     */
    public static String drainRustLogs(int max) {
        return ENGINE.drainNativeLogs(max);
    }

    /**
     * The process-wide engine for hosts' composition roots — the single line that used
     * to be {@code new JavaMyotisEngine()}. Always the same {@link SelectorEngine}
     * instance; the underlying choice is consulted per {@code create()} call.
     */
    public static MyotisEngine engine() {
        return ENGINE;
    }

    /**
     * Which engine hosts {@code network} right now: {@code "java"}, {@code "rust"},
     * {@code "go"}, or {@code null} when it isn't hosted. A documented host-UI
     * exemption (like the Settings engine toggle): the engine-kind distinction is a
     * selector concept, so it deliberately isn't on the {@code MyotisEngine} API.
     * Display-only.
     */
    public static String engineKindFor(String network) {
        return ENGINE.ownerKind(network);
    }

    /** The current choice: {@code java}, {@code rust}, {@code go}, or {@code auto}. */
    public static String choice() {
        return choice;
    }

    /**
     * Change the choice at runtime (e.g. a Settings toggle). Applies to networks
     * (re)started afterwards; live networks keep their engine. Invalid input falls
     * back to {@code java} with a log, mirroring {@code BlsBackends}' tolerance.
     */
    public static synchronized void select(String newChoice) {
        String normalized = normalize(newChoice);
        choice = normalized;
        if ("java".equals(normalized)) {
            // Don't touch RustMyotisEngine here: probing availability class-loads
            // the native binding and maps the library — pure-Java users
            // (Android re-applies the choice on every boot) shouldn't pay that.
            log.info("[engines] engine choice set to java");
        } else if ("go".equals(normalized)) {
            // Same rule mirrored: only the Go choice probes the Go binding —
            // under auto/rust, auto never routes to Go and rust never uses it,
            // so touching GoMyotisEngine would map libmyotis_engine_go on hosts
            // that will never run it (PR #832 review).
            log.info("[engines] engine choice set to go (go available: {})",
                    GoMyotisEngine.isAvailable());
        } else {
            log.info("[engines] engine choice set to {} (rust available: {})",
                    normalized, RustMyotisEngine.isAvailable());
        }
    }

    private static String normalize(String c) {
        String v = c == null ? "auto" : c.trim().toLowerCase(Locale.ROOT);
        return switch (v) {
            case "java", "rust", "go", "auto" -> v;
            default -> {
                LoggerFactory.getLogger(Engines.class)
                        .warn("[engines] unknown myotis.engine choice '{}'; using auto", c);
                yield "auto";
            }
        };
    }
}
