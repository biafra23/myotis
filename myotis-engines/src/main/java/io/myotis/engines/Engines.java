package io.myotis.engines;

import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;

/**
 * Process-wide engine selection, cloning the {@code BlsBackends} pattern. The choice
 * (system property {@code myotis.engine}, default {@code java}) decides which engine a
 * NEW {@code create()} goes to; networks already hosted keep the engine that created
 * them — a runtime switch means "flip the choice, then (re)start the network".
 *
 * <ul>
 *   <li>{@code java} — the JVM engine (node-core). The default.</li>
 *   <li>{@code rust} — the Rust engine, hard: unavailable → {@link EngineException}.</li>
 *   <li>{@code auto} — the Rust engine when it's available AND can serve the call,
 *       else the Java engine (logged fallback).</li>
 * </ul>
 */
public final class Engines {

    private static final Logger log = LoggerFactory.getLogger(Engines.class);
    public static final String PROP = "myotis.engine";

    private static final SelectorEngine ENGINE = new SelectorEngine();
    private static volatile String choice = normalize(System.getProperty(PROP, "java"));

    private Engines() {}

    /**
     * Drain up to {@code max} buffered Rust-engine tracing lines (oldest first,
     * newline-joined; empty string when idle or when the Rust engine is not
     * available). Hosts pump this into their own log pipeline on a short poll
     * (Android: LogBuffer -> Logs tab + logcat; desktop: slf4j) — an internal
     * observability seam, deliberately not on the engine API (like the BLS
     * backend toggle).
     */
    public static String drainRustLogs(int max) {
        // Same lazy-load protection as select(): under the java choice the
        // native library may never have been loaded — probing availability
        // would class-load RustEngineNative and map it just to drain a ring
        // that is empty by construction. rust/auto choices already probed.
        if ("java".equals(choice)) return "";
        if (!RustMyotisEngine.isAvailable()) return "";
        try {
            String batch = RustEngineNative.nativeDrainLogs(max);
            return batch != null ? batch : "";
        } catch (Throwable t) {
            return ""; // observability must never take the host down
        }
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
     * Which engine hosts {@code network} right now: {@code "java"}, {@code "rust"}, or
     * {@code null} when it isn't hosted. A documented host-UI exemption (like the
     * Settings engine toggle): the java/rust distinction is a selector concept, so it
     * deliberately isn't on the {@code MyotisEngine} API. Display-only.
     */
    public static String engineKindFor(String network) {
        return ENGINE.ownerKind(network);
    }

    /** The current choice: {@code java}, {@code rust}, or {@code auto}. */
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
            // RustEngineNative and maps the native library — pure-Java users
            // (Android re-applies the choice on every boot) shouldn't pay that.
            log.info("[engines] engine choice set to java");
        } else {
            log.info("[engines] engine choice set to {} (rust available: {})",
                    normalized, RustMyotisEngine.isAvailable());
        }
    }

    private static String normalize(String c) {
        String v = c == null ? "java" : c.trim().toLowerCase(Locale.ROOT);
        return switch (v) {
            case "java", "rust", "auto" -> v;
            default -> {
                LoggerFactory.getLogger(Engines.class)
                        .warn("[engines] unknown myotis.engine choice '{}'; using java", c);
                yield "java";
            }
        };
    }
}
