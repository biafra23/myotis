package io.myotis.engines;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Process-wide Tor verified-read routing toggle (docs/privacy-and-tor.md),
 * cloning the {@link Engines} / {@code BlsBackends} selector pattern — a host-UI
 * seam, deliberately NOT on the engine API (like the engine and BLS toggles).
 *
 * <p>Tor is a <b>Rust-engine-only</b> capability: Arti is a Rust library embedded
 * in {@code libmyotis_engine} (docs §3). The toggle is a no-op unless the Rust
 * engine's native library is loaded AND was built with {@code --features tor};
 * {@link #supported()} reflects that so a host can grey the switch out.
 *
 * <p><b>Experimental.</b> Routing verified reads over Tor is unreliable in
 * practice — many synced peers reject inbound from Tor exit IPs and {@code
 * :30303} exit coverage is partial (docs §8). While on, balance/state reads may
 * be slow or fail-closed. The routing sets the process-global flag in the Rust
 * engine; the account read path there dials a per-address isolated Tor circuit
 * with a fresh ephemeral identity instead of the clearnet peer pool.
 */
public final class Tor {

    private static final Logger log = LoggerFactory.getLogger(Tor.class);
    public static final String PROP = "myotis.tor";

    private static volatile boolean enabled =
            Boolean.parseBoolean(System.getProperty(PROP, "false"));

    /**
     * Whether we've ever pushed an ON to the native engine (which loads the Rust
     * library). Turning OFF only needs to reach the engine if we previously turned
     * it ON — otherwise the Rust flag is already at its disabled default and
     * probing would pointlessly force-load the library on the pure-Java path.
     */
    private static volatile boolean pushedOn = false;

    private Tor() {}

    /** Whether the host has asked for Tor routing (independent of support). */
    public static boolean enabled() {
        return enabled;
    }

    /**
     * Set Tor routing on/off and push it to the Rust engine. Returns true iff the
     * running engine build actually supports Tor (Rust library loaded AND built
     * with {@code --features tor}); false means the flag was recorded but nothing
     * will route over Tor, so the host should reflect "unsupported".
     */
    public static synchronized boolean select(boolean on) {
        enabled = on;
        System.setProperty(PROP, Boolean.toString(on));
        // Turning OFF when we never turned it ON is a genuine no-op: the Rust flag
        // is already at its disabled default, so there is nothing to push, and
        // probing availability would pointlessly force-load the native library on
        // the pure-Java default path (rustEngine off, Tor never touched) at every
        // startup. But once we HAVE pushed an ON, the engine is holding an enabled
        // flag — turning off MUST reach it (else reads keep routing over Tor until
        // process restart), and the library is already loaded so the probe is free.
        if (!on && !pushedOn) {
            log.info("[tor] verified-read routing disabled");
            return false;
        }
        if (!RustMyotisEngine.isAvailable()) {
            log.info("[tor] requested {} but the Rust engine is unavailable — Tor cannot route",
                    on ? "on" : "off");
            return false;
        }
        try {
            boolean supported = RustEngineNative.nativeSetTorEnabled(on);
            // Remember we reached the engine so a later OFF is delivered; clearing
            // on a successful OFF lets a subsequent OFF short-circuit again.
            pushedOn = on;
            log.info("[tor] verified-read routing {} (supported by this build: {})",
                    on ? "ENABLED" : "disabled", supported);
            return supported;
        } catch (Throwable t) {
            log.warn("[tor] nativeSetTorEnabled failed: {}", t.toString());
            return false;
        }
    }

    /**
     * Status bitmask for the host's Status view: bit0 compiled-in, bit1 enabled,
     * bit2 bootstrapped (a Tor circuit is ready). {@code 0} = this build has no
     * Tor support (Java engine, or a Rust build without {@code --features tor}).
     */
    public static int status() {
        if (!RustMyotisEngine.isAvailable()) {
            return 0;
        }
        try {
            return RustEngineNative.nativeTorStatus();
        } catch (Throwable t) {
            return 0;
        }
    }

    /** Whether this build can route over Tor at all (Rust lib + {@code tor} feature). */
    public static boolean supported() {
        return (status() & 1) != 0;
    }

    /** Whether Tor is on AND a circuit has bootstrapped — i.e. routing is live. */
    public static boolean active() {
        int s = status();
        return (s & 2) != 0 && (s & 4) != 0;
    }
}
