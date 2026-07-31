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
        // Turning OFF must be side-effect-free: the Rust flag defaults to disabled,
        // so there is nothing to push, and probing availability here would map the
        // native library on the pure-Java default path (rustEngine off, Tor never
        // touched) at every startup. Only when turning ON do we probe + push — and
        // by then the caller has opted into the Rust engine (the toggle is gated on
        // it). If the Rust engine isn't loaded/available, Tor can't route.
        if (!on) {
            log.info("[tor] verified-read routing disabled");
            return false;
        }
        if (!RustMyotisEngine.isAvailable()) {
            log.info("[tor] requested on but the Rust engine is unavailable — Tor cannot route");
            return false;
        }
        try {
            boolean supported = RustEngineNative.nativeSetTorEnabled(on);
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
