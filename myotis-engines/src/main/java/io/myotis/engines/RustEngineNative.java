package io.myotis.engines;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The JNI boundary to {@code libmyotis_engine} ({@code rust/myotis-engine}). All natives
 * are static; compound values cross as JSON strings (the hand-JNI + JSON decision —
 * docs/reimplementation/05), pinned by golden tests on both sides.
 *
 * <p>Availability = the library loaded AND {@link #nativeInit()} returned the ABI version
 * this class was compiled against. The version check is the stale-.so guard: a leftover
 * library from an older/newer checkout reports "unavailable" instead of crashing on a
 * missing or reshaped symbol at first use.
 *
 * <p>Load order: an explicit absolute path in {@code -Dmyotis.engine.lib=...} (how the
 * desktop `run` task injects the dev build without baking a path into packaged apps),
 * then {@code System.loadLibrary("myotis_engine")} (java.library.path on the daemon,
 * bundled jniLibs on Android).
 */
final class RustEngineNative {

    private static final Logger log = LoggerFactory.getLogger(RustEngineNative.class);

    /** Must match {@code ABI_VERSION} in rust/myotis-engine/src/lib.rs. */
    static final int EXPECTED_ABI_VERSION = 2;

    private static final boolean AVAILABLE = load();

    private RustEngineNative() {}

    static boolean isAvailable() {
        return AVAILABLE;
    }

    private static boolean load() {
        try {
            String explicit = System.getProperty("myotis.engine.lib");
            if (explicit != null && !explicit.isBlank()) {
                System.load(explicit);
            } else {
                System.loadLibrary("myotis_engine");
            }
        } catch (Throwable t) {
            log.info("[engines] libmyotis_engine not loaded ({}); Rust engine unavailable",
                    t.getMessage());
            return false;
        }
        try {
            int abi = nativeInit();
            if (abi != EXPECTED_ABI_VERSION) {
                log.warn("[engines] libmyotis_engine ABI {} != expected {} (stale library?); "
                        + "Rust engine unavailable", abi, EXPECTED_ABI_VERSION);
                return false;
            }
        } catch (Throwable t) {
            log.warn("[engines] libmyotis_engine loaded but nativeInit failed ({}); "
                    + "Rust engine unavailable", t.toString());
            return false;
        }
        log.info("[engines] libmyotis_engine loaded (ABI {})", EXPECTED_ABI_VERSION);
        return true;
    }

    /** ABI handshake; returns the library's compiled-in ABI version. */
    static native int nativeInit();

    /** The embedded network catalog as a JSON array of NetworkInfo objects. */
    static native String nativeAvailableNetworksJson();

    /** Canonical name for a name/alias, or null when unknown. */
    static native String nativeCanonicalNetworkName(String nameOrAlias);

    // ---- Hosting surface (ABI 2). See RustChainHandle / RustMyotisEngine. ----

    /**
     * Allocate a not-yet-started handle for {@code network} (R1: mainnet only).
     * Returns the handle id (≥ 1), or a negative sentinel: -1 for an unknown name /
     * runtime-init failure, -2 for a canonical-but-not-mainnet network. Any value
     * {@code < 0} is a failure ({@link RustMyotisEngine#create} pre-checks mainnet,
     * so it only ever observes -1). The Rust side owns the tokio runtime the handle
     * runs on.
     */
    static native long nativeCreate(String network, String dataDir);

    /** Start the sync loop for a created handle. True on success. */
    static native boolean nativeStart(long handle);

    /**
     * One handle's status as a JSON object (camelCase keys — see RustChainHandle),
     * or {@code "{}"} for an unknown handle. Null only on an OOM-class JNI failure.
     */
    static native String nativeStatusJson(long handle);

    /** Remove and shut down a handle's sync loop. No-op for an unknown id. */
    static native void nativeStop(long handle);
}
