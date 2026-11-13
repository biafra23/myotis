package io.myotis.engines.go;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The FFI boundary to {@code libmyotis_engine_go} ({@code go/cmd/myotis-capi}, built
 * by the root {@code goBuildCShared} task): plain JNA INTERFACE mapping
 * ({@code Native.load(name, Interface.class)} — symbols resolve LAZILY at the
 * first call that touches one, not at load; PR #832 review) over the
 * engine's C ABI — the SAME {@code rust/include/myotis_engine.h} contract the Rust
 * engine exports (the Go engine re-implements it in Go), so the ABI handshake, the
 * handle sentinels, the JSON-over-FFI convention and the free contract
 * ({@code myotis_string_free} frees every returned {@code char*}) are shared with
 * {@code RustEngineNative}/{@code RustChainHandle}, pinned by the golden tests on
 * the Go side ({@code go/internal/capi}).
 *
 * <p>Only the surface this engine's Java wrapper actually drives is declared here —
 * lifecycle, catalog, status, the verified account/storage reads, the live setters
 * and the log drain. The exports the Go build answers with honest refusals (EVM,
 * ENS, blocks, the log index) need no symbol: adding them to this interface before
 * the Go side implements them would only pretend the surface is used.
 *
 * <p>Load order mirrors {@code RustEngineNative}: an explicit absolute path in
 * {@code -Dmyotis.engine.go.lib} (how the desktop {@code run} task injects the dev
 * build) loads that file directly; otherwise JNA resolves {@code myotis_engine_go}
 * from {@code jna.library.path} + system paths, and this class mirrors
 * {@code java.library.path} into {@code jna.library.path} when the latter is unset
 * (the module's test task and the daemon's run task point java.library.path at
 * {@code go/build}). A host that sets {@code jna.library.path} itself owns the
 * whole search path.
 *
 * <p>Every method keeps the Rust twin's null tolerance: null String arguments
 * normalize to {@code ""} (the Go {@code cstr}/{@code gostrC} shims use
 * {@code C.GoString}, which reads NULL as ""), except a genuinely absent value
 * that carries meaning ({@code canonicalNetworkName} probes with null → NULL
 * never happens because we pass ""; unknown-ness arrives as an empty return).
 *
 * <p>C {@code bool} crosses as {@code byte}, in both directions: JNA's Java
 * {@code boolean} maps to a 4-byte C {@code int}, while cgo's {@code C.bool} is a
 * 1-byte {@code _Bool}. A byte parameter widened into the register's low byte
 * reads correctly as {@code _Bool}; a byte return reads exactly the byte cgo
 * writes, never the undefined high bytes of the return register.
 */
final class GoEngineNative {

    private static final Logger log = LoggerFactory.getLogger(GoEngineNative.class);

    /** Must match {@code MYOTIS_ABI_VERSION} in rust/include/myotis_engine.h (the
     *  contract BOTH engine libraries implement; the Go side pins it too via
     *  TestABIVersionMatchesHeader in go/internal/capi). */
    static final int EXPECTED_ABI_VERSION = 57;

    /** {@code myotis_create} sentinel: canonical network this build does not host
     *  (the Go build: everything but mainnet, until the multichain step). Matches
     *  the Rust {@code UNSUPPORTED_NETWORK}. */
    static final long UNSUPPORTED_NETWORK = -2;

    private static final GoEngineLibrary LIB;
    private static final boolean AVAILABLE;

    static {
        GoEngineLibrary lib = null;
        boolean ok = false;
        try {
            lib = loadLibrary();
            int abi = lib.myotis_init();
            if (abi != EXPECTED_ABI_VERSION) {
                log.warn("[engines] libmyotis_engine_go ABI {} != expected {} (stale library?); "
                        + "Go engine unavailable", abi, EXPECTED_ABI_VERSION);
                lib = null;
            } else {
                ok = true;
                log.info("[engines] libmyotis_engine_go loaded via JNA (ABI {})",
                        EXPECTED_ABI_VERSION);
            }
        } catch (UnsatisfiedLinkError e) {
            // The normal go-less case: no library on the search path, or a cgo
            // dependency (libc version) that will not resolve.
            log.info("[engines] libmyotis_engine_go not loaded ({}); Go engine unavailable",
                    e.toString());
            lib = null;
        } catch (Throwable t) {
            // Library found but something else failed (a renamed symbol surfaces
            // LATER, on the first call touching it — interface mapping resolves
            // symbols lazily; callers contain that LinkageError) — louder than
            // the missing case on purpose, and name the rebuild command.
            log.warn("[engines] libmyotis_engine_go failed to initialize ({}); Go engine "
                    + "unavailable — rebuild it (goBuildCShared)", t.toString(), t);
            lib = null;
        }
        LIB = lib;
        AVAILABLE = ok;
    }

    private GoEngineNative() {}

    static boolean isAvailable() {
        return AVAILABLE;
    }

    private static GoEngineLibrary loadLibrary() {
        String explicit = System.getProperty("myotis.engine.go.lib");
        if (explicit != null && !explicit.isBlank()) {
            return Native.load(explicit, GoEngineLibrary.class);
        }
        // JNA searches jna.library.path, NOT java.library.path — mirror it when
        // unset, exactly as RustEngineNative does for the Rust library.
        if (System.getProperty("jna.library.path") == null) {
            String jlp = System.getProperty("java.library.path");
            if (jlp != null && !jlp.isBlank()) {
                System.setProperty("jna.library.path", jlp);
            }
        }
        return Native.load("myotis_engine_go", GoEngineLibrary.class);
    }

    /** Read a returned {@code char*} and release it per the header contract
     *  (everything returned is freed by {@code myotis_string_free}, never by the
     *  C runtime). NULL → null. */
    private static String take(Pointer p) {
        if (p == null) return null;
        try {
            return p.getString(0, "UTF-8");
        } finally {
            LIB.myotis_string_free(p);
        }
    }

    private static String nz(String s) {
        return s == null || !wellFormed(s) ? "" : s;
    }

    /** The Rust twin's malformed-UTF-16 rule, kept for identical argument
     *  semantics: an unpaired surrogate degrades to {@code ""} (which every
     *  native entry point then refuses by name) rather than crossing as
     *  replacement bytes that could collide with a real input. */
    private static boolean wellFormed(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                    return false;
                }
                i++; // consume the low half of a well-formed pair
            } else if (Character.isLowSurrogate(c)) {
                return false; // low surrogate with no preceding high
            }
        }
        return true;
    }

    // ---- availability / catalog ----

    /** The embedded network catalog as a JSON array of NetworkInfo objects. */
    static String nativeAvailableNetworksJson() {
        return take(LIB.myotis_available_networks_json());
    }

    /** Canonical name for a name/alias, or null when unknown (empty → unknown). */
    static String nativeCanonicalNetworkName(String nameOrAlias) {
        if (nameOrAlias == null) return null;
        String c = take(LIB.myotis_canonical_network_name(nz(nameOrAlias)));
        return c == null || c.isEmpty() ? null : c;
    }

    // ---- lifecycle ----

    /** Allocate a not-yet-started handle (id >= 1, or a negative failure sentinel). */
    static long nativeCreate(String network, String dataDir) {
        if (network == null) return -1;
        return LIB.myotis_create(nz(network), nz(dataDir));
    }

    static boolean nativeStart(long handle) {
        return LIB.myotis_start(handle) != 0;
    }

    static void nativeStop(long handle) {
        LIB.myotis_stop(handle);
    }

    // ---- status / logs ----

    /** The status JSON (Rust key set + the Go-only engine/myotisAbi/capabilities). */
    static String nativeStatusJson(long handle) {
        return take(LIB.myotis_status_json(handle));
    }

    /** Up to {@code max} buffered tracing lines, oldest first, newline-joined. */
    static String nativeDrainLogs(int max) {
        return take(LIB.myotis_drain_logs(max));
    }

    // ---- verified reads ----

    /** Account read at a block selector; result JSON or an error envelope. */
    static String nativeRequestAccountJson(long handle, String address, String block) {
        return take(LIB.myotis_request_account_json(handle, nz(address), nz(block)));
    }

    /** One storage slot; {@code holderOrNull} null → NULL (no AA mapping fold). */
    static String nativeGetStorageProofJson(long handle, String address, long slot,
                                            String holderOrNull) {
        String holder = holderOrNull == null ? null : nz(holderOrNull);
        return take(LIB.myotis_get_storage_proof_json(handle, nz(address), slot, holder));
    }

    // ---- live setters / process-global toggles ----

    static boolean nativeSetServedBlockWindow(long handle, int blocks) {
        return LIB.myotis_set_served_block_window(handle, blocks) != 0;
    }

    static boolean nativeSetWsBoundPeriods(long handle, long periods) {
        return LIB.myotis_set_ws_bound_periods(handle, periods) != 0;
    }

    static boolean nativeAcceptStaleAnchor(long handle) {
        return LIB.myotis_accept_stale_anchor(handle) != 0;
    }

    static boolean nativeSetDnsDiscovery(boolean on) {
        return LIB.myotis_set_dns_discovery((byte) (on ? 1 : 0)) != 0;
    }

    static boolean nativeSetNetworkMetering(int code) {
        return LIB.myotis_set_network_metering(code) != 0;
    }

    static int nativeNetworkMetering() {
        return LIB.myotis_network_metering();
    }

    /** Direct-mapped view of the exported C symbols. */
    interface GoEngineLibrary extends Library {
        int myotis_init();
        Pointer myotis_drain_logs(int max);
        Pointer myotis_available_networks_json();
        Pointer myotis_canonical_network_name(String nameOrAlias);
        long myotis_create(String network, String dataDir);
        byte myotis_start(long handle);
        void myotis_stop(long handle);
        Pointer myotis_status_json(long handle);
        Pointer myotis_request_account_json(long handle, String address, String block);
        Pointer myotis_get_storage_proof_json(long handle, String address, long slot,
                                              String holderOrNull);
        byte myotis_set_served_block_window(long handle, int blocks);
        byte myotis_set_ws_bound_periods(long handle, long periods);
        byte myotis_accept_stale_anchor(long handle);
        byte myotis_set_dns_discovery(byte on);
        byte myotis_set_network_metering(int code);
        int myotis_network_metering();
        void myotis_string_free(Pointer s);
    }
}
