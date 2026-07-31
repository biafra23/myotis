package io.myotis.engines;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uniffi.myotis_engine.Myotis_engineKt;

/**
 * The FFI boundary to {@code libmyotis_engine} ({@code rust/myotis-engine}), since the
 * UniFFI migration a thin STATIC DELEGATOR over the generated Kotlin bindings
 * ({@code uniffi.myotis_engine} — committed at src/main/kotlin, regenerated via the
 * root {@code uniffiGenerateKotlin} task). Compound values still cross as JSON strings
 * (transport swap only — the hand-JNI is gone but the shapes are unchanged and stay
 * pinned by the golden tests on both sides).
 *
 * <p>Availability = the bindings initialized (UniFFI verifies a per-function API
 * checksum against the loaded library — the stale-.so guard is now structural) AND
 * {@link #nativeInit()} returned the coarse ABI version this class was compiled
 * against (kept as a belt-and-braces check + the log line).
 *
 * <p>Load order: an explicit absolute path in {@code -Dmyotis.engine.lib=...} (how the
 * desktop `run` task injects the dev build) is forwarded to the bindings via UniFFI's
 * {@code uniffi.component.myotis_engine.libraryOverride} property; otherwise JNA
 * resolves {@code myotis_engine} from {@code jna.library.path} + system paths — it
 * does NOT consult {@code java.library.path}, so {@link #load()} mirrors that
 * property into {@code jna.library.path} when the latter is unset (the daemon's run
 * task and the module's tests point java.library.path at the cargo build dir). A
 * host that sets {@code jna.library.path} itself owns the full search path. On
 * Android JNA resolves the bundled jniLibs on its own.
 *
 * <p>Every method keeps the old hand-JNI null tolerance: null String arguments are
 * normalized to {@code ""} (the Rust side used {@code unwrap_or_default}) — except
 * the genuinely optional {@code holderOrNull}, which maps to Kotlin's {@code String?}.
 */
final class RustEngineNative {

    private static final Logger log = LoggerFactory.getLogger(RustEngineNative.class);

    /** Must match {@code ABI_VERSION} in rust/myotis-engine/src/lib.rs. */
    static final int EXPECTED_ABI_VERSION = 19; // 19: + nativePendingNonceOverlay (sent-tx slice)

    private static final boolean AVAILABLE = load();

    private RustEngineNative() {}

    static boolean isAvailable() {
        return AVAILABLE;
    }

    private static boolean load() {
        String explicit = System.getProperty("myotis.engine.lib");
        if (explicit != null && !explicit.isBlank()) {
            // Forward the dev-build path to the generated bindings' loader. Set-if-absent
            // so an explicitly configured override always wins.
            if (System.getProperty("uniffi.component.myotis_engine.libraryOverride") == null) {
                System.setProperty("uniffi.component.myotis_engine.libraryOverride", explicit);
            }
        } else if (System.getProperty("jna.library.path") == null) {
            // JNA searches jna.library.path (plus system paths), NOT java.library.path —
            // which is where the daemon's run task and :myotis-engines' test task put the
            // cargo build dir. Mirror it so the pre-UniFFI lookup contract keeps holding.
            // (Android ignores this: JNA resolves bundled jniLibs on its own.)
            String jlp = System.getProperty("java.library.path");
            if (jlp != null && !jlp.isBlank()) {
                System.setProperty("jna.library.path", jlp);
            }
        }
        try {
            // Run UniFFI's integrity gate FIRST: uniffiEnsureInitialized() loads the
            // library and validates the bindings-contract version plus a per-function
            // API checksum against the loaded .so. It must be called explicitly —
            // plain binding calls like engineInit() register the functions WITHOUT
            // checksum validation, so skipping this line would let a reshaped symbol
            // segfault at first use instead of failing loudly here.
            Myotis_engineKt.uniffiEnsureInitialized();
            int abi = Myotis_engineKt.engineInit();
            if (abi != EXPECTED_ABI_VERSION) {
                log.warn("[engines] libmyotis_engine ABI {} != expected {} (stale library?); "
                        + "Rust engine unavailable", abi, EXPECTED_ABI_VERSION);
                return false;
            }
        } catch (UnsatisfiedLinkError e) {
            // The normal cargo-less case: no library on the search path (or one so old
            // it predates UniFFI and lacks the uniffi_* symbols entirely).
            log.info("[engines] libmyotis_engine not loaded ({}); Rust engine unavailable",
                    e.toString());
            return false;
        } catch (Throwable t) {
            // Library FOUND but failed UniFFI's contract/checksum validation (stale or
            // reshaped .so) — louder than the missing-library case on purpose.
            log.warn("[engines] libmyotis_engine failed UniFFI validation ({}); "
                    + "Rust engine unavailable — rebuild the library (cargoBuildHost / "
                    + "cargoNdkAndroid) or regenerate the bindings (uniffiGenerateKotlin)",
                    t.toString());
            return false;
        }
        log.info("[engines] libmyotis_engine loaded via UniFFI (ABI {})", EXPECTED_ABI_VERSION);
        return true;
    }

    private static String nz(String s) {
        return s == null || !wellFormed(s) ? "" : s;
    }

    /** The old hand-JNI surface degraded malformed UTF-16 (unpaired surrogates —
     *  attacker-reachable via JSON-RPC string params) to an absent/empty string on
     *  the Rust side (CESU-8 decode failure → {@code unwrap_or_default}). The
     *  generated bindings instead throw {@code MalformedInputException} from their
     *  UTF-8 lowering; probe first so the pre-UniFFI semantics keep holding. */
    private static boolean wellFormed(String s) {
        return java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(s);
    }

    /** ABI handshake; returns the library's compiled-in ABI version. */
    static int nativeInit() {
        return Myotis_engineKt.engineInit();
    }

    /** {@code nativeCreate} sentinel: the network is canonical but this engine
     *  doesn't host it yet (must match {@code UNSUPPORTED_NETWORK} in
     *  rust/myotis-engine/src/host.rs). */
    static final long UNSUPPORTED_NETWORK = -2;

    /** The embedded network catalog as a JSON array of NetworkInfo objects. */
    static String nativeAvailableNetworksJson() {
        return Myotis_engineKt.availableNetworksJson();
    }

    /** Canonical name for a name/alias, or null when unknown. */
    static String nativeCanonicalNetworkName(String nameOrAlias) {
        if (nameOrAlias == null) return null;
        return Myotis_engineKt.canonicalNetworkName(nz(nameOrAlias));
    }

    // ---- Hosting surface. See RustChainHandle / RustMyotisEngine. ----

    /** Allocate a not-yet-started handle (id ≥ 1, or a negative failure sentinel). */
    static long nativeCreate(String network, String dataDir) {
        if (network == null) return -1;
        // nz also degrades malformed UTF-16 to "" → unknown network → CREATE_FAILED,
        // the old shim's behavior.
        return Myotis_engineKt.createHandle(nz(network), nz(dataDir));
    }

    /** Start the sync loop for a created handle. True on success. */
    static boolean nativeStart(long handle) {
        return Myotis_engineKt.startHandle(handle);
    }

    /** One handle's status as a JSON object, or {@code "{}"} for an unknown handle. */
    static String nativeStatusJson(long handle) {
        return Myotis_engineKt.statusJson(handle);
    }

    /** Remove and shut down a handle's sync loop. No-op for an unknown id. */
    static void nativeStop(long handle) {
        Myotis_engineKt.stopHandle(handle);
    }

    // ---- Idle-sleep surface. See RustChainHandle. ----

    /** Idle-sleep a RUNNING handle; true ONLY on an actual RUNNING→PAUSED transition. */
    static boolean nativePause(long handle) {
        return Myotis_engineKt.pauseHandle(handle);
    }

    /** Rebuild networking for a PAUSED handle; true ONLY on PAUSED→RUNNING. */
    static boolean nativeResume(long handle) {
        return Myotis_engineKt.resumeHandle(handle);
    }

    /** Up to {@code max} buffered engine tracing lines (oldest first, newline-joined). */
    static String nativeDrainLogs(int max) {
        return Myotis_engineKt.drainLogs(max);
    }

    // ---- EL verified-read surface. See RustChainHandle for the JSON contracts. ----

    /** Verified account query as JSON (AccountProofResult shape / {@code error} object). */
    static String nativeRequestAccountJson(long handle, String address) {
        return Myotis_engineKt.requestAccountJson(handle, nz(address));
    }

    /** Verified storage-slot query as JSON; non-null {@code holderOrNull} selects the
     *  ERC-20 mapping key {@code keccak256(pad32(holder) ‖ uint256(slot))}. */
    static String nativeGetStorageProofJson(
            long handle, String address, long slot, String holderOrNull) {
        // Malformed holder → null, matching the old shim (decode failure → None).
        String holder = (holderOrNull != null && wellFormed(holderOrNull)) ? holderOrNull : null;
        return Myotis_engineKt.getStorageProofJson(handle, nz(address), slot, holder);
    }

    /** Verified contract-code query (`eth_getCode`) as JSON. */
    static String nativeGetCodeJson(long handle, String address) {
        return Myotis_engineKt.getCodeJson(handle, nz(address));
    }

    /** Verified RAW-32-byte-position storage query (`eth_getStorageAt`) as JSON. */
    static String nativeGetStorageAtJson(long handle, String address, String position) {
        return Myotis_engineKt.getStorageAtJson(handle, nz(address), nz(position));
    }

    /** Verified {@code eth_call} over the revm executor, as JSON. */
    static String nativeEthCallJson(
            long handle, String from, String to, String data, String value, String block) {
        return Myotis_engineKt.ethCallJson(
                handle, nz(from), nz(to), nz(data), nz(value), nz(block));
    }

    /** Verified {@code eth_estimateGas} over the revm executor, as JSON. */
    static String nativeEstimateGasJson(
            long handle, String from, String to, String data, String value) {
        return Myotis_engineKt.estimateGasJson(handle, nz(from), nz(to), nz(data), nz(value));
    }

    /** Verified ENS forward resolution (name → address record), as JSON. */
    static String nativeResolveEnsJson(long handle, String name) {
        return Myotis_engineKt.resolveEnsJson(handle, nz(name));
    }

    /** One generic ENS record dispatch; method + args travel in {@code paramsJson}. */
    static String nativeEnsRecordJson(long handle, String paramsJson) {
        return Myotis_engineKt.ensRecordJson(handle, nz(paramsJson));
    }

    /** Verified {@code eth_getBlockByNumber} (block JSON / literal "null" / error). */
    static String nativeGetBlockByNumberJson(
            long handle, String blockTag, boolean fullTransactions) {
        return Myotis_engineKt.getBlockByNumberJson(handle, nz(blockTag), fullTransactions);
    }

    /** Verified fee suggestion (`eth_gasPrice` + `eth_maxPriorityFeePerGas`), as JSON. */
    static String nativeFeeEstimateJson(long handle) {
        return Myotis_engineKt.feeEstimateJson(handle);
    }

    /** Gossip a signed raw tx; {@code {"txHash":"0x…"}} or an error object. */
    static String nativeSendRawTransactionJson(long handle, String rawTxHex) {
        return Myotis_engineKt.sendRawTransactionJson(handle, nz(rawTxHex));
    }

    /** Verified {@code eth_getTransactionReceipt} (receipt JSON / "null" / error). */
    static String nativeGetTransactionReceiptJson(long handle, String txHashHex) {
        return Myotis_engineKt.getTransactionReceiptJson(handle, nz(txHashHex));
    }

    /** The "pending" nonce overlay; negative only for malformed input / missing handle. */
    static long nativePendingNonceOverlay(long handle, String addressHex, long minedNonce) {
        return Myotis_engineKt.pendingNonceOverlay(handle, nz(addressHex), minedNonce);
    }

    /** Verified {@code eth_getTransactionByHash} (tx JSON / "null" / error). */
    static String nativeGetTransactionByHashJson(long handle, String txHashHex) {
        return Myotis_engineKt.getTransactionByHashJson(handle, nz(txHashHex));
    }

    /** Verified {@code eth_getBlockByHash} (block JSON / "null" / error). */
    static String nativeGetBlockByHashJson(
            long handle, String blockHashHex, boolean fullTransactions) {
        return Myotis_engineKt.getBlockByHashJson(handle, nz(blockHashHex), fullTransactions);
    }

    /** Verified {@code eth_getBlockReceipts} (receipts array JSON / "null" / error). */
    static String nativeGetBlockReceiptsJson(long handle, String selector) {
        return Myotis_engineKt.getBlockReceiptsJson(handle, nz(selector));
    }

    /** Verified {@code eth_feeHistory} (feeHistory JSON / error). */
    static String nativeFeeHistoryJson(
            long handle, long blockCount, String newestBlockTag, String percentilesJson) {
        return Myotis_engineKt.feeHistoryJson(
                handle, blockCount, nz(newestBlockTag), nz(percentilesJson));
    }
}
