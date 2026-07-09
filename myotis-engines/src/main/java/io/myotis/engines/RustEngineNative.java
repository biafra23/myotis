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
    static final int EXPECTED_ABI_VERSION = 8; // 8: + nativeSendRawTransactionJson

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

    /** Up to {@code max} buffered engine tracing lines (oldest first,
     *  newline-joined; empty when idle). The drainable-ring end of the
     *  on-device observability seam — see the engine's {@code ringlog}. */
    static native String nativeDrainLogs(int max);

    // ---- EL verified-read surface (ABI 4). See RustChainHandle. ----

    /**
     * A verified account query for a running handle, returned as JSON: the full
     * {@link io.myotis.api.AccountProofResult} shape on success (a verification
     * failure carries a {@code failReason}), or an {@code "error"} object for a
     * transport / not-running / bad-input failure (which RustChainHandle raises
     * as an {@link io.myotis.api.EngineException}). {@code address} is 0x-hex.
     */
    static native String nativeRequestAccountJson(long handle, String address);

    /**
     * A verified storage-slot query for a running handle, as JSON (the
     * {@link io.myotis.api.StorageProofResult} shape, same error convention as
     * {@link #nativeRequestAccountJson}). {@code holderOrNull} selects the ERC-20
     * mapping key {@code keccak256(pad32(holder) ‖ uint256(slot))} when non-null.
     */
    static native String nativeGetStorageProofJson(
            long handle, String address, long slot, String holderOrNull);

    /**
     * A verified contract-code query (`eth_getCode`) for a running handle, as
     * JSON: a <code>{codeHex, codeHashHex, verifyMethod, failReason, …}</code>
     * object on success (empty {@code codeHex} for an EOA / empty-code / unverified
     * account), or an {@code "error"} object for a transport / not-running / bad-input failure.
     * {@code address} is 0x-hex.
     */
    static native String nativeGetCodeJson(long handle, String address);

    /**
     * A verified RAW-32-byte-position storage query (`eth_getStorageAt`) for a
     * running handle, as JSON (the {@link io.myotis.api.StorageProofResult} shape,
     * same error convention as {@link #nativeRequestAccountJson}). {@code position}
     * is the 32-byte storage position as 0x-hex — the trie key IS that position,
     * distinct from {@link #nativeGetStorageProofJson}'s {@code (slot, holder)}
     * ERC-20 mapping form.
     */
    static native String nativeGetStorageAtJson(long handle, String address, String position);

    /**
     * Verified {@code eth_getBlockByNumber} (transactions as hashes) for a running
     * handle. {@code blockTag} is an eth block selector ({@code "latest"} / a
     * 0x-hex number / …). Returns the block JSON object, the literal {@code "null"}
     * for a future/unknown block (eth's null), or an {@code "error"} object for a
     * transport / not-running / can't-verify failure. {@code fullTransactions} is
     * handled Java-side (returns null before this native runs).
     */
    static native String nativeGetBlockByNumberJson(long handle, String blockTag);

    /**
     * Verified fee suggestion (`eth_gasPrice` + `eth_maxPriorityFeePerGas`) for a
     * running handle, as JSON: {@code {"gasPriceWei":"…","maxPriorityFeePerGasWei":"…"}}
     * (decimal wei), or an {@code "error"} object when it can't verify. Both RPC
     * methods read this one payload so a paired poll shares a single compute.
     */
    static native String nativeFeeEstimateJson(long handle);

    /**
     * Gossip a signed raw transaction (`eth_sendRawTransaction`) to peers and
     * return {@code {"txHash":"0x…"}} (keccak256 of the raw tx), or an
     * {@code "error"} object when no peer could be reached. A WRITE — the engine
     * never signs and nothing is beacon-verified. {@code rawTxHex} is the 0x-hex
     * raw transaction.
     */
    static native String nativeSendRawTransactionJson(long handle, String rawTxHex);
}
