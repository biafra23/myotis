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
    static final int EXPECTED_ABI_VERSION = 19; // 19: + nativePendingNonceOverlay (sent-tx slice)

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

    /** {@code nativeCreate} sentinel: the network is canonical but this engine
     *  doesn't host it yet (must match {@code UNSUPPORTED_NETWORK} in
     *  rust/myotis-engine/src/host.rs). */
    static final long UNSUPPORTED_NETWORK = -2;

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

    // ---- Idle-sleep surface (ABI 13). See RustChainHandle. ----

    /**
     * Idle-sleep a RUNNING handle: tear all networking down (zero sockets, zero
     * timers) but keep the handle PAUSED with its warm state persisted, so
     * {@link #nativeResume} warm-starts. True ONLY on an actual RUNNING→PAUSED
     * transition — the wrapper layers the contract's idempotent semantics (and
     * the sleep accounting) on top.
     */
    static native boolean nativePause(long handle);

    /**
     * Rebuild networking for a PAUSED handle (warm start from the persisted
     * snapshot / peer caches — no checkpoint re-bootstrap). True ONLY on an
     * actual PAUSED→RUNNING transition; false when the rebuild failed (the
     * handle stays PAUSED, retryable) or the handle isn't paused.
     */
    static native boolean nativeResume(long handle);

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
     * A verified {@code eth_call} over the revm executor for a running handle, as
     * JSON ({@code {"status":"ok","resultHex":"0x…"}} on success,
     * {@code {"status":"revert","dataHex":"0x…"}} on a revert,
     * {@code {"status":"unavailable","reason":"…"}} otherwise, or
     * {@code {"error":"…"}} on a transport/bad-input failure). {@code from} is
     * empty for an anonymous call; {@code value} is wei as a decimal string (an
     * FFI-neutral scalar); {@code block} is the RPC block tag (already gated to the
     * servable window on the Java side).
     */
    static native String nativeEthCallJson(
            long handle, String from, String to, String data, String value, String block);

    /**
     * A verified {@code eth_estimateGas} over the revm executor for a running handle,
     * as JSON ({@code {"status":"ok","gas":N}} on success,
     * {@code {"status":"unavailable","reason":"…"}} for a revert/unverifiable run, or
     * {@code {"error":"…"}} on a transport/bad-input failure). Runs against the verified
     * head (no block arg). {@code from} empty ⇒ anonymous sender; {@code value} is wei
     * as a decimal string.
     */
    static native String nativeEstimateGasJson(
            long handle, String from, String to, String data, String value);

    /**
     * Verified ENS forward resolution (name → address record) over the revm
     * executor, as JSON ({@code {"status":"ok","addressHex":"0x…","blockNumber":N}},
     * {@code {"status":"noRecord",…}} for a successfully-determined absent record,
     * {@code {"status":"offchain",…}} for an ERC-3668 name (exists, needs CCIP-Read),
     * or {@code {"error":"…"}} on a transport/bad-input failure).
     */
    static native String nativeResolveEnsJson(long handle, String name);

    /**
     * One generic ENS record dispatch (EL-C-5-2): the method and its args travel
     * in {@code paramsJson} (see the Rust {@code host::ens_record_json} doc for
     * the exact shapes); returns the record JSON or {@code {"error": "..."}}.
     */
    static native String nativeEnsRecordJson(long handle, String paramsJson);

    /**
     * Verified {@code eth_getBlockByNumber} for a running handle. {@code blockTag}
     * is an eth block selector ({@code "latest"} / a 0x-hex number / …);
     * {@code fullTransactions} selects fully decoded tx objects (the
     * {@code nativeGetTransactionByHashJson} shape) instead of hashes. Returns
     * the block JSON object, the literal {@code "null"} for a future/unknown
     * block (eth's null), or an {@code "error"} object for a transport /
     * not-running / can't-verify failure.
     */
    static native String nativeGetBlockByNumberJson(
            long handle, String blockTag, boolean fullTransactions);

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

    /**
     * Verified {@code eth_getTransactionReceipt} for a running handle.
     * {@code txHashHex} is the 0x-hex 32-byte transaction hash. Returns the
     * receipt JSON object (verified against the containing block's
     * {@code receiptsRoot}), the literal {@code "null"} for a verified
     * "not seen" (pending/unknown tx — the wallet keeps polling), or an
     * {@code "error"} object for a transport / not-running / can't-verify
     * failure.
     */
    static native String nativeGetTransactionReceiptJson(long handle, String txHashHex);

    /**
     * The "pending" nonce overlay for {@code eth_getTransactionCount(addr, "pending")}:
     * {@code max(minedNonce, our broadcast nonce + 1)} while the wallet's own tx is
     * unmined and unexpired, identity otherwise. Negative only for malformed input /
     * a missing handle — the adapter then serves the plain mined nonce. Only the
     * pending tag may consult this (the overlay is not proof-backed; it only ever
     * RAISES above the verified mined floor and self-heals via TTL).
     */
    static native long nativePendingNonceOverlay(long handle, String addressHex, long minedNonce);

    /**
     * Verified {@code eth_getTransactionByHash} for a running handle.
     * {@code txHashHex} is the 0x-hex 32-byte transaction hash. Returns the tx
     * JSON object (located via the same beacon-anchored, transactionsRoot-verified
     * scan as the receipt path, fully decoded incl. the recovered sender), the
     * literal {@code "null"} for a verified "not seen" (unknown/pending tx), or
     * an {@code "error"} object for a transport / not-running / can't-verify
     * failure — including a located tx of an undecodable future type (found but
     * unrenderable must never read as "unknown").
     */
    static native String nativeGetTransactionByHashJson(long handle, String txHashHex);

    /**
     * Verified {@code eth_getBlockByHash} for a running handle.
     * {@code blockHashHex} is the 0x-hex 32-byte block hash, resolved against
     * blocks this engine has ALREADY verified (receipt scans and by-number
     * serves populate the map) and re-served via the verified by-number path;
     * {@code fullTransactions} selects fully decoded tx objects instead of
     * hashes. Returns the block JSON, the literal {@code "null"} for a hash
     * never verified / reorged away (eth's unknown-block null), or an
     * {@code "error"} object.
     */
    static native String nativeGetBlockByHashJson(
            long handle, String blockHashHex, boolean fullTransactions);

    /**
     * Verified {@code eth_getBlockReceipts} for a running handle. {@code selector}
     * is a tag, a 0x-hex block number, or a 0x-32-byte block hash. Returns the
     * receipts ARRAY JSON (each element the {@code nativeGetTransactionReceiptJson}
     * object shape, the whole list verified against the anchored header's
     * {@code receiptsRoot}), the literal {@code "null"} (verified unknown/future
     * block or a never-verified hash), or an {@code "error"} object.
     */
    static native String nativeGetBlockReceiptsJson(long handle, String selector);

    /**
     * Verified {@code eth_feeHistory} for a running handle: base fees and gas-used
     * ratios from the beacon-anchored header window, reward percentiles (when
     * requested) from bodies verified against {@code transactionsRoot} and receipts
     * against {@code receiptsRoot} (geth's gas-used-weighted walk).
     * {@code newestBlockTag} is the RPC block selector; {@code percentilesJson} is
     * a JSON array of percentiles (e.g. {@code [25.0, 75.0]}), or empty to omit the
     * reward matrix. Returns the feeHistory JSON object
     * ({@code {"oldestBlock","baseFeePerGas","gasUsedRatio"[,"reward"]}}) or an
     * {@code "error"} object — no {@code "null"} literal case for this method.
     */
    static native String nativeFeeHistoryJson(
            long handle, long blockCount, String newestBlockTag, String percentilesJson);
}
