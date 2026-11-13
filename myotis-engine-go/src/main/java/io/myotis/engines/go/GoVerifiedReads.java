package io.myotis.engines.go;

import io.myotis.api.AccountProofResult;
import io.myotis.api.CallResult;
import io.myotis.api.EstimateResult;
import io.myotis.api.SendResult;
import io.myotis.api.StorageProofResult;
import io.myotis.api.SyncState;
import io.myotis.api.VerifiedReads;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Go engine's {@link VerifiedReads} adapter — the read surface the host's
 * {@code LoopbackRpc} listener serves on {@code 127.0.0.1:rpcPort}. It is the
 * honest, smaller sibling of {@code RustVerifiedReads}: the Go build serves the
 * proof-verified ACCOUNT and STORAGE reads (at the beacon-finalized state root —
 * its only anchor) and nothing else yet, so:
 *
 * <ul>
 *   <li>{@code getBalance}/{@code getTransactionCount}/{@code getStorageAt} run
 *       the verified reads; a verified-absent account answers balance/nonce 0 and
 *       a proven-zero slot answers 32 zero bytes (eth semantics, like the
 *       Rust twin).</li>
 *   <li>{@code finalized} is the ONLY served selector
 *       ({@link #supportsFinalizedTag()} true — it is APPLIED, never mapped to
 *       another block). {@code latest}/{@code pending}/a number are NOT served,
 *       because serving them would mean answering from finalized state while the
 *       caller asked about the head: the apply-or-refuse rule (#314) says refuse
 *       — null, the contract's "cannot answer verified" — until the Go engine
 *       grows the optimistic-head anchor.</li>
 *   <li>The EVM reads ({@code call}, {@code estimateGas} — the engine has no
 *       EVM), the block/tx/receipt reads, {@code getCode}, {@code gasPrice},
 *       {@code maxPriorityFeePerGas}, {@code feeHistory}, {@code getBlockReceipts}
 *       and {@code sendRawTransaction} cannot answer verified — but the
 *       refusal arrives through whichever channel says PERMANENT: the JSON-string
 *       reads answer the {@code {"error":…,"code":-32602}} envelope the router
 *       serves as a non-retryable -32602 (no API change needed for them — the
 *       shape the Go capi's {@code Unsupported} builds natively), the detailed
 *       variants of {@code call}/{@code estimateGas}/{@code sendRawTransaction}
 *       answer {@code refused(...)}, and only the genuinely typed reads
 *       ({@code getCode}, {@code gasPrice}, {@code maxPriorityFeePerGas}) stay
 *       {@code null}. A plain null becomes the RETRYABLE -32000, and an engine
 *       missing whole subsystems will not grow them between retries — the #314
 *       apply-or-refuse rule, wire side. Every capability flag
 *       ({@code supportsStateOverrides} etc.) keeps its false default so hosts
 *       refuse before waking anything.</li>
 * </ul>
 *
 * <p>What still reaches the wire as the retryable -32000: refused SELECTORS on
 * the typed state reads ({@code getBalance(addr, "latest")} etc. answer null)
 * and {@code getCode}. A permanent refusal for those needs a refused-channel on
 * the typed methods themselves — an {@code :myotis-api} change, the owner's call
 * (PR #832 review), not this module's. {@code supportsFinalizedTag()} true is
 * what lets {@code finalized} reach this adapter at all (the router would
 * otherwise refuse it up front); with the envelope above,
 * {@code eth_getBlockByNumber("finalized")} is now a permanent refusal too,
 * while {@code eth_getCode(addr, "finalized")} waits on the API channel.
 *
 * <p><b>Never throws</b> — the router's {@code tryVerified} dispatch is not
 * exception-guarded, so every native failure (transport, pruned-root rotation,
 * stale-anchor park — all arriving as the Go engine's error envelope) maps to
 * {@code null}, same rule as the Rust adapter.
 */
final class GoVerifiedReads implements VerifiedReads {

    private static final Logger log = LoggerFactory.getLogger(GoVerifiedReads.class);

    private final GoChainHandle handle;

    GoVerifiedReads(GoChainHandle handle) {
        this.handle = handle;
    }

    @Override
    public long chainId() {
        return handle.chainId();
    }

    @Override
    public Long headBlockNumber() {
        // The Go engine has no optimistic head yet; its eth_blockNumber answer is
        // the beacon-FINALIZED execution block — verified, never reorged, but
        // materially further behind the tip than a node's "latest": mainnet
        // finality lags the head by ~2-3 epochs (~13-19 min at 12s slots) before
        // it moves at all, and the checkpoint it rides advances only ~once per
        // epoch (~6.4 min). A wallet reading balances here sees confirmations and
        // nonce lag of that order — more than the usual light-client skew, and
        // something the engine-parity step (an optimistic anchor) will shrink;
        // honest for a desktop Bee integration meanwhile. 0 (no anchor) → null.
        try {
            long fin = handle.status().finalizedBlockNumber();
            return fin > 0 ? fin : null;
        } catch (RuntimeException | LinkageError e) {
            log.debug("[engines] headBlockNumber unavailable on the Go engine: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public SyncState syncState() {
        try {
            return switch (handle.status().beaconState()) {
                case SYNCED -> SyncState.SYNCED;
                case CATCHING_UP -> SyncState.CATCHING_UP;
                case STARTING, SYNCING -> SyncState.SYNCING;
                case STALE_ANCHOR -> SyncState.STALE_ANCHOR;
            };
        } catch (RuntimeException | LinkageError e) {
            // Never throw from the read surface: an unreadable status reads as
            // "not synced yet" (the Rust adapter's containment rule). LinkageError
            // too: JNA resolves interface-mapping symbols LAZILY, at the FIRST
            // CALL, so a missing symbol on a stale library surfaces here as
            // UnsatisfiedLinkError, not at class-load (PR #832 review).
            log.debug("[engines] syncState fell back to SYNCING on the Go engine: {}",
                    e.getMessage());
            return SyncState.SYNCING;
        }
    }

    /** APPLIED everywhere this engine answers: reads run AT the beacon-finalized
     *  block, never mapped to the head — the inverse of the Rust engine, which
     *  serves both anchors. Hosts may send {@code finalized}; everything else
     *  this adapter answers as unanswerable. */
    @Override
    public boolean supportsFinalizedTag() {
        return true;
    }

    @Override
    public byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block) {
        return null; // no EVM on this engine yet (engine-parity increment)
    }

    /** REFUSED, not the default's UNAVAILABLE (which the router maps to the
     *  retryable -32000): this engine has no EVM and will not grow one between
     *  retries, so a permanent refusal is the honest status (#314, wire side). */
    @Override
    public CallResult callDetailed(byte[] from, byte[] to, byte[] data, String valueWei,
                                   String block, String stateOverridesJson) {
        return CallResult.refused("the Go engine has no EVM yet (engine-parity increment)");
    }

    @Override
    public String getBalance(byte[] address, String block) {
        if (!isFinalizedSelector(block)) return null;
        AccountProofResult r = queryAccount(address, block);
        if (r == null || !isVerified(r)) return null;
        // Verified-absent answers 0 (eth semantics), like the Rust twin.
        return r.exists() ? r.balanceWei() : "0";
    }

    @Override
    public Long getTransactionCount(byte[] address, String block) {
        if (!isFinalizedSelector(block)) return null;
        AccountProofResult r = queryAccount(address, block);
        if (r == null || !isVerified(r)) return null;
        // Verified-absent → nonce 0 (r.nonce() is -1 when !exists). No pending
        // overlay: the Go engine broadcasts nothing yet, so mined == pending.
        return r.exists() ? r.nonce() : 0L;
    }

    @Override
    public byte[] getCode(byte[] address, String block) {
        // The Go build's myotis_get_code_json is a named refusal (the reader
        // fetches codeHashes with the account but no code walk over the trie
        // yet), so there is nothing to call. null = cannot answer verified.
        return null;
    }

    @Override
    public byte[] getStorageAt(byte[] address, byte[] slot32, String block) {
        if (!isFinalizedSelector(block)) return null;
        if (address == null || address.length != 20) return null;
        if (slot32 == null || slot32.length != 32) return null;
        // The verified read takes the slot as an int64 (the ABI's int64_t); a
        // slot at/above 2^63 rides its two's-complement bit pattern (the Go
        // side recovers it), a slot beyond 8 significant BYTES cannot be named
        // by that ABI at all — refuse it, never truncate it into another slot.
        for (int i = 0; i < 24; i++) {
            if (slot32[i] != 0) return null;
        }
        long slot = 0L;
        for (int i = 24; i < 32; i++) {
            slot = (slot << 8) | (slot32[i] & 0xff);
        }
        try {
            StorageProofResult r = handle.getStorageProof(toHex(address), slot, null);
            if (r.verifyMethod() == null) return null; // no verdict (failReason set)
            // A proven-zero / proven-absent slot is 32 zero bytes (the Rust
            // adapter's rule); a present slot carries its word.
            if (!r.exists() || r.valueHex() == null) return new byte[32];
            return toWord(r.valueHex());
        } catch (RuntimeException | LinkageError e) {
            log.info("[engines] verified storage read unavailable on the Go engine: {}",
                    e.getMessage());
            return null;
        }
    }

    /**
     * The Go engine's storage value hex → the 32-byte word the contract returns.
     * The Go reader emits the value MINIMAL big-endian — {@code hex0x(s.Value)}
     * straight off RLP-decoded bytes, and its {@code mpt.DecodeStorageLeaf}
     * REJECTS a leading zero byte ({@code helpers.go}), so slot 42 arrives as
     * {@code "0x2a"}, not {@code "0x00…2a"}. The contract's word is 32 bytes, so
     * left-pad; a value WIDER than 32 bytes is shape drift (a storage word cannot
     * be wider) — refuse it, never truncate into a different word. This is the
     * apply-or-refuse rule (#314) applied to the value's own width.
     */
    static byte[] toWord(String valueHex) {
        byte[] v = GoChainHandle.hexToBytes(valueHex);
        if (v.length > 32) return null;
        byte[] word = new byte[32];
        System.arraycopy(v, 0, word, 32 - v.length, v.length);
        return word;
    }

    @Override
    public byte[] sendRawTransaction(byte[] rawTx) {
        return null; // the Go engine is dial-only with no broadcast path yet
    }

    /** REFUSED (permanent, named) — see {@link #callDetailed} for why not the
     *  default's retryable UNAVAILABLE. */
    @Override
    public SendResult sendRawTransactionDetailed(byte[] rawTx) {
        return SendResult.refused("the Go engine has no transaction broadcast path yet "
                + "(dial-only; engine-parity increment)");
    }

    // The JSON-string reads answer the engine's PERMANENT-REFUSAL envelope —
    // the same `{"error":…,"code":-32602}` shape the Go capi's Unsupported
    // builds natively — because the router unwraps it into a -32602 the wallet
    // stops retrying (RpcRouter.orEngineThrow/permanentCode), while a bare null
    // becomes the generic retryable -32000 that a client repeats forever
    // against an engine with no block/tx/receipt reads at all (PR #832 review;
    // same reasoning as callDetailed). The typed reads (gasPrice,
    // maxPriorityFeePerGas, getBalance, …) have no JSON channel to carry the
    // code — those stay null until the :myotis-api refused-channel decision.

    @Override
    public String getTransactionReceipt(byte[] txHash) {
        return permanentRefusalJson("transaction-receipt");
    }

    @Override
    public String getTransactionByHash(byte[] txHash) {
        return permanentRefusalJson("transaction");
    }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        return permanentRefusalJson("block");
    }

    @Override
    public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) {
        return permanentRefusalJson("block");
    }

    @Override
    public String getBlockReceipts(String blockSelector) {
        return permanentRefusalJson("block-receipts");
    }

    @Override
    public String gasPrice() {
        return null; // typed read: no JSON channel for the code (see above)
    }

    @Override
    public String maxPriorityFeePerGas() {
        return null; // typed read: no JSON channel for the code (see above)
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        return permanentRefusalJson("fee-history");
    }

    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        return null; // no EVM
    }

    /** REFUSED (permanent, named) — see {@link #callDetailed}. */
    @Override
    public EstimateResult estimateGasDetailed(byte[] from, byte[] to, byte[] data, String valueWei) {
        return EstimateResult.refused("the Go engine has no EVM to estimate against yet");
    }

    // ---- internals ----

    /** The router-visible permanent refusal: the exact
     *  {@code {"error":…,"code":-32602}} shape the router's
     *  {@code orEngineThrow}/{@code permanentCode} serve as a non-retryable
     *  -32602 — built through minimal-json, like the Go capi's
     *  {@code permanentErr}, so a message can never break the document. */
    static String permanentRefusalJson(String what) {
        return new com.eclipsesource.json.JsonObject()
                .add("error", "go engine: the " + what
                        + " read is not served by this build yet (engine-parity increment)")
                .add("code", -32602)
                .toString();
    }

    /** Only the exact {@code finalized} tag (trimmed, case-insensitive); a
     *  missing/empty selector means the caller asked for the head — which this
     *  engine cannot anchor, so it is refused, not quietly run at finalized. */
    static boolean isFinalizedSelector(String block) {
        return block != null && "finalized".equals(block.trim()
                .toLowerCase(java.util.Locale.ROOT));
    }

    private AccountProofResult queryAccount(byte[] address, String block) {
        // An eth address is exactly 20 bytes; a bogus length never crosses the
        // FFI (the Rust adapter's rule).
        if (address == null || address.length != 20) return null;
        try {
            return handle.accountVerified(toHex(address), block);
        } catch (RuntimeException | LinkageError e) {
            // Contain every unchecked failure (the error-envelope
            // EngineException — pruned root, stale-anchor park, not-started —
            // and the LinkageError JNA's lazy interface-mapping symbol
            // resolution can throw on the first call against a stale library)
            // as "can't answer verified right now".
            log.info("[engines] verified account read unavailable on the Go engine: {}",
                    e.getMessage());
            return null;
        }
    }

    /** A verified answer produced a verdict (verifyMethod set), not a failReason. */
    private static boolean isVerified(AccountProofResult r) {
        return r.verifyMethod() != null;
    }

    /** Fixed-width bytes → lowercase 0x-hex: the ONE definition
     *  ({@code :myotis-engine-common}'s Hex — same call the Rust adapter makes;
     *  not {@code java.util.HexFormat}, which is Android API 34). */
    private static String toHex(byte[] bytes) {
        return io.myotis.engines.common.Hex.formatHexPrefixed(bytes);
    }
}
