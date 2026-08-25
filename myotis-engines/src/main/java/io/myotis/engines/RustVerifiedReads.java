package io.myotis.engines;

import io.myotis.api.AccountProofResult;
import io.myotis.api.EngineException;
import io.myotis.api.SyncState;
import io.myotis.api.VerifiedReads;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Rust engine's {@link VerifiedReads} adapter — the verified eth_* read
 * surface the shared {@code jsonrpc-server} ({@code MyotisRpcServer}/{@code RpcRouter})
 * serves on {@code 127.0.0.1:rpcPort}. It maps each JSON-RPC read onto the Rust
 * engine's already-live, beacon-anchored verified queries
 * ({@link RustChainHandle#requestAccount}) and status.
 *
 * <p>It answers the reads a wallet needs for an ETH send, from the beacon-anchored,
 * proof-verified queries: {@code chainId}, {@code headBlockNumber}, {@code syncState},
 * {@code getBalance}, {@code getTransactionCount}, {@code getCode}, {@code getStorageAt},
 * {@code getBlockByNumber}, {@code getBlockByHash}, {@code getTransactionReceipt},
 * {@code getTransactionByHash}, {@code gasPrice}, {@code maxPriorityFeePerGas},
 * {@code feeHistory}, {@code sendRawTransaction}, plus the EVM-backed {@code call}
 * and {@code estimateGas} (revm over proof-verified state). Block reads serve
 * both shapes: tx hashes or, with {@code fullTransactions=true}, fully decoded
 * tx objects (verified against the block's {@code transactionsRoot}).
 *
 * <p><b>Head-anchored.</b> The Rust reader verifies against the peer's fresh head
 * (the CL-anchored latest state), so state reads resolve to that head. A selector
 * of {@code latest}/{@code pending}/{@code safe}/{@code finalized}/default, OR a
 * specific number within {@code [head-64, head+16]} (wallets pin reads to the
 * just-fetched latest number), is served from the verified head. A genuinely older
 * block returns {@code null} — the head state does NOT stand in for it. So within
 * the lag window a near-head number resolves to the verified head state (standard
 * light-client skew); a caller needing exact historical state below the window
 * gets {@code null}, never head data mislabeled as an old block.
 *
 * <p><b>Never throws.</b> {@link RustChainHandle#requestAccount} raises an
 * {@link EngineException} on a transport / not-running failure, but the router's
 * {@code tryVerified} dispatch is not exception-guarded and the Java backend it
 * mirrors never throws — so every method here maps such a failure to {@code null}
 * ("can't answer verified right now"), never an HTTP 500 to the wallet.
 */
final class RustVerifiedReads implements VerifiedReads {

    private static final Logger log = LoggerFactory.getLogger(RustVerifiedReads.class);

    private final RustChainHandle handle;

    RustVerifiedReads(RustChainHandle handle) {
        this.handle = handle;
    }

    @Override
    public long chainId() {
        return handle.chainId();
    }

    @Override
    public Long headBlockNumber() {
        // The beacon optimistic-head execution block number (eth_blockNumber), from
        // the anchor via the status JSON. 0 == the anchor has no head yet (not
        // synced enough) → null, per the contract.
        //
        // Head/state skew: this is the beacon optimistic head N, whereas getBalance/
        // getCode/getStorageAt("latest") are served against a peer's fresh tip, which
        // is typically a few blocks AHEAD of N. Both are beacon-verified, so a read
        // at a block > N is not a trust violation — just the standard light-client
        // skew that wallets (MetaMask) tolerate.
        try {
            // Wake-and-hold first (mirrors GatedVerifiedReads.headBlockNumber): a
            // request on a paused stack triggers the resume and is held until the
            // node can answer, rather than serving the frozen pause-time head.
            if (!handle.awaitReadyForReads()) return null;
            long head = handle.status().optimisticBlockNumber();
            return head > 0 ? head : null;
        } catch (RuntimeException e) {
            log.debug("[engines] headBlockNumber unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public SyncState syncState() {
        try {
            // Note activity and kick a wake if paused, but answer NON-blocking from
            // the (frozen) status — wallets gate on sync state, and holding a status
            // probe for the full wake would deadlock them (mirrors GatedVerifiedReads).
            handle.noteActivityAndWake();
            return switch (handle.status().beaconState()) {
                case SYNCED -> SyncState.SYNCED;
                case CATCHING_UP -> SyncState.CATCHING_UP;
                case STARTING, SYNCING -> SyncState.SYNCING;
                case STALE_ANCHOR -> SyncState.STALE_ANCHOR;
            };
        } catch (RuntimeException e) {
            // Never throw from the read surface: an unreadable status reads as
            // "not synced yet" rather than crashing the eth_syncing request. Catch
            // the broad RuntimeException (not just EngineException) so any unchecked
            // failure from the native status path stays contained (the router's
            // tryVerified dispatch is not exception-guarded).
            log.debug("[engines] syncState fell back to SYNCING: {}", e.getMessage());
            return SyncState.SYNCING;
        }
    }

    @Override
    public String getBalance(byte[] address, String block) {
        if (!isServableBlock(block)) return null;
        AccountProofResult r = queryAccount(address);
        if (r == null || !isVerified(r)) return null;
        // A verified-absent account has balance 0 (eth semantics), even though the
        // proof-of-exclusion carries a null balanceWei.
        return r.exists() ? r.balanceWei() : "0";
    }

    @Override
    public Long getTransactionCount(byte[] address, String block) {
        if (!isServableBlock(block)) return null;
        AccountProofResult r = queryAccount(address);
        if (r == null || !isVerified(r)) return null;
        // Verified-absent → nonce 0 (r.nonce() is -1 when !exists).
        //
        // Nonce freshness: the Java backend (VerifiedRpcBackend) gates nonce
        // serving on a TIGHTER staleness bound than balance, because a stale nonce
        // is uniquely dangerous — the wallet signs against it and the tx bounces
        // ("nonce too low") or silently replaces a pending one. This adapter has no
        // separate bound: the Rust verified read only sets verifyMethod against a
        // beacon-anchored head that is not behind finalized (a stale-behind peer
        // fails verification → null), so staleness is bounded to the peer's current
        // tip (slot-scale seconds). Replicating the Java engine's explicit tighter
        // nonce gate is a follow-up, pending a head-age field in the Rust status.
        long mined = r.exists() ? r.nonce() : 0L;
        // ONLY the pending tag consults the sent-tx overlay (max(mined, ours+1)
        // while our broadcast is unmined+unexpired) — the Java engine's
        // getTransactionCount "pending" branch, mirrored.
        if ("pending".equals(block)) {
            return handle.pendingNonceOverlay(toHex(address), mined);
        }
        return mined;
    }

    @Override
    public byte[] getCode(byte[] address, String block) {
        if (!isServableBlock(block)) return null;
        if (address == null || address.length != 20) return null;
        try {
            return handle.codeVerified(toHex(address));
        } catch (RuntimeException e) {
            log.debug("[engines] verified code read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public byte[] getStorageAt(byte[] address, byte[] slot32, String block) {
        if (!isServableBlock(block)) return null;
        if (address == null || address.length != 20) return null;
        // The router pads the position to a full 32-byte word (asWord32) before the
        // call; reject anything else defensively.
        if (slot32 == null || slot32.length != 32) return null;
        try {
            return handle.storageAtVerified(toHex(address), toHex(slot32));
        } catch (RuntimeException e) {
            log.debug("[engines] verified storage read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public boolean supportsContractCreation() {
        return true;   // revm runs the init code (TxKind::Create)
    }

    @Override
    public boolean supportsStateOverrides() {
        return true;   // the revm executor applies them (myotis_evm::overrides)
    }

    @Override
    public byte[] callWithOverrides(
            byte[] from,
            byte[] to,
            byte[] data,
            String valueWei,
            String block,
            String stateOverridesJson) {
        if (!isServableBlock(block)) return null;
        // A NULL `to` is contract creation (eth_call with no `to`), passed to
        // the engine as an empty string — not an error.
        if (to != null && to.length != 20) return null;
        if (from != null && from.length != 20) return null;
        try {
            return handle.ethCallVerifiedWithOverrides(
                    from == null ? "" : toHex(from),
                    to == null ? "" : toHex(to),
                    data == null ? "" : toHex(data),
                    valueWei == null ? "" : valueWei,
                    block,
                    stateOverridesJson == null ? "" : stateOverridesJson);
        } catch (RuntimeException e) {
            log.debug("[engines] verified eth_call (overrides) unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block) {
        if (!isServableBlock(block)) return null;
        if (to != null && to.length != 20) return null;        // null 'to' = creation
        if (from != null && from.length != 20) return null;    // if present, must be 20 bytes
        try {
            // 'from' empty → anonymous zero sender; the revm executor runs the call
            // over verified state and returns the result bytes (or null on a revert /
            // unverifiable outcome — callDetailed carries the revert payload).
            return handle.ethCallVerified(
                    from == null ? "" : toHex(from),
                    to == null ? "" : toHex(to),
                    data == null ? "" : toHex(data),
                    valueWei == null ? "" : valueWei,
                    block);
        } catch (RuntimeException e) {
            log.debug("[engines] verified eth_call unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public io.myotis.api.CallResult callDetailed(byte[] from, byte[] to, byte[] data,
                                                 String valueWei, String block,
                                                 String stateOverridesJson) {
        // Same guards as call()/callWithOverrides(); all are "cannot answer", not reverts.
        if (!isServableBlock(block)) return io.myotis.api.CallResult.unavailable("block not servable");
        if (to != null && to.length != 20) return io.myotis.api.CallResult.unavailable("malformed to");
        if (from != null && from.length != 20) return io.myotis.api.CallResult.unavailable("malformed from");
        try {
            String fromHex = from == null ? "" : toHex(from);
            String toHex20 = to == null ? "" : toHex(to);
            String dataHex = data == null ? "" : toHex(data);
            String value = valueWei == null ? "" : valueWei;
            return (stateOverridesJson == null || stateOverridesJson.isEmpty())
                    ? handle.ethCallVerifiedDetailed(fromHex, toHex20, dataHex, value, block)
                    : handle.ethCallVerifiedDetailedWithOverrides(
                            fromHex, toHex20, dataHex, value, block, stateOverridesJson);
        } catch (RuntimeException e) {
            log.debug("[engines] verified eth_call (detailed) unavailable: {}", e.getMessage());
            return io.myotis.api.CallResult.unavailable(e.getMessage());
        }
    }

    @Override
    public byte[] sendRawTransaction(byte[] rawTx) {
        if (rawTx == null || rawTx.length == 0) return null;
        try {
            // The engine never signs — it gossips the user-signed tx and returns
            // keccak256(rawTx). null on no-peer / not-a-tx (→ strict -32000).
            return handle.sendRawTransactionVerified(toHex(rawTx));
        } catch (RuntimeException e) {
            log.debug("[engines] sendRawTransaction failed: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String getTransactionReceipt(byte[] txHash) {
        // A tx hash is exactly 32 bytes; anything else can't be answered.
        if (txHash == null || txHash.length != 32) return null;
        try {
            // The receipt JSON (verified vs the anchored header's receiptsRoot), the
            // "null" literal (verified "not seen" — pending/unknown, the wallet keeps
            // polling), or throws when it can't verify (→ null → strict -32000).
            return handle.transactionReceiptJson(toHex(txHash));
        } catch (RuntimeException e) {
            log.debug("[engines] verified receipt read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String getTransactionByHash(byte[] txHash) {
        // A tx hash is exactly 32 bytes; anything else can't be answered.
        if (txHash == null || txHash.length != 32) return null;
        try {
            // The tx JSON (located via the transactionsRoot-verified scan, fully
            // decoded incl. the recovered sender), the "null" literal (verified
            // "not seen" — unknown/pending), or throws when it can't verify
            // (→ null → strict -32000). Unlike the Java engine there is no
            // own-sent-tx pending answer yet (needs the sent-tx cache).
            return handle.transactionByHashJson(toHex(txHash));
        } catch (RuntimeException e) {
            log.debug("[engines] verified tx read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        String tag = (block == null || block.isBlank()) ? "latest" : block;
        try {
            // Returns the block JSON (tx hashes, or fully decoded tx objects when
            // fullTransactions), the "null" literal (verified future/unknown
            // block), or throws when it can't verify (→ null → -32000).
            return handle.blockByNumberJson(tag, fullTransactions);
        } catch (RuntimeException e) {
            log.debug("[engines] verified block read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) {
        if (blockHash32 == null || blockHash32.length != 32) return null;
        try {
            // The block JSON (tx hashes, or fully decoded tx objects when
            // fullTransactions), the "null" literal (a hash this engine never
            // verified / reorged away), or throws (→ null → strict -32000).
            return handle.blockByHashJson(toHex(blockHash32), fullTransactions);
        } catch (RuntimeException e) {
            log.debug("[engines] verified block-by-hash read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String getLogs(String filterJson) {
        try {
            // Array or {"error": ...} — passed through verbatim; the router
            // turns the error envelope into a -32000 with the engine's
            // message (coverage progress, unwatched address, ...).
            return handle.getLogsJson(filterJson);
        } catch (RuntimeException e) {
            log.debug("[engines] getLogs unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String getBlockReceipts(String blockSelector) {
        try {
            String sel = (blockSelector == null || blockSelector.isBlank())
                    ? "latest" : blockSelector;
            // The receipts array JSON (every element verified vs the anchored
            // header's receiptsRoot), the "null" literal (verified unknown/future
            // block or never-verified hash), or throws (→ null → strict -32000).
            return handle.blockReceiptsJson(sel);
        } catch (RuntimeException e) {
            log.debug("[engines] verified blockReceipts read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String gasPrice() {
        // Decimal wei (next-block base fee + suggested tip), or null when unverifiable.
        try {
            return handle.feeEstimate().gasPriceWei();
        } catch (RuntimeException e) {
            log.debug("[engines] gasPrice unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String maxPriorityFeePerGas() {
        // Decimal wei (median tip over recent verified blocks), or null.
        try {
            return handle.feeEstimate().maxPriorityFeePerGasWei();
        } catch (RuntimeException e) {
            log.debug("[engines] maxPriorityFeePerGas unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        if (blockCount < 1) return null;
        try {
            // Percentiles cross as a JSON number array (compound values cross as
            // JSON, like every other native); null → empty → no reward matrix.
            // Arrays.toString emits "[25.0, 75.0]" — valid JSON.
            String percentilesJson = rewardPercentiles == null
                    ? "" : java.util.Arrays.toString(rewardPercentiles);
            String tag = (newestBlock == null || newestBlock.isBlank()) ? "latest" : newestBlock;
            // The feeHistory JSON object, or throws when it can't verify
            // (→ null → strict -32000). No "null" literal case for this method.
            return handle.feeHistoryJson(blockCount, tag, percentilesJson);
        } catch (RuntimeException e) {
            log.debug("[engines] verified feeHistory unavailable: {}", e.getMessage());
            return null;
        }
    }
    @Override
    public io.myotis.api.EstimateResult estimateGasDetailed(byte[] from, byte[] to,
                                                            byte[] data, String valueWei) {
        // Same guards + 21000 fast path as estimateGas(); all are "cannot answer",
        // not reverts.
        if (to == null || to.length != 20) {
            return io.myotis.api.EstimateResult.unavailable("contract creation not estimated");
        }
        if (from != null && from.length != 20) {
            return io.myotis.api.EstimateResult.unavailable("malformed from");
        }
        if (data == null || data.length == 0) {
            byte[] code = getCode(to, "latest");
            if (code != null && code.length == 0) return io.myotis.api.EstimateResult.ok(21_000L);
            if (code == null) return io.myotis.api.EstimateResult.unavailable("recipient unverifiable");
        }
        try {
            return handle.estimateGasVerifiedDetailed(
                    from == null ? "" : toHex(from),
                    toHex(to),
                    data == null ? "" : toHex(data),
                    valueWei == null ? "" : valueWei);
        } catch (RuntimeException e) {
            log.debug("[engines] verified estimateGas (detailed) unavailable: {}", e.getMessage());
            return io.myotis.api.EstimateResult.unavailable(e.getMessage());
        }
    }

    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        // Legacy two-state view of estimateGasDetailed (single source for the
        // guards + 21000 fast path) — a revert reads as null here.
        io.myotis.api.EstimateResult r = estimateGasDetailed(from, to, data, valueWei);
        return r.status() == io.myotis.api.EstimateResult.Status.OK ? r.gas() : null;
    }

    // ---- helpers ----

    /** Run the verified account query, mapping a transport/not-running failure to null. */
    private AccountProofResult queryAccount(byte[] address) {
        // An eth address is exactly 20 bytes. Reject any other length (incl. null) up
        // front — "can't answer" (null) rather than round-tripping a bogus key through
        // the native query — so a malformed address never crosses the JNI boundary.
        if (address == null || address.length != 20) return null;
        try {
            return handle.requestAccount(toHex(address));
        } catch (RuntimeException e) {
            // Contain any unchecked failure (transport/not-running EngineException,
            // or a raw unchecked throwable off the native path) as "can't answer
            // verified right now" — the router's tryVerified dispatch is not
            // exception-guarded, so nothing may escape this adapter.
            log.debug("[engines] verified account read unavailable: {}", e.getMessage());
            return null;
        }
    }

    /** A verified answer produced a verdict (verifyMethod set), not a failReason. */
    private static boolean isVerified(AccountProofResult r) {
        return r.verifyMethod() != null;
    }

    /**
     * Whether a block selector can be served from the anchored head. Accepts the
     * head tags (latest/pending/safe/finalized/default) AND a specific block NUMBER
     * within [head-64, head+16] — wallets (MetaMask) pin reads to the number they
     * just got from eth_blockNumber, which is at/near the head; rejecting those
     * left every number-pinned getBalance/getCode erroring. A genuinely older block
     * (or earliest / not-synced) is not served (the reader is head-anchored).
     * Mirrors the Java engine's {@code verifiedHeadFor} window.
     */
    private boolean isServableBlock(String block) {
        // headBlockNumber() (a status read) is fetched only for the number path.
        return blockInWindow(block, this::headBlockNumber);
    }

    /** Package-private, JNI-free: the block-window decision, with the anchored head
     *  supplied lazily (fetched only when a numeric pin needs validating). The
     *  policy + tolerances live ONCE in jsonrpc-server's RpcBlockWindow, shared
     *  with the iOS backend so the serving window can never drift between hosts. */
    static boolean blockInWindow(String block, java.util.function.Supplier<Long> head) {
        return io.myotis.jsonrpc.RpcBlockWindow.INSTANCE.blockInWindow(block, head::get);
    }

    /** Fixed-width bytes → lowercase 0x-hex (a 20-byte address or a 32-byte
     *  storage position — the forms the natives expect). */
    private static String toHex(byte[] bytes) {
        if (bytes == null) throw new EngineException("byte input is required");
        // HexFormat is desugared for Android here (desugar_jdk_libs 2.1.x) — the same
        // API node-core (ChainStack) and myotis-ens already rely on in main code.
        return "0x" + java.util.HexFormat.of().formatHex(bytes);
    }
}
