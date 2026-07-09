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
 * {@code getBlockByNumber}, {@code gasPrice}, {@code maxPriorityFeePerGas},
 * {@code sendRawTransaction}, and a 21000 {@code estimateGas} shortcut for plain
 * transfers. The EVM-backed reads — {@code call}, and {@code estimateGas} for a
 * contract/calldata target — return {@code null} ("cannot answer verified right
 * now"), which the router maps to a strict-mode {@code -32000}, until EL-C (revm).
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
            return switch (handle.status().beaconState()) {
                case SYNCED -> SyncState.SYNCED;
                case CATCHING_UP -> SyncState.CATCHING_UP;
                case STARTING, SYNCING -> SyncState.SYNCING;
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
        // Verified-absent → nonce 0 (r.nonce() is -1 when !exists). No pending
        // overlay yet: "pending" resolves to the verified head nonce, which is
        // correct for a wallet sending its first not-yet-mined tx.
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
        return r.exists() ? r.nonce() : 0L;
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
    public byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block) {
        if (!isServableBlock(block)) return null;
        if (to == null || to.length != 20) return null;        // 'to' is required
        if (from != null && from.length != 20) return null;    // if present, must be 20 bytes
        try {
            // 'from' empty → anonymous zero sender; the revm executor runs the call
            // over verified state and returns the result bytes (or null on a revert /
            // unverifiable outcome, matching the reference engine).
            return handle.ethCallVerified(
                    from == null ? "" : toHex(from),
                    toHex(to),
                    data == null ? "" : toHex(data),
                    valueWei == null ? "" : valueWei,
                    block);
        } catch (RuntimeException e) {
            log.debug("[engines] verified eth_call unavailable: {}", e.getMessage());
            return null;
        }
    }

    // ---- not yet served verified on the Rust engine (later EL-C slices) ----

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
    @Override public String getTransactionReceipt(byte[] txHash) { return null; }
    @Override public String getTransactionByHash(byte[] txHash) { return null; }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        // Full tx objects need tx decode + sender recovery — not served verified yet
        // (mirrors the Java engine); null → strict -32000.
        if (fullTransactions) return null;
        String tag = (block == null || block.isBlank()) ? "latest" : block;
        try {
            // Returns the block JSON, the "null" literal (verified future/unknown
            // block), or throws when it can't verify (→ null → -32000).
            return handle.blockByNumberJson(tag);
        } catch (RuntimeException e) {
            log.debug("[engines] verified block read unavailable: {}", e.getMessage());
            return null;
        }
    }

    @Override public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) { return null; }
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

    @Override public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) { return null; }
    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        // The trivial case only, without the EVM (EL-C): a plain value transfer to an
        // EOA with no calldata costs exactly 21000 intrinsic gas. Anything else needs
        // the EVM → null:
        //  - to == null  → contract creation
        //  - non-empty data → runs code
        //  - a recipient WITH code (a contract, or a 7702-delegated EOA) → its
        //    receive/fallback (or delegated code) can run on a bare value transfer.
        if (to == null || to.length != 20) return null;
        if (data != null && data.length != 0) return null;
        byte[] code = getCode(to, "latest"); // verified recipient bytecode
        if (code == null || code.length != 0) return null;
        return 21_000L;
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

    /** How far ABOVE the anchored head a number-pin is still served (the head may
     *  advance a few blocks between eth_blockNumber and the pinned read). */
    private static final long BLOCK_NUM_TOLERANCE = 16;
    /** How far BELOW the anchored head a number-pin is still served from the head's
     *  verified state (a genuinely older block can't be represented). */
    private static final long BLOCK_NUM_LAG_TOLERANCE = 64;

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
     *  supplied lazily (fetched only when a numeric pin needs validating). */
    static boolean blockInWindow(String block, java.util.function.Supplier<Long> head) {
        if (block == null || block.isBlank()) return true;
        String b = block.trim();
        if (b.equalsIgnoreCase("latest") || b.equalsIgnoreCase("pending")
                || b.equalsIgnoreCase("safe") || b.equalsIgnoreCase("finalized")) {
            return true;
        }
        if (b.equalsIgnoreCase("earliest")) return false;
        long n;
        try {
            // Explicit radix (not Long.decode, which reads a leading-zero decimal as
            // octal). JSON-RPC block numbers are 0x-hex; decimal is tolerated too.
            n = (b.startsWith("0x") || b.startsWith("0X"))
                    ? Long.parseLong(b.substring(2), 16)
                    : Long.parseLong(b, 10);
        } catch (NumberFormatException e) {
            return false;
        }
        if (n < 0) return false;
        Long h = head.get();
        if (h == null) return false; // not synced enough to validate the pin
        return n >= h - BLOCK_NUM_LAG_TOLERANCE && n <= h + BLOCK_NUM_TOLERANCE;
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
