package io.myotis.engines.go;

import io.myotis.api.AccountProofResult;
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
 *       and {@code sendRawTransaction} answer {@code null}: "cannot answer
 *       verified" is exactly their truth, and every capability flag
 *       ({@code supportsStateOverrides} etc.) keeps its false default so hosts
 *       refuse before waking anything.</li>
 * </ul>
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
        // the beacon-FINALIZED execution block — verified, never reorged, ~2-4
        // min behind the tip. Wallets tolerate the lag like the standard
        // light-client skew; 0 (no anchor yet) → null per the contract.
        try {
            long fin = handle.status().finalizedBlockNumber();
            return fin > 0 ? fin : null;
        } catch (RuntimeException e) {
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
        } catch (RuntimeException e) {
            // Never throw from the read surface: an unreadable status reads as
            // "not synced yet" (the Rust adapter's containment rule).
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
            byte[] v = GoChainHandle.hexToBytes(r.valueHex());
            return v.length == 32 ? v : null; // shape drift: refuse, never pad
        } catch (RuntimeException e) {
            log.info("[engines] verified storage read unavailable on the Go engine: {}",
                    e.getMessage());
            return null;
        }
    }

    @Override
    public byte[] sendRawTransaction(byte[] rawTx) {
        return null; // the Go engine is dial-only with no broadcast path yet
    }

    @Override
    public String getTransactionReceipt(byte[] txHash) {
        return null;
    }

    @Override
    public String getTransactionByHash(byte[] txHash) {
        return null;
    }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        return null;
    }

    @Override
    public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) {
        return null;
    }

    @Override
    public String getBlockReceipts(String blockSelector) {
        return null;
    }

    @Override
    public String gasPrice() {
        return null;
    }

    @Override
    public String maxPriorityFeePerGas() {
        return null;
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        return null;
    }

    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        return null; // no EVM
    }

    // ---- internals ----

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
        } catch (RuntimeException e) {
            // Contain every unchecked failure (the error-envelope
            // EngineException — pruned root, stale-anchor park, not-started —
            // included) as "can't answer verified right now".
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
