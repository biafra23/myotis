package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import io.myotis.api.SyncState;
import io.myotis.api.VerifiedReads;

/**
 * The {@link VerifiedReads} the JSON-RPC server (and any host holding
 * {@code ChainHandle.reads()}) keeps across the stack's whole lifetime, while the
 * real {@code VerifiedRpcBackend} underneath is torn down on pause and rebuilt on
 * resume. Every verified read first goes through
 * {@link ChainStack#awaitReadyForReads}: a request arriving while the stack is
 * paused triggers the wake and is held (bounded) until the node can answer — a
 * {@code null} return then maps to the router's retryable "cannot be served
 * verified right now" error, so no jsonrpc-server change is needed.
 *
 * <p>Two deliberate exceptions to the hold:
 * <ul>
 *   <li>{@link #chainId()} answers from static network config without waking —
 *       wallet polling must not keep the node awake.</li>
 *   <li>{@link #syncState()} notes activity and kicks the wake but answers
 *       non-blocking from the retained {@code BeaconSyncState} — wallets gate on
 *       sync state, and holding a status probe for the full wake would deadlock
 *       them.</li>
 * </ul>
 */
final class GatedVerifiedReads implements VerifiedReads {

    private final ChainStack stack;

    GatedVerifiedReads(ChainStack stack) {
        this.stack = stack;
    }

    /**
     * Wake-and-wait, then run {@code call} against the live backend under an in-flight
     * guard; returns null (unanswerable) without calling when no backend is available.
     * The backend is re-read from the stack after the wait, so a resume's freshly-built
     * backend is picked up and a paused stack's torn-down one is never touched. The
     * {@code beginRequest}/{@code endRequest} pair marks the stack busy so the host idle
     * timer can't pause it mid-call (which would close the backend under the request).
     */
    private <T> T guarded(java.util.function.Function<VerifiedReads, T> call) {
        VerifiedReads d = stack.awaitReadyForReads(ChainStack.WAKE_WAIT_CAP_MS);
        if (d == null) return null;
        stack.beginRequest();
        try {
            return call.apply(d);
        } finally {
            stack.endRequest();
        }
    }

    @Override
    public long chainId() {
        return stack.network().networkId();
    }

    @Override
    public SyncState syncState() {
        stack.noteActivityAndWake();
        BeaconSyncState bss = stack.beaconSyncState();
        if (bss == null) return SyncState.SYNCING;
        return SyncState.valueOf(bss.getSyncState(
                stack.network().clGenesisTime(), stack.network().secondsPerSlot()).name());
    }

    @Override
    public Long headBlockNumber() {
        return guarded(d -> d.headBlockNumber());
    }

    @Override
    public byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block) {
        return guarded(d -> d.call(from, to, data, valueWei, block));
    }

    @Override
    public String getBalance(byte[] address, String block) {
        return guarded(d -> d.getBalance(address, block));
    }

    @Override
    public Long getTransactionCount(byte[] address, String block) {
        return guarded(d -> d.getTransactionCount(address, block));
    }

    @Override
    public byte[] getCode(byte[] address, String block) {
        return guarded(d -> d.getCode(address, block));
    }

    @Override
    public byte[] getStorageAt(byte[] address, byte[] slot32, String block) {
        return guarded(d -> d.getStorageAt(address, slot32, block));
    }

    @Override
    public byte[] sendRawTransaction(byte[] rawTx) {
        return guarded(d -> d.sendRawTransaction(rawTx));
    }

    @Override
    public String getTransactionReceipt(byte[] txHash) {
        return guarded(d -> d.getTransactionReceipt(txHash));
    }

    @Override
    public String getTransactionByHash(byte[] txHash) {
        return guarded(d -> d.getTransactionByHash(txHash));
    }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        return guarded(d -> d.getBlockByNumber(block, fullTransactions));
    }

    @Override
    public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) {
        return guarded(d -> d.getBlockByHash(blockHash32, fullTransactions));
    }

    @Override
    public String getBlockReceipts(String blockSelector) {
        return guarded(d -> d.getBlockReceipts(blockSelector));
    }

    @Override
    public String gasPrice() {
        return guarded(VerifiedReads::gasPrice);
    }

    @Override
    public String maxPriorityFeePerGas() {
        return guarded(VerifiedReads::maxPriorityFeePerGas);
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        return guarded(d -> d.feeHistory(blockCount, newestBlock, rewardPercentiles));
    }

    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        return guarded(d -> d.estimateGas(from, to, data, valueWei));
    }
}
