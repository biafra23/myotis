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
     * Wake-and-wait, then return the live backend — or null (unanswerable). The
     * backend reference is re-read from the stack after the wait, so a resume's
     * freshly-built backend is picked up and a paused stack's torn-down one is
     * never touched.
     */
    private VerifiedReads awaitReady() {
        return stack.awaitReadyForReads(ChainStack.WAKE_WAIT_CAP_MS);
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
        VerifiedReads d = awaitReady();
        return d == null ? null : d.headBlockNumber();
    }

    @Override
    public byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.call(from, to, data, valueWei, block);
    }

    @Override
    public String getBalance(byte[] address, String block) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getBalance(address, block);
    }

    @Override
    public Long getTransactionCount(byte[] address, String block) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getTransactionCount(address, block);
    }

    @Override
    public byte[] getCode(byte[] address, String block) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getCode(address, block);
    }

    @Override
    public byte[] getStorageAt(byte[] address, byte[] slot32, String block) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getStorageAt(address, slot32, block);
    }

    @Override
    public byte[] sendRawTransaction(byte[] rawTx) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.sendRawTransaction(rawTx);
    }

    @Override
    public String getTransactionReceipt(byte[] txHash) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getTransactionReceipt(txHash);
    }

    @Override
    public String getTransactionByHash(byte[] txHash) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getTransactionByHash(txHash);
    }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getBlockByNumber(block, fullTransactions);
    }

    @Override
    public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.getBlockByHash(blockHash32, fullTransactions);
    }

    @Override
    public String gasPrice() {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.gasPrice();
    }

    @Override
    public String maxPriorityFeePerGas() {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.maxPriorityFeePerGas();
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.feeHistory(blockCount, newestBlock, rewardPercentiles);
    }

    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        VerifiedReads d = awaitReady();
        return d == null ? null : d.estimateGas(from, to, data, valueWei);
    }
}
