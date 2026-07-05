package io.myotis.node.api;

import io.myotis.api.SyncState;
import io.myotis.api.VerifiedReads;
import io.myotis.rpc.VerifiedRpcBackend;

import java.math.BigInteger;

/**
 * Maps {@link VerifiedRpcBackend} onto the language-neutral {@link VerifiedReads} shape:
 * BigInteger ⇄ decimal String, hash bytes ⇄ hex, enum for the sync state. Pure conversion —
 * every verification decision stays in the backend. Interim adapter: the SPI-retirement step
 * (plan PR4) makes the backend implement {@link VerifiedReads} directly and deletes this.
 */
final class VerifiedReadsAdapter implements VerifiedReads {

    private final VerifiedRpcBackend backend;

    VerifiedReadsAdapter(VerifiedRpcBackend backend) {
        this.backend = backend;
    }

    @Override public long chainId() { return backend.chainId(); }

    @Override public Long headBlockNumber() { return backend.headBlockNumber(); }

    @Override public SyncState syncState() { return SyncState.valueOf(backend.syncState()); }

    @Override
    public byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block) {
        return backend.call(from, to, data, toBigInt(valueWei), block);
    }

    @Override
    public String getBalance(byte[] address, String block) {
        BigInteger b = backend.getBalance(address, block);
        return b == null ? null : b.toString();
    }

    @Override
    public Long getTransactionCount(byte[] address, String block) {
        return backend.getTransactionCount(address, block);
    }

    @Override
    public byte[] getCode(byte[] address, String block) {
        return backend.getCode(address, block);
    }

    @Override
    public byte[] getStorageAt(byte[] address, byte[] slot32, String block) {
        return backend.getStorageAt(address, slot32, block);
    }

    @Override
    public byte[] sendRawTransaction(byte[] rawTx) {
        return backend.sendRawTransaction(rawTx);
    }

    @Override
    public String getTransactionReceipt(byte[] txHash) {
        return backend.getTransactionReceipt(txHash);
    }

    @Override
    public String getTransactionByHash(byte[] txHash) {
        return backend.getTransactionByHash(txHash);
    }

    @Override
    public String getBlockByNumber(String block, boolean fullTransactions) {
        return backend.getBlockByNumber(block, fullTransactions);
    }

    @Override
    public String getBlockByHash(byte[] blockHash32, boolean fullTransactions) {
        return backend.getBlockByHash(toHex(blockHash32), fullTransactions);
    }

    @Override
    public String gasPrice() {
        BigInteger p = backend.gasPrice();
        return p == null ? null : p.toString();
    }

    @Override
    public String maxPriorityFeePerGas() {
        BigInteger p = backend.maxPriorityFeePerGas();
        return p == null ? null : p.toString();
    }

    @Override
    public String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles) {
        return backend.feeHistory(blockCount, newestBlock, rewardPercentiles);
    }

    @Override
    public Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei) {
        BigInteger gas = backend.estimateGas(from, to, data, toBigInt(valueWei));
        return gas == null ? null : gas.longValue();
    }

    private static BigInteger toBigInt(String decimal) {
        return decimal == null ? null : new BigInteger(decimal);
    }

    private static String toHex(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder sb = new StringBuilder(2 + bytes.length * 2);
        sb.append("0x");
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
