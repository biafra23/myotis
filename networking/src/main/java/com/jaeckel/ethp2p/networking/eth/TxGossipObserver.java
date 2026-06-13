package com.jaeckel.ethp2p.networking.eth;

import org.apache.tuweni.bytes.Bytes32;

/**
 * Sink for transaction hashes observed in mempool gossip — Transactions (0x12) and
 * NewPooledTransactionHashes (0x18).
 *
 * <p>A light wallet ignores the mempool firehose for state verification. But a node
 * that has just broadcast its <em>own</em> signed tx can watch for that exact hash
 * coming back over gossip to confirm the tx is propagating (a "mini-mempool" of only
 * our own sends) — and, by its continued absence, that it may have been dropped.
 *
 * <p>{@link EthHandler} consults {@link #watchingAny()} before decoding any gossip
 * message, so when nothing of ours is in flight the firehose is dropped untouched on
 * the event loop (its normal, cheap path). Only while we hold an unconfirmed broadcast
 * does the handler decode announcements/bodies and report their hashes here, where a
 * cheap membership check matches them against what we sent.
 */
public interface TxGossipObserver {

    /** True while the node holds at least one broadcast-but-unconfirmed tx worth
     *  watching for. Called on the event loop for every gossip message, so it must be
     *  O(1) and allocation-free; when false the handler skips gossip decoding entirely. */
    boolean watchingAny();

    /** Report one tx hash seen on the network. Cheap no-op for hashes that aren't ours. */
    void onTxHashSeen(Bytes32 txHash);
}
