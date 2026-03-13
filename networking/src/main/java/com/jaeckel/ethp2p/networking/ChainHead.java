package com.jaeckel.ethp2p.networking;

import org.apache.tuweni.bytes.Bytes32;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe holder for the best known chain head.
 * Updated as we learn about new blocks from peers.
 */
public final class ChainHead {

    public record Head(long blockNumber, Bytes32 blockHash) {}

    private final AtomicReference<Head> head;

    public ChainHead(Bytes32 genesisHash) {
        this.head = new AtomicReference<>(new Head(0, genesisHash));
    }

    /**
     * Update to a newer head if blockNumber is higher than current.
     * Uses CAS to be lock-free and thread-safe.
     */
    public void update(long blockNumber, Bytes32 blockHash) {
        while (true) {
            Head current = head.get();
            if (blockNumber <= current.blockNumber) return;
            Head next = new Head(blockNumber, blockHash);
            if (head.compareAndSet(current, next)) return;
        }
    }

    public Head get() {
        return head.get();
    }
}
