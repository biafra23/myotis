package com.jaeckel.ethp2p.networking.discv4;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Kademlia routing table for discv4.
 *
 * 256 buckets (one per bit of distance), each holding up to K=16 peers.
 * Distance = XOR of keccak256(pubkey) node IDs.
 */
public final class KademliaTable {

    private static final int BUCKET_SIZE = 16;

    public record Entry(InetSocketAddress udpAddr, int tcpPort, Bytes nodeId, long lastSeenMs) {}

    private final Bytes32 localId;
    // Bucket index → list of entries (most recently seen last)
    private final List<Deque<Entry>> buckets;

    public KademliaTable(Bytes32 localId) {
        this.localId = localId;
        this.buckets = new ArrayList<>(256);
        for (int i = 0; i < 256; i++) {
            buckets.add(new ArrayDeque<>());
        }
    }

    /** Add or refresh a peer in the table. */
    public synchronized void add(Entry entry) {
        int bucketIdx = bucketIndex(entry.nodeId());
        Deque<Entry> bucket = buckets.get(bucketIdx);

        // Remove existing entry with same nodeId
        bucket.removeIf(e -> e.nodeId().equals(entry.nodeId()));

        if (bucket.size() < BUCKET_SIZE) {
            bucket.addLast(entry);
        } else {
            // Drop oldest (front); would normally ping it first (ping-before-evict)
            bucket.pollFirst();
            bucket.addLast(entry);
        }
    }

    /** Find the K closest peers to a target node ID. */
    public synchronized List<Entry> closestPeers(Bytes target, int k) {
        List<Entry> all = new ArrayList<>();
        for (Deque<Entry> bucket : buckets) {
            all.addAll(bucket);
        }
        Bytes32 targetId = toNodeId(target);

        // Node IDs are 64-byte pubkeys; hash them to the 32-byte Kademlia id
        // before XOR (Bytes32.wrap on a 64-byte value throws). Matches the
        // Rust twin's to_node_id().
        all.sort(Comparator.comparing(e -> xorDistance(toNodeId(e.nodeId()), targetId)));
        return all.subList(0, Math.min(k, all.size()));
    }

    public synchronized int size() {
        return buckets.stream().mapToInt(Deque::size).sum();
    }

    public synchronized List<Entry> allPeers() {
        List<Entry> result = new ArrayList<>();
        for (Deque<Entry> bucket : buckets) result.addAll(bucket);
        return result;
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------
    private int bucketIndex(Bytes nodeId) {
        int lz = leadingZeros(xorDistance(localId, toNodeId(nodeId)));
        return Math.min(lz, 255);
    }

    /** A 32-byte node id: a 32-byte value used directly, else keccak256(pubkey). */
    private static Bytes32 toNodeId(Bytes keyOrId) {
        return keyOrId.size() == 32 ? Bytes32.wrap(keyOrId)
                : org.apache.tuweni.crypto.Hash.keccak256(keyOrId);
    }

    private static Bytes32 xorDistance(Bytes32 a, Bytes32 b) {
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++) {
            result[i] = (byte) (a.get(i) ^ b.get(i));
        }
        return Bytes32.wrap(result);
    }

    private static int leadingZeros(Bytes32 b) {
        for (int i = 0; i < 32; i++) {
            if (b.get(i) != 0) {
                return i * 8 + Integer.numberOfLeadingZeros(b.get(i) & 0xFF) - 24;
            }
        }
        return 256;
    }
}
