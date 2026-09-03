package io.myotis.evm.world;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Abstraction over a snap/1-capable peer connection.
 *
 * <p>{@code :myotis-evm} stays decoupled from {@code :networking} on purpose;
 * the wallet integration plugs an implementation of this interface backed by
 * an {@code EthHandler} (or a pool of them) when constructing the
 * {@link SnapBackedStateOracle}. Tests use an in-memory fixture
 * implementation.
 *
 * <p>Both methods return raw response bytes — the oracle is responsible for
 * verifying them (proof verification for trie nodes, hash matching for
 * bytecode).
 */
public interface SnapPeer {

    /**
     * One {@code GetTrieNodes} path set per the snap/1 spec: an account path
     * followed by zero or more storage paths within that account's storage
     * trie. Paths are full keccak256 hashes (32 bytes) for leaf-node lookups.
     */
    record PathSet(Bytes accountPath, List<Bytes> storagePaths) {

        public PathSet {
            Objects.requireNonNull(accountPath, "accountPath");
            Objects.requireNonNull(storagePaths, "storagePaths");
        }

        public static PathSet account(Bytes32 accountHash) {
            return new PathSet(accountHash, List.of());
        }

        public static PathSet storageSlot(Bytes32 accountHash, Bytes32 slotHash) {
            return new PathSet(accountHash, List.of(slotHash));
        }
    }

    /**
     * Issue a snap/1 GetTrieNodes request. Returns the raw trie nodes the
     * peer responds with. The caller must verify each node against
     * {@code stateRoot} via the MPT verifier; nodes whose hash doesn't fit
     * the implied path are an indictment of the peer.
     */
    CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 stateRoot, List<PathSet> paths);

    /**
     * Issue a snap/1 GetByteCodes request. Returns the raw bytecode blobs in
     * the same order as {@code hashes}. The caller must verify each blob's
     * keccak256 matches the requested hash.
     */
    CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> hashes);

    /**
     * Signal that this peer could not serve the requested state root for the current
     * head, so a peer-routing implementation can deprioritize it and rotate to one
     * that actually retains the state — instead of re-dialing it across every retry.
     *
     * <p>The oracle calls this for any failure that makes the peer useless for this
     * short-lived head context, whether or not the peer is permanently broken:
     * <ul>
     *   <li>an empty proof for a non-empty root, or no state at all — it doesn't
     *       retain that stateRoot's trie ({@code InvalidProof} / {@code StateUnavailable});</li>
     *   <li>it accepted the request then hung ({@code TimeoutException}) or the
     *       connection dropped ({@code IOException}) — equally useless here.</li>
     * </ul>
     * Because timeouts/drops can be transient, an implementation should treat this as
     * a per-head deprioritization signal, not a permanent eviction — the same peer may
     * serve a later head. Default no-op for fixture/test implementations.
     */
    default void reportRootUnavailable() {}

    /** Reported when a fetch through this peer VERIFIED (Merkle proof or hash
     *  checked by the oracle) — the trustworthy "this peer served" signal.
     *  Routing preference and any pool/cache serve credit must hang off this,
     *  NOT off a merely non-empty response: a structurally valid but junk
     *  response otherwise clears failure streaks before its verification
     *  fails, letting a byzantine peer oscillate a strike ladder 0↔1 and
     *  dodge eviction forever. Default no-op. */
    default void reportServed() {}

    /**
     * Short human-readable identity for logs ("ip:port" for network-backed
     * implementations). Purely diagnostic — never used for routing decisions.
     */
    default String describe() {
        String simple = getClass().getSimpleName();
        return simple.isEmpty() ? getClass().getName() : simple;
    }

    /**
     * Stable identity of the underlying peer, used to recognize "same peer
     * again" across supplier calls within one oracle operation (the fail-fast
     * dedup). Implementations that wrap a per-call adapter around a long-lived
     * connection MUST return the underlying connection object — otherwise
     * every supplier call looks like a fresh peer and the dedup never fires.
     * Compared by object identity, never by equals.
     */
    default Object identity() {
        return this;
    }
}
