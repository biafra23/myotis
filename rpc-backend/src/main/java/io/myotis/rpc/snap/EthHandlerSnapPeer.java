package io.myotis.rpc.snap;

import com.jaeckel.ethp2p.networking.eth.EthHandler;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.ByteCodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
import io.myotis.rpc.SnapLaneGate;
import io.myotis.evm.world.SnapPeer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * {@link SnapPeer} adapter over a single {@link EthHandler}.
 *
 * <p>Port of {@code com.jaeckel.ethp2p.app.snap.EthHandlerSnapPeer}. The bridge
 * has to live in a module that sees both {@code :networking} (the wire layer)
 * and {@code :myotis-evm} (the EVM's {@code SnapPeer}); {@code :app} can't be a
 * dependency of {@code :android-app}, so the adapter is duplicated here. If a
 * third consumer appears, extract it into a shared {@code :snap-evm-bridge}
 * module instead of copying a third time.
 *
 * <p>Routes through {@code GetAccountRange} (account-only path sets) and
 * {@code GetStorageRanges} (path sets carrying a storage slot) rather than
 * {@code GetTrieNodes}, because only those return the full root-to-leaf Merkle
 * proof {@code SnapBackedStateOracle} needs to descend from a stateRoot.
 */
public final class EthHandlerSnapPeer implements SnapPeer {

    private final EthHandler handler;
    private final Runnable onRootUnavailable;
    private final Runnable onRootServed;
    /** Optional concurrency gate: when the current EVM thread is the HEAVY lane, each snap
     *  request holds a permit so a sweep can't use more than its share of the peer pool.
     *  Null = no gating (small/legacy callers). */
    private final SnapLaneGate laneGate;

    public EthHandlerSnapPeer(EthHandler handler) {
        this(handler, null, null, null);
    }

    /** @param onRootUnavailable run when the oracle reports this peer can't serve the
     *  current state root, so the routing supplier can deprioritize it for this head. */
    public EthHandlerSnapPeer(EthHandler handler, Runnable onRootUnavailable) {
        this(handler, onRootUnavailable, null, null);
    }

    public EthHandlerSnapPeer(EthHandler handler, Runnable onRootUnavailable, Runnable onRootServed) {
        this(handler, onRootUnavailable, onRootServed, null);
    }

    /**
     * @param onRootUnavailable run when the oracle reports this peer can't serve the
     *  current state root (deprioritize it for this head). Runs SYNCHRONOUSLY on
     *  the reporting thread (often the Netty event loop): keep it to lock-free
     *  routing mutations and offload anything that can block.
     * @param onRootServed run when this peer returns a usable (non-empty) proof, so
     *  the EL peer cache can record it as a proven snap-serving peer to dial first
     *  on a restart. The two callbacks are mutually exclusive per fetch: a non-empty
     *  proof fires {@code onRootServed}; an empty one is treated by the oracle as
     *  no-state and ultimately fires {@code onRootUnavailable}.
     */
    public EthHandlerSnapPeer(EthHandler handler, Runnable onRootUnavailable,
                              Runnable onRootServed, SnapLaneGate laneGate) {
        this.handler = handler;
        this.onRootUnavailable = onRootUnavailable;
        this.onRootServed = onRootServed;
        this.laneGate = laneGate;
    }

    @Override
    public Object identity() {
        return handler;
    }

    @Override
    public String describe() {
        return handler.getRemoteAddress();
    }

    @Override
    public void reportRootUnavailable() {
        // SYNCHRONOUS on purpose: the oracle's fail-fast skim consults the peer
        // supplier immediately after this returns, and the supplier's routing
        // state (rootDenied/rootServed in VerifiedRpcBackend) must already
        // reflect the deny — an async offload here loses that race and the
        // skim sees the pre-failure world, failing operations fast while
        // untried peers exist. The callback contract is therefore: routing
        // mutations only (lock-free sets); any potentially blocking work
        // (quality sinks, persistence) must be offloaded BY THE CALLBACK.
        if (onRootUnavailable != null) {
            try { onRootUnavailable.run(); } catch (RuntimeException ignore) {}
        }
    }

    @Override
    public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 stateRoot, List<PathSet> paths) {
        // Heavy-lane permit: blocks here (on the EVM pool thread that issued this fetch)
        // until a slot frees, capping how many snap peers a sweep uses at once. Small-lane
        // callers and the no-gate constructors return false immediately (unthrottled).
        final boolean permit = laneGate != null && laneGate.acquireIfHeavy();
        try {
            CompletableFuture<List<Bytes>> result = doGetTrieNodes(stateRoot, paths);
            return permit ? result.whenComplete((r, e) -> laneGate.release()) : result;
        } catch (RuntimeException ex) {
            if (permit) laneGate.release();
            throw ex;
        }
    }

    private CompletableFuture<List<Bytes>> doGetTrieNodes(Bytes32 stateRoot, List<PathSet> paths) {
        List<CompletableFuture<List<Bytes>>> perSet = new ArrayList<>(paths.size());
        for (PathSet p : paths) {
            Bytes32 accountHash = Bytes32.wrap(p.accountPath());
            if (p.storagePaths().isEmpty()) {
                perSet.add(handler.requestAccountByHashAsync(accountHash, stateRoot)
                    .thenApply(AccountRangeMessage.DecodeResult::proof));
            } else {
                List<CompletableFuture<List<Bytes>>> storageFuts =
                    new ArrayList<>(p.storagePaths().size());
                for (Bytes sp : p.storagePaths()) {
                    Bytes32 slotHash = Bytes32.wrap(sp);
                    storageFuts.add(handler
                        .requestStorageByHashAsync(accountHash, slotHash, stateRoot)
                        .thenApply(StorageRangesMessage.DecodeResult::proof));
                }
                perSet.add(CompletableFuture
                    .allOf(storageFuts.toArray(new CompletableFuture<?>[0]))
                    .thenApply(v -> {
                        List<Bytes> merged = new ArrayList<>();
                        for (CompletableFuture<List<Bytes>> f : storageFuts) {
                            merged.addAll(f.join());
                        }
                        return merged;
                    }));
            }
        }
        return CompletableFuture.allOf(perSet.toArray(new CompletableFuture<?>[0]))
            .thenApply(v -> {
                List<Bytes> all = new ArrayList<>();
                for (CompletableFuture<List<Bytes>> f : perSet) {
                    all.addAll(f.join());
                }
                // A non-empty proof means this peer actually retains the trie for
                // this root — the durable "snap-serving" signal the EL cache wants.
                // Empty proofs fall through to the oracle's no-state path, which
                // calls reportRootUnavailable instead. Synchronous, mirroring
                // reportRootUnavailable: the supplier's rootServed preference
                // should see the serve before the next consult, and the callback
                // contract requires callbacks to offload their own blocking work
                // (see reportRootUnavailable).
                if (!all.isEmpty() && onRootServed != null) {
                    try { onRootServed.run(); } catch (RuntimeException ignore) {}
                }
                return all;
            });
    }

    @Override
    public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> hashes) {
        final boolean permit = laneGate != null && laneGate.acquireIfHeavy();
        try {
            CompletableFuture<List<Bytes>> result = handler.requestByteCodesAsync(hashes)
                    .thenApply(ByteCodesMessage.DecodeResult::codes);
            return permit ? result.whenComplete((r, e) -> laneGate.release()) : result;
        } catch (RuntimeException ex) {
            if (permit) laneGate.release();
            throw ex;
        }
    }
}
