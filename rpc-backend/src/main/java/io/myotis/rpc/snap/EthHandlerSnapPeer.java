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
     * @param onRootServed run when a fetch through this peer VERIFIES (fired via
     *  {@link #reportServed} from the oracle, never on a merely non-empty
     *  response), so the EL peer cache can record it as a proven snap-serving
     *  peer to dial first on a restart. The two callbacks are mutually exclusive
     *  per fetch: a verified fetch fires {@code onRootServed}; an empty or
     *  unverifiable one ultimately fires {@code onRootUnavailable}.
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
    public void reportServed() {
        // Fired by the oracle AFTER the fetched proof verified (never on a
        // merely non-empty response — see SnapPeer.reportServed): the serve
        // credit must not be spoofable with junk bytes. Synchronous, mirroring
        // reportRootUnavailable: the supplier's rootServed preference should
        // see the serve before the next consult.
        if (onRootServed != null) {
            try { onRootServed.run(); } catch (RuntimeException ignore) {}
        }
    }

    @Override
    public void reportRootUnavailable() {
        // SYNCHRONOUS on purpose: the oracle's fail-fast skim consults the peer
        // supplier immediately after this returns, and the supplier's routing
        // state (rootDenied/rootServed in VerifiedRpcBackend) must already
        // reflect the deny — an async offload here loses that race and the
        // skim sees the pre-failure world, failing operations fast while
        // untried peers exist. The callback contract is therefore: routing and
        // pool-discipline mutations only — lock-free sets, plus the connector's
        // read-failure monitor, which is verified non-blocking (a short scan, a
        // volatile bench, an async close; no I/O and no other lock is ever held
        // with it); any potentially blocking work (quality sinks, persistence)
        // must be offloaded BY THE CALLBACK.
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
                // NO serve credit here: a non-empty node list is not yet a
                // serve — the oracle still has to verify it, and fires
                // reportServed only when it does. Crediting on non-empty bytes
                // let a junk response clear failure streaks (review finding on
                // the eviction ladder). Empty proofs fall through to the
                // oracle's no-state path → reportRootUnavailable.
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
