package com.jaeckel.ethp2p.app.snap;

import com.jaeckel.ethp2p.networking.eth.EthHandler;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.ByteCodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
import io.myotis.evm.world.SnapPeer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * {@link SnapPeer} adapter over a single {@link EthHandler}.
 *
 * <p>{@code :myotis-evm} doesn't depend on {@code :networking} (and shouldn't
 * — the wallet's local EVM machinery is independent of the wire protocol).
 * The adapter lives here in {@code :app}, where both modules are already on
 * the classpath, and translates {@link SnapPeer.PathSet} requests into the
 * snap/1 wire calls that actually return verifiable proofs.
 *
 * <p><b>Why not GetTrieNodes:</b> the {@link SnapPeer#getTrieNodes} name is
 * historical. Geth's {@code GetTrieNodes} handler returns only the node at
 * the requested path (one node per path set) — useful for fetching a
 * specific intermediate or leaf, but it does not include the root-to-leaf
 * Merkle path that {@code SnapBackedStateOracle} needs to descend from a
 * stateRoot. So this adapter routes through {@code GetAccountRange} (for
 * account-only path sets) and {@code GetStorageRanges} (for path sets that
 * carry a storage slot), both of which return the proof as part of the
 * response. The verifier then has every node it needs to descend from
 * stateRoot (or storageRoot) to the leaf.
 *
 * <p>Multi-peer fallback is the oracle's responsibility, not this adapter's.
 * Construct one {@code EthHandlerSnapPeer} per peer, hand a
 * {@code Supplier<SnapPeer>} that picks among them to
 * {@code SnapBackedStateOracle}, and the oracle will rotate on
 * {@code InvalidProof} / IO failures.
 */
public final class EthHandlerSnapPeer implements SnapPeer {

    private final EthHandler handler;

    public EthHandlerSnapPeer(EthHandler handler) {
        this.handler = handler;
    }

    @Override
    public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 stateRoot, List<PathSet> paths) {
        // For each PathSet collect a future that yields the proof nodes for
        // that path set. Account-only sets go through GetAccountRange; sets
        // with one or more storage paths fan out to one GetStorageRanges
        // per slot (the oracle currently never asks for more than one slot
        // per set, but the chain still works if it does). Storage requests
        // within a set run concurrently — EthHandler keys pending requests
        // by reqId so concurrent sends on the same handler are safe, and
        // the verifier looks proof nodes up by hash so merge order doesn't
        // matter.
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
                return all;
            });
    }

    @Override
    public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> hashes) {
        return handler.requestByteCodesAsync(hashes)
                .thenApply(ByteCodesMessage.DecodeResult::codes);
    }
}
