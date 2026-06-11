package com.jaeckel.ethp2p.android.snap;

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

    public EthHandlerSnapPeer(EthHandler handler) {
        this(handler, null);
    }

    /** @param onRootUnavailable run when the oracle reports this peer can't serve the
     *  current state root, so the routing supplier can deprioritize it for this head. */
    public EthHandlerSnapPeer(EthHandler handler, Runnable onRootUnavailable) {
        this.handler = handler;
        this.onRootUnavailable = onRootUnavailable;
    }

    @Override
    public void reportRootUnavailable() {
        if (onRootUnavailable != null) onRootUnavailable.run();
    }

    @Override
    public CompletableFuture<List<Bytes>> getTrieNodes(Bytes32 stateRoot, List<PathSet> paths) {
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
