package com.jaeckel.ethp2p.app.snap;

import com.jaeckel.ethp2p.networking.eth.EthHandler;
import com.jaeckel.ethp2p.networking.snap.messages.ByteCodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetTrieNodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.TrieNodesMessage;
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
 * the classpath, and translates between {@link SnapPeer.PathSet} and the
 * {@link GetTrieNodesMessage.PathSet} type the wire layer speaks.
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
        List<GetTrieNodesMessage.PathSet> wirePaths = new ArrayList<>(paths.size());
        for (PathSet p : paths) {
            wirePaths.add(new GetTrieNodesMessage.PathSet(p.accountPath(), p.storagePaths()));
        }
        return handler.requestTrieNodesAsync(stateRoot, wirePaths)
                .thenApply(TrieNodesMessage.DecodeResult::nodes);
    }

    @Override
    public CompletableFuture<List<Bytes>> getByteCodes(List<Bytes32> hashes) {
        return handler.requestByteCodesAsync(hashes)
                .thenApply(ByteCodesMessage.DecodeResult::codes);
    }
}
