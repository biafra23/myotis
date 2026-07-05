package io.myotis.node;

import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import io.myotis.api.HeaderInfo;
import io.myotis.api.HeadersResult;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Shared header-range fetch (the daemon's {@code get-headers}): integrity-checked headers
 * ({@code hash} is the locally recomputed keccak256 of the RLP) mapped into the API shape.
 * Chain-of-custody verification against the beacon anchor is {@link VerifiedBlockQuery}'s
 * job; this is the raw fetch surface.
 */
public final class HeaderQuery {

    private HeaderQuery() {}

    /** Blocking (worker thread; single 30 s fetch). Failures come back in
     *  {@link HeadersResult#error()} with an empty list. */
    public static HeadersResult fetch(RLPxConnector connector, long startBlock, int count) {
        try {
            List<BlockHeadersMessage.VerifiedHeader> headers =
                    connector.requestBlockHeaders(startBlock, count).get(30, TimeUnit.SECONDS);
            List<HeaderInfo> out = new ArrayList<>(headers.size());
            for (BlockHeadersMessage.VerifiedHeader vh : headers) {
                var h = vh.header();
                out.add(new HeaderInfo(
                        h.number,
                        vh.hash().toHexString(),
                        h.parentHash.toHexString(),
                        h.stateRoot.toHexString(),
                        h.transactionsRoot.toHexString(),
                        h.timestamp,
                        h.gasUsed,
                        h.gasLimit,
                        h.baseFeePerGas != null ? h.baseFeePerGas.toString() : null));
            }
            return new HeadersResult(out, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new HeadersResult(List.of(), "interrupted");
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return new HeadersResult(List.of(), cause.getMessage() != null
                    ? cause.getMessage() : cause.getClass().getSimpleName());
        }
    }
}
