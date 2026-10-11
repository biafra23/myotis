package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.proof.OrderedTrieRoot;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.eth.HeaderChains;
import com.jaeckel.ethp2p.networking.eth.messages.BlockBodiesMessage;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import io.myotis.api.BlockResult;
import org.apache.tuweni.bytes.Bytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Shared, host-agnostic verified single-block query — the engine home of the daemon's
 * {@code get-block} verification (moved out of the JVM {@code CommandHandler} verbatim).
 *
 * <p>Verification: <b>headerChain</b> — the light client attests the block HASH of the
 * finalized and the optimistic execution heads. Fetch the header window from the target up
 * to the attested block at or above it (the finalized block for a target at or below
 * finality, else the optimistic head), require its TOP to hash to that attested hash and every
 * header to hash-link to the next ({@link HeaderChains#anchoredAtTop}), and require the
 * window's FIRST header to be the very header this query reports (same block hash). Trust
 * flows down from the attested block only — see {@link HeaderChains}. A target above the
 * optimistic head is not attested yet → {@code failReason:"blockAheadOfAnchor"}.
 *
 * <p>There is no state-root fast path: a matching attested state root proves the root, not
 * the rest of the header, and the transaction count reported here is checked against the
 * header's transactionsRoot.
 *
 * <p>Pre-Merge blocks can't tie to the beacon chain → {@code failReason:"preMergeBlock"}.
 */
public final class VerifiedBlockQuery {

    private static final Logger log = LoggerFactory.getLogger(VerifiedBlockQuery.class);

    /** The Merge block — first PoS block on mainnet (Sep 15 2022). */
    private static final long MERGE_BLOCK = 15_537_394L;
    private static final int MAX_HEADER_CHAIN_GAP = VerifiedAccountQuery.MAX_HEADER_CHAIN_GAP;
    /** keccak256(RLP([])) — the ommersHash of every uncle-free (so every post-Merge) block. */
    private static final Bytes32 EMPTY_OMMERS_HASH = Bytes32.fromHexString(
            "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

    private VerifiedBlockQuery() {}

    /**
     * Blocking (worker thread; bounded by the internal fetch timeouts, ~180 s worst case).
     * Fetch failures come back as {@link BlockResult#error()}; verification failures as
     * {@link BlockResult#failReason()}.
     */
    public static BlockResult query(RLPxConnector connector,
                                    BeaconSyncState beaconSyncState,
                                    long blockNumber) {
        try {
            // Step 1: header (batched path — retries across peers).
            List<BlockHeadersMessage.VerifiedHeader> headers =
                    connector.requestBlockHeadersBatched(blockNumber, 1)
                            .get(30, TimeUnit.SECONDS);
            if (headers.isEmpty()) {
                return errorResult("No header returned for block " + blockNumber);
            }
            BlockHeadersMessage.VerifiedHeader vh = headers.get(0);
            BlockHeader h = vh.header();

            // Step 2: body by the recomputed block hash.
            List<BlockBodiesMessage.BlockBody> bodies =
                    connector.requestBlockBodies(vh.hash()).get(30, TimeUnit.SECONDS);
            if (bodies.isEmpty()) {
                return errorResult("No body returned for block " + blockNumber);
            }
            BlockBodiesMessage.BlockBody body = bodies.get(0);
            // The body is raw peer data until tied to the header: rebuild the tx trie
            // and require it to root at transactionsRoot, so the reported txCount
            // can't be a byzantine peer's junk riding a "headerChain" badge. Like the
            // empty reply above, a mismatch is a FETCH failure (this peer failed to
            // produce the block's body) rather than a header-verification verdict,
            // hence error() and not failReason.
            if (!OrderedTrieRoot.verify(body.transactions(), h.transactionsRoot)) {
                return errorResult("Body for block " + blockNumber
                        + " failed transactionsRoot verification");
            }
            // uncleCount/withdrawalCount: the wire decoder keeps only counts, not the
            // raw uncle/withdrawal RLP a full ommersHash/withdrawalsRoot rebuild would
            // need — but the EMPTY cases pin them exactly, and every post-Merge block
            // (all this path verifies) has the empty ommersHash.
            if (EMPTY_OMMERS_HASH.equals(h.ommersHash) && body.uncleCount() != 0) {
                return errorResult("Body for block " + blockNumber
                        + " reports uncles for an empty ommersHash");
            }
            if (OrderedTrieRoot.EMPTY_ROOT.equals(h.withdrawalsRoot)
                    && body.withdrawalCount() != 0) {
                return errorResult("Body for block " + blockNumber
                        + " reports withdrawals for an empty withdrawalsRoot");
            }

            // Step 3: beacon verification.
            Verdict v = verifyAgainstBeacon(connector, beaconSyncState, vh, blockNumber);

            return new BlockResult(
                    h.number,
                    vh.hash().toHexString(),
                    h.parentHash.toHexString(),
                    h.stateRoot.toHexString(),
                    h.transactionsRoot.toHexString(),
                    h.receiptsRoot.toHexString(),
                    h.timestamp,
                    h.gasUsed,
                    h.gasLimit,
                    h.baseFeePerGas != null ? h.baseFeePerGas.toString() : null,
                    body.transactions().size(),
                    body.uncleCount(),
                    body.withdrawalCount(),
                    beaconSyncState.isSynced(),
                    v.beaconChainVerified,
                    v.blsVerified,
                    v.matchedSlot,
                    v.verifyMethod,
                    v.failReason,
                    null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return errorResult("interrupted");
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return errorResult(cause.getMessage() != null
                    ? cause.getMessage() : cause.getClass().getSimpleName());
        }
    }

    private static final class Verdict {
        boolean beaconChainVerified;
        boolean blsVerified;
        long matchedSlot = -1;
        String verifyMethod;
        String failReason;
    }

    private static Verdict verifyAgainstBeacon(RLPxConnector connector,
                                               BeaconSyncState beaconSyncState,
                                               BlockHeadersMessage.VerifiedHeader reported,
                                               long blockNumber) {
        Verdict v = new Verdict();
        if (blockNumber < MERGE_BLOCK) {
            // Pre-merge blocks cannot be verified via the beacon chain (the embedded
            // pre-Merge accumulator is designed but not built yet).
            v.failReason = "preMergeBlock";
            return v;
        }
        if (!beaconSyncState.isSynced()) {
            v.failReason = "beaconNotSynced";
            return v;
        }
        BeaconSyncState.FinalizedExecution fin = beaconSyncState.getFinalizedExecution();
        if (fin.blockNumber() <= 0 || fin.blockHash() == null || fin.blockHash().length != 32) {
            v.failReason = "beaconBlockHashUnavailable";
            return v;
        }
        // A finality that came from a verified update has its root in the window as
        // BLS-verified; the seed fallbacks (no bootstrap) do not, and are reported so.
        BeaconSyncState.SlottedStateRoot finRoot =
                fin.stateRoot() != null ? beaconSyncState.findStateRoot(fin.stateRoot()) : null;
        BlockAnchor anchor = blockAnchor(blockNumber, fin, beaconSyncState.getFinalizedSlot(),
                finRoot != null && finRoot.blsVerified(), beaconSyncState.getOptimisticExecution());
        if (anchor == null) {
            v.failReason = "blockAheadOfAnchor";
            return v;
        }
        long gap = anchor.blockNumber() - blockNumber;
        log.info("[verify-block] headerChain: block={}, anchorBlock={}, gap={}",
                blockNumber, anchor.blockNumber(), gap);
        if (gap >= MAX_HEADER_CHAIN_GAP) {
            v.failReason = "headerChainGapTooLarge";
            return v;
        }
        try {
            List<BlockHeadersMessage.VerifiedHeader> window = gap == 0
                    ? List.of(reported)
                    : connector.requestBlockHeadersBatched(blockNumber, (int) (gap + 1))
                            .get(120, TimeUnit.SECONDS);
            if (windowProves(window, gap + 1, anchor.blockHash(), reported)) {
                v.beaconChainVerified = true;
                v.matchedSlot = anchor.slot();
                v.blsVerified = anchor.blsVerified();
                v.verifyMethod = "headerChain";
            } else {
                log.info("[verify-block] header window for #{} did not anchor at #{}",
                        blockNumber, anchor.blockNumber());
                v.failReason = "headerChainInvalid";
            }
        } catch (Exception e) {
            log.info("[verify-block] Header chain verification failed: {}", e.getMessage());
            v.failReason = "headerChainError";
        }
        return v;
    }

    /** The attested block a block query's walk ends at, the slot reported with it, and
     *  whether its hash came under a sync-committee signature. */
    record BlockAnchor(long blockNumber, byte[] blockHash, long slot, boolean blsVerified) {}

    /**
     * The attested block at or above {@code blockNumber} its walk ends at: the finalized block
     * for a target at or below it (the shorter walk), else the optimistic head — or null when
     * nothing attested lies at or above the target yet ({@code blockAheadOfAnchor}). Each
     * (number, hash) pair is one atomic snapshot; the slot is only reported. The optimistic
     * head is always signed (no seed path sets it); the finality is as {@code finalizedBls}
     * says.
     */
    static BlockAnchor blockAnchor(long blockNumber, BeaconSyncState.FinalizedExecution fin,
                                   long finalizedSlot, boolean finalizedBls,
                                   BeaconSyncState.OptimisticExecution opt) {
        if (blockNumber <= fin.blockNumber()) {
            return new BlockAnchor(fin.blockNumber(), fin.blockHash(), finalizedSlot, finalizedBls);
        }
        if (opt != null && opt.blockHash() != null && opt.blockNumber() >= blockNumber) {
            return new BlockAnchor(opt.blockNumber(), opt.blockHash(), opt.slot(), true);
        }
        return null;
    }

    /** True iff {@code window}, fetched as {@code [target .. anchor]}, proves {@code reported}:
     *  exactly {@code expected} headers, hash-linked up to {@code anchorHash}
     *  ({@link HeaderChains#anchoredAtTop}), and its FIRST header is the very header this query
     *  reports — the window proves its own headers, not one fetched separately. */
    static boolean windowProves(List<BlockHeadersMessage.VerifiedHeader> window, long expected,
                                byte[] anchorHash, BlockHeadersMessage.VerifiedHeader reported) {
        return window.size() == expected
                && HeaderChains.anchoredAtTop(window, anchorHash)
                && window.get(0).hash().equals(reported.hash());
    }

    private static BlockResult errorResult(String message) {
        return new BlockResult(0, null, null, null, null, null, 0, 0, 0, null,
                0, 0, 0, false, false, false, -1, null, null, message);
    }
}
