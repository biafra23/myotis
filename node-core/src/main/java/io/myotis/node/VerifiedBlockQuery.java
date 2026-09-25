package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.proof.OrderedTrieRoot;
import com.jaeckel.ethp2p.core.types.BlockHeader;
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
 * <p>Verification strategy:
 * <ol>
 *   <li><b>stateRootMatch</b> — the block's stateRoot matches a beacon-attested root.</li>
 *   <li><b>headerChain</b> — the beacon's ExecutionPayloadHeader carries a BLS-verified
 *       block_hash; fetch the header range between the finalized block and the target,
 *       require the finalized header's keccak256(RLP) to equal that anchor, then walk the
 *       parent-hash chain. Forging any header would need a keccak preimage.</li>
 * </ol>
 * Pre-Merge blocks can't tie to the beacon chain → {@code failReason:"preMergeBlock"}.
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
            Verdict v = verifyAgainstBeacon(connector, beaconSyncState, h, blockNumber);

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
                                               BlockHeader header, long blockNumber) {
        Verdict v = new Verdict();
        if (blockNumber < MERGE_BLOCK) {
            // Pre-merge blocks cannot be verified via the beacon chain (the embedded
            // pre-Merge accumulator is designed but not built yet).
            v.failReason = "preMergeBlock";
            return v;
        }
        byte[] blockStateRoot = header.stateRoot.toArrayUnsafe();
        BeaconSyncState.SlottedStateRoot match = beaconSyncState.findStateRoot(blockStateRoot);
        if (match != null) {
            v.beaconChainVerified = true;
            v.matchedSlot = match.slot();
            v.blsVerified = match.blsVerified();
            v.verifyMethod = "stateRootMatch";
            return v;
        }
        if (!beaconSyncState.isSynced()) {
            v.failReason = "beaconNotSynced";
            return v;
        }
        long finalizedBlockNum = beaconSyncState.getExecutionBlockNumber();
        byte[] beaconBlockHash = beaconSyncState.getExecutionBlockHash();
        long gap = Math.abs(blockNumber - finalizedBlockNum);
        log.info("[verify-block] headerChain: block={}, finalizedBlock={}, gap={}",
                blockNumber, finalizedBlockNum, gap);
        if (finalizedBlockNum <= 0 || beaconBlockHash == null || beaconBlockHash.length != 32) {
            v.failReason = "beaconBlockHashUnavailable";
            return v;
        }
        if (gap > MAX_HEADER_CHAIN_GAP && blockNumber != finalizedBlockNum) {
            v.failReason = "headerChainGapTooLarge";
            return v;
        }
        try {
            boolean chainValid;
            if (blockNumber == finalizedBlockNum) {
                chainValid = verifyBlockHashAgainstBeacon(
                        connector, finalizedBlockNum, beaconBlockHash, blockStateRoot);
            } else if (blockNumber > finalizedBlockNum) {
                chainValid = verifyBlockChainFromBeacon(
                        connector, beaconSyncState, finalizedBlockNum, blockNumber, beaconBlockHash);
            } else {
                chainValid = verifyBlockChainFromBeacon(
                        connector, beaconSyncState, blockNumber, finalizedBlockNum, beaconBlockHash);
            }
            if (chainValid) {
                v.beaconChainVerified = true;
                v.matchedSlot = beaconSyncState.getFinalizedSlot();
                v.blsVerified = true;
                v.verifyMethod = "headerChain";
            } else {
                v.failReason = "headerChainInvalid";
            }
        } catch (Exception e) {
            log.info("[verify-block] Header chain verification failed: {}", e.getMessage());
            v.failReason = "headerChainError";
        }
        return v;
    }

    /** The requested block IS the finalized block: compare its recomputed hash to the
     *  beacon-attested block hash and its stateRoot to the header's. */
    private static boolean verifyBlockHashAgainstBeacon(RLPxConnector connector,
                                                        long blockNumber, byte[] beaconBlockHash,
                                                        byte[] expectedStateRoot) throws Exception {
        List<BlockHeadersMessage.VerifiedHeader> headers =
                connector.requestBlockHeaders(blockNumber, 1).get(30, TimeUnit.SECONDS);
        if (headers.isEmpty()) return false;
        BlockHeadersMessage.VerifiedHeader vh = headers.get(0);
        // VerifiedHeader.hash() is keccak256(rawRLP) computed locally — compare to the anchor.
        if (!java.util.Arrays.equals(vh.hash().toArrayUnsafe(), beaconBlockHash)) {
            log.info("[verify-block] Finalized block hash mismatch: peer={} beacon={}",
                    vh.hash().toShortHexString(), Bytes32.wrap(beaconBlockHash).toShortHexString());
            return false;
        }
        return java.util.Arrays.equals(vh.header().stateRoot.toArrayUnsafe(), expectedStateRoot);
    }

    /** Fetch [startBlock..endBlock], require the finalized header's hash to equal the
     *  beacon anchor, and verify parent-hash continuity across the whole range. */
    private static boolean verifyBlockChainFromBeacon(RLPxConnector connector,
                                                      BeaconSyncState beaconSyncState,
                                                      long startBlock, long endBlock,
                                                      byte[] beaconBlockHash) throws Exception {
        long finalizedBlockNum = beaconSyncState.getExecutionBlockNumber();
        int total = (int) (endBlock - startBlock + 1);
        if (total < 2 || total > MAX_HEADER_CHAIN_GAP) {
            log.info("[verify-block] Block chain gap {} — out of range [2, {}]", total, MAX_HEADER_CHAIN_GAP);
            return false;
        }
        log.info("[verify-block] Fetching {} headers from block #{} to #{}", total, startBlock, endBlock);
        List<BlockHeadersMessage.VerifiedHeader> allHeaders =
                connector.requestBlockHeadersBatched(startBlock, total).get(120, TimeUnit.SECONDS);
        if (allHeaders.size() != total) {
            log.info("[verify-block] Expected {} headers, got {}", total, allHeaders.size());
            return false;
        }
        int anchorIndex = (int) (finalizedBlockNum - startBlock);
        if (anchorIndex < 0 || anchorIndex >= allHeaders.size()) {
            log.info("[verify-block] Finalized block #{} not in range [{}, {}]",
                    finalizedBlockNum, startBlock, endBlock);
            return false;
        }
        BlockHeadersMessage.VerifiedHeader anchorHeader = allHeaders.get(anchorIndex);
        if (!java.util.Arrays.equals(anchorHeader.hash().toArrayUnsafe(), beaconBlockHash)) {
            log.info("[verify-block] Anchor block hash mismatch at #{}: peer={} beacon={}",
                    finalizedBlockNum, anchorHeader.hash().toShortHexString(),
                    Bytes32.wrap(beaconBlockHash).toShortHexString());
            return false;
        }
        for (int i = 0; i < allHeaders.size() - 1; i++) {
            Bytes32 currentHash = allHeaders.get(i).hash();
            Bytes32 nextParent = allHeaders.get(i + 1).header().parentHash;
            if (!currentHash.equals(nextParent)) {
                log.info("[verify-block] Hash chain break at index {}: block #{} hash={} != block #{} parentHash={}",
                        i, allHeaders.get(i).header().number, currentHash.toShortHexString(),
                        allHeaders.get(i + 1).header().number, nextParent.toShortHexString());
                return false;
            }
        }
        log.info("[verify-block] Block chain verified: {} headers anchored at finalized block #{}",
                total, finalizedBlockNum);
        return true;
    }

    private static BlockResult errorResult(String message) {
        return new BlockResult(0, null, null, null, null, null, 0, 0, 0, null,
                0, 0, 0, false, false, false, -1, null, null, message);
    }
}
