package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.core.concurrent.Futures;
import com.jaeckel.ethp2p.consensus.proof.MerklePatriciaVerifier;
import com.jaeckel.ethp2p.networking.eth.HeaderChains;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Shared, host-agnostic verified account query: fetch an account proof from a READY+snap peer
 * and verify it against the beacon-attested state root. Extracted from the Android
 * {@code NodeService} so the daemon, Android, and the Desktop CMP host all run the SAME
 * verification ladder instead of each duplicating it.
 *
 * <p>Two verification methods, in the order checked:
 * <ul>
 *   <li><b>stateRootMatch</b> (fast-path) — if the peer's reported stateRoot is one the beacon
 *       light client has already attested ({@link BeaconSyncState#findStateRoot}), we're done.
 *       Rare: only fires when the peer's head briefly aligns with an attested slot.</li>
 *   <li><b>headerChain</b> (load-bearing) — for a peer block above finality and at or below
 *       the light client's optimistic head, fetch the contiguous header range
 *       {@code [peerBlock .. optimisticHead]}, verify the parent-hash chain, and require the
 *       last header to hash to the optimistic head's attested block hash and the first
 *       header's stateRoot to equal the peer-reported stateRoot ({@link #verifyHeaderChain}:
 *       trust flows only DOWN from an attested hash).</li>
 * </ul>
 * Verification <em>failures</em> are reported via {@link Result#failReason()} — the returned
 * future only completes exceptionally for bad arguments or a not-running node.
 */
public final class VerifiedAccountQuery {

    private static final Logger log = LoggerFactory.getLogger(VerifiedAccountQuery.class);

    /** Same bound the JVM daemon uses (CommandHandler.MAX_HEADER_CHAIN_GAP). */
    public static final int MAX_HEADER_CHAIN_GAP = 8192;
    public static final long HEADER_CHAIN_TIMEOUT_SEC = 60;

    private VerifiedAccountQuery() {}

    /** Result of a get-account query. Mirrors the JVM daemon's JSON response shape. */
    public record Result(
            String address,                  // 0x-prefixed input
            boolean exists,                  // false when the account isn't in the trie
            long nonce,                      // -1 when !exists
            String balanceWei,               // decimal string (BigInteger.toString); null when !exists
            String storageRootHex,           // null when !exists
            String codeHashHex,              // null when !exists
            long blockNumber,                // peer-reported block number the proof is anchored to
            String peerStateRootHex,         // 0x… root the proof was built against
            boolean peerProofValid,          // proof verifies against peerStateRoot
            boolean beaconChainVerified,     // peerStateRoot matches a beacon-attested root
            boolean blsVerified,             // beacon match was BLS-signed (vs. unverified header)
            long matchedBeaconSlot,          // -1 when not matched
            String verifyMethod,             // "stateRootMatch" or "headerChain" or null
            String failReason                // null when verified
    ) {}

    /**
     * Validate the address, query a peer on {@code stack}, and verify the proof. The future
     * completes exceptionally only for argument/state errors; verification failures surface as
     * {@link Result#failReason()}.
     */
    public static CompletableFuture<Result> query(ChainStack stack, String hexAddress) {
        RLPxConnector connector = stack != null ? stack.connector() : null;
        BeaconSyncState beaconSyncState = stack != null ? stack.beaconSyncState() : null;
        if (stack == null || !stack.isRunning() || connector == null) {
            return Futures.failedFuture(
                    new IllegalStateException("Node is not running"));
        }
        if (hexAddress == null) {
            return Futures.failedFuture(
                    new IllegalArgumentException("Address is required"));
        }
        String hex = hexAddress.strip();
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.length() != 40) {
            return Futures.failedFuture(
                    new IllegalArgumentException("Address must be 20 bytes (40 hex chars)"));
        }
        final String hexAddrFinal = hex;
        Bytes address;
        try {
            address = Bytes.fromHexString(hex);
        } catch (Exception e) {
            return Futures.failedFuture(
                    new IllegalArgumentException("Invalid hex address: " + e.getMessage()));
        }
        Bytes32 accountHash = Hash.keccak256(address);
        BeaconSyncState bss = beaconSyncState;
        RLPxConnector conn = connector;
        return connector.requestAccount(address).thenCompose(result ->
                buildAccountResult("0x" + hexAddrFinal, address, accountHash, result, bss, conn));
    }

    /**
     * The immutable verification verdict. {@code verifiedStorageRootHex}/{@code verifiedCodeHashHex}
     * come from the proof-verified leaf (authoritative — a peer can't forge them while keeping
     * nonce/balance honest) and are null when the leaf proof didn't verify; callers needing the
     * peer-claimed slim values must fall back explicitly.
     *
     * @param peerProofValid        proof verifies against the peer's own stateRoot (necessary,
     *                              not sufficient for trust)
     * @param verifiedStorageRootHex storage root from the proof-verified leaf, or null
     * @param verifiedCodeHashHex   code hash from the proof-verified leaf, or null
     * @param beaconChainVerified   the peer's stateRoot ties to a beacon-attested root
     * @param blsVerified           the beacon match was BLS-signed
     * @param matchedSlot           slot of the matching attestation; -1 when none
     * @param verifyMethod          "stateRootMatch" / "headerChain" / null
     * @param failReason            null when verified
     */
    public record Verification(
            boolean peerProofValid,
            String verifiedStorageRootHex,
            String verifiedCodeHashHex,
            boolean beaconChainVerified,
            boolean blsVerified,
            long matchedSlot,
            String verifyMethod,
            String failReason) {}

    /** Mutable scratchpad the async verify chain fills before freezing into a {@link Verification}. */
    private static final class Scratch {
        boolean peerProofValid;
        MerklePatriciaVerifier.VerifiedAccount verifiedAcct;
        boolean beaconChainVerified;
        boolean blsVerified;
        long matchedSlot = -1;
        String verifyMethod;
        String failReason;

        Verification freeze() {
            return new Verification(
                    peerProofValid,
                    verifiedAcct != null ? Bytes.wrap(verifiedAcct.storageRoot()).toHexString() : null,
                    verifiedAcct != null ? Bytes.wrap(verifiedAcct.codeHash()).toHexString() : null,
                    beaconChainVerified, blsVerified, matchedSlot, verifyMethod, failReason);
        }
    }

    private static CompletableFuture<Result> buildAccountResult(
            String addr,
            Bytes address,
            Bytes32 accountHash,
            AccountRangeMessage.DecodeResult result,
            BeaconSyncState bss,
            RLPxConnector connector) {
        AccountRangeMessage.AccountData found = null;
        for (AccountRangeMessage.AccountData a : result.accounts()) {
            if (a.accountHash().equals(accountHash)) {
                found = a;
                break;
            }
        }
        final AccountRangeMessage.AccountData foundFinal = found;
        return verify(result, address, foundFinal, bss, connector)
                .thenApply(v -> finalizeResult(addr, foundFinal, result, v));
    }

    /**
     * Like {@link #query} but returning the full {@link io.myotis.api.AccountProofResult} —
     * account data + proof material + verdict + beacon diagnostics — so an IPC/API host can
     * reproduce its complete response from this record alone. Same validation and the same
     * single verification ladder.
     */
    public static CompletableFuture<io.myotis.api.AccountProofResult> queryProof(
            ChainStack stack, String hexAddress) {
        if (stack == null || !stack.isRunning()) {
            return Futures.failedFuture(new IllegalStateException("Node is not running"));
        }
        return queryProof(stack.connector(), stack.beaconSyncState(),
                stack.network().clGenesisTime(), stack.network().secondsPerSlot(), hexAddress,
                stack.readStats());
    }

    /**
     * {@link #queryProof(ChainStack, String)} for callers holding the parts rather than a
     * stack. {@code readStats} receives the verified account fact (proof-verified AND
     * beacon-anchored — never the peer's slim body) with the snap round-trip's cost.
     */
    public static CompletableFuture<io.myotis.api.AccountProofResult> queryProof(
            RLPxConnector connector, BeaconSyncState bss,
            long clGenesisTime, int secondsPerSlot, String hexAddress,
            io.myotis.evm.world.ReadStats readStats) {
        if (connector == null) {
            return Futures.failedFuture(new IllegalStateException("Node is not running"));
        }
        if (hexAddress == null) {
            return Futures.failedFuture(new IllegalArgumentException("Address is required"));
        }
        String hex = hexAddress.strip();
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.length() != 40) {
            return Futures.failedFuture(
                    new IllegalArgumentException("Address must be 20 bytes (40 hex chars)"));
        }
        Bytes address;
        try {
            address = Bytes.fromHexString(hex);
        } catch (Exception e) {
            return Futures.failedFuture(
                    new IllegalArgumentException("Invalid hex address: " + e.getMessage()));
        }
        final String addr = "0x" + hex;
        final Bytes32 accountHash = Hash.keccak256(address);
        final BeaconSyncState bssFinal = bss;
        final RLPxConnector conn = connector;
        final long snapStarted = System.nanoTime();
        return connector.requestAccount(address).thenCompose(result -> {
            // The snap round-trip's cost (the shadow cache's measure); the
            // verify() below may add a header-chain walk, which is not
            // something a state cache would have saved.
            final long snapElapsedNanos = System.nanoTime() - snapStarted;
            AccountRangeMessage.AccountData found = null;
            for (AccountRangeMessage.AccountData a : result.accounts()) {
                if (a.accountHash().equals(accountHash)) { found = a; break; }
            }
            final AccountRangeMessage.AccountData foundFinal = found;
            return verify(result, address, foundFinal, bssFinal, conn).thenApply(v -> {
                // Shadow-cache bookkeeping for the VERIFIED answer only: the leaf
                // proof must have verified (verifyMethod alone is not enough — the
                // stateRootMatch fast path does not consult peerProofValid, and
                // the hex fields below then fall back to the peer's slim body).
                if (readStats != null && v.peerProofValid() && v.verifyMethod() != null
                        && result.stateRoot() != null) {
                    var fact = foundFinal == null
                            ? io.myotis.evm.world.ReadStats.AccountFact.absent()
                            : new io.myotis.evm.world.ReadStats.AccountFact(
                                    foundFinal.nonce(), foundFinal.balance(),
                                    Bytes32.fromHexString(v.verifiedStorageRootHex()),
                                    Bytes32.fromHexString(v.verifiedCodeHashHex()));
                    readStats.observeAccount(address.toArrayUnsafe(),
                            result.stateRoot().toArrayUnsafe(), fact, snapElapsedNanos);
                }
                List<String> proofHex = new ArrayList<>(result.proof().size());
                for (Bytes b : result.proof()) proofHex.add(b.toHexString());
                String storageRootHex = v.verifiedStorageRootHex() != null
                        ? v.verifiedStorageRootHex()
                        : (foundFinal != null ? foundFinal.storageRoot().toHexString() : null);
                String codeHashHex = v.verifiedCodeHashHex() != null
                        ? v.verifiedCodeHashHex()
                        : (foundFinal != null ? foundFinal.codeHash().toHexString() : null);
                boolean synced = bssFinal != null && bssFinal.isSynced();
                long finalizedPeriod = bssFinal != null ? bssFinal.getFinalizedPeriod() : 0;
                long wallClockPeriod = com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec
                        .currentPeriod(clGenesisTime, secondsPerSlot);
                long finalizedBlockNumber = bssFinal != null
                        ? bssFinal.getFinalizedExecution().blockNumber() : 0;
                long optimisticBlockNumber = bssFinal != null ? bssFinal.getOptimisticBlockNumber() : 0;
                return new io.myotis.api.AccountProofResult(
                        addr,
                        foundFinal != null,
                        foundFinal != null ? foundFinal.nonce() : -1,
                        foundFinal != null ? foundFinal.balance().toString() : null,
                        storageRootHex,
                        codeHashHex,
                        result.blockNumber(),
                        result.stateRoot() != null ? result.stateRoot().toHexString() : null,
                        v.peerProofValid(),
                        v.beaconChainVerified(),
                        v.blsVerified(),
                        v.matchedSlot(),
                        v.verifyMethod(),
                        v.failReason(),
                        accountHash.toHexString(),
                        proofHex,
                        synced,
                        finalizedPeriod,
                        wallClockPeriod,
                        finalizedBlockNumber,
                        optimisticBlockNumber,
                        // No block timestamp on this engine yet: one is reported only
                        // from the light client's attested execution header, which this
                        // read path does not consult (AccountProofResult.blockTimestamp).
                        -1L);
            });
        });
    }

    /**
     * Run the proof + beacon verification ladder for a snap AccountRange response, returning the
     * {@link Verification} verdict WITHOUT building the full {@link Result}. This is the single
     * home of the trust anchor (proof-against-peer-root → beacon stateRootMatch → BLS-attested
     * headerChain): {@link #query} and the JVM daemon's {@code get-account} both call it, so the
     * verification logic lives in exactly one place. The returned future normally completes with
     * a verdict rather than exceptionally: a transport error in the header fetch is caught and
     * surfaced as {@code failReason="headerChainError"}, and all other verification *failures*
     * likewise set {@link Verification#failReason} while completing the future normally.
     */
    public static CompletableFuture<Verification> verify(
            AccountRangeMessage.DecodeResult result,
            Bytes address,
            BeaconSyncState bss,
            RLPxConnector connector) {
        Bytes32 accountHash = Hash.keccak256(address);
        AccountRangeMessage.AccountData found = null;
        for (AccountRangeMessage.AccountData a : result.accounts()) {
            if (a.accountHash().equals(accountHash)) {
                found = a;
                break;
            }
        }
        return verify(result, address, found, bss, connector);
    }

    /**
     * Same as {@link #verify(AccountRangeMessage.DecodeResult, Bytes, BeaconSyncState,
     * RLPxConnector)} but accepting the already-located {@code found} account, so callers that
     * scanned {@code result.accounts()} themselves don't pay a second scan.
     */
    public static CompletableFuture<Verification> verify(
            AccountRangeMessage.DecodeResult result,
            Bytes address,
            AccountRangeMessage.AccountData found,
            BeaconSyncState bss,
            RLPxConnector connector) {
        long nonce = found != null ? found.nonce() : -1;
        String balance = found != null ? found.balance().toString() : null;

        Scratch v = new Scratch();
        if (result.stateRoot() != null && !result.proof().isEmpty()) {
            List<byte[]> proofBytes = new ArrayList<>(result.proof().size());
            for (Bytes b : result.proof()) proofBytes.add(b.toArrayUnsafe());
            // verifyAndExtractAccount returns the storageRoot/codeHash from the proof-verified
            // leaf — NOT the peer's slim body — so a peer can't forge those two while keeping
            // nonce/balance honest.
            v.verifiedAcct = MerklePatriciaVerifier.verifyAndExtractAccount(
                    result.stateRoot().toArrayUnsafe(),
                    address.toArrayUnsafe(),
                    proofBytes, nonce, balance);
            v.peerProofValid = (v.verifiedAcct != null);
        }

        // Fast-path shortcut: if the BLC has already attested the peer's exact stateRoot, we're
        // done — no header fetch needed. Rare, but free to check.
        if (bss != null && result.stateRoot() != null) {
            BeaconSyncState.SlottedStateRoot match =
                    bss.findStateRoot(result.stateRoot().toArrayUnsafe());
            if (match != null) {
                v.beaconChainVerified = true;
                v.matchedSlot = match.slot();
                v.blsVerified = match.blsVerified();
                v.verifyMethod = "stateRootMatch";
                return CompletableFuture.completedFuture(v.freeze());
            }
        }

        // Main verification path: headerChain. Walk the failure ladder — only run the fetch +
        // chain verification if every prerequisite holds.
        if (result.stateRoot() == null) {
            v.failReason = "noPeerStateRoot";
        } else if (!v.peerProofValid) {
            v.failReason = "peerProofInvalid";
        } else if (bss == null || !bss.isSynced()) {
            v.failReason = "beaconNotSynced";
        } else {
            long peerBlockNumber = result.blockNumber();
            // Read block number + block hash from one atomic snapshot — reading them via two
            // separate getters can pair a block number with a hash from a different
            // finalized payload if an update lands between the calls.
            BeaconSyncState.FinalizedExecution fin = bss.getFinalizedExecution();
            long finalizedBlock = fin.blockNumber();
            WalkAnchor anchor = walkAnchor(peerBlockNumber, bss.getOptimisticExecution());

            if (peerBlockNumber <= 0) {
                v.failReason = "noPeerBlockNumber";
            } else if (finalizedBlock <= 0 || fin.blockHash() == null) {
                v.failReason = "beaconBlockUnavailable";
            } else if (peerBlockNumber <= finalizedBlock) {
                // The freshness floor: state at or below finality is too old to answer with.
                v.failReason = "peerBlockBehindFinalized";
            } else if (anchor == null) {
                v.failReason = "peerBlockAheadOfAnchor";
            } else if (anchor.blockNumber() - peerBlockNumber >= MAX_HEADER_CHAIN_GAP) {
                v.failReason = "headerChainGapTooLarge";
            } else {
                // headerChain: fetch [peerBlock .. anchor] inclusive from a single peer and
                // verify the chain end-to-end, down from the attested anchor.
                log.info("[verify] headerChain: peerBlock={}, anchorBlock={}, gap={}",
                        peerBlockNumber, anchor.blockNumber(), anchor.blockNumber() - peerBlockNumber);
                return verifyHeaderChainBatched(
                                connector, peerBlockNumber, anchor.blockNumber(),
                                anchor.blockHash(), result.stateRoot().toArrayUnsafe())
                        .handle((chainValid, ex) -> {
                            if (ex != null) {
                                log.info("[verify] headerChain error: {}", ex.getMessage());
                                v.failReason = "headerChainError";
                            } else if (Boolean.TRUE.equals(chainValid)) {
                                v.beaconChainVerified = true;
                                v.matchedSlot = anchor.slot();
                                v.blsVerified = true;
                                v.verifyMethod = "headerChain";
                                v.failReason = null;
                            } else {
                                v.failReason = "headerChainInvalid";
                            }
                            return v.freeze();
                        });
            }
        }

        return CompletableFuture.completedFuture(v.freeze());
    }

    private static Result finalizeResult(String addr,
                                         AccountRangeMessage.AccountData found,
                                         AccountRangeMessage.DecodeResult result,
                                         Verification v) {
        long nonce = found != null ? found.nonce() : -1;
        String balance = found != null ? found.balance().toString() : null;
        // storageRoot/codeHash come from the proof-verified leaf when we have it, so they're
        // cryptographically anchored rather than peer-claimed. Fall back to the slim (peer-claimed)
        // body only when the leaf proof didn't verify (verifiedStorageRootHex == null). Note this
        // is gated on peerProofValid, NOT beaconChainVerified: the beacon stateRootMatch fast-path
        // can set beaconChainVerified=true even when the leaf proof didn't verify, so it is not a
        // proxy for "we have a proof-verified leaf".
        String storageRootHex = v.verifiedStorageRootHex() != null
                ? v.verifiedStorageRootHex()
                : (found != null ? found.storageRoot().toHexString() : null);
        String codeHashHex = v.verifiedCodeHashHex() != null
                ? v.verifiedCodeHashHex()
                : (found != null ? found.codeHash().toHexString() : null);
        return new Result(
                addr,
                found != null,
                nonce,
                balance,
                storageRootHex,
                codeHashHex,
                result.blockNumber(),
                result.stateRoot() != null ? result.stateRoot().toHexString() : null,
                v.peerProofValid(),
                v.beaconChainVerified(),
                v.blsVerified(),
                v.matchedSlot(),
                v.verifyMethod(),
                v.failReason());
    }

    /** The attested block a header-chain walk ends at, and the beacon slot that attested it. */
    record WalkAnchor(long blockNumber, byte[] blockHash, long slot) {}

    /**
     * The attested block a header-chain walk for {@code peerBlock} ends at — the optimistic
     * head, when the peer's block is at or below it — or null when nothing attested lies at or
     * above the peer's block yet ({@code peerBlockAheadOfAnchor}). The anchor must be at or
     * ABOVE the peer's block; see {@link #verifyHeaderChain} for why. Twin of the anchor choice
     * in the Rust {@code el::verify::ladder_precheck}. Package-private:
     * {@link VerifiedStorageQuery} runs the same ladder.
     */
    static WalkAnchor walkAnchor(long peerBlock, BeaconSyncState.OptimisticExecution opt) {
        if (opt != null && opt.blockHash() != null && opt.blockNumber() > 0
                && peerBlock <= opt.blockNumber()) {
            return new WalkAnchor(opt.blockNumber(), opt.blockHash(), opt.slot());
        }
        return null;
    }

    /**
     * Fetch headers {@code [peerBlock .. anchorBlock]} in a single batch and verify the chain
     * end-to-end ({@link #verifyHeaderChain}): the last header hashes to the attested
     * {@code anchorHash}, the first carries the peer's state root, every link holds.
     */
    /** Package-private: {@link VerifiedStorageQuery} anchors its account root with the
     *  same walk, so the headerChain fetch+verify lives once. */
    static CompletableFuture<Boolean> verifyHeaderChainBatched(
            RLPxConnector connector, long peerBlock, long anchorBlock,
            byte[] anchorHash, byte[] peerStateRoot) {
        long totalLong = anchorBlock - peerBlock + 1;
        if (totalLong < 1 || totalLong > MAX_HEADER_CHAIN_GAP) {
            log.info("[verify] headerChain length {} out of range [1, {}]", totalLong, MAX_HEADER_CHAIN_GAP);
            return CompletableFuture.completedFuture(false);
        }
        int total = (int) totalLong;
        log.info("[verify] Fetching {} headers from #{} to #{}", total, peerBlock, anchorBlock);
        return Futures.orTimeout(connector.requestBlockHeadersBatched(peerBlock, total),
                        HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS)
                .thenApply(headers -> {
                    boolean valid = verifyHeaderChain(headers, anchorHash, peerStateRoot);
                    log.info("[verify] Full header chain ({} blocks) valid: {}", headers.size(), valid);
                    return valid;
                });
    }

    /** Pure verification of a contiguous header range. Package-private so the
     *  cross-language conformance test (ElVerifyVectorConformanceTest) can pin
     *  it against the Rust twin (myotis-net el::verify::verify_header_chain).
     *
     *  <p>The LAST header is the trust anchor, matched by its BLOCK HASH: the
     *  keccak256 of the whole header, so it pins that header completely (a
     *  state-root-only match would let a peer copy an attested state root into
     *  a fabricated header). The FIRST header carries the peer's state root.
     *
     *  <p>The anchor must be the NEWEST header. A parent hash commits a header
     *  to its parent, never to its children, so trust flows only DOWN from the
     *  anchor: it pins its parent, which pins its own, and so on to the first
     *  header. This walk was once anchored at the OLDEST header (the finalized
     *  block) instead, which pinned nothing above it — a peer could name the
     *  real finalized block as the parent of a header it made up, with any
     *  state root, and pass. */
    static boolean verifyHeaderChain(List<BlockHeadersMessage.VerifiedHeader> headers,
                                             byte[] expectedLastBlockHash,
                                             byte[] expectedFirstStateRoot) {
        if (!HeaderChains.anchoredAtTop(headers, expectedLastBlockHash)) return false;
        byte[] firstStateRoot = headers.get(0).header().stateRoot.toArrayUnsafe();
        return java.util.Arrays.equals(firstStateRoot, expectedFirstStateRoot);
    }
}
