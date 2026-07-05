package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.proof.MerklePatriciaVerifier;
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
 *   <li><b>headerChain</b> (load-bearing) — fetch the contiguous header range
 *       {@code [finalizedBlock .. peerBlock]} from the same peer, verify the parent-hash chain,
 *       and require the first header's stateRoot to equal the beacon-finalized execution
 *       stateRoot and the last header's stateRoot to equal the peer-reported stateRoot.</li>
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
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Node is not running"));
        }
        if (hexAddress == null) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Address is required"));
        }
        String hex = hexAddress.strip();
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.length() != 40) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Address must be 20 bytes (40 hex chars)"));
        }
        final String hexAddrFinal = hex;
        Bytes address;
        try {
            address = Bytes.fromHexString(hex);
        } catch (Exception e) {
            return CompletableFuture.failedFuture(
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
        RLPxConnector connector = stack != null ? stack.connector() : null;
        BeaconSyncState bss = stack != null ? stack.beaconSyncState() : null;
        if (stack == null || !stack.isRunning() || connector == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Node is not running"));
        }
        if (hexAddress == null) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Address is required"));
        }
        String hex = hexAddress.strip();
        if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
        if (hex.length() != 40) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Address must be 20 bytes (40 hex chars)"));
        }
        Bytes address;
        try {
            address = Bytes.fromHexString(hex);
        } catch (Exception e) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Invalid hex address: " + e.getMessage()));
        }
        final String addr = "0x" + hex;
        final Bytes32 accountHash = Hash.keccak256(address);
        final long clGenesisTime = stack.network().clGenesisTime();
        final int secondsPerSlot = stack.network().secondsPerSlot();
        final BeaconSyncState bssFinal = bss;
        final RLPxConnector conn = connector;
        return connector.requestAccount(address).thenCompose(result -> {
            AccountRangeMessage.AccountData found = null;
            for (AccountRangeMessage.AccountData a : result.accounts()) {
                if (a.accountHash().equals(accountHash)) { found = a; break; }
            }
            final AccountRangeMessage.AccountData foundFinal = found;
            return verify(result, address, foundFinal, bssFinal, conn).thenApply(v -> {
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
                        optimisticBlockNumber);
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
            // Read block number + state root from one atomic snapshot — reading them via two
            // separate getters can pair a block number with a state root from a different
            // finalized payload if an update lands between the calls.
            BeaconSyncState.FinalizedExecution fin = bss.getFinalizedExecution();
            long finalizedBlock = fin.blockNumber();
            byte[] beaconRoot = fin.stateRoot();

            if (peerBlockNumber <= 0) {
                v.failReason = "noPeerBlockNumber";
            } else if (finalizedBlock <= 0 || beaconRoot == null) {
                v.failReason = "beaconBlockUnavailable";
            } else if (peerBlockNumber <= finalizedBlock) {
                v.failReason = "peerBlockBehindFinalized";
            } else if (peerBlockNumber - finalizedBlock > MAX_HEADER_CHAIN_GAP) {
                v.failReason = "headerChainGapTooLarge";
            } else {
                // headerChain: fetch [finalized .. peerBlock] inclusive from a single peer and
                // verify the chain end-to-end.
                final long finalizedSlot = bss.getFinalizedSlot();
                log.info("[verify] headerChain: peerBlock={}, finalizedBlock={}, gap={}",
                        peerBlockNumber, finalizedBlock, peerBlockNumber - finalizedBlock);
                return verifyHeaderChainBatched(
                                connector, finalizedBlock, peerBlockNumber,
                                beaconRoot, result.stateRoot().toArrayUnsafe())
                        .handle((chainValid, ex) -> {
                            if (ex != null) {
                                log.info("[verify] headerChain error: {}", ex.getMessage());
                                v.failReason = "headerChainError";
                            } else if (Boolean.TRUE.equals(chainValid)) {
                                v.beaconChainVerified = true;
                                v.matchedSlot = finalizedSlot;
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

    /**
     * Fetch headers in a single batch and verify the chain end-to-end. Completes with
     * {@code true} iff the first header's stateRoot equals the beacon-finalized root, the last
     * header's stateRoot equals the peer's reported root, and every header's hash equals the
     * next header's parentHash.
     */
    private static CompletableFuture<Boolean> verifyHeaderChainBatched(
            RLPxConnector connector, long finalizedBlock, long peerBlock,
            byte[] beaconStateRoot, byte[] peerStateRoot) {
        long totalLong = peerBlock - finalizedBlock + 1;
        if (totalLong < 2 || totalLong > MAX_HEADER_CHAIN_GAP) {
            log.info("[verify] headerChain gap {} out of range [2, {}]", totalLong, MAX_HEADER_CHAIN_GAP);
            return CompletableFuture.completedFuture(false);
        }
        int total = (int) totalLong;
        log.info("[verify] Fetching {} headers from #{} to #{}", total, finalizedBlock, peerBlock);
        return connector.requestBlockHeadersBatched(finalizedBlock, total)
                .orTimeout(HEADER_CHAIN_TIMEOUT_SEC, TimeUnit.SECONDS)
                .thenApply(headers -> {
                    boolean valid = verifyHeaderChain(headers, beaconStateRoot, peerStateRoot);
                    log.info("[verify] Full header chain ({} blocks) valid: {}", headers.size(), valid);
                    return valid;
                });
    }

    /** Pure verification of a contiguous header range. */
    private static boolean verifyHeaderChain(List<BlockHeadersMessage.VerifiedHeader> headers,
                                             byte[] expectedFirstStateRoot,
                                             byte[] expectedLastStateRoot) {
        if (headers.isEmpty()) return false;

        byte[] firstStateRoot = headers.get(0).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(firstStateRoot, expectedFirstStateRoot)) return false;

        byte[] lastStateRoot = headers.get(headers.size() - 1).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(lastStateRoot, expectedLastStateRoot)) return false;

        for (int i = 0; i < headers.size() - 1; i++) {
            Bytes32 currentHash = headers.get(i).hash();
            Bytes32 nextParent = headers.get(i + 1).header().parentHash;
            if (!currentHash.equals(nextParent)) {
                log.info("[verify] hash chain break at index {}: block #{} hash={} != block #{} parentHash={}",
                        i, headers.get(i).header().number, currentHash.toShortHexString(),
                        headers.get(i + 1).header().number, nextParent.toShortHexString());
                return false;
            }
        }
        return true;
    }
}
