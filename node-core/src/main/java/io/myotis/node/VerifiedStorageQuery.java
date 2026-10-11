package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.proof.MerklePatriciaVerifier;
import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
import io.myotis.api.StorageProofResult;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Shared, host-agnostic verified storage-slot query — the engine home of the daemon's
 * {@code get-storage} ladder (moved out of the JVM {@code CommandHandler} verbatim):
 *
 * <ol>
 *   <li>Fetch the contract account at the peer's fresh state root (peers prune beyond
 *       ~128 blocks, so a beacon-finalized root is usually too stale for them to serve).</li>
 *   <li>Take {@code storageRoot} from the PROOF-VERIFIED account leaf, never the peer's
 *       slim body — a peer could otherwise forge storageRoot (keeping nonce/balance
 *       honest) plus a matching storage proof and fabricate a "verified" slot value.</li>
 *   <li>Fetch + MPT-verify the slot against that storageRoot. The reported value is the
 *       PROOF's ({@link #verifySlot}) — a peer's slot list that disagrees with its own proof
 *       invalidates the answer — and a proven-absent slot is a valid zero.</li>
 *   <li>Anchor the account's state root to the beacon chain: stateRootMatch fast-path,
 *       else the BLS-attested headerChain walk (shared with {@link VerifiedAccountQuery}).</li>
 * </ol>
 *
 * <p>Verification failures surface in the result's {@code failReason}; malformed input and
 * unservable fetches throw ({@link IllegalArgumentException}/{@link IllegalStateException}
 * with the daemon's established messages, which hosts fold into their error responses).
 */
public final class VerifiedStorageQuery {

    private static final Logger log = LoggerFactory.getLogger(VerifiedStorageQuery.class);

    private VerifiedStorageQuery() {}

    /**
     * Blocking query (call from a worker thread; internally bounded — two 30 s fetches plus
     * the 60 s header walk worst-case). {@code holderHexOrNull} switches the queried key to
     * the Solidity mapping slot {@code keccak256(pad32(holder) ‖ uint256(slot))} (ERC-20
     * balance lookups).
     */
    public static StorageProofResult query(RLPxConnector connector,
                                           BeaconSyncState beaconSyncState,
                                           String hexAddress,
                                           long slotNumber,
                                           String holderHexOrNull,
                                           io.myotis.evm.world.ReadStats readStats) throws Exception {
        String addr = hexAddress == null ? "" : hexAddress;
        String hex = (addr.startsWith("0x") || addr.startsWith("0X")) ? addr.substring(2) : addr;
        if (hex.length() != 40) {
            throw new IllegalArgumentException("address must be a 20-byte hex string (40 hex chars)");
        }
        Bytes contractAddress = Bytes.fromHexString(hex);

        // Compute the storage key: plain uint256(slot), or the ERC-20 mapping key
        // keccak256(abi.encode(holderAddress, uint256(slot))).
        String holderEcho = null;
        byte[] storageSlotKey;
        if (holderHexOrNull != null) {
            holderEcho = holderHexOrNull;
            String holderHex = (holderHexOrNull.startsWith("0x") || holderHexOrNull.startsWith("0X"))
                    ? holderHexOrNull.substring(2) : holderHexOrNull;
            if (holderHex.length() != 40) {
                throw new IllegalArgumentException("holder must be a 20-byte hex string (40 hex chars)");
            }
            byte[] holderBytes = Bytes.fromHexString(holderHex).toArrayUnsafe();
            byte[] encoded = new byte[64];
            System.arraycopy(holderBytes, 0, encoded, 12, 20); // left-pad holder to 32 bytes
            writeSlotBe(encoded, 56, slotNumber);
            storageSlotKey = Hash.keccak256(Bytes.wrap(encoded)).toArrayUnsafe();
        } else {
            byte[] slotBytes = new byte[32];
            writeSlotBe(slotBytes, 24, slotNumber);
            storageSlotKey = slotBytes;
        }
        Bytes32 storageKeyHash = Hash.keccak256(Bytes.wrap(storageSlotKey));

        // Step 1: fetch the account to get the proof-verified storageRoot.
        // (Each snap round-trip is timed for the read-fetch shadow cache — not
        // the beacon-anchoring walk in step 4.)
        Bytes32 accountHash = Hash.keccak256(contractAddress);
        long accountStarted = System.nanoTime();
        AccountRangeMessage.DecodeResult accountResult =
                connector.requestAccount(contractAddress).get(30, TimeUnit.SECONDS);
        long accountElapsedNanos = System.nanoTime() - accountStarted;
        AccountRangeMessage.AccountData account = accountResult.accounts().stream()
                .filter(a -> a.accountHash().equals(accountHash))
                .findFirst().orElse(null);
        if (account == null) {
            throw new IllegalStateException("Contract account not found");
        }

        Bytes32 snapStateRoot = accountResult.stateRoot();
        List<byte[]> accountProofBytes = accountResult.proof().stream()
                .map(Bytes::toArrayUnsafe).toList();
        MerklePatriciaVerifier.VerifiedAccount verifiedAccount =
                snapStateRoot == null ? null
                        : MerklePatriciaVerifier.verifyAndExtractAccount(
                                snapStateRoot.toArrayUnsafe(),
                                contractAddress.toArrayUnsafe(), accountProofBytes,
                                account.nonce(), account.balance().toString());
        if (verifiedAccount == null) {
            throw new IllegalStateException("Contract account proof did not verify against peer state root");
        }
        Bytes32 storageRoot = Bytes32.wrap(verifiedAccount.storageRoot());

        // Step 2: fetch the slot at the SAME peer state root for consistency.
        long slotStarted = System.nanoTime();
        StorageRangesMessage.DecodeResult storageResult =
                connector.requestStorage(contractAddress, storageKeyHash, snapStateRoot)
                        .get(30, TimeUnit.SECONDS);
        long slotElapsedNanos = System.nanoTime() - slotStarted;

        List<String> proofHex = storageResult.proof().stream().map(Bytes::toHexString).toList();

        // Step 3: verify the slot against the proof-verified storageRoot. The VALUE is the
        // proof's, never the peer's slot list (see verifySlot).
        SlotProof slotProof = verifySlot(storageRoot, storageKeyHash, storageResult);
        boolean storageProofValid = slotProof.valid();

        // Step 4: anchor the account's state root to the beacon chain — stateRootMatch
        // fast-path, then the same failure ladder + headerChain walk as get-account.
        boolean beaconChainVerified = false;
        boolean blsVerified = false;
        long matchedSlot = -1;
        String verifyMethod = null;
        String failReason = null;
        Bytes32 usedStateRoot = accountResult.stateRoot();
        if (usedStateRoot != null) {
            // The account proof verified in step 1; the slot's must have too.
            BeaconSyncState.SlottedStateRoot match = VerifiedAccountQuery.stateRootMatch(
                    beaconSyncState, usedStateRoot, storageProofValid);
            if (match != null) {
                beaconChainVerified = true;
                matchedSlot = match.slot();
                blsVerified = match.blsVerified();
                verifyMethod = "stateRootMatch";
            }
        }
        long peerBlockNumber = accountResult.blockNumber();
        if (!beaconChainVerified) {
            // Atomic snapshot: block number + block hash must come from the same finalized
            // payload — a walk anchored there ends at the number and must hash to the hash.
            BeaconSyncState.FinalizedExecution fin = beaconSyncState.getFinalizedExecution();
            long finalizedBlockNum = fin.blockNumber();
            // The walk ends at an attested block AT OR ABOVE the peer's, matched by its
            // BLOCK HASH — see VerifiedAccountQuery.verifyHeaderChain's javadoc.
            VerifiedAccountQuery.WalkAnchor anchor = VerifiedAccountQuery.walkAnchor(
                    peerBlockNumber, beaconSyncState.getOptimisticExecution());
            if (usedStateRoot == null) {
                failReason = "noPeerStateRoot";
            } else if (!storageProofValid) {
                failReason = "peerProofInvalid";
            } else if (!beaconSyncState.isSynced()) {
                failReason = "beaconNotSynced";
            } else if (peerBlockNumber <= 0) {
                failReason = "noPeerBlockNumber";
            } else if (finalizedBlockNum <= 0 || fin.blockHash() == null) {
                failReason = "beaconBlockUnavailable";
            } else if (peerBlockNumber <= finalizedBlockNum) {
                failReason = "peerBlockBehindFinalized";
            } else if (anchor == null) {
                failReason = "peerBlockAheadOfAnchor";
            } else if (anchor.blockNumber() - peerBlockNumber >= VerifiedAccountQuery.MAX_HEADER_CHAIN_GAP) {
                failReason = "headerChainGapTooLarge";
            } else {
                log.info("[verify] headerChain: peerBlock={}, anchorBlock={}, gap={}",
                        peerBlockNumber, anchor.blockNumber(), anchor.blockNumber() - peerBlockNumber);
                try {
                    boolean chainValid = VerifiedAccountQuery.verifyHeaderChainBatched(
                                    connector, peerBlockNumber, anchor.blockNumber(),
                                    anchor.blockHash(), usedStateRoot.toArrayUnsafe())
                            .get(VerifiedAccountQuery.HEADER_CHAIN_TIMEOUT_SEC + 10, TimeUnit.SECONDS);
                    if (chainValid) {
                        beaconChainVerified = true;
                        matchedSlot = anchor.slot();
                        blsVerified = true;
                        verifyMethod = "headerChain";
                    } else {
                        failReason = "headerChainInvalid";
                    }
                } catch (Exception e) {
                    log.info("[verify] Header chain verification failed: {}", e.getMessage());
                    failReason = "headerChainError";
                }
            }
        }

        // Only a proven value is ever reported: a slot the proof does not show holding a value
        // (proven absent/zero, or the proof failed) has none here; storageProofValid and
        // failReason say which.
        String valueHex = slotProof.exists()
                ? Bytes.wrap(slotProof.value().toByteArray()).trimLeadingZeros().toHexString()
                : null;
        String valueDecimal = slotProof.exists() ? slotProof.value().toString() : null;

        // Shadow-cache bookkeeping for the VERIFIED answer only. The account
        // proof verified above (step 1 throws otherwise), and a verifyMethod
        // now implies the slot proof held too: neither the stateRootMatch fast
        // path nor the headerChain ladder anchors a failed slot proof. The
        // inner check keeps that explicit — an unproven peer value is not a
        // fact a cache could have served.
        if (verifyMethod != null && usedStateRoot != null) {
            readStats.observeAccount(contractAddress.toArrayUnsafe(), usedStateRoot.toArrayUnsafe(),
                    new io.myotis.evm.world.ReadStats.AccountFact(
                            account.nonce(), account.balance(), storageRoot,
                            Bytes32.wrap(verifiedAccount.codeHash())),
                    accountElapsedNanos);
            if (storageProofValid) {
                // A proven-absent slot is zero.
                readStats.observeStorage(contractAddress.toArrayUnsafe(), storageSlotKey,
                        usedStateRoot.toArrayUnsafe(), storageRoot.toArrayUnsafe(), slotProof.value(),
                        slotElapsedNanos);
            }
        }

        return new StorageProofResult(
                addr,
                slotNumber,
                holderEcho,
                "0x" + Bytes.wrap(storageSlotKey).toUnprefixedHexString(),
                storageKeyHash.toHexString(),
                slotProof.exists(),
                valueHex,
                valueDecimal,
                storageResult.slots().size(),
                storageRoot.toHexString(),
                proofHex,
                storageProofValid,
                beaconSyncState.isSynced(),
                beaconChainVerified,
                blsVerified,
                matchedSlot,
                verifyMethod,
                failReason,
                peerBlockNumber,
                // Diagnostics mirror the daemon's historical output: the finalized anchor
                // here reads getExecutionBlockNumber() (not the atomic pair used for the
                // walk above) — keep it so the emitted numbers don't shift.
                beaconSyncState.getExecutionBlockNumber(),
                beaconSyncState.getOptimisticBlockNumber(),
                beaconSyncState.getFinalizedSlot(),
                beaconSyncState.getOptimisticSlot(),
                VerifiedAccountQuery.MAX_HEADER_CHAIN_GAP);
    }

    /**
     * A storage slot's verdict, read from the proof alone.
     *
     * @param valid  the proof verifies against the storage root (showing the slot's value, or
     *               proving it absent) and the peer's slot list does not contradict it
     * @param value  the proven value — zero for a proven-absent slot (a zero slot is pruned
     *               from the trie) — or null when not {@code valid}
     */
    record SlotProof(boolean valid, BigInteger value) {
        static final SlotProof INVALID = new SlotProof(false, null);

        /** The proof shows the slot holding a value: valid and non-zero (Rust's {@code found}). */
        boolean exists() {
            return valid && value.signum() != 0;
        }
    }

    /**
     * Verify one slot of a {@code StorageRanges} response against {@code storageRoot}, the
     * account's proof-verified storage root. The value comes from the proof — the peer's slot
     * list is only its claim, so a list entry for this key that disagrees with the proof makes
     * the whole answer invalid rather than one side winning. An entry the list omits does not:
     * the proof alone answers the query. A proven absence (an exclusion proof, or no proof
     * against the empty-trie root) is a valid answer of zero.
     */
    static SlotProof verifySlot(Bytes32 storageRoot, Bytes32 storageKeyHash,
                                StorageRangesMessage.DecodeResult response) {
        MerklePatriciaProofVerifier.Result result = MerklePatriciaProofVerifier.verify(
                storageRoot, storageKeyHash.toArrayUnsafe(), response.proof());
        if (result instanceof MerklePatriciaProofVerifier.Result.Invalid) {
            return SlotProof.INVALID;
        }
        BigInteger proven;
        try {
            proven = result instanceof MerklePatriciaProofVerifier.Result.Found found
                    ? MerklePatriciaProofVerifier.storageInteger(found.value())
                    : BigInteger.ZERO;
        } catch (IllegalArgumentException e) {
            return SlotProof.INVALID;
        }
        for (StorageRangesMessage.StorageData entry : response.slots()) {
            // Compared as numbers: the list's encoding is the peer's, the value is not.
            if (entry.slotHash().equals(storageKeyHash)
                    && !new BigInteger(1, entry.slotValue().toArrayUnsafe()).equals(proven)) {
                return SlotProof.INVALID;
            }
        }
        return new SlotProof(true, proven);
    }

    /** uint64 → 8 big-endian bytes at {@code offset}..{@code offset+7}. */
    private static void writeSlotBe(byte[] out, int offset, long slot) {
        out[offset + 7] = (byte) (slot);
        out[offset + 6] = (byte) (slot >>> 8);
        out[offset + 5] = (byte) (slot >>> 16);
        out[offset + 4] = (byte) (slot >>> 24);
        out[offset + 3] = (byte) (slot >>> 32);
        out[offset + 2] = (byte) (slot >>> 40);
        out[offset + 1] = (byte) (slot >>> 48);
        out[offset]     = (byte) (slot >>> 56);
    }
}
