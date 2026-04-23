package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.bls.BlsVerifier;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ForkData;
import com.jaeckel.ethp2p.consensus.types.SyncAggregate;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Verifies sync committee BLS signatures over beacon block headers.
 */
public final class SyncCommitteeVerifier {

    private static final Logger log = LoggerFactory.getLogger(SyncCommitteeVerifier.class);

    private SyncCommitteeVerifier() {}

    /**
     * Verify that a sync aggregate is a valid signature over attestedHeader from currentSyncCommittee.
     *
     * <p>Returns true if:
     * <ol>
     *   <li>The participation count is at least 2/3 of SYNC_COMMITTEE_SIZE (512); and</li>
     *   <li>The BLS fast-aggregate-verify succeeds for the participating keys.</li>
     * </ol>
     *
     * @param syncAggregate        the aggregate to verify
     * @param syncCommittee        the current sync committee
     * @param attestedHeader       the beacon block header being attested
     * @param forkVersion          4-byte fork version (from network config)
     * @param genesisValidatorsRoot 32-byte genesis validators root (from network config)
     * @return true if the signature is valid
     */
    public static boolean verify(
            SyncAggregate syncAggregate,
            SyncCommittee syncCommittee,
            BeaconBlockHeader attestedHeader,
            byte[] forkVersion,
            byte[] genesisValidatorsRoot
    ) {
        // 1. Check participation: must be >= 2/3 of SYNC_COMMITTEE_SIZE
        int participants = syncAggregate.countParticipants();
        if (participants * 3 < BeaconChainSpec.SYNC_COMMITTEE_SIZE * 2) {
            log.info("[sync-verify] Insufficient participation: {}/{} (< 2/3 of {})",
                    participants, BeaconChainSpec.SYNC_COMMITTEE_SIZE,
                    BeaconChainSpec.SYNC_COMMITTEE_SIZE);
            return false;
        }

        // 2. Collect participating pubkeys
        List<byte[]> pubkeys = new ArrayList<>(participants);
        for (int i = 0; i < BeaconChainSpec.SYNC_COMMITTEE_SIZE; i++) {
            if (syncAggregate.getBit(i)) {
                pubkeys.add(syncCommittee.pubkeys()[i]);
            }
        }

        // 3. Compute signing root
        byte[] domain = ForkData.computeDomain(
                BeaconChainSpec.DOMAIN_SYNC_COMMITTEE, forkVersion, genesisValidatorsRoot);
        byte[] signingRoot = computeSigningRoot(attestedHeader.hashTreeRoot(), domain);

        // 4. BLS fast-aggregate verify
        boolean ok = BlsVerifier.fastAggregateVerify(pubkeys, signingRoot, syncAggregate.syncCommitteeSignature());
        if (!ok) {
            StringBuilder fvHex = new StringBuilder();
            for (byte b : forkVersion) fvHex.append(String.format("%02x", b));
            StringBuilder dHex = new StringBuilder();
            for (int i = 0; i < Math.min(8, domain.length); i++) dHex.append(String.format("%02x", domain[i]));
            log.info("[sync-verify] BLS fast_aggregate_verify FAILED: participants={}, fork_version=0x{}, "
                            + "domain[0..8]=0x{}, attestedSlot={}",
                    participants, fvHex, dHex, attestedHeader.slot());
        }
        return ok;
    }

    /**
     * Compute the signing root for an object.
     *
     * <p>SigningData = Container(object_root: Bytes32, domain: Bytes32)
     * signing_root = hash_tree_root(SigningData)
     *
     * @param objectRoot 32-byte hash_tree_root of the object being signed
     * @param domain     32-byte domain
     * @return 32-byte signing root
     */
    private static byte[] computeSigningRoot(byte[] objectRoot, byte[] domain) {
        // SigningData has two bytes32 fields: object_root and domain
        return SszUtil.hashTreeRootContainer(objectRoot, domain);
    }
}
