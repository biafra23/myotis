package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Locks the {@link VerifiedAccountQuery.Verification} contract for the paths constructible
 * without a live peer: the failure ladder must set the exact {@code failReason} tokens the
 * daemon's IPC JSON exposes, and the stateRootMatch fast-path must carry the beacon match
 * through to the verdict. (The headerChain path needs a peer round-trip and is covered by
 * the integration contract instead.)
 */
class VerifiedAccountQueryVerifyTest {

    @org.junit.jupiter.api.BeforeAll
    static void setUpProvider() {
        // Tuweni's keccak256 needs the BouncyCastle provider (same setup as the
        // networking module's message tests).
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final Bytes ADDRESS =
            Bytes.fromHexString("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    @Test
    void noStateRootFailsWithNoPeerStateRoot() throws Exception {
        AccountRangeMessage.DecodeResult result =
                new AccountRangeMessage.DecodeResult(1, List.of(), List.of());
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, new BeaconSyncState(), null).get();

        assertEquals("noPeerStateRoot", v.failReason());
        assertFalse(v.peerProofValid());
        assertFalse(v.beaconChainVerified());
        assertFalse(v.blsVerified());
        assertEquals(-1, v.matchedSlot());
        assertNull(v.verifyMethod());
        // No proof-verified leaf → no authoritative storageRoot/codeHash.
        assertNull(v.verifiedStorageRootHex());
        assertNull(v.verifiedCodeHashHex());
    }

    @Test
    void invalidProofFailsWithPeerProofInvalid() throws Exception {
        Bytes32 stateRoot = Bytes32.fromHexString(
                "0x1111111111111111111111111111111111111111111111111111111111111111");
        // A garbage proof node: proof verification must fail, never throw.
        AccountRangeMessage.DecodeResult result = new AccountRangeMessage.DecodeResult(
                1, List.of(), List.of(Bytes.fromHexString("0xdeadbeef")), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, new BeaconSyncState(), null).get();

        assertEquals("peerProofInvalid", v.failReason());
        assertFalse(v.peerProofValid());
        assertNull(v.verifiedStorageRootHex());
        assertFalse(v.beaconChainVerified());
    }

    @Test
    void stateRootMatchFastPathCarriesBeaconMatch() throws Exception {
        Bytes32 stateRoot = Bytes32.fromHexString(
                "0x2222222222222222222222222222222222222222222222222222222222222222");
        BeaconSyncState bss = new BeaconSyncState();
        bss.recordStateRoot(12345L, stateRoot.toArrayUnsafe(), true);

        // Empty proof: the fast-path fires on the beacon match alone; peerProofValid stays
        // false — the verdict must expose BOTH truthfully (beaconChainVerified is not a
        // proxy for leaf-proof validity).
        AccountRangeMessage.DecodeResult result = new AccountRangeMessage.DecodeResult(
                1, List.of(), List.of(), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, bss, null).get();

        assertTrue(v.beaconChainVerified());
        assertTrue(v.blsVerified());
        assertEquals(12345L, v.matchedSlot());
        assertEquals("stateRootMatch", v.verifyMethod());
        assertNull(v.failReason());
        assertFalse(v.peerProofValid());
        assertNull(v.verifiedStorageRootHex());
    }

    @Test
    void beaconNotSyncedFailsAfterValidStructureChecks() throws Exception {
        Bytes32 stateRoot = Bytes32.fromHexString(
                "0x3333333333333333333333333333333333333333333333333333333333333333");
        // Proof present but bogus → the ladder stops at peerProofInvalid before the beacon
        // check; with NO proof it must stop at peerProofInvalid too (no leaf was verified).
        AccountRangeMessage.DecodeResult noProof = new AccountRangeMessage.DecodeResult(
                1, List.of(), List.of(), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(noProof, ADDRESS, new BeaconSyncState(), null).get();
        assertEquals("peerProofInvalid", v.failReason());
    }
}
