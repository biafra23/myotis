package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Locks the {@link VerifiedAccountQuery.Verification} contract for the paths constructible
 * without a live peer: the failure ladder must set the exact {@code failReason} tokens the
 * daemon's IPC JSON exposes, and the stateRootMatch fast-path must carry the beacon match
 * through to the verdict — but only for a proof that verified, and the slim entry must agree
 * with what the proof shows (present, or proven absent). (The headerChain path needs a peer
 * round-trip and is covered by the integration contract instead.)
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
        Bytes32 storageRoot = Bytes32.fromHexString(
                "0x4444444444444444444444444444444444444444444444444444444444444444");
        Bytes leaf = accountLeaf(Hash.keccak256(ADDRESS), 7, BALANCE, storageRoot, CODE_HASH);
        Bytes32 stateRoot = Hash.keccak256(leaf);
        BeaconSyncState bss = new BeaconSyncState();
        bss.recordStateRoot(12345L, stateRoot.toArrayUnsafe(), true);

        AccountRangeMessage.DecodeResult result = new AccountRangeMessage.DecodeResult(
                1, List.of(slim(7, BALANCE, storageRoot)), List.of(leaf), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, bss, null).get();

        assertTrue(v.peerProofValid());
        assertTrue(v.beaconChainVerified());
        assertTrue(v.blsVerified());
        assertEquals(12345L, v.matchedSlot());
        assertEquals("stateRootMatch", v.verifyMethod());
        assertNull(v.failReason());
        assertEquals(storageRoot.toHexString(), v.verifiedStorageRootHex());
    }

    @Test
    void stateRootMatchNeedsAValidProof() throws Exception {
        Bytes32 stateRoot = Bytes32.fromHexString(
                "0x2222222222222222222222222222222222222222222222222222222222222222");
        BeaconSyncState bss = new BeaconSyncState();
        bss.recordStateRoot(12345L, stateRoot.toArrayUnsafe(), true);

        // An attested root with NO proof under it: a slim body claiming anything must not be
        // reported as stateRootMatch-verified (it used to be — the root vouched for values no
        // proof had proved).
        AccountRangeMessage.DecodeResult result = new AccountRangeMessage.DecodeResult(
                1, List.of(slim(999, BigInteger.TEN.pow(30), CODE_HASH)), List.of(), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, bss, null).get();

        assertFalse(v.peerProofValid());
        assertFalse(v.beaconChainVerified());
        assertNull(v.verifyMethod());
        assertEquals("peerProofInvalid", v.failReason());
    }

    @Test
    void anAccountTheProofShowsCannotBeWithheldFromTheList() throws Exception {
        // The proof proves the account exists, but the peer's list leaves it out: reported as
        // "absent" with a valid proof before this fix (no slim entry ⇒ no nonce/balance check).
        Bytes leaf = accountLeaf(Hash.keccak256(ADDRESS), 7, BALANCE, CODE_HASH, CODE_HASH);
        Bytes32 stateRoot = Hash.keccak256(leaf);
        BeaconSyncState bss = new BeaconSyncState();
        bss.recordStateRoot(12345L, stateRoot.toArrayUnsafe(), true);

        AccountRangeMessage.DecodeResult result = new AccountRangeMessage.DecodeResult(
                1, List.of(), List.of(leaf), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, bss, null).get();

        assertFalse(v.peerProofValid());
        assertNull(v.verifyMethod());
        assertEquals("peerProofInvalid", v.failReason());
    }

    @Test
    void aProvenAbsenceVerifies() throws Exception {
        // A one-leaf trie holding a DIFFERENT account: an exclusion proof for ADDRESS.
        Bytes otherAddress = Bytes.fromHexString("1111111111111111111111111111111111111111");
        Bytes leaf = accountLeaf(Hash.keccak256(otherAddress), 1, BigInteger.ONE, CODE_HASH, CODE_HASH);
        Bytes32 stateRoot = Hash.keccak256(leaf);
        BeaconSyncState bss = new BeaconSyncState();
        bss.recordStateRoot(12345L, stateRoot.toArrayUnsafe(), true);

        AccountRangeMessage.DecodeResult result = new AccountRangeMessage.DecodeResult(
                1, List.of(), List.of(leaf), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, bss, null).get();

        assertTrue(v.peerProofValid());
        assertEquals("stateRootMatch", v.verifyMethod());
        assertNull(v.failReason());
        assertNull(v.verifiedStorageRootHex(), "an absent account has no leaf");
    }

    @Test
    void aSlimEntryForAnAbsentAccountIsRefused() throws Exception {
        // The proof shows ADDRESS absent, yet the list carries an entry for it.
        Bytes otherAddress = Bytes.fromHexString("1111111111111111111111111111111111111111");
        Bytes leaf = accountLeaf(Hash.keccak256(otherAddress), 1, BigInteger.ONE, CODE_HASH, CODE_HASH);
        Bytes32 stateRoot = Hash.keccak256(leaf);
        BeaconSyncState bss = new BeaconSyncState();
        bss.recordStateRoot(12345L, stateRoot.toArrayUnsafe(), true);

        AccountRangeMessage.DecodeResult result = new AccountRangeMessage.DecodeResult(
                1, List.of(slim(7, BALANCE, CODE_HASH)), List.of(leaf), stateRoot, 100);
        VerifiedAccountQuery.Verification v =
                VerifiedAccountQuery.verify(result, ADDRESS, bss, null).get();

        assertFalse(v.peerProofValid());
        assertEquals("peerProofInvalid", v.failReason());
    }

    @Test
    void theFastPathGateNeedsBothAMatchAndAValidProof() {
        // The gate get-storage shares: its slot proof's validity decides, not the account's.
        Bytes32 stateRoot = Bytes32.fromHexString(
                "0x7777777777777777777777777777777777777777777777777777777777777777");
        BeaconSyncState bss = new BeaconSyncState();
        bss.recordStateRoot(42L, stateRoot.toArrayUnsafe(), true);

        assertNull(VerifiedAccountQuery.stateRootMatch(bss, stateRoot, false));
        assertEquals(42L, VerifiedAccountQuery.stateRootMatch(bss, stateRoot, true).slot());
        assertNull(VerifiedAccountQuery.stateRootMatch(bss, Bytes32.ZERO, true), "no match");
    }

    private static final BigInteger BALANCE = new BigInteger("1000000000000000000");
    /** Any 32-byte value; stands in for a code hash or storage root the test does not inspect. */
    private static final Bytes32 CODE_HASH = Bytes32.fromHexString(
            "0x5555555555555555555555555555555555555555555555555555555555555555");

    /** The peer's slim entry for ADDRESS. */
    private static AccountRangeMessage.AccountData slim(long nonce, BigInteger balance,
                                                        Bytes32 storageRoot) {
        return new AccountRangeMessage.AccountData(
                Hash.keccak256(ADDRESS), nonce, balance, storageRoot, CODE_HASH);
    }

    /**
     * A one-leaf state trie's root node: {@code [hexPrefix(leaf, keyHash), rlp(account)]}. Its
     * keccak is the state root, and the node alone is the proof for {@code keyHash} (and an
     * exclusion proof for any other key).
     */
    static Bytes accountLeaf(Bytes32 keyHash, long nonce, BigInteger balance,
                             Bytes32 storageRoot, Bytes32 codeHash) {
        Bytes account = RLP.encodeList(w -> {
            w.writeLong(nonce);
            w.writeBigInteger(balance);
            w.writeValue(storageRoot);
            w.writeValue(codeHash);
        });
        Bytes path = Bytes.concatenate(Bytes.of(0x20), keyHash); // leaf flag, even length
        return RLP.encodeList(w -> {
            w.writeValue(path);
            w.writeValue(account);
        });
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
