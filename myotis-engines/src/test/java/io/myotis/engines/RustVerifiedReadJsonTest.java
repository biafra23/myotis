package io.myotis.engines;

import io.myotis.api.AccountProofResult;
import io.myotis.api.EngineException;
import io.myotis.api.StorageProofResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Java half of the EL verified-read JSON golden contract: parse the exact
 * {@link AccountProofResult} / {@link StorageProofResult} shapes the Rust
 * {@code eljson} module emits (pinned there by its {@code account_json_shape} /
 * {@code storage_json_shape} tests) into the api records, and assert the
 * mapping. Needs no native library — it exercises the JSON→record seam that
 * {@link RustChainHandle} uses once {@code nativeRequestAccountJson} /
 * {@code nativeGetStorageProofJson} return.
 *
 * <p>The values here mirror the Rust {@code eljson} sample (a headerChain-verified
 * vitalik-style account), so the two sides are visibly parallel.
 */
class RustVerifiedReadJsonTest {

    /** A headerChain-verified account (mirrors the Rust eljson sample_account). */
    private static final String ACCOUNT_JSON =
            "{\"address\":\"0xd8da6bf26964af9d7eed9e03e53415d37aa96045\","
            + "\"exists\":true,\"nonce\":5898,\"balanceWei\":\"1000000000000000000\","
            + "\"storageRootHex\":\"0x56e81f171bcac1a441cf3f1d5f0b8d5f0f3f0e5e5b5b5b5b5b5b5b5b5b5b5b5b5\","
            + "\"codeHashHex\":\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\","
            + "\"blockNumber\":21000000,"
            + "\"peerStateRootHex\":\"0x5555555555555555555555555555555555555555555555555555555555555555\","
            + "\"peerProofValid\":true,\"beaconChainVerified\":true,\"blsVerified\":true,"
            + "\"matchedBeaconSlot\":7000000,\"verifyMethod\":\"headerChain\",\"failReason\":null,"
            + "\"accountHashHex\":\"0x2222222222222222222222222222222222222222222222222222222222222222\","
            + "\"proofNodesHex\":[],\"beaconSynced\":true,"
            + "\"finalizedPeriod\":1777,\"wallClockPeriod\":1795,"
            + "\"finalizedBlockNumber\":20999000,\"optimisticBlockNumber\":21000010}";

    @Test
    void accountJsonMapsToRecord() {
        AccountProofResult r = RustChainHandle.accountFromJson(
                "0xd8da6bf26964af9d7eed9e03e53415d37aa96045", ACCOUNT_JSON);
        assertEquals("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", r.address());
        assertTrue(r.exists());
        assertEquals(5898L, r.nonce());
        assertEquals("1000000000000000000", r.balanceWei());
        assertEquals(21000000L, r.blockNumber());
        assertTrue(r.peerProofValid());
        assertTrue(r.beaconChainVerified());
        assertTrue(r.blsVerified());
        assertEquals(7000000L, r.matchedBeaconSlot());
        // THE gate token.
        assertEquals("headerChain", r.verifyMethod());
        assertNull(r.failReason());
        assertTrue(r.beaconSynced());
        assertEquals(1777L, r.finalizedPeriod());
        assertEquals(1795L, r.wallClockPeriod());
        assertEquals(20999000L, r.finalizedBlockNumber());
        assertEquals(21000010L, r.optimisticBlockNumber());
        assertTrue(r.proofNodesHex().isEmpty());
    }

    @Test
    void absentAccountUsesNegativeOneAndNull() {
        String json = "{\"address\":\"0x0\",\"exists\":false,\"nonce\":-1,\"balanceWei\":null,"
                + "\"beaconChainVerified\":false,\"verifyMethod\":null,\"failReason\":\"beaconNotSynced\","
                + "\"matchedBeaconSlot\":-1,\"proofNodesHex\":[]}";
        AccountProofResult r = RustChainHandle.accountFromJson("0x0", json);
        assertFalse(r.exists());
        assertEquals(-1L, r.nonce());
        assertNull(r.balanceWei());
    }

    @Test
    void verificationFailureIsAResultNotAnException() {
        // beaconNotSynced is a VERDICT, not a transport error — it must parse to a
        // record with failReason set, never throw.
        String json = "{\"address\":\"0x0\",\"exists\":true,\"nonce\":0,\"balanceWei\":\"0\","
                + "\"beaconChainVerified\":false,\"blsVerified\":false,\"verifyMethod\":null,"
                + "\"failReason\":\"beaconNotSynced\",\"matchedBeaconSlot\":-1,\"proofNodesHex\":[]}";
        AccountProofResult r = RustChainHandle.accountFromJson("0x0", json);
        assertNull(r.verifyMethod());
        assertEquals("beaconNotSynced", r.failReason());
        assertFalse(r.beaconChainVerified());
    }

    @Test
    void errorObjectBecomesEngineException() {
        EngineException e = assertThrows(EngineException.class,
                () -> RustChainHandle.accountFromJson("0x0", "{\"error\":\"no snap peer available\"}"));
        assertTrue(e.getMessage().contains("no snap peer available"));
    }

    @Test
    void nullAndMalformedPayloadsThrow() {
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", null));
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", ""));
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", "not json"));
    }

    /** A headerChain-verified storage slot (mirrors the Rust eljson storage sample). */
    private static final String STORAGE_JSON =
            "{\"addressHex\":\"0xC0\",\"slot\":3,\"holderHex\":null,"
            + "\"storageKeyHex\":\"0x0000000000000000000000000000000000000000000000000000000000000003\","
            + "\"storageKeyHashHex\":\"0x6666666666666666666666666666666666666666666666666666666666666666\","
            + "\"exists\":true,\"valueHex\":\"0x2a\",\"valueDecimal\":\"42\",\"slotsReturned\":1,"
            + "\"storageRootHex\":\"0x3333333333333333333333333333333333333333333333333333333333333333\","
            + "\"proofNodesHex\":[],\"storageProofValid\":true,\"beaconSynced\":true,"
            + "\"beaconChainVerified\":true,\"blsVerified\":true,\"matchedBeaconSlot\":7000000,"
            + "\"verifyMethod\":\"headerChain\",\"failReason\":null,\"peerBlockNumber\":21000000,"
            + "\"finalizedBlockNumber\":20999000,\"optimisticBlockNumber\":21000010,"
            + "\"finalizedSlot\":14560000,\"optimisticSlot\":14560032,\"maxHeaderChainGap\":8192}";

    @Test
    void storageJsonMapsToRecord() {
        StorageProofResult r = RustChainHandle.storageFromJson("0xC0", 3, STORAGE_JSON);
        assertEquals("0xC0", r.addressHex());
        assertEquals(3L, r.slot());
        assertNull(r.holderHex());
        assertTrue(r.exists());
        assertEquals("0x2a", r.valueHex());
        assertEquals("42", r.valueDecimal());
        assertEquals(1, r.slotsReturned());
        assertTrue(r.storageProofValid());
        assertTrue(r.beaconChainVerified());
        assertEquals("headerChain", r.verifyMethod());
        assertNull(r.failReason());
        assertEquals(21000000L, r.peerBlockNumber());
        assertEquals(14560000L, r.finalizedSlot());
        assertEquals(14560032L, r.optimisticSlot());
        assertEquals(8192, r.maxHeaderChainGap());
    }

    @Test
    void storageErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.storageFromJson("0x0", 1, "{\"error\":\"handle not started\"}"));
    }
}
