package io.myotis.engines;

import io.myotis.api.AccountProofResult;
import io.myotis.api.EngineException;
import io.myotis.api.StorageProofResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
    void structuredErrorValueStillBecomesEngineException() {
        // A non-string error value must not leak a raw library exception.
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson(
                "0x0", "{\"error\":{\"code\":-32000,\"message\":\"boom\"}}"));
    }

    @Test
    void nullAndMalformedPayloadsThrow() {
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", null));
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", ""));
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", "not json"));
        // A non-object payload (e.g. a bare number) → EngineException, not a raw throw.
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", "42"));
    }

    @Test
    void driftedArrayFieldFailsClosed() {
        // proofNodesHex present but not an array → EngineException (fail closed),
        // NOT a silently-swallowed empty list.
        String json = "{\"exists\":true,\"nonce\":0,\"proofNodesHex\":{\"unexpected\":true}}";
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", json));
    }

    @Test
    void typeMismatchedFieldBecomesEngineException() {
        // Rust-side shape drift: a numeric field arrives as a string. The
        // field-extraction must surface an EngineException, not a raw
        // UnsupportedOperationException from the JSON library.
        String json = "{\"exists\":true,\"nonce\":\"not-a-number\",\"proofNodesHex\":[]}";
        assertThrows(EngineException.class, () -> RustChainHandle.accountFromJson("0x0", json));
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

    // ---- eth_getCode (codeFromJson) ----

    /** A headerChain-verified contract (mirrors the Rust eljson code sample). */
    private static final String CODE_JSON =
            "{\"address\":\"0xC0\",\"exists\":true,\"codeHex\":\"0x60806040\","
            + "\"codeHashHex\":\"0x4444444444444444444444444444444444444444444444444444444444444444\","
            + "\"blockNumber\":21000000,\"beaconChainVerified\":true,\"blsVerified\":true,"
            + "\"matchedBeaconSlot\":7000000,\"verifyMethod\":\"headerChain\",\"failReason\":null,"
            + "\"beaconSynced\":true,\"finalizedPeriod\":1777,\"wallClockPeriod\":1795,"
            + "\"finalizedBlockNumber\":20999000,\"optimisticBlockNumber\":21000010}";

    @Test
    void codeJsonMapsToVerifiedBytecode() {
        assertArrayEquals(new byte[] {0x60, (byte) 0x80, 0x60, 0x40},
                RustChainHandle.codeFromJson(CODE_JSON));
    }

    @Test
    void emptyVerifiedCodeIsEmptyArray() {
        // A verified EOA / empty-code account: codeHex "0x" → empty bytecode (not null).
        String json = "{\"exists\":false,\"codeHex\":\"0x\",\"verifyMethod\":\"headerChain\"}";
        assertArrayEquals(new byte[0], RustChainHandle.codeFromJson(json));
    }

    @Test
    void unverifiedCodeIsNull() {
        // No verdict (verifyMethod null) → can't answer verified → null (router -32000).
        String json = "{\"exists\":true,\"codeHex\":\"0x6080\",\"verifyMethod\":null,"
                + "\"failReason\":\"beaconNotSynced\"}";
        assertNull(RustChainHandle.codeFromJson(json));
    }

    @Test
    void codeErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.codeFromJson("{\"error\":\"no snap peer available\"}"));
    }

    // ---- eth_call (callResultFromJson) ----

    @Test
    void okCallReturnsResultBytes() {
        String json = "{\"status\":\"ok\",\"resultHex\":\"0x00000000000000000000000000000000"
                + "0000000000000000000000000000002a\"}";
        byte[] out = RustChainHandle.callResultFromJson(json);
        byte[] expected = new byte[32];
        expected[31] = 0x2a;
        assertArrayEquals(expected, out);
    }

    @Test
    void emptyOkCallIsEmptyArray() {
        // A call that returns no data (resultHex "0x") → empty bytes, not null.
        assertArrayEquals(new byte[0],
                RustChainHandle.callResultFromJson("{\"status\":\"ok\",\"resultHex\":\"0x\"}"));
    }

    @Test
    void revertedCallIsNull() {
        // A revert carries data but is "no answer" at the RPC layer → null.
        String json = "{\"status\":\"revert\",\"dataHex\":\"0x08c379a0\"}";
        assertNull(RustChainHandle.callResultFromJson(json));
    }

    @Test
    void unavailableCallIsNull() {
        assertNull(RustChainHandle.callResultFromJson(
                "{\"status\":\"unavailable\",\"reason\":\"out of gas\"}"));
    }

    @Test
    void callErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.callResultFromJson("{\"error\":\"no snap peer available\"}"));
    }

    // ---- eth_estimateGas (estimateGasFromJson) ----

    @Test
    void okEstimateReturnsGasNumber() {
        assertEquals(Long.valueOf(24_150L),
                RustChainHandle.estimateGasFromJson("{\"status\":\"ok\",\"gas\":24150}"));
    }

    @Test
    void unavailableEstimateIsNull() {
        assertNull(RustChainHandle.estimateGasFromJson(
                "{\"status\":\"unavailable\",\"reason\":\"execution reverted\"}"));
    }

    @Test
    void estimateErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.estimateGasFromJson("{\"error\":\"handle not started\"}"));
    }

    @Test
    void okEstimateWithoutGasFailsClosed() {
        // status=ok but no numeric gas is native shape drift → EngineException, not a
        // silent null (which would masquerade as a legitimate "unavailable").
        assertThrows(EngineException.class,
                () -> RustChainHandle.estimateGasFromJson("{\"status\":\"ok\"}"));
    }

    // ---- resolve-ens (ensResolutionFromJson) ----

    @Test
    void okEnsResolutionCarriesAddressAndBlock() {
        var r = RustChainHandle.ensResolutionFromJson("vitalik.eth",
                "{\"status\":\"ok\",\"addressHex\":\"0xd8da6bf26964af9d7eed9e03e53415d37aa96045\","
                + "\"blockNumber\":21000010}");
        assertEquals("vitalik.eth", r.name());
        assertEquals("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", r.addressHex());
        assertEquals(21000010L, r.blockNumber());
        assertNull(r.error());
    }

    @Test
    void noRecordEnsResolutionIsSuccessfulNull() {
        // API convention: addressHex==null && error==null = successful "no record".
        var r = RustChainHandle.ensResolutionFromJson("nonexistent.eth",
                "{\"status\":\"noRecord\",\"blockNumber\":21000010}");
        assertNull(r.addressHex());
        assertNull(r.error());
        assertEquals(21000010L, r.blockNumber());
    }

    @Test
    void offchainEnsResolutionCarriesError() {
        var r = RustChainHandle.ensResolutionFromJson("offchain.cb.id",
                "{\"status\":\"offchain\",\"blockNumber\":21000010}");
        assertNull(r.addressHex());
        assertTrue(r.error().contains("offchain"));
    }

    @Test
    void ensErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class, () -> RustChainHandle.ensResolutionFromJson(
                "vitalik.eth", "{\"error\":\"no snap peer available\"}"));
    }

    @Test
    void okEnsWithoutAddressFailsClosed() {
        // status=ok without an addressHex is native shape drift -> EngineException,
        // never a silent "no record" (same convention as okEstimateWithoutGasFailsClosed).
        assertThrows(EngineException.class, () -> RustChainHandle.ensResolutionFromJson(
                "vitalik.eth", "{\"status\":\"ok\",\"blockNumber\":21000010}"));
    }

    @Test
    void ensWithoutBlockNumberFailsClosed() {
        // blockNumber is part of the pinned shape for every status — missing = drift.
        assertThrows(EngineException.class, () -> RustChainHandle.ensResolutionFromJson(
                "vitalik.eth",
                "{\"status\":\"ok\",\"addressHex\":\"0xd8da6bf26964af9d7eed9e03e53415d37aa96045\"}"));
        assertThrows(EngineException.class, () -> RustChainHandle.ensResolutionFromJson(
                "vitalik.eth", "{\"status\":\"noRecord\"}"));
    }

    @Test
    void unknownEnsStatusFailsClosed() {
        assertThrows(EngineException.class, () -> RustChainHandle.ensResolutionFromJson(
                "vitalik.eth", "{\"status\":\"weird\"}"));
    }

    // ---- eth_getStorageAt (storageValueFromJson) ----

    @Test
    void storageValueLeftPadsToWord() {
        // valueHex is the big-endian value (0x2a in STORAGE_JSON) → a full 32-byte word.
        byte[] word = RustChainHandle.storageValueFromJson(STORAGE_JSON);
        byte[] expected = new byte[32];
        expected[31] = 0x2a;
        assertArrayEquals(expected, word);
    }

    @Test
    void unsetStorageSlotIsZeroWord() {
        // A verified zero/unset slot: valueHex null → 32 zero bytes (eth_getStorageAt 0x0…0).
        String json = "{\"exists\":false,\"valueHex\":null,\"verifyMethod\":\"headerChain\"}";
        assertArrayEquals(new byte[32], RustChainHandle.storageValueFromJson(json));
    }

    @Test
    void unverifiedStorageValueIsNull() {
        String json = "{\"valueHex\":\"0x2a\",\"verifyMethod\":null,\"failReason\":\"beaconNotSynced\"}";
        assertNull(RustChainHandle.storageValueFromJson(json));
    }

    // ---- eth_getBlockByNumber (blockJsonOrThrow) ----

    @Test
    void blockJsonPassesThroughObject() {
        String block = "{\"number\":\"0x1406f40\",\"hash\":\"0x99\",\"transactions\":[],\"uncles\":[]}";
        assertEquals(block, RustChainHandle.blockJsonOrThrow(block));
    }

    @Test
    void blockNullLiteralIsVerifiedNotFound() {
        // "null" (a verified future/unknown block) is returned as-is → the router
        // emits a JSON null result (eth's unknown-block convention), not an error.
        assertEquals("null", RustChainHandle.blockJsonOrThrow("null"));
    }

    @Test
    void blockErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.blockJsonOrThrow("{\"error\":\"beacon not synced\"}"));
    }

    @Test
    void blockBlankOrMalformedPayloadThrows() {
        assertThrows(EngineException.class, () -> RustChainHandle.blockJsonOrThrow(null));
        assertThrows(EngineException.class, () -> RustChainHandle.blockJsonOrThrow(""));
        assertThrows(EngineException.class, () -> RustChainHandle.blockJsonOrThrow("not json"));
    }

    // ---- eth_getTransactionReceipt (receiptJsonOrThrow) ----

    @Test
    void receiptJsonPassesThroughObject() {
        // The exact shape the Rust eljson::receipt_json emits (its
        // receipt_json_shape_and_values test pins the other half of this golden):
        // buildReceiptJson field order, minimal-hex QUANTITYs, block-global logIndex.
        String receipt = "{\"transactionHash\":\"0x" + "a1".repeat(32) + "\""
                + ",\"transactionIndex\":\"0x2\""
                + ",\"blockHash\":\"0x" + "99".repeat(32) + "\""
                + ",\"blockNumber\":\"0x1406f40\""
                + ",\"cumulativeGasUsed\":\"0xf4240\""
                + ",\"gasUsed\":\"0xc738\""
                + ",\"from\":\"0x" + "cc".repeat(20) + "\""
                + ",\"to\":\"0x" + "bb".repeat(20) + "\",\"contractAddress\":null"
                + ",\"effectiveGasPrice\":\"0x2cb417800\""
                + ",\"status\":\"0x1\",\"type\":\"0x2\""
                + ",\"logsBloom\":\"0x" + "00".repeat(256) + "\""
                + ",\"logs\":[{\"address\":\"0x" + "aa".repeat(20) + "\""
                + ",\"topics\":[\"0x" + "11".repeat(32) + "\"],\"data\":\"0xdead\""
                + ",\"blockNumber\":\"0x1406f40\",\"blockHash\":\"0x" + "99".repeat(32) + "\""
                + ",\"transactionHash\":\"0x" + "a1".repeat(32) + "\""
                + ",\"transactionIndex\":\"0x2\",\"logIndex\":\"0x7\",\"removed\":false}]}";
        assertEquals(receipt, RustChainHandle.receiptJsonOrThrow(receipt));
    }

    @Test
    void receiptNullLiteralIsVerifiedNotSeen() {
        // "null" (a verified pending/unknown tx) passes through → the router emits
        // a JSON null result (eth's receipt-not-available convention), not an error.
        assertEquals("null", RustChainHandle.receiptJsonOrThrow("null"));
    }

    @Test
    void receiptErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.receiptJsonOrThrow("{\"error\":\"no snap peer available\"}"));
    }

    @Test
    void receiptBlankOrMalformedPayloadThrows() {
        assertThrows(EngineException.class, () -> RustChainHandle.receiptJsonOrThrow(null));
        assertThrows(EngineException.class, () -> RustChainHandle.receiptJsonOrThrow(""));
        assertThrows(EngineException.class, () -> RustChainHandle.receiptJsonOrThrow("not json"));
    }

    // ---- eth_getTransactionByHash (transactionJsonOrThrow) ----

    @Test
    void transactionJsonPassesThroughObject() {
        // The exact shape the Rust eljson::tx_json emits (its
        // tx_json_shape_and_values test pins the other half of this golden):
        // buildTxJson field order, minimal-hex QUANTITYs, 32-byte DATA r/s.
        String tx = "{\"hash\":\"0x" + "a1".repeat(32) + "\""
                + ",\"blockHash\":\"0x" + "99".repeat(32) + "\""
                + ",\"blockNumber\":\"0x1406f40\",\"transactionIndex\":\"0x2\""
                + ",\"type\":\"0x2\",\"chainId\":\"0x1\",\"nonce\":\"0x5\""
                + ",\"from\":\"0x" + "cc".repeat(20) + "\""
                + ",\"to\":\"0x" + "bb".repeat(20) + "\""
                + ",\"value\":\"0xde0b6b3a7640000\",\"gas\":\"0x15f90\""
                + ",\"maxFeePerGas\":\"0xba43b7400\",\"maxPriorityFeePerGas\":\"0x77359400\""
                + ",\"input\":\"0xa9059cbb\",\"v\":\"0x1\",\"yParity\":\"0x1\""
                + ",\"r\":\"0x" + "11".repeat(32) + "\",\"s\":\"0x" + "22".repeat(32) + "\"}";
        assertEquals(tx, RustChainHandle.transactionJsonOrThrow(tx));
    }

    @Test
    void transactionNullLiteralIsVerifiedNotSeen() {
        // "null" (a verified unknown/pending tx) passes through → the router
        // emits a JSON null result, not an error.
        assertEquals("null", RustChainHandle.transactionJsonOrThrow("null"));
    }

    @Test
    void transactionErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class, () -> RustChainHandle.transactionJsonOrThrow(
                "{\"error\":\"transaction located but its type cannot be decoded\"}"));
    }

    @Test
    void transactionBlankOrMalformedPayloadThrows() {
        assertThrows(EngineException.class, () -> RustChainHandle.transactionJsonOrThrow(null));
        assertThrows(EngineException.class, () -> RustChainHandle.transactionJsonOrThrow(""));
        assertThrows(EngineException.class, () -> RustChainHandle.transactionJsonOrThrow("not json"));
    }

    // ---- eth_feeHistory (feeHistoryJsonOrThrow) ----

    @Test
    void feeHistoryJsonPassesThroughObject() {
        // The exact shape the Rust eljson::fee_history_json emits (its
        // fee_history_json_shape_and_values test pins the other half of this
        // golden): oldestBlock + hex QUANTITYs, raw JSON doubles, reward rows.
        String feeHistory = "{\"oldestBlock\":\"0x1406f40\""
                + ",\"baseFeePerGas\":[\"0x2540be400\",\"0x28fa6ae00\",\"0x2dfdc1c35\"]"
                + ",\"gasUsedRatio\":[0.5,0.9932]"
                + ",\"reward\":[[\"0x3b9aca00\",\"0x77359400\"],[\"0x0\",\"0xb2d05e00\"]]}";
        assertEquals(feeHistory, RustChainHandle.feeHistoryJsonOrThrow(feeHistory));
        // Without percentiles the reward key is absent — still a plain pass-through.
        String noReward = "{\"oldestBlock\":\"0x1\",\"baseFeePerGas\":[\"0x0\",\"0x0\"]"
                + ",\"gasUsedRatio\":[0.0,1.0]}";
        assertEquals(noReward, RustChainHandle.feeHistoryJsonOrThrow(noReward));
    }

    @Test
    void feeHistoryErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class, () -> RustChainHandle.feeHistoryJsonOrThrow(
                "{\"error\":\"oldest block 20 is beyond the 256-block verify window\"}"));
    }

    @Test
    void feeHistoryBlankOrMalformedPayloadThrows() {
        assertThrows(EngineException.class, () -> RustChainHandle.feeHistoryJsonOrThrow(null));
        assertThrows(EngineException.class, () -> RustChainHandle.feeHistoryJsonOrThrow(""));
        assertThrows(EngineException.class, () -> RustChainHandle.feeHistoryJsonOrThrow("not json"));
    }

    // ---- eth_gasPrice / eth_maxPriorityFeePerGas (feeFromJson) ----

    @Test
    void feeJsonMapsToEstimate() {
        RustChainHandle.FeeEstimate est = RustChainHandle.feeFromJson(
                "{\"gasPriceWei\":\"12345678900\",\"maxPriorityFeePerGasWei\":\"1500000000\"}");
        assertEquals("12345678900", est.gasPriceWei());
        assertEquals("1500000000", est.maxPriorityFeePerGasWei());
    }

    @Test
    void feeErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.feeFromJson("{\"error\":\"beacon not synced\"}"));
    }

    @Test
    void feeMissingFieldThrows() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.feeFromJson("{\"gasPriceWei\":\"100\"}"));
    }

    // ---- eth_sendRawTransaction (txHashFromJson) ----

    @Test
    void txHashJsonMapsToHash() {
        byte[] h = RustChainHandle.txHashFromJson("{\"txHash\":\"0x" + "ab".repeat(32) + "\"}");
        byte[] expected = new byte[32];
        java.util.Arrays.fill(expected, (byte) 0xab);
        assertArrayEquals(expected, h);
    }

    @Test
    void sendTxErrorObjectBecomesEngineException() {
        assertThrows(EngineException.class,
                () -> RustChainHandle.txHashFromJson("{\"error\":\"no peer available to broadcast\"}"));
    }

    @Test
    void sendTxMissingHashThrows() {
        assertThrows(EngineException.class, () -> RustChainHandle.txHashFromJson("{}"));
    }

    @Test
    void sendTxNon32ByteHashThrows() {
        // A txHash that isn't exactly 32 bytes fails closed (contract: 32-byte hash).
        assertThrows(EngineException.class,
                () -> RustChainHandle.txHashFromJson("{\"txHash\":\"0xdead\"}"));
    }
}
