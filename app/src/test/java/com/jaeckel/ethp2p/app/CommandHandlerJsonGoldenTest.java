package com.jaeckel.ethp2p.app;

import io.myotis.api.AccountProofResult;
import io.myotis.api.BlockResult;
import io.myotis.api.HeaderInfo;
import io.myotis.api.HeadersResult;
import io.myotis.api.StorageProofResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * GOLDEN TESTS for the daemon's IPC JSON serializers. These lock the exact byte shape of
 * the {@code get-account} / {@code get-storage} / {@code get-block} / {@code get-headers}
 * responses across the engine-API refactor: the fetch/verification logic moved into
 * node-core, and these strings are the contract that move must not disturb (the
 * integration test additionally greps {@code "verifyMethod":"headerChain"} on a synced
 * daemon). Do not "fix" an expected string here without treating it as an IPC contract
 * change.
 */
class CommandHandlerJsonGoldenTest {

    @org.junit.jupiter.api.BeforeAll
    static void setUpProvider() {
        // CommandHandler's static init computes a keccak256 (the ENS snap-probe hash),
        // which needs the BC provider registered.
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    // -- get-account ---------------------------------------------------------

    private static AccountProofResult account(boolean exists, boolean verified, String failReason) {
        return new AccountProofResult(
                "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
                exists,
                exists ? 42 : -1,
                exists ? "123450000000000000000" : null,
                exists ? "0x1111111111111111111111111111111111111111111111111111111111111111" : null,
                exists ? "0x2222222222222222222222222222222222222222222222222222222222222222" : null,
                21000123,
                "0x3333333333333333333333333333333333333333333333333333333333333333",
                true,
                verified,
                verified,
                verified ? 12345678 : -1,
                verified ? "headerChain" : null,
                failReason,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                List.of("0xf90211a0dead", "0xf90211a0beef"),
                true,
                1490,
                1492,
                21000100,
                21000130);
    }

    @Test
    void accountExistsVerified() {
        assertEquals(
                "{\"ok\":true,\"exists\":true"
                + ",\"address\":\"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\""
                + ",\"accountHash\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
                + ",\"nonce\":42"
                + ",\"balance\":\"123450000000000000000\""
                + ",\"storageRoot\":\"0x1111111111111111111111111111111111111111111111111111111111111111\""
                + ",\"codeHash\":\"0x2222222222222222222222222222222222222222222222222222222222222222\""
                + ",\"proof\":[\"0xf90211a0dead\",\"0xf90211a0beef\"]"
                + ",\"verification\":{\"peerProofValid\":true"
                + ",\"peerStateRoot\":\"0x3333333333333333333333333333333333333333333333333333333333333333\""
                + ",\"beaconSynced\":true"
                + ",\"beaconChainVerified\":true"
                + ",\"matchedBeaconSlot\":12345678"
                + ",\"blsVerified\":true"
                + ",\"verifyMethod\":\"headerChain\"}}",
                // The raw request address is echoed verbatim (mixed case preserved).
                CommandHandler.buildAccountJson(
                        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                        account(true, true, null)));
    }

    @Test
    void accountExistsUnverifiedCarriesDiagnostics() {
        assertEquals(
                "{\"ok\":true,\"exists\":true"
                + ",\"address\":\"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\""
                + ",\"accountHash\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
                + ",\"nonce\":42"
                + ",\"balance\":\"123450000000000000000\""
                + ",\"storageRoot\":\"0x1111111111111111111111111111111111111111111111111111111111111111\""
                + ",\"codeHash\":\"0x2222222222222222222222222222222222222222222222222222222222222222\""
                + ",\"proof\":[\"0xf90211a0dead\",\"0xf90211a0beef\"]"
                + ",\"verification\":{\"peerProofValid\":true"
                + ",\"peerStateRoot\":\"0x3333333333333333333333333333333333333333333333333333333333333333\""
                + ",\"beaconSynced\":true"
                + ",\"beaconChainVerified\":false"
                + ",\"failReason\":\"headerChainGapTooLarge\""
                + ",\"finalizedPeriod\":1490"
                + ",\"wallClockPeriod\":1492"
                + ",\"periodLag\":2"
                + ",\"peerBlockNumber\":21000123"
                + ",\"finalizedBlockNumber\":21000100"
                + ",\"optimisticBlockNumber\":21000130}}",
                CommandHandler.buildAccountJson(
                        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                        account(true, false, "headerChainGapTooLarge")));
    }

    @Test
    void accountAbsent() {
        assertEquals(
                "{\"ok\":true,\"exists\":false"
                + ",\"address\":\"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\""
                + ",\"accountHash\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
                + ",\"proof\":[\"0xf90211a0dead\",\"0xf90211a0beef\"]"
                + ",\"verification\":{\"peerProofValid\":true"
                + ",\"peerStateRoot\":\"0x3333333333333333333333333333333333333333333333333333333333333333\""
                + ",\"beaconSynced\":true"
                + ",\"beaconChainVerified\":true"
                + ",\"matchedBeaconSlot\":12345678"
                + ",\"blsVerified\":true"
                + ",\"verifyMethod\":\"headerChain\"}}",
                CommandHandler.buildAccountJson(
                        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                        account(false, true, null)));
    }

    // -- get-storage ---------------------------------------------------------

    @Test
    void storageExistsVerifiedWithHolder() {
        StorageProofResult r = new StorageProofResult(
                "0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4",
                1,
                "0x308686553a1EAC2fE721Ac8B814De638975a276e",
                "0x4444444444444444444444444444444444444444444444444444444444444444",
                "0x5555555555555555555555555555555555555555555555555555555555555555",
                true,
                "0x0de0b6b3a7640000",
                "1000000000000000000",
                1,
                "0x6666666666666666666666666666666666666666666666666666666666666666",
                List.of("0xf90211a0cafe"),
                true, true, true, true,
                12345678,
                "stateRootMatch",
                null,
                21000123, 21000100, 21000130, 9876543, 9876575, 8192);
        assertEquals(
                "{\"ok\":true"
                + ",\"address\":\"0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4\""
                + ",\"slot\":1"
                + ",\"holder\":\"0x308686553a1EAC2fE721Ac8B814De638975a276e\""
                + ",\"storageKey\":\"0x4444444444444444444444444444444444444444444444444444444444444444\""
                + ",\"storageKeyHash\":\"0x5555555555555555555555555555555555555555555555555555555555555555\""
                + ",\"exists\":true"
                + ",\"value\":\"0x0de0b6b3a7640000\""
                + ",\"valueDecimal\":\"1000000000000000000\""
                + ",\"storageRoot\":\"0x6666666666666666666666666666666666666666666666666666666666666666\""
                + ",\"proof\":[\"0xf90211a0cafe\"]"
                + ",\"verification\":{\"storageProofValid\":true"
                + ",\"beaconSynced\":true"
                + ",\"beaconChainVerified\":true"
                + ",\"matchedBeaconSlot\":12345678"
                + ",\"blsVerified\":true"
                + ",\"verifyMethod\":\"stateRootMatch\"}}",
                CommandHandler.buildStorageJson(r));
    }

    @Test
    void storageAbsentUnverifiedCarriesAnchors() {
        StorageProofResult r = new StorageProofResult(
                "0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4",
                7,
                null,
                "0x0000000000000000000000000000000000000000000000000000000000000007",
                "0x5555555555555555555555555555555555555555555555555555555555555555",
                false,
                null,
                null,
                3,
                "0x6666666666666666666666666666666666666666666666666666666666666666",
                List.of("0xf90211a0feed"),
                true, true, false, false,
                -1,
                null,
                "beaconNotSynced",
                21000123, 21000100, 21000130, 9876543, 9876575, 8192);
        assertEquals(
                "{\"ok\":true"
                + ",\"address\":\"0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4\""
                + ",\"slot\":7"
                + ",\"storageKey\":\"0x0000000000000000000000000000000000000000000000000000000000000007\""
                + ",\"storageKeyHash\":\"0x5555555555555555555555555555555555555555555555555555555555555555\""
                + ",\"exists\":false"
                + ",\"slotsReturned\":3"
                + ",\"storageRoot\":\"0x6666666666666666666666666666666666666666666666666666666666666666\""
                + ",\"proof\":[\"0xf90211a0feed\"]"
                + ",\"verification\":{\"storageProofValid\":true"
                + ",\"beaconSynced\":true"
                + ",\"beaconChainVerified\":false"
                + ",\"failReason\":\"beaconNotSynced\""
                + ",\"peerBlockNumber\":21000123"
                + ",\"finalizedBlockNumber\":21000100"
                + ",\"optimisticBlockNumber\":21000130"
                + ",\"blockGap\":23"
                + ",\"optimisticBlockGap\":-7"
                + ",\"maxHeaderChainGap\":8192"
                + ",\"finalizedSlot\":9876543"
                + ",\"optimisticSlot\":9876575}}",
                CommandHandler.buildStorageJson(r));
    }

    // -- get-block -----------------------------------------------------------

    @Test
    void blockVerified() {
        BlockResult r = new BlockResult(
                21000123,
                "0x7777777777777777777777777777777777777777777777777777777777777777",
                "0x8888888888888888888888888888888888888888888888888888888888888888",
                "0x9999999999999999999999999999999999999999999999999999999999999999",
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1734567890,
                12500000,
                30000000,
                "7000000000",
                142, 0, 16,
                true, true, true,
                12345678,
                "headerChain",
                null,
                null);
        assertEquals(
                "{\"ok\":true,\"block\":{"
                + "\"number\":21000123"
                + ",\"hash\":\"0x7777777777777777777777777777777777777777777777777777777777777777\""
                + ",\"parentHash\":\"0x8888888888888888888888888888888888888888888888888888888888888888\""
                + ",\"stateRoot\":\"0x9999999999999999999999999999999999999999999999999999999999999999\""
                + ",\"transactionsRoot\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
                + ",\"receiptsRoot\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""
                + ",\"timestamp\":1734567890"
                + ",\"gasUsed\":12500000"
                + ",\"gasLimit\":30000000"
                + ",\"baseFeePerGas\":\"7000000000\""
                + ",\"transactionCount\":142"
                + ",\"uncleCount\":0"
                + ",\"withdrawalCount\":16"
                + "},\"verification\":{"
                + "\"beaconSynced\":true"
                + ",\"beaconChainVerified\":true"
                + ",\"matchedBeaconSlot\":12345678"
                + ",\"blsVerified\":true"
                + ",\"verifyMethod\":\"headerChain\"}}",
                CommandHandler.buildBlockJson(r));
    }

    @Test
    void blockPreMerge() {
        BlockResult r = new BlockResult(
                15000000,
                "0x7777777777777777777777777777777777777777777777777777777777777777",
                "0x8888888888888888888888888888888888888888888888888888888888888888",
                "0x9999999999999999999999999999999999999999999999999999999999999999",
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1658000000,
                12000000,
                30000000,
                null,
                97, 0, 0,
                true, false, false,
                -1,
                null,
                "preMergeBlock",
                null);
        assertEquals(
                "{\"ok\":true,\"block\":{"
                + "\"number\":15000000"
                + ",\"hash\":\"0x7777777777777777777777777777777777777777777777777777777777777777\""
                + ",\"parentHash\":\"0x8888888888888888888888888888888888888888888888888888888888888888\""
                + ",\"stateRoot\":\"0x9999999999999999999999999999999999999999999999999999999999999999\""
                + ",\"transactionsRoot\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
                + ",\"receiptsRoot\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""
                + ",\"timestamp\":1658000000"
                + ",\"gasUsed\":12000000"
                + ",\"gasLimit\":30000000"
                + ",\"transactionCount\":97"
                + ",\"uncleCount\":0"
                + ",\"withdrawalCount\":0"
                + "},\"verification\":{"
                + "\"beaconSynced\":true"
                + ",\"beaconChainVerified\":false"
                + ",\"failReason\":\"preMergeBlock\"}}",
                CommandHandler.buildBlockJson(r));
    }

    // -- get-headers ---------------------------------------------------------

    @Test
    void headersWithAndWithoutBaseFee() {
        HeadersResult r = new HeadersResult(List.of(
                new HeaderInfo(21000000,
                        "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "0x2222222222222222222222222222222222222222222222222222222222222222",
                        "0x3333333333333333333333333333333333333333333333333333333333333333",
                        "0x4444444444444444444444444444444444444444444444444444444444444444",
                        1734567890, 12500000, 30000000, "7000000000"),
                new HeaderInfo(12000000,
                        "0x5555555555555555555555555555555555555555555555555555555555555555",
                        "0x6666666666666666666666666666666666666666666666666666666666666666",
                        "0x7777777777777777777777777777777777777777777777777777777777777777",
                        "0x8888888888888888888888888888888888888888888888888888888888888888",
                        1610000000, 12000000, 12500000, null)),
                null);
        assertEquals(
                "{\"ok\":true,\"count\":2,\"headers\":["
                + "{\"number\":21000000"
                + ",\"hash\":\"0x1111111111111111111111111111111111111111111111111111111111111111\""
                + ",\"parentHash\":\"0x2222222222222222222222222222222222222222222222222222222222222222\""
                + ",\"stateRoot\":\"0x3333333333333333333333333333333333333333333333333333333333333333\""
                + ",\"transactionsRoot\":\"0x4444444444444444444444444444444444444444444444444444444444444444\""
                + ",\"timestamp\":1734567890"
                + ",\"gasUsed\":12500000"
                + ",\"gasLimit\":30000000"
                + ",\"baseFeePerGas\":\"7000000000\"}"
                + ",{\"number\":12000000"
                + ",\"hash\":\"0x5555555555555555555555555555555555555555555555555555555555555555\""
                + ",\"parentHash\":\"0x6666666666666666666666666666666666666666666666666666666666666666\""
                + ",\"stateRoot\":\"0x7777777777777777777777777777777777777777777777777777777777777777\""
                + ",\"transactionsRoot\":\"0x8888888888888888888888888888888888888888888888888888888888888888\""
                + ",\"timestamp\":1610000000"
                + ",\"gasUsed\":12000000"
                + ",\"gasLimit\":12500000}"
                + "]}",
                CommandHandler.buildHeadersJson(r));
    }
}
