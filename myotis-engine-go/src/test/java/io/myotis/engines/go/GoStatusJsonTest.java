package io.myotis.engines.go;

import io.myotis.api.AccountProofResult;
import io.myotis.api.BeaconState;
import io.myotis.api.BeaconStatus;
import io.myotis.api.CallResult;
import io.myotis.api.DataUsage;
import io.myotis.api.EngineException;
import io.myotis.api.EstimateResult;
import io.myotis.api.SendResult;
import io.myotis.api.NetworkMetering;
import io.myotis.api.StatusSnapshot;
import io.myotis.api.StorageProofResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The JSON→snapshot mapping of the GO status shape, without the native library:
 * the document below is assembled from {@code go/internal/capi}'s statusJSON
 * struct field-by-field (the Rust 37-key set — pinned Go-side by
 * TestStatusCarriesTheRustKeySet — plus the Go-only engine/myotisAbi/
 * capabilities), so this test proves the JVM reads exactly what the Go build
 * writes. The Go-side key-set test and this one together pin the contract in
 * both directions.
 */
class GoStatusJsonTest {

    /** A serveable Go status: SYNCED, finalized anchor, snap servers.
     *  Field order mirrors the Go struct; the Go-only keys come last. */
    private static String goStatus(String beaconState, long finalizedBlock, int snapServing,
                                   String metering) {
        return "{"
                + "\"running\":true,\"paused\":false,\"network\":\"mainnet\","
                + "\"beaconState\":\"" + beaconState + "\",\"bootstrapped\":true,"
                + "\"finalizedSlot\":15634912,\"optimisticSlot\":0,"
                + "\"currentPeriod\":1909,\"targetPeriod\":1909,\"peerCount\":7,"
                + "\"servedPeersLastMinute\":0,"
                + "\"discv5TableSize\":42,\"syncStartPeriod\":-1,\"lcHunting\":false,"
                + "\"wsBoundPeriods\":13,"
                + "\"finalizedRootHex\":\"e04f511b55ee0c7a3cbb7f0f6b4cba99e2604119d4ae29e0a4c0e56e3d5c2b1a\","
                + "\"elReaderAvailable\":true,\"snapPeers\":4,\"snapServingPeers\":" + snapServing + ","
                + "\"snap2ServingPeers\":2,\"readyPeers\":4,\"discoveredPeers\":188,"
                + "\"attemptedDials\":57,\"backedOffPeers\":0,\"blacklistedPeers\":0,"
                + "\"optimisticBlockNumber\":0,\"finalizedBlockNumber\":" + finalizedBlock + ","
                + "\"peerHeaderRequests\":0,\"peerHeaderRequestsServed\":0,"
                + "\"peerBodyRequests\":0,\"peerBodyRequestsServed\":0,"
                + "\"executionBlockNumber\":" + finalizedBlock + ",\"elHunting\":false,"
                + "\"upgradeAdvisory\":null,\"dataUsage\":null,\"networkMetering\":\"" + metering + "\","
                + "\"engine\":\"go\",\"myotisAbi\":57,"
                + "\"capabilities\":{\"wsBoundOverride\":true,\"staleAnchorConsent\":true,"
                + "\"servedBlockWindow\":true}"
                + "}";
    }

    @Test
    void serveableStatusMapsEverySnapshotField() {
        StatusSnapshot s = GoChainHandle.statusFromJson("mainnet",
                goStatus("SYNCED", 26404150, 3, "METERED"));
        assertTrue(s.running());
        assertEquals(io.myotis.api.LifecycleState.RUNNING, s.lifecycle());
        assertEquals("mainnet", s.network());
        assertEquals(BeaconState.SYNCED, s.beaconState());
        assertEquals(7, s.connectedPeers());          // CL peers via peerCount
        assertEquals(4, s.readyPeers());              // EL pool == snap pool
        assertEquals(4, s.snapPeers());
        assertEquals(3, s.snapServingPeers());
        assertEquals(2, s.snap2ServingPeers());
        assertEquals(188, s.discoveredPeers());
        assertEquals(57, s.attemptedDials());
        assertEquals(42, s.discv5TableSize());
        assertEquals(26404150L, s.executionBlockNumber());
        assertEquals(0L, s.optimisticBlockNumber());  // no optimistic machinery yet
        assertEquals(26404150L, s.finalizedBlockNumber());
        assertEquals(15634912L, s.finalizedSlot());
        // finalizedPeriod = slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD, not currentPeriod.
        assertEquals(15634912L / 8192L, s.finalizedPeriod());
        assertEquals(-1L, s.syncStartPeriod());       // Go has no hunt phase: -1, like Rust's initial
        assertEquals(1909L, s.syncCurrentPeriod());
        assertEquals(1909L, s.syncTargetPeriod());
        assertEquals(1909L, s.wallClockPeriod());
        assertEquals(13L, s.wsBoundPeriods());        // the ENFORCED bound, override included
        assertTrue(s.verifiedHeadAgeMs() >= 0 && s.verifiedHeadAgeMs() < 10_000L,
                "serveable age must be a real (small) age, got " + s.verifiedHeadAgeMs());
        assertEquals(0, s.readyPeerList().size());    // per-peer detail: none on this engine
        // Honest zeros for machinery the Go build lacks, and the shared display rules:
        assertEquals(0, s.pauseCount());
        assertEquals(0L, s.totalPausedMs());
        assertNull(s.lastWakeReason());
        assertEquals(0L, s.peerHeaderRequests());
        assertFalse(s.lcHunting());
        assertFalse(s.elHunting());
        assertEquals(0, s.rpcPort());                 // no listener in this seam
        assertFalse(s.rpcServing());
        assertNull(s.upgradeAdvisory());
        assertEquals(DataUsage.NONE, s.dataUsage());  // Go emits null dataUsage → NONE
        assertEquals(NetworkMetering.METERED, s.networkMetering()); // the STRING, like Rust
    }

    @Test
    void notServeableStatusKeepsTheMaxAgeSentinel() {
        StatusSnapshot s = GoChainHandle.statusFromJson("mainnet",
                goStatus("CATCHING_UP", 26404150, 0, "UNMETERED"));
        assertEquals(BeaconState.CATCHING_UP, s.beaconState());
        assertEquals(Long.MAX_VALUE, s.verifiedHeadAgeMs());
        assertEquals(NetworkMetering.UNMETERED, s.networkMetering());
    }

    @Test
    void unknownHandleShapesParseAsNotRunning() {
        for (String json : new String[]{"{}", "", null}) {
            StatusSnapshot s = GoChainHandle.statusFromJson("mainnet", json);
            assertFalse(s.running());
            assertEquals(io.myotis.api.LifecycleState.STOPPED, s.lifecycle());
            assertEquals(BeaconState.STARTING, s.beaconState());
            assertEquals(0, s.rpcPort());
        }
    }

    @Test
    void unknownBeaconStateAndMeteringFailClosed() {
        // A future Go state must not throw the whole parse (the Rust twin's rule).
        StatusSnapshot s = GoChainHandle.statusFromJson("mainnet",
                goStatus("SYNCED_FOREVER", 5, 1, "LIQUID"));
        assertEquals(BeaconState.STARTING, s.beaconState());
        assertEquals(NetworkMetering.UNKNOWN, s.networkMetering());
    }

    @Test
    void beaconStatusDerivesTheFinalizedPeriodFromTheSlot() {
        BeaconStatus b = GoChainHandle.beaconStatusFromJson("mainnet",
                goStatus("SYNCED", 26404150, 3, "UNKNOWN"));
        assertEquals(BeaconState.SYNCED, b.state());
        assertEquals(15634912L / 8192L, b.finalizedPeriod());
        assertEquals(7L, b.lightClientPeers());
        assertEquals(26404150L, b.executionBlockNumber());
        assertEquals(13L, b.wsBoundPeriods());
    }

    // ---- account / storage result shapes (go/internal/engine/eljson goldens) ----

    private static final String ACCOUNT_JSON = "{"
            + "\"address\":\"0xd8da6bf26964af9d7eed9e03e53415d37aa96045\",\"exists\":true,"
            + "\"nonce\":5970,\"balanceWei\":\"5798969845714110716\","
            + "\"storageRootHex\":\"0x56e81f171bcac59f0a53b2e4f855b4d1e3c5e2e0\","
            + "\"codeHashHex\":\"0x8d8d5e2c0e5b4e9a\","
            + "\"blockNumber\":26404150,\"peerStateRootHex\":\"0xe04f511b55ee0c7a\","
            + "\"peerProofValid\":true,\"beaconChainVerified\":true,\"blsVerified\":true,"
            + "\"matchedBeaconSlot\":15634912,\"verifyMethod\":\"stateRootMatch\","
            + "\"failReason\":null,\"accountHashHex\":\"0x9b0e\","
            + "\"proofNodesHex\":[],\"beaconSynced\":true,\"finalizedPeriod\":1909,"
            + "\"wallClockPeriod\":1909,\"finalizedBlockNumber\":26404150,"
            + "\"optimisticBlockNumber\":0,\"blockTimestamp\":1761000000,"
            + "\"blockHash\":\"0xe04f511b\",\"anchor\":\"finalized\"}";

    @Test
    void accountJsonMapsToTheRecord() {
        AccountProofResult r = GoChainHandle.accountFromJson(
                "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", ACCOUNT_JSON);
        assertTrue(r.exists());
        assertEquals(5970L, r.nonce());
        assertEquals("5798969845714110716", r.balanceWei());
        assertEquals(26404150L, r.blockNumber());
        assertEquals("stateRootMatch", r.verifyMethod());
        assertNull(r.failReason());
        assertEquals(1761000000L, r.blockTimestamp());
        assertEquals("0xe04f511b", r.blockHashHex());
    }

    @Test
    void missingBlockTimestampReadsAsMinusOne() {
        String json = ACCOUNT_JSON.replace(",\"blockTimestamp\":1761000000", "");
        assertEquals(-1L, GoChainHandle.accountFromJson("0x0", json).blockTimestamp());
    }

    @Test
    void errorEnvelopeBecomesANamedEngineException() {
        // The Go build's pruned-root rotation leaves as this envelope (the
        // classifyReadErr taxonomy): the reason must reach the caller's log.
        EngineException ex = assertThrows(EngineException.class, () ->
                GoChainHandle.accountFromJson("0x0",
                        "{\"error\":\"empty proof for non-empty root [id=pruned-root]\"}"));
        assertTrue(ex.getMessage().contains("pruned-root"), ex.getMessage());
        assertFalse(ex.getMessage().contains("permanent"), "retryable must not claim permanent");
        // The permanent (-32602) form says so — the selector/UI may act on it.
        EngineException perm = assertThrows(EngineException.class, () ->
                GoChainHandle.accountFromJson("0x0",
                        "{\"error\":\"block selector latest not supported; use finalized\","
                        + "\"code\":-32602}"));
        assertTrue(perm.getMessage().contains("permanent"), perm.getMessage());
    }

    @Test
    void emptyReplyMeansUnknownHandle() {
        EngineException ex = assertThrows(EngineException.class,
                () -> GoChainHandle.accountFromJson("0x0", ""));
        assertTrue(ex.getMessage().contains("unknown handle"), ex.getMessage());
    }

    @Test
    void storageJsonMapsToTheRecord() {
        StorageProofResult r = GoChainHandle.storageFromJson("0xdead", 1L, "{"
                + "\"addressHex\":\"0xdead\",\"slot\":1,\"holderHex\":null,"
                + "\"storageKeyHex\":\"0x01\",\"storageKeyHashHex\":\"0xb931be0b\","
                + "\"exists\":true,\"valueHex\":\"0x2a\",\"valueDecimal\":\"42\","
                + "\"slotsReturned\":1,\"storageRootHex\":\"0x56e8\",\"proofNodesHex\":[],"
                + "\"storageProofValid\":true,\"beaconSynced\":true,\"beaconChainVerified\":true,"
                + "\"blsVerified\":true,\"matchedBeaconSlot\":15634912,"
                + "\"verifyMethod\":\"storageRootMatch\",\"failReason\":null,"
                + "\"peerBlockNumber\":26404150,\"finalizedBlockNumber\":26404150,"
                + "\"optimisticBlockNumber\":0,\"finalizedSlot\":15634912,\"optimisticSlot\":0,"
                + "\"maxHeaderChainGap\":8192,\"anchor\":\"finalized\"}");
        assertEquals(1L, r.slot());
        assertEquals("0xb931be0b", r.storageKeyHashHex());
        assertEquals("42", r.valueDecimal());
        assertEquals("storageRootMatch", r.verifyMethod());
        assertEquals(8192, r.maxHeaderChainGap());
    }

    // ---- storage VALUE width (PR #832 review: the Go reader's value is MINIMAL
    // big-endian — mpt.DecodeStorageLeaf rejects a leading zero byte — so slot 42
    // arrives as "0x2a"; the contract's word is 32 bytes, so the adapter pads) ----

    @Test
    void minimalBigEndianValuesAreLeftPaddedIntoWords() {
        byte[] fortyTwo = GoVerifiedReads.toWord("0x2a");
        assertEquals(32, fortyTwo.length);
        for (int i = 0; i < 31; i++) assertEquals(0, fortyTwo[i], "byte " + i + " must be zero");
        assertEquals(0x2a, fortyTwo[31] & 0xff);
        // "0x" (RLP-empty = value zero) → the all-zero word, not a refusal.
        assertEquals(32, GoVerifiedReads.toWord("0x").length);
        // A full word passes through untouched.
        String full = "0x" + "ab".repeat(32);
        assertEquals(full, io.myotis.engines.common.Hex.formatHexPrefixed(GoVerifiedReads.toWord(full)));
        // WIDER than a word is shape drift — refused, never truncated (#314).
        assertNull(GoVerifiedReads.toWord("0x" + "cd".repeat(33)));
    }

    // ---- detailed refusals (PR #314 line: permanent refusals must not arrive
    // as the router's RETRYABLE -32000; the detailed channel is the honest one) ----

    @Test
    void unimplementedReadsRefusePermanentlyOnTheDetailedChannel() {
        // No native round-trip: these overrides answer from the engine's shape,
        // so a handle that never crossed the FFI is enough (same trick the
        // pure-parse helpers above use).
        GoVerifiedReads reads = new GoVerifiedReads(new GoChainHandle(0L, "mainnet", 1L, 0, null));
        assertEquals(CallResult.Status.REFUSED,
                reads.callDetailed(null, new byte[20], new byte[]{1}, null, "finalized", null).status());
        assertEquals(EstimateResult.Status.REFUSED,
                reads.estimateGasDetailed(null, new byte[20], null, null).status());
        assertEquals(SendResult.Status.REFUSED,
                reads.sendRawTransactionDetailed(new byte[]{1, 2, 3}).status());
        // …while the plain reads keep their null contract ("cannot answer").
        assertNull(reads.call(null, new byte[20], null, null, "finalized"));
        assertNull(reads.estimateGas(null, new byte[20], null, null));
        assertNull(reads.sendRawTransaction(new byte[]{1}));
    }

    // ---- selector rule ----

    @Test
    void onlyFinalizedIsServable() {
        assertTrue(GoVerifiedReads.isFinalizedSelector("finalized"));
        assertTrue(GoVerifiedReads.isFinalizedSelector(" Finalized "));
        // The DEFAULT (absent selector) means the head — refused, not quietly
        // answered from finalized state (apply-or-refuse, #314).
        assertFalse(GoVerifiedReads.isFinalizedSelector(null));
        assertFalse(GoVerifiedReads.isFinalizedSelector(""));
        assertFalse(GoVerifiedReads.isFinalizedSelector("latest"));
        assertFalse(GoVerifiedReads.isFinalizedSelector("pending"));
        assertFalse(GoVerifiedReads.isFinalizedSelector("0x1930e36"));
    }
}
