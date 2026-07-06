package io.myotis.engines;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import io.myotis.api.AccountProofResult;
import io.myotis.api.BeaconState;
import io.myotis.api.BeaconStatus;
import io.myotis.api.BlockResult;
import io.myotis.api.ChainHandle;
import io.myotis.api.ClPeerInfo;
import io.myotis.api.ConnectedPeer;
import io.myotis.api.DialResult;
import io.myotis.api.DiscoveredPeer;
import io.myotis.api.EngineException;
import io.myotis.api.EnsApi;
import io.myotis.api.HeadersResult;
import io.myotis.api.PeerInfo;
import io.myotis.api.StatusSnapshot;
import io.myotis.api.StorageProofResult;
import io.myotis.api.VerifiedReads;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * The Rust engine's {@link ChainHandle}: one hosted mainnet network backed by a
 * {@code myotis_net::SyncHandle} (the light-client sync loop) running on the tokio
 * runtime the native engine owns. Lifecycle + status cross the JNI boundary via
 * {@link RustEngineNative}; compound status is a JSON object (the hand-JNI + JSON
 * decision, pinned by golden tests on both sides).
 *
 * <p>R1 scope is CL-only + mainnet-only: the beacon fields of the status snapshot
 * are real (finalized slot, sync period, peer count, beacon state); the EL-side
 * fields (execution block number, snap peers, RPC head age, …) are zero because
 * this engine has no execution layer yet. The verified-read / proof / header
 * queries throw {@link EngineException} until the EL surface lands.
 */
final class RustChainHandle implements ChainHandle {

    private static final Logger log = LoggerFactory.getLogger(RustChainHandle.class);

    /** Message for the queries the CL-only R1 engine can't answer yet. */
    private static final String NOT_AVAILABLE = "not available on the R1 Rust engine (CL-only)";

    private final long handle;
    private final String networkName;
    private final long chainId;

    RustChainHandle(long handle, String networkName, long chainId) {
        this.handle = handle;
        this.networkName = networkName;
        this.chainId = chainId;
    }

    @Override public String networkName() { return networkName; }

    @Override public long chainId() { return chainId; }

    @Override public boolean start() { return RustEngineNative.nativeStart(handle); }

    @Override public void stop() { RustEngineNative.nativeStop(handle); }

    @Override public boolean isRunning() { return readStatus().running(); }

    // ---- status ----

    /** Parse the native status JSON; a null/empty payload → an unknown/dead handle. */
    private ParsedStatus readStatus() {
        String json = RustEngineNative.nativeStatusJson(handle);
        return ParsedStatus.parse(json);
    }

    /** The parsed native status object — CL fields only (see the class javadoc). */
    private record ParsedStatus(
            boolean running,
            BeaconState beaconState,
            boolean bootstrapped,
            long finalizedSlot,
            long optimisticSlot,
            long currentPeriod,
            long targetPeriod,
            long peerCount,
            int servedPeersLastMinute,
            int discv5TableSize) {

        static ParsedStatus parse(String json) {
            if (json == null || json.isBlank()) return notRunning();
            try {
                JsonObject o = Json.parse(json).asObject();
                if (o.isEmpty()) return notRunning(); // "{}" == unknown handle
                return new ParsedStatus(
                        o.getBoolean("running", false),
                        BeaconState.valueOf(o.getString("beaconState", "STARTING")),
                        o.getBoolean("bootstrapped", false),
                        o.getLong("finalizedSlot", 0L),
                        o.getLong("optimisticSlot", 0L),
                        o.getLong("currentPeriod", 0L),
                        o.getLong("targetPeriod", 0L),
                        o.getLong("peerCount", 0L),
                        o.getInt("servedPeersLastMinute", 0),
                        o.getInt("discv5TableSize", 0));
            } catch (RuntimeException e) {
                throw new EngineException(
                        "malformed status JSON from the Rust engine: " + e.getMessage(), e);
            }
        }

        static ParsedStatus notRunning() {
            return new ParsedStatus(false, BeaconState.STARTING, false, 0L, 0L, 0L, 0L, 0L, 0, 0);
        }
    }

    @Override
    public StatusSnapshot status() {
        return status(readStatus());
    }

    /**
     * Map a native status JSON payload to a {@link StatusSnapshot} for {@code network}.
     * Package-private test seam: exercises the JSON→snapshot mapping without JNI.
     */
    static StatusSnapshot statusFromJson(String network, String json) {
        return new RustChainHandle(0L, network, 1L).status(ParsedStatus.parse(json));
    }

    /** Package-private test seam: JSON→{@link BeaconStatus} without JNI. */
    static BeaconStatus beaconStatusFromJson(String network, String json) {
        return new RustChainHandle(0L, network, 1L).beaconStatus(ParsedStatus.parse(json));
    }

    private StatusSnapshot status(ParsedStatus s) {
        int peers = (int) Math.min(s.peerCount(), Integer.MAX_VALUE);
        // Older natives don't emit "targetPeriod" (parsed as 0): fall back to
        // currentPeriod — the pre-targetPeriod mirror — so the target >= current
        // invariant holds against any .so vintage.
        long targetPeriod = Math.max(s.targetPeriod(), s.currentPeriod());
        // CL-only: EL fields (executionBlockNumber, snapPeers, discv4 table, RPC
        // head age, …) are zero — the Rust engine has no execution layer in R1.
        return new StatusSnapshot(
                s.running(),
                networkName,
                s.beaconState(),
                peers,          // connectedPeers (CL libp2p peers)
                0,              // readyPeers (EL)
                0,              // snapPeers
                0,              // snapServingPeers
                0,              // discoveredPeers (discv4)
                0,              // backedOffPeers
                0,              // blacklistedPeers
                0,              // attemptedDials
                s.discv5TableSize(),
                0L,             // executionBlockNumber
                0L,             // optimisticBlockNumber
                s.finalizedSlot(),
                0L,             // finalizedBlockNumber
                -1L,            // syncStartPeriod (unknown)
                s.currentPeriod(),
                targetPeriod,
                s.finalizedSlot() / 8192L, // finalizedPeriod (SLOTS_PER_SYNC_COMMITTEE_PERIOD)
                targetPeriod,   // wallClockPeriod == the catch-up target
                Long.MAX_VALUE, // verifiedHeadAgeMs (no verified RPC head yet)
                List.<PeerInfo>of());
    }

    @Override
    public BeaconStatus beaconStatus() {
        return beaconStatus(readStatus());
    }

    private BeaconStatus beaconStatus(ParsedStatus s) {
        int peers = (int) Math.min(s.peerCount(), Integer.MAX_VALUE);
        return new BeaconStatus(
                s.beaconState(),
                s.bootstrapped(),
                s.currentPeriod(),
                // Same older-.so fallback as status(): missing key parses as 0.
                Math.max(s.targetPeriod(), s.currentPeriod()),
                s.discv5TableSize(),
                peers,                 // connectedPeers (CL)
                s.peerCount(),         // lightClientPeers
                s.servedPeersLastMinute(),
                s.finalizedSlot(),
                s.optimisticSlot(),
                s.finalizedSlot() / 8192L,  // finalizedPeriod = period OF the finalized
                                            // slot (SLOTS_PER_SYNC_COMMITTEE_PERIOD),
                                            // consistent with StatusSnapshot — not the
                                            // committee's currentPeriod.
                null,                  // executionStateRootHex (EL)
                null,                  // executionBlockHashHex (EL)
                0L,                    // executionBlockNumber
                0,                     // knownStateRoots
                0,                     // fillThreshold
                List.<ClPeerInfo>of());
    }

    // ---- CL-only R1 scope: EL / verified-read surface not available yet ----
    //
    // reads()/ens() return null — that IS the ChainHandle contract ("or null when
    // this network has no ENS registry" / "or null ... if the RPC port was
    // unavailable"), and callers null-check it. The EL QUERY methods below
    // (requestAccount/getStorageProof/getHeaders/getBlockVerified/dialPeer) throw
    // EngineException: the contract reserves exceptions for malformed input / not
    // running, and a CL-only engine asked for an EL proof is a capability-state
    // error (there is no verification to report a failReason for — the capability
    // categorically does not exist yet). A failReason record would misrepresent
    // "we can't" as "we tried and failed". The real fix is EL support (or the
    // selector routing EL queries to the Java engine while Rust hosts the CL side);
    // tracked for a later phase.

    @Override public VerifiedReads reads() { return null; }

    @Override public EnsApi ens() { return null; }

    @Override
    public List<DiscoveredPeer> discoveredPeers() { return List.of(); }

    @Override
    public List<ConnectedPeer> connectedPeers() { return List.of(); }

    @Override
    public void setTargetSnapPeers(int target) {
        log.debug("[engines] setTargetSnapPeers({}) is a no-op on the R1 Rust engine (CL-only)",
                target);
    }

    @Override
    public void clearPeerState() {
        log.debug("[engines] clearPeerState is a no-op on the R1 Rust engine (CL-only)");
    }

    @Override
    public AccountProofResult requestAccount(String hexAddress) {
        throw new EngineException(NOT_AVAILABLE);
    }

    @Override
    public StorageProofResult getStorageProof(String hexAddress, long slot, String holderHexOrNull) {
        throw new EngineException(NOT_AVAILABLE);
    }

    @Override
    public HeadersResult getHeaders(long startBlock, int count) {
        throw new EngineException(NOT_AVAILABLE);
    }

    @Override
    public BlockResult getBlockVerified(long blockNumber) {
        throw new EngineException(NOT_AVAILABLE);
    }

    @Override
    public DialResult dialPeer(String host, int port, String pubkeyHex) {
        throw new EngineException(NOT_AVAILABLE);
    }
}
