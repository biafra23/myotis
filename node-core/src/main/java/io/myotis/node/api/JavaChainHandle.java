package io.myotis.node.api;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import io.myotis.api.AccountProofResult;
import io.myotis.api.BeaconState;
import io.myotis.api.BlockResult;
import io.myotis.api.ChainHandle;
import io.myotis.api.DialResult;
import io.myotis.api.EngineException;
import io.myotis.api.EnsApi;
import io.myotis.api.HeadersResult;
import io.myotis.api.LifecycleState;
import io.myotis.api.PeerInfo;
import io.myotis.api.StatusSnapshot;
import io.myotis.api.StorageProofResult;
import io.myotis.api.VerifiedReads;
import io.myotis.node.ChainStack;
import io.myotis.node.VerifiedAccountQuery;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The JVM implementation of {@link ChainHandle}: wraps one {@link ChainStack} and assembles
 * the API shapes from the stack's internal accessors. This is the single place the host-facing
 * status snapshot is built (previously duplicated across the desktop, Android, and daemon
 * status paths).
 */
public final class JavaChainHandle implements ChainHandle {

    private final ChainStack stack;
    private final boolean strictStateFreshness;

    JavaChainHandle(ChainStack stack, boolean strictStateFreshness) {
        this.stack = stack;
        this.strictStateFreshness = strictStateFreshness;
    }

    /** Package-private: {@link JavaMyotisEngine#debugStack} only. */
    ChainStack stack() {
        return stack;
    }

    @Override public String networkName() { return stack.network().name(); }

    @Override public long chainId() { return stack.network().networkId(); }

    @Override
    public boolean start() {
        // The freshness knob is a process-global system property in the reference engine
        // (VerifiedRpcBackend reads it once, during this start()); set it here — not at
        // create() — so interleaved create()/start() across networks can't cross-apply.
        // Per-network divergence within one process is not supported yet.
        System.setProperty(io.myotis.rpc.VerifiedRpcBackend.STRICT_STATE_FRESHNESS_PROP,
                String.valueOf(strictStateFreshness));
        return stack.start();
    }

    @Override public void stop() { stack.shutdown(); }

    @Override public boolean isRunning() { return stack.isRunning(); }

    @Override public boolean pause() { return stack.pause(); }

    @Override public boolean resume() { return stack.resume(); }

    @Override public boolean resume(String reason) { return stack.resume(reason); }

    @Override public LifecycleState lifecycle() { return stack.lifecycle(); }

    @Override public long lastActivityEpochMillis() { return stack.lastActivityMs(); }

    /**
     * Wake-and-wait shared by the verified operator queries: a query on a paused
     * stack triggers resume and holds here until the node is ready. On a
     * PAUSED-at-deadline timeout (resume kept failing) this throws; a STOPPED
     * stack falls through to each query's existing "Node is not running" guard.
     */
    private void awaitWake() {
        stack.awaitReadyForReads(ChainStack.WAKE_WAIT_CAP_MS);
        if (stack.lifecycle() == LifecycleState.PAUSED) {
            throw new EngineException("node did not become ready within "
                    + (ChainStack.WAKE_WAIT_CAP_MS / 1000) + "s (paused; resume failing)");
        }
    }

    @Override public void setTargetSnapPeers(int target) { stack.setTargetSnapPeers(target); }

    @Override
    public void clearPeerState() {
        stack.backoff().clear();
        stack.blacklistedNodeIds().clear();
    }

    @Override
    public StatusSnapshot status() {
        NetworkConfig net = stack.network();
        RLPxConnector conn = stack.connector();
        BeaconSyncState bss = stack.beaconSyncState();

        BeaconState beaconState = bss == null
                ? BeaconState.STARTING
                : BeaconState.valueOf(bss.getSyncState(net.clGenesisTime(), net.secondsPerSlot()).name());

        List<RLPxConnector.PeerInfo> active = conn != null ? conn.getActivePeers() : List.of();
        List<RLPxConnector.PeerInfo> ready = new ArrayList<>();
        for (RLPxConnector.PeerInfo p : active) {
            // "ready" = past the eth handshake; the raw active list also includes peers
            // still negotiating Hello/Status.
            if ("READY".equals(p.state())) ready.add(p);
        }
        // Snap-capable peers first (clientId tiebreak), matching the established UI ordering.
        ready.sort(Comparator.comparing(RLPxConnector.PeerInfo::snapSupported).reversed()
                .thenComparing(p -> p.clientId() != null ? p.clientId() : ""));
        List<PeerInfo> readyRows = new ArrayList<>(ready.size());
        int snapNegotiated = 0;
        for (RLPxConnector.PeerInfo p : ready) {
            if (p.snapSupported()) snapNegotiated++;
            readyRows.add(new PeerInfo(p.remoteAddress(), p.snapSupported(), p.clientId()));
        }

        // Two DISTINCT counts: peers that negotiated snap/1 vs peers currently in the
        // serving pool (activeSnapHandlers filters out serving-failed peers). Surfacing
        // both makes a serving-pool collapse visible — the live operational issue on
        // peer-scarce chains — so never feed one into the other.
        int snapServing = conn != null ? conn.activeSnapHandlers().size() : 0;
        long wallClockPeriod = BeaconChainSpec.currentPeriod(net.clGenesisTime(), net.secondsPerSlot());
        io.myotis.rpc.VerifiedRpcBackend backend = stack.rpcBackend();

        return new StatusSnapshot(
                stack.isRunning(),
                stack.lifecycle(),
                net.name(),
                beaconState,
                active.size(),
                ready.size(),
                snapNegotiated,
                snapServing,
                stack.discV4() != null ? stack.discV4().table().size() : 0,
                stack.pruneAndCountActiveBackoff(),
                stack.blacklistedNodeIds().size(),
                stack.attemptedCount(),
                stack.discV5() != null ? stack.discV5().liveNodeCount() : 0,
                bss != null ? bss.getExecutionBlockNumber() : 0L,
                bss != null ? bss.getOptimisticBlockNumber() : 0L,
                bss != null ? bss.getFinalizedSlot() : 0L,
                bss != null ? bss.getFinalizedExecution().blockNumber() : 0L,
                bss != null ? bss.getCatchUpStartPeriod() : -1L,
                bss != null ? bss.getCurrentSyncCommitteePeriod() : 0L,
                wallClockPeriod,
                bss != null ? bss.getFinalizedPeriod() : 0L,
                wallClockPeriod,
                backend != null ? backend.verifiedHeadAgeMs() : Long.MAX_VALUE,
                readyRows,
                stack.pauseCount(),
                stack.totalPausedMs(),
                stack.lastPauseEpochMs(),
                stack.lastResumeEpochMs(),
                stack.lastWakeReason());
    }

    @Override
    public java.util.List<io.myotis.api.DiscoveredPeer> discoveredPeers() {
        var disc = stack.discV4();
        if (disc == null) return List.of();
        List<io.myotis.api.DiscoveredPeer> out = new ArrayList<>();
        for (var e : disc.table().allPeers()) {
            out.add(new io.myotis.api.DiscoveredPeer(
                    e.udpAddr().getAddress().getHostAddress(),
                    e.udpAddr().getPort(),
                    e.tcpPort(),
                    e.nodeId().toHexString()));
        }
        return out;
    }

    @Override
    public java.util.List<io.myotis.api.ConnectedPeer> connectedPeers() {
        RLPxConnector conn = stack.connector();
        if (conn == null) return List.of();
        List<io.myotis.api.ConnectedPeer> out = new ArrayList<>();
        for (RLPxConnector.PeerInfo p : conn.getActivePeers()) {
            out.add(new io.myotis.api.ConnectedPeer(
                    p.remoteAddress(), p.state(), p.snapSupported(), p.clientId()));
        }
        return out;
    }

    @Override
    public io.myotis.api.BeaconStatus beaconStatus() {
        NetworkConfig net = stack.network();
        BeaconSyncState bss = stack.beaconSyncState();
        var blc = stack.beaconLightClient();

        List<io.myotis.api.ClPeerInfo> peers = new ArrayList<>();
        int lightClientPeers = 0;
        if (blc != null) {
            for (var p : blc.getConnectedPeers()) {
                boolean lc = p.supportsLightClient();
                if (lc) lightClientPeers++;
                peers.add(new io.myotis.api.ClPeerInfo(
                        p.peerId(), p.remoteAddress(), p.agentVersion(), lc, p.protocols().size()));
            }
        }
        io.myotis.api.BeaconState state = bss == null
                ? io.myotis.api.BeaconState.STARTING
                : io.myotis.api.BeaconState.valueOf(
                        bss.getSyncState(net.clGenesisTime(), net.secondsPerSlot()).name());
        byte[] stateRoot = bss != null ? bss.getVerifiedExecutionStateRoot() : null;
        byte[] blockHash = bss != null ? bss.getExecutionBlockHash() : null;
        long finalizedSlot = bss != null ? bss.getFinalizedSlot() : 0L;
        return new io.myotis.api.BeaconStatus(
                state,
                blc != null && blc.isBootstrapped(),
                bss != null ? bss.getCurrentSyncCommitteePeriod() : 0L,
                BeaconChainSpec.currentPeriod(net.clGenesisTime(), net.secondsPerSlot()),
                stack.discV5() != null ? stack.discV5().liveNodeCount() : 0,
                peers.size(),
                lightClientPeers,
                blc != null ? blc.recentlyServedPeerCount() : 0,
                finalizedSlot,
                bss != null ? bss.getOptimisticSlot() : 0L,
                finalizedSlot / BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD,
                stateRoot != null ? org.apache.tuweni.bytes.Bytes.wrap(stateRoot).toHexString() : null,
                blockHash != null ? org.apache.tuweni.bytes.Bytes.wrap(blockHash).toHexString() : null,
                bss != null ? bss.getExecutionBlockNumber() : 0L,
                bss != null ? bss.getKnownStateRootCount() : 0,
                BeaconSyncState.FILL_THRESHOLD,
                peers);
    }

    @Override
    public VerifiedReads reads() {
        // The gate, not the raw backend: it stays valid across pause/resume cycles
        // (the backend is torn down on pause and rebuilt on resume) and a read on a
        // paused stack wakes it. Null only when the RPC pipeline never came up.
        return stack.verifiedReads();
    }

    @Override
    public EnsApi ens() {
        if (!stack.network().hasEns()) return null;
        return new JavaEnsApi(stack);
    }

    @Override
    public AccountProofResult requestAccount(String hexAddress) {
        awaitWake();
        try {
            // queryProof internally bounds the header fetch (60 s); the outer bound covers
            // the snap fetch + verification end to end.
            return VerifiedAccountQuery.queryProof(stack, hexAddress).get(120, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new EngineException("interrupted while querying account", e);
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new EngineException(cause.getMessage() != null
                    ? cause.getMessage() : cause.getClass().getSimpleName(), cause);
        }
    }

    @Override
    public StorageProofResult getStorageProof(String hexAddress, long slot, String holderHexOrNull) {
        awaitWake();
        RLPxConnector conn = stack.connector();
        if (!stack.isRunning() || conn == null) throw new EngineException("Node is not running");
        try {
            return io.myotis.node.VerifiedStorageQuery.query(
                    conn, stack.beaconSyncState(), hexAddress, slot, holderHexOrNull);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new EngineException("interrupted while querying storage", e);
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new EngineException(cause.getMessage() != null
                    ? cause.getMessage() : cause.getClass().getSimpleName(), cause);
        }
    }

    @Override
    public HeadersResult getHeaders(long startBlock, int count) {
        awaitWake();
        RLPxConnector conn = stack.connector();
        if (!stack.isRunning() || conn == null) throw new EngineException("Node is not running");
        return io.myotis.node.HeaderQuery.fetch(conn, startBlock, count);
    }

    @Override
    public BlockResult getBlockVerified(long blockNumber) {
        awaitWake();
        RLPxConnector conn = stack.connector();
        if (!stack.isRunning() || conn == null) throw new EngineException("Node is not running");
        return io.myotis.node.VerifiedBlockQuery.query(conn, stack.beaconSyncState(), blockNumber);
    }

    @Override
    public DialResult dialPeer(String host, int port, String pubkeyHex) {
        awaitWake();
        RLPxConnector conn = stack.connector();
        if (!stack.isRunning() || conn == null) throw new EngineException("Node is not running");
        try {
            SECP256K1.PublicKey pubKey =
                    SECP256K1.PublicKey.fromBytes(Bytes.fromHexString(pubkeyHex));
            conn.connect(new InetSocketAddress(host, port), pubKey);
            return new DialResult(true, null);
        } catch (Exception e) {
            return new DialResult(false, e.getMessage() != null
                    ? e.getMessage() : e.getClass().getSimpleName());
        }
    }
}
