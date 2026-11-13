package io.myotis.engines.go;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import io.myotis.api.AccountProofResult;
import io.myotis.api.BeaconState;
import io.myotis.api.BeaconStatus;
import io.myotis.api.BlockResult;
import io.myotis.api.ChainHandle;
import io.myotis.api.ConnectedPeer;
import io.myotis.api.DataUsage;
import io.myotis.api.DialResult;
import io.myotis.api.EnsApi;
import io.myotis.api.EngineException;
import io.myotis.api.HeadersResult;
import io.myotis.api.LifecycleState;
import io.myotis.api.NetworkMetering;
import io.myotis.api.NodeStatusReads;
import io.myotis.api.PeerInfo;
import io.myotis.api.StorageProofResult;
import io.myotis.api.UpgradeAdvisory;
import io.myotis.api.UpgradePhase;
import io.myotis.api.VerifiedReads;
import io.myotis.api.WakeReason;
import io.myotis.api.WebAccessPolicy;
import io.myotis.api.WebOrigin;
import io.myotis.engines.common.Hex;
import io.myotis.engines.common.LoopbackRpc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * One Go-engine-hosted network behind the {@link ChainHandle} contract — the twin
 * of {@code RustChainHandle} over {@link GoEngineNative}, with the parts the Go
 * build does not serve yet handled HONESTLY rather than faked:
 *
 * <ul>
 *   <li><b>No idle sleep yet.</b> The Go ABI's pause/resume refuse (no teardown/
 *       warm-start machinery), so this lifecycle is RUNNING/STOPPED only and
 *       there is no {@code WakeGate}: {@link #pause()} returns false, a resume of
 *       a running stack succeeds, of a stopped one does not. Hosts' idle timers
 *       simply never reach a Go-hosted network (pause() false means "not paused").</li>
 *   <li><b>Finalized-anchor reads.</b> The Go reader has no optimistic-head
 *       machinery yet, so every verified read runs at the beacon-FINALIZED state
 *       root: {@link #requestAccount} passes the {@code "finalized"} selector
 *       (the Rust twin passes head), {@code finalized} is the only selector
 *       {@link GoVerifiedReads} serves, and the status's verified-head age ages
 *       by FINALIZED-block advance — on mainnet that finality tick is ~2–4 min,
 *       so the hosts' 45 s readiness dot reads amber for a Go-hosted network.
 *       That is honest (the read state IS older by design), not a regression to
 *       paper over with a constant.</li>
 *   <li><b>No EVM, no block/tx/receipt reads, no ENS, no log index.</b> The
 *       operator queries throw {@link EngineException} (the Rust twin's
 *       NOT_AVAILABLE rule), {@link #ens()} answers an API that throws the same
 *       named refusal, and the unimplemented VerifiedReads methods answer
 *       {@code null} ("cannot answer verified") via the interface defaults.</li>
 * </ul>
 *
 * <p>{@link #reads()} and the loopback listener follow the Rust twin exactly:
 * a host-attached {@link LoopbackRpc} starts on {@code 127.0.0.1:rpcPort} at
 * {@link #start()} and gates what {@link #reads()} means on the wire.
 */
final class GoChainHandle implements ChainHandle, NodeStatusReads, io.myotis.api.NodeLifecycle {

    private static final Logger log = LoggerFactory.getLogger(GoChainHandle.class);

    /** Message for the operator queries the Go engine does not serve yet — the
     *  Go twin of {@code RustChainHandle.NOT_AVAILABLE}. Block reads join the
     *  engine-parity increment; the contract reserves records for verification
     *  verdicts, and a surface this engine does not implement is a capability
     *  error ("we don't"), not a failReason ("we tried and failed"). */
    private static final String NOT_AVAILABLE =
            "not available on the Go engine yet (operator query: get-headers, get-block, dial)";

    /** The block selector every Go verified read runs at (see class doc). */
    static final String READ_SELECTOR = "finalized";

    private final long handle;
    private final String networkName;
    private final long chainId;
    /** Loopback JSON-RPC port; {@code <= 0} disables the listener (test seams). */
    private final int rpcPort;
    private final GoVerifiedReads verifiedReads = new GoVerifiedReads(this);
    /** The host's loopback listener (a port — see {@link LoopbackRpc}), or null. */
    private final LoopbackRpc rpc;
    private volatile boolean rpcStarted;

    /** Uptime anchoring (Rust-twin parity): nanoTime from the start REQUEST,
     *  paired with a set flag because nanoTime's origin is arbitrary. */
    private volatile long startedAtNs;
    private volatile boolean started;

    /** Finalized-anchor freshness for verifiedHeadAgeMs (see class doc): the last
     *  finalized block number seen and the monotonic time it was first seen,
     *  guarded so concurrent status() callers cannot tear the pair. */
    private final Object headAgeLock = new Object();
    private long lastFinalizedBlock = -1L;
    private long lastFinalizeAdvanceNanos;

    /** Idle-sleep accounting is Java-side even here: the Go engine never pauses,
     *  so these stay at their zeros — but they are reported through the same
     *  SleepMetrics type so the two engines' status screens cannot drift. */
    private final io.myotis.engines.common.SleepMetrics sleepMetrics =
            new io.myotis.engines.common.SleepMetrics();
    /** Requests in flight: while non-zero lastActivityEpochMillis reports "now"
     *  so a host idle timer never acts mid-query (the Go engine cannot be
     *  paused anyway; kept so the field means the same thing on every engine). */
    private final java.util.concurrent.atomic.AtomicLong lastActivityMs =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicInteger inFlight =
            new java.util.concurrent.atomic.AtomicInteger();

    GoChainHandle(long handle, String networkName, long chainId, int rpcPort, LoopbackRpc rpc) {
        this.handle = handle;
        this.networkName = networkName;
        this.chainId = chainId;
        this.rpcPort = rpcPort;
        this.rpc = rpc;
    }

    @Override public String networkName() { return networkName; }

    @Override public long chainId() { return chainId; }

    @Override
    public synchronized boolean start() {
        long startRequestNs = System.nanoTime();
        boolean ok = GoEngineNative.nativeStart(handle);
        if (ok) {
            if (!started) { startedAtNs = startRequestNs; started = true; }
            startRpc();
        }
        return ok;
    }

    @Override
    public synchronized void stop() {
        if (rpcStarted) {
            try { rpc.stop(); } catch (Throwable ignored) {}
            rpcStarted = false;
        }
        started = false;
        GoEngineNative.nativeStop(handle);
    }

    // ---- lifecycle (no idle sleep yet; see class doc) ----

    @Override
    public synchronized boolean pause() {
        // The Go ABI has no pause (myotis_pause refuses, no PAUSED state exists).
        // The contract's answer for "cannot be PAUSED on return" is false; the
        // host's idle timer treats that as "the engine declined".
        log.debug("[engines] pause is not implemented on the Go engine yet");
        return false;
    }

    @Override public boolean resume() { return resume(WakeReason.MANUAL); }

    @Override
    public boolean resume(String reason) {
        // No PAUSED state to leave: a running stack is a no-op success per the
        // contract; a stopped one cannot warm-start (that is the engine-parity
        // increment), so it fails like a resume whose rebuild failed.
        return isRunning();
    }

    @Override
    public LifecycleState lifecycle() {
        ParsedStatus s = readStatus();
        if (s.running()) return LifecycleState.RUNNING;
        return s.paused() ? LifecycleState.PAUSED : LifecycleState.STOPPED;
    }

    @Override public boolean wakeUp() { return resume(WakeReason.IPC); }
    @Override public String lifecycleName() { return lifecycle().name(); }

    @Override
    public long lastActivityEpochMillis() {
        return inFlight.get() > 0 ? System.currentTimeMillis() : lastActivityMs.get();
    }

    /** The Go twin of the Rust handle's {@code gated()}, minus the wake gate
     *  (there is no pause to wake from): stamp activity, mark in flight, run. */
    private <T> T gated(java.util.function.Supplier<T> nativeCall) {
        lastActivityMs.set(System.currentTimeMillis());
        inFlight.incrementAndGet();
        try {
            return nativeCall.get();
        } finally {
            inFlight.decrementAndGet();
        }
    }

    @Override
    public long uptimeSeconds() {
        return !started ? 0L : (System.nanoTime() - startedAtNs) / 1_000_000_000L;
    }

    private boolean rpcServing() {
        return rpcStarted && rpc.isServing();
    }

    /** Start the host's {@link LoopbackRpc} listener (Rust-twin parity: a bind
     *  failure is logged, the stack continues without JSON-RPC). */
    private void startRpc() {
        if (rpc == null) return;
        if (rpcPort <= 0) return;
        if (rpcStarted) return;
        try {
            rpc.start(rpcPort, verifiedReads, this, this);
            rpcStarted = true;
            log.info("[{}] JSON-RPC listening on http://127.0.0.1:{} (verified, strict, Go engine)",
                    networkName, rpcPort);
        } catch (java.io.IOException bindEx) {
            log.warn("[{}][rpc] port {} unavailable ({}); continuing without JSON-RPC",
                    networkName, rpcPort, bindEx.getMessage());
        } catch (Throwable t) {
            log.warn("[{}][rpc] failed to start JSON-RPC; continuing without it: {}",
                    networkName, t.toString());
        }
    }

    @Override public boolean isRunning() { return readStatus().running(); }

    // ---- status ----

    /** Parse the native status JSON; a null/empty payload → an unknown/dead handle. */
    private ParsedStatus readStatus() {
        String json = GoEngineNative.nativeStatusJson(handle);
        return ParsedStatus.parse(json);
    }

    /**
     * The parsed native status object. Same field set and same tolerant defaults
     * as the Rust twin's ParsedStatus (the Go status JSON is emitted from
     * {@code go/internal/capi}'s statusJSON struct, whose key set is pinned to
     * the Rust one by TestStatusCarriesTheRustKeySet; the Go-only keys
     * engine/myotisAbi/capabilities carry no snapshot field — the badge reads
     * them from the raw JSON's {@code engine} value). Keys whose machinery the Go
     * build lacks carry honest zeros THERE; the defaults here are the
     * never-seen-that-vintage backstop, not load-bearing.
     */
    private record ParsedStatus(
            boolean running,
            boolean paused,
            boolean elReaderAvailable,
            BeaconState beaconState,
            boolean bootstrapped,
            long finalizedSlot,
            long optimisticSlot,
            long currentPeriod,
            long targetPeriod,
            long peerCount,
            int servedPeersLastMinute,
            int discv5TableSize,
            long syncStartPeriod,
            int snapPeers,
            int snapServingPeers,
            int snap2ServingPeers,
            int discoveredPeers,
            int attemptedDials,
            int backedOffPeers,
            int blacklistedPeers,
            long optimisticBlockNumber,
            long finalizedBlockNumber,
            long peerHeaderRequests,
            long peerHeaderRequestsServed,
            long peerBodyRequests,
            long peerBodyRequestsServed,
            boolean lcHunting,
            boolean elHunting,
            long wsBoundPeriods,
            UpgradeAdvisory upgradeAdvisory,
            DataUsage dataUsage,
            NetworkMetering networkMetering) {

        /** Unrecognized beacon state → STARTING (fail closed), as the Rust twin. */
        private static BeaconState beaconStateOf(String name) {
            try {
                return BeaconState.valueOf(name);
            } catch (IllegalArgumentException e) {
                return BeaconState.STARTING;
            }
        }

        static ParsedStatus parse(String json) {
            if (json == null || json.isBlank()) return notRunning();
            try {
                JsonObject o = Json.parse(json).asObject();
                if (o.isEmpty()) return notRunning(); // "{}" == unknown handle
                return new ParsedStatus(
                        o.getBoolean("running", false),
                        o.getBoolean("paused", false),
                        o.getBoolean("elReaderAvailable", false),
                        beaconStateOf(o.getString("beaconState", "STARTING")),
                        o.getBoolean("bootstrapped", false),
                        o.getLong("finalizedSlot", 0L),
                        o.getLong("optimisticSlot", 0L),
                        o.getLong("currentPeriod", 0L),
                        o.getLong("targetPeriod", 0L),
                        o.getLong("peerCount", 0L),
                        o.getInt("servedPeersLastMinute", 0),
                        o.getInt("discv5TableSize", 0),
                        o.getLong("syncStartPeriod", -1L),
                        o.getInt("snapPeers", 0),
                        o.getInt("snapServingPeers", 0),
                        o.getInt("snap2ServingPeers", 0),
                        o.getInt("discoveredPeers", 0),
                        o.getInt("attemptedDials", 0),
                        o.getInt("backedOffPeers", 0),
                        o.getInt("blacklistedPeers", 0),
                        o.getLong("optimisticBlockNumber", 0L),
                        o.getLong("finalizedBlockNumber", 0L),
                        o.getLong("peerHeaderRequests", 0L),
                        o.getLong("peerHeaderRequestsServed", 0L),
                        o.getLong("peerBodyRequests", 0L),
                        o.getLong("peerBodyRequestsServed", 0L),
                        o.getBoolean("lcHunting", false),
                        o.getBoolean("elHunting", false),
                        o.getLong("wsBoundPeriods", 0L),
                        parseAdvisory(o.get("upgradeAdvisory")),
                        parseDataUsage(o.get("dataUsage")),
                        meteringOf(o.get("networkMetering")));
            } catch (RuntimeException e) {
                throw new EngineException(
                        "malformed status JSON from the Go engine: " + e.getMessage(), e);
            }
        }

        static ParsedStatus notRunning() {
            return new ParsedStatus(false, false, false, BeaconState.STARTING, false, 0L, 0L, 0L,
                    0L, 0L, 0, 0, -1L, 0, 0, 0, 0, 0, 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, false, false, 0L,
                    null, DataUsage.NONE, NetworkMetering.UNKNOWN);
        }

        static DataUsage parseDataUsage(JsonValue v) {
            if (v == null || !v.isObject()) return DataUsage.NONE;
            JsonObject u = v.asObject();
            try {
                return new DataUsage(
                        u.getLong("bytesIn", 0L), u.getLong("bytesOut", 0L),
                        u.getLong("elBytesIn", 0L), u.getLong("elBytesOut", 0L),
                        u.getLong("clBytesIn", 0L), u.getLong("clBytesOut", 0L),
                        u.getString("day", ""),
                        u.getLong("todayBytesIn", 0L), u.getLong("todayBytesOut", 0L),
                        u.getLong("todayMeteredBytesIn", 0L),
                        u.getLong("todayMeteredBytesOut", 0L));
            } catch (RuntimeException wrongType) {
                return DataUsage.NONE;
            }
        }

        static NetworkMetering meteringOf(JsonValue v) {
            if (v == null || !v.isString()) return NetworkMetering.UNKNOWN;
            try {
                return NetworkMetering.valueOf(v.asString());
            } catch (IllegalArgumentException e) {
                return NetworkMetering.UNKNOWN;
            }
        }

        static UpgradeAdvisory parseAdvisory(JsonValue v) {
            if (v == null || !v.isObject()) return null;
            JsonObject a = v.asObject();
            try {
                return new UpgradeAdvisory(UpgradePhase.valueOf(a.getString("phase", "")),
                        a.getLong("activationTime", 0L), a.getString("forkId", ""),
                        a.getInt("observedPeers", 0));
            } catch (RuntimeException unknownPhaseOrWrongType) {
                return null;
            }
        }
    }

    @Override
    public io.myotis.api.StatusSnapshot status() {
        return status(readStatus());
    }

    /** Package-private test seam: JSON→{@link io.myotis.api.StatusSnapshot} without JNA. */
    static io.myotis.api.StatusSnapshot statusFromJson(String network, String json) {
        return new GoChainHandle(0L, network, 1L, 0, null).status(ParsedStatus.parse(json));
    }

    /** Package-private test seam: JSON→{@link BeaconStatus} without JNA. */
    static BeaconStatus beaconStatusFromJson(String network, String json) {
        return new GoChainHandle(0L, network, 1L, 0, null).beaconStatus(ParsedStatus.parse(json));
    }

    private io.myotis.api.StatusSnapshot status(ParsedStatus s) {
        int peers = (int) Math.min(s.peerCount(), Integer.MAX_VALUE);
        long targetPeriod = Math.max(s.targetPeriod(), s.currentPeriod());
        // verifiedHeadAgeMs on this engine ages by FINALIZED-block advance — the
        // anchor every Go read actually runs at (class doc: honest amber on the
        // hosts' 45 s dot, not a constant green). The advance clock pins to "now"
        // while not serveable, so a serving stretch starts fresh instead of
        // leaking the outage gap in (Rust-twin rule).
        long fin = s.finalizedBlockNumber();
        long nowNanos = System.nanoTime();
        boolean serveable = serveable(s);
        long verifiedHeadAgeMs;
        synchronized (headAgeLock) {
            if (!serveable) {
                lastFinalizedBlock = fin;
                lastFinalizeAdvanceNanos = nowNanos;
                verifiedHeadAgeMs = Long.MAX_VALUE;
            } else {
                if (fin != lastFinalizedBlock) {
                    lastFinalizedBlock = fin;
                    lastFinalizeAdvanceNanos = nowNanos;
                }
                verifiedHeadAgeMs = Math.max(0L, (nowNanos - lastFinalizeAdvanceNanos) / 1_000_000L);
            }
        }
        return new io.myotis.api.StatusSnapshot(
                s.running(),
                s.running() ? LifecycleState.RUNNING
                        : s.paused() ? LifecycleState.PAUSED : LifecycleState.STOPPED,
                networkName,
                s.beaconState(),
                peers,                 // connectedPeers (CL libp2p peers, as the Rust twin)
                s.snapPeers(),         // readyPeers (EL pool holds only snap-ready)
                s.snapPeers(),         // snapPeers
                s.snapServingPeers(),  // snapServingPeers
                s.snap2ServingPeers(), // snap2ServingPeers
                s.discoveredPeers(),   // discoveredPeers (discv4)
                s.backedOffPeers(),    // backedOffPeers (Go: honest 0)
                s.blacklistedPeers(),  // blacklistedPeers (Go: honest 0)
                s.attemptedDials(),    // attemptedDials
                s.discv5TableSize(),
                s.finalizedBlockNumber(),   // executionBlockNumber (== finalized payload's block)
                s.optimisticBlockNumber(),  // optimisticBlockNumber (0 on the Go engine yet)
                s.finalizedSlot(),
                s.finalizedBlockNumber(),   // finalizedBlockNumber
                s.syncStartPeriod(),
                s.currentPeriod(),
                targetPeriod,
                s.finalizedSlot() / 8192L, // finalizedPeriod (SLOTS_PER_SYNC_COMMITTEE_PERIOD)
                targetPeriod,              // wallClockPeriod == the catch-up target
                verifiedHeadAgeMs,
                s.wsBoundPeriods(),
                List.<PeerInfo>of(),
                sleepMetrics.pauseCount(),
                sleepMetrics.totalPausedMs(),
                sleepMetrics.lastPauseEpochMs(),
                sleepMetrics.lastResumeEpochMs(),
                sleepMetrics.lastWakeReason(),
                s.peerHeaderRequests(),
                s.peerHeaderRequestsServed(),
                s.peerBodyRequests(),
                s.peerBodyRequestsServed(),
                s.lcHunting(),
                s.elHunting(),
                // Host-side listener truth, Rust-twin rule: the configured port
                // while the handle runs, 0 when stopped; serving = live listener.
                (s.running() || s.paused()) && rpc != null && rpcPort > 0 ? rpcPort : 0,
                rpcServing(),
                s.upgradeAdvisory(),
                s.dataUsage(),
                s.networkMetering());
    }

    /** A verified read can be served NOW on this engine: SYNCED, a finalized
     *  anchor, and a pooled snap peer that can answer AT THAT ROOT. The Go twin
     *  of the Rust predicate with the head replaced by the finalized block (the
     *  Go reader's only anchor). */
    private static boolean serveable(ParsedStatus s) {
        return s.beaconState() == BeaconState.SYNCED
                && s.finalizedBlockNumber() > 0 && s.snapServingPeers() > 0;
    }

    // ---- read surface ----

    /** Rust-twin contract: null before a successful start when a listener is
     *  attached (its bind may have failed), or before start with none. */
    @Override public VerifiedReads reads() {
        return (rpc == null ? started : rpcStarted) ? verifiedReads : null;
    }

    /** The Go build answers ENS with a named refusal, so the API exists but
     *  every method throws the capability error (NOT_AVAILABLE rule — a record's
     *  error field would misrepresent "we don't resolve names" as a verdict). */
    private static final EnsApi ENS_REFUSED = new EnsApi() {
        private EngineException refuse() {
            return new EngineException("ENS resolution is not implemented on the Go engine yet");
        }
        @Override public io.myotis.api.EnsResolutionResult resolveAddress(String name,
                io.myotis.api.EnsRoot root) { throw refuse(); }
        @Override public io.myotis.api.EnsResolutionResult reverseResolve(String hexAddress) {
            throw refuse(); }
        @Override public io.myotis.api.EnsTextResult resolveText(String name, String key) {
            throw refuse(); }
        @Override public io.myotis.api.EnsContenthashResult resolveContenthash(String name) {
            throw refuse(); }
        @Override public io.myotis.api.EnsMultiCoinResult resolveMultiCoinAddr(String name,
                long coinType) { throw refuse(); }
        @Override public io.myotis.api.EnsPubkeyResult resolvePubkey(String name) {
            throw refuse(); }
        @Override public io.myotis.api.EnsAbiResult resolveAbi(String name, long contentTypes) {
            throw refuse(); }
        @Override public io.myotis.api.EnsDnsRecordResult resolveDnsRecord(String name,
                String dnsName, int recordType) { throw refuse(); }
        @Override public io.myotis.api.EnsInterfaceResult resolveInterfaceImplementer(String name,
                byte[] interfaceId4) { throw refuse(); }
    };

    @Override public EnsApi ens() { return ENS_REFUSED; }

    @Override public List<io.myotis.api.DiscoveredPeer> discoveredPeers() { return List.of(); }

    @Override public List<ConnectedPeer> connectedPeers() { return List.of(); }

    @Override
    public void setTargetSnapPeers(int target) {
        // The Go dialer sizes its own pool (internal/transport) and exports no
        // target knob, as the Rust engine — a Settings value with nothing to reach.
        log.debug("[engines] setTargetSnapPeers({}) is a no-op on the Go engine", target);
    }

    @Override
    public void setServedBlockWindow(int blocks) {
        // The Go ABI records the value and clamps it ([1,4096]); the dial-only
        // engine serves no blocks, so no answer depends on it (capabilities say
        // so). False only for an unknown handle — log it, same rule as the twin.
        if (!GoEngineNative.nativeSetServedBlockWindow(handle, blocks)) {
            log.warn("[engines] setServedBlockWindow({}) dropped: unknown handle {}", blocks, handle);
        }
    }

    @Override
    public void setWsBoundPeriods(long periods) {
        // APPLIED live on the Go engine: the LC loop re-reads the bound at every
        // weak-subjectivity gate and a parked bootstrap restarts within a second.
        if (!GoEngineNative.nativeSetWsBoundPeriods(handle, periods)) {
            log.warn("[engines] setWsBoundPeriods({}) dropped: unknown handle {}", periods, handle);
        }
    }

    @Override
    public WebAccessPolicy setWebAccessPolicy(WebAccessPolicy policy) {
        // Listener-side, never crosses the FFI (both engines share this rule):
        // with a listener the gate applies it live; without one the contract's
        // answer is the same pure normalization so a host's dropped-entry
        // compare works either way (applied-or-refused, CLAUDE.md).
        if (rpc != null) return rpc.setWebAccessPolicy(policy);
        return new WebAccessPolicy(policy.mode(),
                io.myotis.jsonrpc.policy.WebOrigins.INSTANCE.normalizeEach(policy.origins()));
    }

    @Override
    public List<WebOrigin> recentWebOrigins() {
        return rpc == null ? List.of() : rpc.recentWebOrigins();
    }

    @Override
    public void acceptStaleAnchor() {
        // APPLIED live: releases a STALE_ANCHOR park and stays armed this run.
        if (!GoEngineNative.nativeAcceptStaleAnchor(handle)) {
            log.warn("[engines] acceptStaleAnchor dropped: unknown handle {}", handle);
        }
    }

    @Override
    public void clearPeerState() {
        // Same shape as the Rust engine: the Go engine's peer caches are files
        // under the data dir and there is no FFI clear; hosts delete the files
        // while the network is stopped.
        log.debug("[engines] clearPeerState is a no-op on the Go engine (the hosts delete its cache files)");
    }

    // ---- verified operator queries ----

    @Override
    public AccountProofResult requestAccount(String hexAddress) {
        // The Go reader anchors at finalized (class doc): the Rust twin passes ""
        // (its verified head); there is no head here to ask for.
        return accountVerified(hexAddress, READ_SELECTOR);
    }

    /** The account read at an explicit selector — {@link GoVerifiedReads} drives
     *  it with "finalized" (the only selector the Go build applies). */
    AccountProofResult accountVerified(String hexAddress, String block) {
        JsonObject o = parseResultOrThrow(
                gated(() -> GoEngineNative.nativeRequestAccountJson(handle, hexAddress, block)),
                "account");
        return accountFromJson(hexAddress, o);
    }

    @Override
    public StorageProofResult getStorageProof(String hexAddress, long slot, String holderHexOrNull) {
        // A holder is folded Go-side into the Solidity mapping key
        // keccak256(pad32(holder) ‖ pad32(slot)) — the same rule as the Rust
        // reader's storage_key (pinned there by reader.rs, here by
        // TestStorageRequestShapes) — and a malformed holder is refused by name,
        // never folded from wrong bytes.
        JsonObject o = parseResultOrThrow(
                gated(() -> GoEngineNative.nativeGetStorageProofJson(
                        handle, hexAddress, slot, holderHexOrNull)),
                "storage");
        return storageFromJson(hexAddress, slot, o);
    }

    // ---- operator queries the Go engine does not serve yet ----

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

    // ---- JSON → result records (Rust-twin shapes, pinned Go-side) ----

    /** Package-private test seam: JSON → {@link AccountProofResult} without JNA. */
    static AccountProofResult accountFromJson(String hexAddress, String json) {
        return accountFromJson(hexAddress, parseResultOrThrow(json, "account"));
    }

    private static AccountProofResult accountFromJson(String hexAddress, JsonObject o) {
        try {
            return new AccountProofResult(
                    o.getString("address", hexAddress),
                    o.getBoolean("exists", false),
                    o.getLong("nonce", -1L),
                    stringOrNull(o, "balanceWei"),
                    stringOrNull(o, "storageRootHex"),
                    stringOrNull(o, "codeHashHex"),
                    o.getLong("blockNumber", 0L),
                    stringOrNull(o, "peerStateRootHex"),
                    o.getBoolean("peerProofValid", false),
                    o.getBoolean("beaconChainVerified", false),
                    o.getBoolean("blsVerified", false),
                    o.getLong("matchedBeaconSlot", -1L),
                    stringOrNull(o, "verifyMethod"),
                    stringOrNull(o, "failReason"),
                    stringOrNull(o, "accountHashHex"),
                    stringList(o, "proofNodesHex"),
                    o.getBoolean("beaconSynced", false),
                    o.getLong("finalizedPeriod", 0L),
                    o.getLong("wallClockPeriod", 0L),
                    o.getLong("finalizedBlockNumber", 0L),
                    o.getLong("optimisticBlockNumber", 0L),
                    longOrMinusOne(o, "blockTimestamp"),
                    stringOrNull(o, "blockHash"));
            // The Go shape's one extra key ("anchor", always "finalized" here) is
            // diagnostics; the record has no field for it and none is needed —
            // the selector that produced the read is this handle's own constant.
        } catch (RuntimeException e) {
            throw new EngineException("malformed account JSON from the Go engine: "
                    + e.getMessage(), e);
        }
    }

    /** Package-private test seam: JSON → {@link StorageProofResult} without JNA. */
    static StorageProofResult storageFromJson(String hexAddress, long slot, String json) {
        return storageFromJson(hexAddress, slot, parseResultOrThrow(json, "storage"));
    }

    private static StorageProofResult storageFromJson(String hexAddress, long slot, JsonObject o) {
        try {
            return new StorageProofResult(
                    o.getString("addressHex", hexAddress),
                    o.getLong("slot", slot),
                    stringOrNull(o, "holderHex"),
                    stringOrNull(o, "storageKeyHex"),
                    stringOrNull(o, "storageKeyHashHex"),
                    o.getBoolean("exists", false),
                    stringOrNull(o, "valueHex"),
                    stringOrNull(o, "valueDecimal"),
                    o.getInt("slotsReturned", 0),
                    stringOrNull(o, "storageRootHex"),
                    stringList(o, "proofNodesHex"),
                    o.getBoolean("storageProofValid", false),
                    o.getBoolean("beaconSynced", false),
                    o.getBoolean("beaconChainVerified", false),
                    o.getBoolean("blsVerified", false),
                    o.getLong("matchedBeaconSlot", -1L),
                    stringOrNull(o, "verifyMethod"),
                    stringOrNull(o, "failReason"),
                    o.getLong("peerBlockNumber", 0L),
                    o.getLong("finalizedBlockNumber", 0L),
                    o.getLong("optimisticBlockNumber", 0L),
                    o.getLong("finalizedSlot", 0L),
                    o.getLong("optimisticSlot", 0L),
                    o.getInt("maxHeaderChainGap", 0));
        } catch (RuntimeException e) {
            throw new EngineException("malformed storage JSON from the Go engine: "
                    + e.getMessage(), e);
        }
    }

    /** Parse a native reply that must be a JSON object, mapping the error
     *  envelope (retryable {@code {"error"}} or permanent
     *  {@code {"error","code":-32602}}) to an {@link EngineException} that
     *  carries the engine's own reason — the Go build reports a pruned-root
     *  rotation, a stale-anchor park and a refused selector this way, exactly
     *  as the Rust build does, and a caller decides retry from the text. */
    private static JsonObject parseResultOrThrow(String json, String what) {
        if (json == null || json.isBlank()) {
            throw new EngineException("empty " + what + " JSON from the Go engine"
                    + " (unknown handle?)");
        }
        JsonObject o;
        try {
            o = Json.parse(json).asObject();
        } catch (RuntimeException e) {
            throw new EngineException("malformed " + what + " JSON from the Go engine: "
                    + e.getMessage(), e);
        }
        JsonValue err = o.get("error");
        if (err != null && !err.isNull()) {
            JsonValue code = o.get("code");
            String suffix = code != null && code.isNumber() && code.asInt() == -32602
                    ? " (permanent, do not retry)" : "";
            throw new EngineException(what + " read failed on the Go engine: "
                    + err.asString() + suffix);
        }
        return o;
    }

    private static String stringOrNull(JsonObject o, String key) {
        JsonValue v = o.get(key);
        return v == null || v.isNull() ? null : v.asString();
    }

    private static long longOrMinusOne(JsonObject o, String key) {
        JsonValue v = o.get(key);
        return v == null || v.isNull() ? -1L : v.asLong();
    }

    private static List<String> stringList(JsonObject o, String key) {
        JsonValue v = o.get(key);
        if (v == null || !v.isArray()) return List.of();
        return v.asArray().values().stream().map(JsonValue::asString).toList();
    }

    /** 0x-hex → bytes via the shared strict parser (minSdk-safe, same as the
     *  Rust engine's boundary; "0x"/null → empty). */
    static byte[] hexToBytes(String hexOrNull) {
        return Hex.parseHexPrefixed(hexOrNull);
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
                Math.max(s.targetPeriod(), s.currentPeriod()),
                s.discv5TableSize(),
                peers,                 // connectedPeers (CL libp2p peers)
                s.peerCount(),         // lightClientPeers
                s.servedPeersLastMinute(),
                s.finalizedSlot(),
                s.optimisticSlot(),
                s.finalizedSlot() / 8192L,  // period OF the finalized slot
                null,                  // executionStateRootHex (not in the status JSON)
                null,                  // executionBlockHashHex (not in the status JSON)
                s.finalizedBlockNumber(),  // executionBlockNumber (== finalized payload's block)
                0,                     // knownStateRoots
                0,                     // fillThreshold
                s.wsBoundPeriods(),
                List.<io.myotis.api.ClPeerInfo>of());
    }
}
