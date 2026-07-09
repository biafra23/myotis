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
import io.myotis.api.LifecycleState;
import io.myotis.api.NodeStatusReads;
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
 * <p>Mainnet-only. The beacon fields of the status snapshot are real (finalized
 * slot, sync period, peer count, beacon state); some EL-side status fields
 * (snap-peer counts, RPC head age) are still zero. The verified-read
 * {@link #requestAccount}/{@link #getStorageProof} queries ARE live — they cross
 * to the Rust {@code ElReader} (discovery + peer pool + the CL-fed execution
 * anchor) and return the same proof/verdict records as the Java engine. The
 * remaining EL queries ({@link #getHeaders}/{@link #getBlockVerified}/
 * {@link #dialPeer}) throw {@link EngineException} until those surfaces land.
 *
 * <p>{@link #reads()} now serves the verified JSON-RPC endpoint (EL-B): on
 * {@link #start()} this handle self-starts the shared {@code jsonrpc-server} on
 * {@code 127.0.0.1:rpcPort} backed by {@link RustVerifiedReads}, mirroring how the
 * Java engine self-starts it inside {@code ChainStack}.
 */
final class RustChainHandle implements ChainHandle, NodeStatusReads {

    private static final Logger log = LoggerFactory.getLogger(RustChainHandle.class);

    /** Message for the queries the CL-only R1 engine can't answer yet. */
    private static final String NOT_AVAILABLE = "not available on the R1 Rust engine (CL-only)";

    private final long handle;
    private final String networkName;
    private final long chainId;
    /** Loopback JSON-RPC port; {@code <= 0} disables the server (e.g. the JSON test seams). */
    private final int rpcPort;
    /** The verified read surface the JSON-RPC server serves; never null. */
    private final RustVerifiedReads verifiedReads = new RustVerifiedReads(this);
    /** The running JSON-RPC server, or null when disabled / not started. */
    private volatile io.myotis.jsonrpc.MyotisRpcServer rpcServer;

    /** Monotonic start time (ns) of the current run; drives {@link #uptimeSeconds()}. Paired
     *  with {@link #started} because nanoTime()'s origin is arbitrary (0 is a valid reading). */
    private volatile long startedAtNs;
    private volatile boolean started;

    /** Head-freshness tracking for verifiedHeadAgeMs: the last optimistic-head block
     *  number seen, and the monotonic time it was first seen. The reported age is the
     *  elapsed time since the head last ADVANCED — a real age (0 → ~12 s per block,
     *  growing if the head stalls), not a constant. Guarded by {@link #headAgeLock}
     *  so the paired check-and-update is atomic across concurrent status() callers
     *  (UI poll + health thread) — a torn read would yield a spurious huge age.
     *  A DEDICATED lock (not {@code this}) so it never contends with start()/stop(). */
    private final Object headAgeLock = new Object();
    private long lastHeadBlock = -1L;
    private long lastHeadAdvanceNanos;

    RustChainHandle(long handle, String networkName, long chainId, int rpcPort) {
        this.handle = handle;
        this.networkName = networkName;
        this.chainId = chainId;
        this.rpcPort = rpcPort;
    }

    @Override public String networkName() { return networkName; }

    @Override public long chainId() { return chainId; }

    @Override
    public synchronized boolean start() {
        boolean ok = RustEngineNative.nativeStart(handle);
        // Only expose the verified JSON-RPC endpoint once the native stack is up.
        if (ok) {
            // Anchor uptime to this successful start (cleared in stop() so a restart re-anchors).
            if (!started) { startedAtNs = System.nanoTime(); started = true; }
            startRpc();
        }
        return ok;
    }

    @Override
    public synchronized void stop() {
        // Stop serving before tearing down the native stack the reads depend on.
        io.myotis.jsonrpc.MyotisRpcServer server = this.rpcServer;
        if (server != null) {
            try { server.stop(); } catch (Throwable ignored) {}
            this.rpcServer = null;
        }
        started = false;   // a fresh start() after stop re-anchors uptime to that run
        RustEngineNative.nativeStop(handle);
    }

    // ---- idle-sleep lifecycle: NO-OP on the Rust engine (see class javadoc) ----
    //
    // The Java engine idle-pauses by tearing down + rebuilding its networking
    // (ChainStack.pause/resume via WakeGate). The Rust engine owns a tokio/libp2p
    // stack it can't cheaply suspend yet, so it implements the contract as a no-op:
    // it simply never idle-sleeps. pause() reports it did NOT pause (stays RUNNING);
    // resume() is a no-op success; lifecycle() is RUNNING/STOPPED (never PAUSED); and
    // lastActivityEpochMillis() reports "now" so a host idle controller sees constant
    // activity and never attempts a pause. Real Rust pause/resume is a later follow-up.

    @Override
    public boolean pause() {
        // Did not enter PAUSED — the Rust engine keeps RUNNING.
        return false;
    }

    @Override
    public boolean resume() {
        // Always RUNNING → resume is a no-op success (mirrors the "already RUNNING" case).
        return isRunning();
    }

    @Override
    public boolean resume(String reason) {
        return resume();
    }

    @Override
    public LifecycleState lifecycle() {
        return isRunning() ? LifecycleState.RUNNING : LifecycleState.STOPPED;
    }

    @Override
    public long lastActivityEpochMillis() {
        // No activity tracking; report "now" so a host idle timer never elapses and
        // never tries to pause (which would be a no-op returning false anyway).
        return System.currentTimeMillis();
    }

    /** {@link NodeStatusReads}: node uptime for the JSON-RPC myotis_status result. Monotonic
     *  (nanoTime), so it's immune to wall-clock/NTP adjustments; 0 before the first start. */
    @Override
    public long uptimeSeconds() {
        return !started ? 0L : (System.nanoTime() - startedAtNs) / 1_000_000_000L;
    }

    /**
     * Start the shared {@code jsonrpc-server} on {@code 127.0.0.1:rpcPort}, backed by
     * {@link RustVerifiedReads} — the Rust-engine counterpart to
     * {@code ChainStack.startRpc()}. Loopback only, strict (no upstream proxy). A
     * bind failure is logged and the stack continues without JSON-RPC (mirrors the
     * Java engine): the IPC socket still serves the same verified primitives.
     */
    private void startRpc() {
        if (rpcPort <= 0) return;        // RPC disabled (test seam / explicit opt-out)
        if (rpcServer != null) return;   // already started — avoid a re-bind / server leak
        try {
            // Deterministic up-front bind probe: Ktor's CIO engine surfaces bind
            // failures asynchronously, which a try/catch around start() can miss.
            try (java.net.ServerSocket probe = new java.net.ServerSocket()) {
                probe.setReuseAddress(true);
                probe.bind(new java.net.InetSocketAddress("127.0.0.1", rpcPort));
            }
            io.myotis.jsonrpc.MyotisRpcServer server =
                    new io.myotis.jsonrpc.MyotisRpcServer(rpcPort, null, "127.0.0.1", verifiedReads, this);
            server.start();
            this.rpcServer = server;
            log.info("[{}] JSON-RPC listening on http://127.0.0.1:{} (verified, strict)",
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
        String json = RustEngineNative.nativeStatusJson(handle);
        return ParsedStatus.parse(json);
    }

    /** The parsed native status object — CL fields plus the EL pool/discovery
     *  counts. Older natives omit the EL keys → they default to 0. */
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
            int discv5TableSize,
            long syncStartPeriod,
            int snapPeers,
            int discoveredPeers,
            int attemptedDials,
            int backedOffPeers,
            int blacklistedPeers,
            long optimisticBlockNumber,
            long finalizedBlockNumber) {

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
                        o.getInt("discv5TableSize", 0),
                        o.getLong("syncStartPeriod", -1L),
                        o.getInt("snapPeers", 0),
                        o.getInt("discoveredPeers", 0),
                        o.getInt("attemptedDials", 0),
                        o.getInt("backedOffPeers", 0),
                        o.getInt("blacklistedPeers", 0),
                        o.getLong("optimisticBlockNumber", 0L),
                        o.getLong("finalizedBlockNumber", 0L));
            } catch (RuntimeException e) {
                throw new EngineException(
                        "malformed status JSON from the Rust engine: " + e.getMessage(), e);
            }
        }

        static ParsedStatus notRunning() {
            return new ParsedStatus(false, BeaconState.STARTING, false, 0L, 0L, 0L, 0L, 0L, 0, 0, -1L,
                    0, 0, 0, 0, 0, 0L, 0L);
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
        return new RustChainHandle(0L, network, 1L, 0).status(ParsedStatus.parse(json));
    }

    /** Package-private test seam: JSON→{@link BeaconStatus} without JNI. */
    static BeaconStatus beaconStatusFromJson(String network, String json) {
        return new RustChainHandle(0L, network, 1L, 0).beaconStatus(ParsedStatus.parse(json));
    }

    /** Package-private test seam: map a status JSON on THIS handle (so head-age
     *  tracking persists across calls). Lets a test observe verifiedHeadAgeMs grow. */
    StatusSnapshot statusFromJsonOnThisHandle(String json) {
        return status(ParsedStatus.parse(json));
    }

    private StatusSnapshot status(ParsedStatus s) {
        int peers = (int) Math.min(s.peerCount(), Integer.MAX_VALUE);
        // Older natives don't emit "targetPeriod" (parsed as 0): fall back to
        // currentPeriod — the pre-targetPeriod mirror — so the target >= current
        // invariant holds against any .so vintage.
        long targetPeriod = Math.max(s.targetPeriod(), s.currentPeriod());
        // EL pool/discovery counts now come from the Rust status JSON. The pool
        // keeps only snap-capable READY peers, so readyPeers == snapPeers (and
        // snapServingPeers is approximated by the same). Execution block numbers
        // (optimistic head + finalized) come from the beacon anchor via the status.
        //
        // verifiedHeadAgeMs drives the host's readiness dot (< 45 s = ready/green).
        // The Rust reader anchors every query to the peer's fresh head; there's no
        // separate head context to age, so age it by how long since the optimistic
        // head last ADVANCED (a new block ~every 12 s resets it) — a REAL, changing
        // age, not a constant. Reported only when a verified read CAN be served
        // (SYNCED, an anchored head, snap peers); else the Long.MAX_VALUE "no
        // verified head yet" sentinel — and while NOT serveable we hold the advance
        // clock at "now" so the age starts fresh the instant we become serveable
        // (a not-serving stretch must not leak in as a stale age → amber flicker).
        // Monotonic nanoTime — a wall-clock/NTP jump must not distort the age.
        long optHead = s.optimisticBlockNumber();
        long nowNanos = System.nanoTime();
        boolean serveable = s.beaconState() == BeaconState.SYNCED
                && optHead > 0 && s.snapPeers() > 0;
        long verifiedHeadAgeMs;
        synchronized (headAgeLock) {
            if (!serveable) {
                // No verified head to age; keep the clock pinned to now so the first
                // serveable poll starts near 0 rather than carrying the outage gap.
                lastHeadBlock = optHead;
                lastHeadAdvanceNanos = nowNanos;
                verifiedHeadAgeMs = Long.MAX_VALUE;
            } else {
                if (optHead != lastHeadBlock) {
                    lastHeadBlock = optHead;
                    lastHeadAdvanceNanos = nowNanos;
                }
                verifiedHeadAgeMs = Math.max(0L, (nowNanos - lastHeadAdvanceNanos) / 1_000_000L);
            }
        }
        return new StatusSnapshot(
                s.running(),
                s.running() ? LifecycleState.RUNNING : LifecycleState.STOPPED,
                networkName,
                s.beaconState(),
                peers,                 // connectedPeers (CL libp2p peers)
                s.snapPeers(),         // readyPeers (EL — pool holds only snap-ready)
                s.snapPeers(),         // snapPeers
                s.snapPeers(),         // snapServingPeers (approx)
                s.discoveredPeers(),   // discoveredPeers (discv4)
                s.backedOffPeers(),    // backedOffPeers
                s.blacklistedPeers(),  // blacklistedPeers
                s.attemptedDials(),    // attemptedDials
                s.discv5TableSize(),
                s.finalizedBlockNumber(),   // executionBlockNumber (== finalized payload's block)
                s.optimisticBlockNumber(),  // optimisticBlockNumber (the eth_blockNumber head)
                s.finalizedSlot(),
                s.finalizedBlockNumber(),   // finalizedBlockNumber
                s.syncStartPeriod(),
                s.currentPeriod(),
                targetPeriod,
                s.finalizedSlot() / 8192L, // finalizedPeriod (SLOTS_PER_SYNC_COMMITTEE_PERIOD)
                targetPeriod,   // wallClockPeriod == the catch-up target
                verifiedHeadAgeMs,
                List.<PeerInfo>of(),
                // Idle-sleep metrics: the Rust engine does not idle-pause yet (pause()
                // is a no-op — see below), so it never accrues pause stats.
                0,      // pauseCount
                0L,     // totalPausedMs
                0L,     // lastPauseEpochMs
                0L,     // lastResumeEpochMs
                null);  // lastWakeReason
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

    // ---- verified-read surface (EL-B) ----
    //
    // reads() returns the RustVerifiedReads adapter — the JSON-RPC read surface the
    // shared jsonrpc-server serves on 127.0.0.1:rpcPort (started in startRpc()). It
    // answers the beacon-anchored reads a wallet needs to build a plain-ETH send
    // (chainId/getBalance/getTransactionCount/syncState) from the same proof-verified
    // account query as requestAccount below; the rest of VerifiedReads returns null
    // ("can't answer verified") until later EL-B / EL-C slices land.
    //
    // Per the ChainHandle contract, reads() is null "while the RPC backend isn't
    // started (e.g. the RPC port was unavailable at start())". The adapter is itself
    // transport-independent (it queries the native directly), but reads() gates on
    // rpcServer so it means the same thing on both engines: the Java engine's
    // rpcBackend is null until startRpc() succeeds, and hosts null-check reads()
    // to decide whether verified RPC is available. So: null before start(), when
    // rpcPort<=0, or on a bind failure; non-null once serving.
    //
    // ens() still returns null (no ENS registry served yet) — that IS the ChainHandle
    // contract ("or null when this network has no ENS registry"), and callers
    // null-check it. The EL QUERY methods further down (getHeaders/getBlockVerified/
    // dialPeer) still throw EngineException: the contract reserves exceptions for
    // malformed input / not running, and an unimplemented EL surface is a capability
    // error (no verification to report a failReason for) — a failReason record would
    // misrepresent "we can't" as "we tried and failed".

    @Override public VerifiedReads reads() { return rpcServer != null ? verifiedReads : null; }

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
        JsonObject o = parseResultOrThrow(
                RustEngineNative.nativeRequestAccountJson(handle, hexAddress), "account");
        return accountFromJson(hexAddress, o);
    }

    /** Package-private test seam: JSON → {@link AccountProofResult} without JNI. */
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
                o.getLong("optimisticBlockNumber", 0L));
        } catch (RuntimeException e) {
            // A type-mismatched field (Rust-side shape drift) surfaces as an
            // EngineException, never a raw UnsupportedOperationException.
            throw new EngineException("malformed account JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    @Override
    public StorageProofResult getStorageProof(String hexAddress, long slot, String holderHexOrNull) {
        JsonObject o = parseResultOrThrow(
                RustEngineNative.nativeGetStorageProofJson(handle, hexAddress, slot, holderHexOrNull),
                "storage");
        return storageFromJson(hexAddress, slot, o);
    }

    /** Package-private test seam: JSON → {@link StorageProofResult} without JNI. */
    static StorageProofResult storageFromJson(String hexAddress, long slot, String json) {
        return storageFromJson(hexAddress, slot, parseResultOrThrow(json, "storage"));
    }

    // ---- VerifiedReads helpers (used by RustVerifiedReads; not ChainHandle API) ----

    /**
     * Verified contract bytecode for {@code hexAddress} (eth_getCode), or null when
     * the query produced no verdict (can't answer verified). A verified EOA /
     * empty-code account yields an empty array. Throws {@link EngineException} on a
     * transport / not-running failure (the adapter maps that to null).
     */
    byte[] codeVerified(String hexAddress) {
        return codeFromJson(RustEngineNative.nativeGetCodeJson(handle, hexAddress));
    }

    /** Package-private test seam: code JSON → verified bytecode (or null) without JNI. */
    static byte[] codeFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "code");
        try {
            if (stringOrNull(o, "verifyMethod") == null) return null; // unverified → can't answer
            return hexToBytes(stringOrNull(o, "codeHex")); // 0x / empty → empty bytecode
        } catch (RuntimeException e) {
            throw new EngineException("malformed code JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * One verified {@code eth_call}: run it and return the result bytes, or null.
     * {@code from} is empty for an anonymous sender; {@code valueDecimal} is wei as
     * a decimal string. Throws {@link EngineException} on a transport / not-running
     * failure (the adapter maps that to null).
     */
    byte[] ethCallVerified(
            String fromHex, String toHex, String dataHex, String valueDecimal, String block) {
        return callResultFromJson(
                RustEngineNative.nativeEthCallJson(handle, fromHex, toHex, dataHex, valueDecimal, block));
    }

    /** Package-private test seam: call JSON → result bytes (or null) without JNI. */
    static byte[] callResultFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "call");
        try {
            // Only "ok" carries a result. A revert or an unavailable/unverifiable
            // outcome is "no answer" → null, mirroring the reference engine (a
            // reverting or unverifiable eth_call returns a JSON-RPC null, not -32000).
            if ("ok".equals(stringOrNull(o, "status"))) {
                return hexToBytes(stringOrNull(o, "resultHex")); // 0x / empty → empty bytes
            }
            return null;
        } catch (RuntimeException e) {
            throw new EngineException("malformed call JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * One verified 32-byte storage word at a RAW position (eth_getStorageAt), or
     * null when unverified. The value is left-padded to a full 32-byte word (a
     * zero/unset slot → 32 zero bytes). {@code position32Hex} is the 0x-hex 32-byte
     * position. Throws {@link EngineException} on a transport / not-running failure.
     */
    byte[] storageAtVerified(String hexAddress, String position32Hex) {
        return storageValueFromJson(
                RustEngineNative.nativeGetStorageAtJson(handle, hexAddress, position32Hex));
    }

    /**
     * Verified eth_getBlockByNumber (transactions as hashes): the block JSON object,
     * the literal {@code "null"} (a verified future/unknown block → eth null), or
     * throws {@link EngineException} when it can't verify (transport / not-running).
     * {@code blockTag} is an eth block selector ({@code "latest"} / 0x-hex number).
     */
    String blockByNumberJson(String blockTag) {
        return blockJsonOrThrow(RustEngineNative.nativeGetBlockByNumberJson(handle, blockTag));
    }

    /** Package-private test seam: native block payload → block JSON | "null" | throw. */
    static String blockJsonOrThrow(String json) {
        if (json == null || json.isBlank()) {
            throw new EngineException("blank block JSON from the Rust engine (native failure?)");
        }
        // The eth-null literal (verified future/unknown block) is not a JSON object;
        // return it before parsing so the router can emit a JSON null result.
        if (json.equals("null")) return "null";
        JsonObject o;
        try {
            o = Json.parse(json).asObject();
        } catch (RuntimeException e) {
            throw new EngineException("malformed block JSON from the Rust engine: " + e.getMessage(), e);
        }
        var error = o.get("error");
        if (error != null && !error.isNull()) {
            throw new EngineException(error.isString() ? error.asString() : error.toString());
        }
        return json; // the verified block object
    }

    /** A verified fee suggestion — both values decimal-wei strings. */
    record FeeEstimate(String gasPriceWei, String maxPriorityFeePerGasWei) {}

    /** How long a fee estimate is reused so a paired gasPrice+maxPriorityFee poll
     *  shares one native compute (each is a 3-block verified fetch). */
    private static final long FEE_CACHE_TTL_NANOS = 3_000_000_000L; // 3s
    /** Value+timestamp in one volatile so a reader can't pair a fresh estimate with
     *  a stale stamp (or vice versa). Monotonic nanoTime — immune to wall-clock/NTP
     *  jumps that could otherwise expire the cache early or serve it too long. */
    private record CachedFee(FeeEstimate est, long atNanos) {}
    private volatile CachedFee cachedFee;

    /**
     * Verified fee suggestion, cached for {@link #FEE_CACHE_TTL_NANOS}. Throws
     * {@link EngineException} when it can't verify (transport / not-running) — the
     * error is never cached, so the next call retries.
     */
    FeeEstimate feeEstimate() {
        CachedFee c = cachedFee;
        if (c != null && System.nanoTime() - c.atNanos() < FEE_CACHE_TTL_NANOS) {
            return c.est();
        }
        FeeEstimate est = feeFromJson(RustEngineNative.nativeFeeEstimateJson(handle));
        cachedFee = new CachedFee(est, System.nanoTime());
        return est;
    }

    /** Package-private test seam: fee JSON → {@link FeeEstimate} without JNI. */
    static FeeEstimate feeFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "fee");
        String gas;
        String tip;
        try {
            // Field extraction only — a type-mismatched value (asString on a non-
            // string) is Rust-side shape drift → "malformed".
            gas = stringOrNull(o, "gasPriceWei");
            tip = stringOrNull(o, "maxPriorityFeePerGasWei");
        } catch (RuntimeException e) {
            throw new EngineException("malformed fee JSON from the Rust engine: " + e.getMessage(), e);
        }
        // Missing-field check OUTSIDE the try so its message isn't re-wrapped as
        // "malformed" by the catch (EngineException is a RuntimeException).
        if (gas == null || tip == null) {
            throw new EngineException("fee JSON missing gasPriceWei/maxPriorityFeePerGasWei");
        }
        return new FeeEstimate(gas, tip);
    }

    /**
     * Gossip a signed raw transaction and return its 32-byte hash. Throws
     * {@link EngineException} when no peer could be reached / the input isn't a
     * plausible tx. {@code rawTxHex} is the 0x-hex raw transaction.
     */
    byte[] sendRawTransactionVerified(String rawTxHex) {
        return txHashFromJson(RustEngineNative.nativeSendRawTransactionJson(handle, rawTxHex));
    }

    /** Package-private test seam: send-tx JSON → the 32-byte tx hash (throws on error). */
    static byte[] txHashFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "sendRawTransaction");
        String hex;
        try {
            hex = stringOrNull(o, "txHash");
        } catch (RuntimeException e) {
            throw new EngineException("malformed send-tx JSON from the Rust engine: " + e.getMessage(), e);
        }
        // Missing-field check OUTSIDE the try so its message isn't re-wrapped.
        if (hex == null) {
            throw new EngineException("send-tx JSON missing txHash");
        }
        byte[] hash;
        try {
            hash = hexToBytes(hex);
        } catch (RuntimeException e) {
            throw new EngineException("malformed send-tx txHash hex: " + e.getMessage(), e);
        }
        // A tx hash is exactly 32 bytes — fail closed rather than return a short/long
        // array the caller (router → hexData) would silently mis-encode.
        if (hash.length != 32) {
            throw new EngineException("send-tx txHash is not 32 bytes: " + hash.length);
        }
        return hash;
    }

    /** Package-private test seam: storage-at JSON → verified 32-byte word (or null). */
    static byte[] storageValueFromJson(String json) {
        JsonObject o = parseResultOrThrow(json, "storage");
        try {
            if (stringOrNull(o, "verifyMethod") == null) return null; // unverified → can't answer
            // valueHex is the big-endian value (leading zeros stripped) or null when the
            // slot is zero/unset; eth_getStorageAt returns a full 32-byte word.
            return leftPad32(hexToBytes(stringOrNull(o, "valueHex")));
        } catch (RuntimeException e) {
            throw new EngineException("malformed storage JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /** 0x-hex (or null/"0x"/empty) → bytes; null/empty → an empty array. */
    private static byte[] hexToBytes(String hexOrNull) {
        if (hexOrNull == null) return new byte[0];
        String h = (hexOrNull.startsWith("0x") || hexOrNull.startsWith("0X"))
                ? hexOrNull.substring(2) : hexOrNull;
        if (h.isEmpty()) return new byte[0];
        return java.util.HexFormat.of().parseHex(h);
    }

    /** Left-pad a big-endian value to a 32-byte word (a storage value is ≤ 32 bytes). */
    private static byte[] leftPad32(byte[] v) {
        if (v.length == 32) return v;
        if (v.length > 32) {
            throw new EngineException("storage value exceeds 32 bytes: " + v.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(v, 0, out, 32 - v.length, v.length);
        return out;
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
            throw new EngineException("malformed storage JSON from the Rust engine: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a native verified-read payload. A {@code {"error": "..."}} object (a
     * transport / not-running / bad-input failure) becomes an {@link EngineException};
     * a null/blank/malformed payload likewise. A verification FAILURE is NOT an error —
     * it is a full result whose {@code failReason} is set, and is returned normally.
     */
    private static JsonObject parseResultOrThrow(String json, String what) {
        if (json == null || json.isBlank()) {
            throw new EngineException((json == null ? "null" : "blank") + " " + what
                    + " JSON from the Rust engine (native failure?)");
        }
        JsonObject o;
        try {
            o = Json.parse(json).asObject();
        } catch (RuntimeException e) {
            throw new EngineException(
                    "malformed " + what + " JSON from the Rust engine: " + e.getMessage(), e);
        }
        var error = o.get("error");
        if (error != null && !error.isNull()) {
            // The Rust side always emits a string error, but tolerate a
            // structured value rather than throwing a raw library exception.
            throw new EngineException(error.isString() ? error.asString() : error.toString());
        }
        return o;
    }

    /** A JSON string field, or null when absent/JSON-null. */
    private static String stringOrNull(JsonObject o, String key) {
        var v = o.get(key);
        return (v == null || v.isNull()) ? null : v.asString();
    }

    /**
     * A JSON string-array field as an unmodifiable List. An ABSENT field yields
     * an empty list (forward-compat with an older native that omits it), but a
     * PRESENT field that isn't a string array throws (via {@code asArray()} /
     * {@code asString()}) — caught by the field-mapping try/catch as an
     * {@link EngineException}, failing closed on Rust-side shape drift.
     */
    private static List<String> stringList(JsonObject o, String key) {
        var v = o.get(key);
        if (v == null || v.isNull()) return List.of();
        List<String> out = new java.util.ArrayList<>();
        v.asArray().forEach(e -> out.add(e.asString()));
        // Unmodifiable: these lists live inside immutable result records.
        return java.util.Collections.unmodifiableList(out);
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
