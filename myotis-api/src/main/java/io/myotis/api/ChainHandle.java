package io.myotis.api;

/**
 * One hosted network's engine surface: lifecycle, live status, verified reads,
 * ENS, and the verified operator queries the desktop IPC / UIs are built on.
 *
 * <p>All methods are blocking — call from a worker thread. The long-running
 * verification queries are internally timeout-bounded (noted per method) and
 * return result records whose {@code failReason}/{@code error} fields describe
 * verification failures; they throw {@link EngineException} only for
 * programmer/state errors (bad address, network not running).
 */
public interface ChainHandle {

    /** Canonical network name this handle serves. */
    String networkName();

    /** The network's EVM chain id. */
    long chainId();

    /**
     * Build and start the stack. Blocking (DNS discovery + component startup,
     * typically a few seconds). Fault-isolated: on any failure the stack's
     * resources are closed and {@code false} is returned — never an exception,
     * and never an effect on sibling networks.
     */
    boolean start();

    /** Tear the stack down (reverse component order). Idempotent. */
    void stop();

    boolean isRunning();

    /**
     * Suspend all networking (zero sockets, zero periodic timers) while keeping
     * the stack instance and its warm verified state — beacon light-client
     * store, sync state, peer knowledge — in memory. The JSON-RPC server keeps
     * listening; a verified read arriving while paused triggers {@link #resume()}
     * and is held until the node can answer (bounded, ~90 s). Blocking (a few
     * seconds). Idempotent; a no-op unless {@code RUNNING}.
     *
     * @return {@code true} when the stack is {@code PAUSED} on return
     */
    boolean pause();

    /**
     * Rebuild networking after {@link #pause()}. Blocking (seconds; skips the
     * cold DNS walk). Fault-isolated like {@link #start()}: on failure returns
     * {@code false} and the stack stays {@code PAUSED} (retryable). A no-op
     * returning {@code true} when already {@code RUNNING}.
     */
    boolean resume();

    /**
     * As {@link #resume()}, but records {@code reason} (a {@link WakeReason} tag) as
     * the wake cause for the status screens' "last wake" line. {@link WakeReason#FOREGROUND}
     * is treated as an observation and does not overwrite the recorded last-wake reason.
     */
    boolean resume(String reason);

    /** Coarse lifecycle state; {@link #isRunning()} == {@code lifecycle() == RUNNING}. */
    LifecycleState lifecycle();

    /**
     * Epoch millis of the last host-relevant activity: any gated verified read
     * (JSON-RPC / ENS) or verified operator query. {@code 0} if none since
     * start. Hosts poll this for their idle-sleep timer — deliberately a getter
     * rather than a callback so the engine surface stays FFI-portable.
     */
    long lastActivityEpochMillis();

    /** Live-update the snap-peer maintainer target (no restart). */
    void setTargetSnapPeers(int target);

    /**
     * Live-update the eth/69 served-block window (no restart): how many recent block
     * headers this node retains and advertises as servable to peers via the EIP-7642
     * Status range / BlockRangeUpdate. Clamped by the engine at both ends
     * (currently [1, 4096]: 0 would disable serving; an unbounded window is an
     * archive-node promise a light client cannot keep).
     * Engines without an EL treat this as a no-op.
     */
    void setServedBlockWindow(int blocks);

    /**
     * Clear the live dial bookkeeping — backoff entries and this session's
     * blacklist — so discovery re-dials from a fresh slate. On-disk peer-cache
     * FILES are host-owned; deleting those is the host's job.
     */
    void clearPeerState();

    /**
     * One coherent status snapshot including per-peer rows. Cheap to build;
     * suitable for polling at 1–2 s.
     */
    StatusSnapshot status();

    /** EL discovery's routing-table entries (operator diagnostics). Cheap. */
    java.util.List<DiscoveredPeer> discoveredPeers();

    /** All EL peers with an open RLPx session, including those still handshaking. Cheap. */
    java.util.List<ConnectedPeer> connectedPeers();

    /** Deep beacon/CL status including per-peer detail. Cheap. */
    BeaconStatus beaconStatus();

    /**
     * The verified eth_* read surface, or {@code null} while the RPC backend
     * isn't started (e.g. the RPC port was unavailable at {@link #start()}).
     */
    VerifiedReads reads();

    /**
     * The ENS resolution surface, or {@code null} when this network has no ENS
     * registry (see {@link NetworkInfo#hasEns()}).
     */
    EnsApi ens();

    // ---- verified operator queries ----

    /**
     * Fetch {@code hexAddress}'s account from a snap peer and run the full
     * verification ladder (proof-against-peer-root → beacon stateRootMatch →
     * BLS-attested headerChain). Blocking, bounded at ~90 s worst case.
     *
     * @throws EngineException on a malformed address or when not running
     */
    AccountProofResult requestAccount(String hexAddress);

    /**
     * Fetch and verify one storage slot of {@code hexAddress}. When
     * {@code holderHexOrNull} is set, the queried key is the Solidity mapping
     * slot {@code keccak256(holder ‖ slot)} (ERC-20 balance lookups). Blocking,
     * bounded at ~90 s worst case.
     *
     * @throws EngineException on malformed input or when not running
     */
    StorageProofResult getStorageProof(String hexAddress, long slot, String holderHexOrNull);

    /**
     * Fetch {@code count} consecutive block headers starting at
     * {@code startBlock} from a peer. Headers are integrity-checked (each hash
     * is recomputed); chain-of-custody verification against the beacon anchor is
     * the caller's concern ({@link #getBlockVerified} does it for one block).
     * Blocking, bounded at ~30 s.
     */
    HeadersResult getHeaders(long startBlock, int count);

    /**
     * Fetch one block (header + body summary) and verify it against the beacon
     * chain (stateRootMatch, else a parent-hash header-chain walk from the
     * beacon-attested block hash, ≤ 8192 blocks). Blocking, bounded at ~90 s.
     */
    BlockResult getBlockVerified(long blockNumber);

    /**
     * Dial one specific EL peer by endpoint + secp256k1 public key (operator
     * debugging). Returns immediately after the connect is initiated.
     *
     * @throws EngineException on a malformed pubkey or when not running
     */
    DialResult dialPeer(String host, int port, String pubkeyHex);
}
