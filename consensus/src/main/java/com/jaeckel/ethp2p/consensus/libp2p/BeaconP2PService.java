package com.jaeckel.ethp2p.consensus.libp2p;

import com.jaeckel.ethp2p.consensus.types.MetadataMessage;
import com.jaeckel.ethp2p.consensus.types.StatusMessage;
import io.libp2p.core.Host;
import io.libp2p.core.P2PChannel;
import io.libp2p.core.PeerId;
import io.libp2p.core.StreamPromise;
import io.libp2p.core.crypto.KeyType;
import io.libp2p.core.dsl.HostBuilder;
import io.libp2p.core.multiformats.Multiaddr;
import io.libp2p.core.multistream.ProtocolBinding;
import io.libp2p.core.multistream.ProtocolDescriptor;
import io.libp2p.core.mux.StreamMuxerProtocol;
import io.libp2p.protocol.Identify;
import io.libp2p.protocol.IdentifyController;
import io.libp2p.security.noise.NoiseXXSecureChannel;
import io.libp2p.transport.tcp.TcpTransport;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Supplier;

/**
 * Manages libp2p connections to Consensus Layer peers and executes req/resp
 * light client protocols defined in the Ethereum 2 specification.
 *
 * <p>Each protocol is registered with the libp2p host at startup. Per-request
 * state (request bytes, response future) is passed through a concurrent queue
 * that the binding dequeues from when {@code initChannel} is called.
 */
public class BeaconP2PService implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(BeaconP2PService.class);

    static final String STATUS =
            "/eth2/beacon_chain/req/status/2/ssz_snappy";
    static final String STATUS_V1 =
            "/eth2/beacon_chain/req/status/1/ssz_snappy";
    static final String BOOTSTRAP =
            "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy";
    static final String UPDATES =
            "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy";
    static final String FINALITY =
            "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy";
    static final String OPTIMISTIC =
            "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy";
    static final String BLOCKS_BY_RANGE =
            "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";
    static final String PING =
            "/eth2/beacon_chain/req/ping/1/ssz_snappy";
    static final String METADATA =
            "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
    static final String GOODBYE =
            "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";

    /**
     * Handler contract for peer-initiated streams.
     * <p>Given the decoded SSZ request body (empty byte[] for no-payload
     * protocols like metadata / finality_update) and the remote peer's
     * libp2p peer id, returns the SSZ body to send back as a successful
     * response (result=0). Returning {@code null} signals {@code
     * ResourceUnavailable} (result=3). Throwing {@code
     * IllegalArgumentException} signals {@code InvalidRequest} (result=1);
     * anything else signals {@code ServerError} (result=2).
     */
    @FunctionalInterface
    public interface ReqRespHandler {
        byte[] handle(byte[] requestSsz, String peerId) throws Exception;
    }

    private volatile Host host;
    private Identify identifyBinding;

    /** One binding per protocol, registered once at startup. */
    private final Map<String, QueuedReqRespBinding> bindings = new ConcurrentHashMap<>();

    /** Cached Identify protocol lists per peer ID (populated lazily). */
    private final Map<String, List<String>> peerProtocols = new ConcurrentHashMap<>();

    /** Cached agent version (client ID) per peer ID. */
    private final Map<String, String> peerAgentVersions = new ConcurrentHashMap<>();

    /**
     * Supplies the local {@link StatusMessage} used when a peer opens {@code /status}
     * on us (responder role). May be {@code null} if the caller did not provide one —
     * in that case we fall back to the previous behavior of rejecting inbound
     * status streams, which typically causes the peer to drop the connection.
     */
    private final Supplier<StatusMessage> localStatusSupplier;

    /** Connection-open timestamps (millis) keyed by peer id, for liveness diagnostics. */
    private final Map<String, Long> connectionOpenMillis = new ConcurrentHashMap<>();

    /**
     * Relay cache: the most recent successful response we observed for a
     * given protocol. Used to serve peer-initiated requests for the same
     * protocol without needing a full-node view — we simply forward whatever
     * upstream peer last gave us, provided it is still fresh. Values are the
     * raw SSZ payload, not the wire-format response frame.
     */
    private final Map<String, byte[]> relayCache = new ConcurrentHashMap<>();

    /** Wall-clock timestamp (ms) when each relay entry was last updated. */
    private final Map<String, Long> relayCacheAtMs = new ConcurrentHashMap<>();

    /** Max age we'll relay a cached response. Older than this we 503 the peer. */
    private static final long RELAY_MAX_AGE_MS = 90_000; // 3 slots * 12s + buffer

    /**
     * If non-null, the 32-byte finalized block root our bootstrap corresponds
     * to; a peer requesting {@code /light_client_bootstrap/1} with this root
     * gets the cached bootstrap SSZ back.
     */
    private volatile byte[] bootstrapBlockRoot;

    /** Current seq_number we advertise in MetaData responses (0 for pure light client). */
    private final java.util.concurrent.atomic.AtomicLong metadataSeqNumber =
            new java.util.concurrent.atomic.AtomicLong(0);

    /**
     * Per-peer cooldown: wall-clock millis after which we're allowed to
     * re-dial a peer that sent us a Goodbye. Honoring the disconnect hint
     * the spec defines is what separates "good citizen" from "peer-scoring
     * penalty": rapid reconnects get us tagged as a bad peer on most
     * clients.
     */
    private final Map<String, Long> goodbyeUntilMs = new ConcurrentHashMap<>();
    // Short enough to unblock a normal 12 s sync cycle after at most 2-3
    // retries, long enough to stop us hammering a peer that just said no.
    // 2 min (the previous value) caused bootstrap to fail indefinitely when
    // the 2-3 reachable Lighthouse peers in the hardcoded list all
    // goodbye'd us at the first contact.
    private static final long GOODBYE_COOLDOWN_MS = 30_000;

    /** Periodic task that sends Ping to keep connections warm. */
    private java.util.concurrent.ScheduledExecutorService keepaliveExecutor;
    private static final long PING_INTERVAL_SECS = 15;

    /**
     * Gossipsub instance. Observation-only: handler logs incoming messages
     * and always returns {@code Ignore}. Only created when
     * {@link #gossipsubEnabled} is true, which defaults to {@code false}
     * because the primary target (short-lived Android sessions) doesn't
     * benefit from mesh participation — mesh-join latency is longer than a
     * whole session, and churning the mesh every 24 h is worse citizenship
     * than not joining.
     */
    private io.libp2p.pubsub.gossip.Gossip gossip;

    /** Off by default; call {@link #setGossipsubEnabled(boolean)} before {@link #start()}. */
    private boolean gossipsubEnabled = false;

    /** Toggle gossipsub subscription. Must be called before {@link #start()}. */
    public void setGossipsubEnabled(boolean enabled) {
        if (host != null) {
            throw new IllegalStateException("gossipsub flag cannot change after start()");
        }
        this.gossipsubEnabled = enabled;
    }

    public BeaconP2PService() {
        this(null);
    }

    public BeaconP2PService(Supplier<StatusMessage> localStatusSupplier) {
        this.localStatusSupplier = localStatusSupplier;
    }

    // -------------------------------------------------------------------------
    // Relay-cache public API (called by BeaconLightClient on every successful
    // upstream response). Callers pass the raw SSZ payload we received — same
    // thing we just gave back to our own caller — and we hold onto it so
    // peers who query us can get the same data back until it ages out.
    // -------------------------------------------------------------------------

    public void cacheFinalityUpdate(byte[] sszPayload) {
        cacheRelay(FINALITY, sszPayload);
    }

    public void cacheOptimisticUpdate(byte[] sszPayload) {
        cacheRelay(OPTIMISTIC, sszPayload);
    }

    public void cacheBootstrap(byte[] blockRoot32, byte[] sszPayload) {
        if (blockRoot32 != null && blockRoot32.length == 32) {
            this.bootstrapBlockRoot = blockRoot32.clone();
        }
        cacheRelay(BOOTSTRAP, sszPayload);
    }

    private void cacheRelay(String protocolId, byte[] sszPayload) {
        if (sszPayload == null || sszPayload.length == 0) return;
        relayCache.put(protocolId, sszPayload);
        relayCacheAtMs.put(protocolId, System.currentTimeMillis());
    }

    private byte[] freshRelay(String protocolId) {
        byte[] payload = relayCache.get(protocolId);
        Long at = relayCacheAtMs.get(protocolId);
        if (payload == null || at == null) return null;
        if (System.currentTimeMillis() - at > RELAY_MAX_AGE_MS) return null;
        return payload;
    }

    /**
     * Start the underlying libp2p host and register light client protocol handlers.
     */
    public void start() {
        // Observation-only gossipsub: installed so we appear as a mesh-
        // capable peer in Identify, subscribe to light-client topics and
        // log messages without propagating them. PR 1 of the gossipsub
        // rollout plan (see plan-gossipsub-subscription.md).
        //
        // Gated off by default — mesh participation is net-negative for
        // short-session clients (see commit message / gossipsub plan).
        HostBuilder hostBuilder = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> new NoiseXXSecureChannel(key, muxers))
                .muxer(StreamMuxerProtocol::getYamux)
                .muxer(StreamMuxerProtocol::getMplex)
                .listen("/ip4/0.0.0.0/tcp/0") // ephemeral port; some peers reject dial-only hosts
                // Ethereum CL spec requires secp256k1 identity keys
                .builderModifier(b -> b.getIdentity().random(KeyType.SECP256K1));
        if (gossipsubEnabled) {
            gossip = new io.libp2p.pubsub.gossip.Gossip();
            hostBuilder.protocol(gossip);
        }
        host = hostBuilder.build();

        // Log connection events and auto-query Identify for protocol support
        host.addConnectionHandler(conn -> {
            String pid = conn.secureSession().getRemoteId().toString();
            String remote = conn.remoteAddress().toString();
            long openedAt = System.currentTimeMillis();
            connectionOpenMillis.put(pid, openedAt);
            log.info("[beacon-p2p] Connection established to peer={} remote={} local={}",
                    pid, remote, conn.localAddress());
            // Log when the connection dies so we can tell if LC-capable peers
            // are dropping us (the prime symptom of a botched Status exchange).
            conn.closeFuture().thenRun(() -> {
                String agent = peerAgentVersions.get(pid);
                List<String> protos = peerProtocols.get(pid);
                boolean wasLc = protos != null && protos.stream().anyMatch(p -> p.contains("light_client"));
                Long t0 = connectionOpenMillis.remove(pid);
                long durMs = t0 != null ? System.currentTimeMillis() - t0 : -1;
                log.info("[beacon-p2p] Connection closed remote={} agent={} lightClient={} durationMs={}",
                        remote, agent != null ? agent : "?", wasLc, durMs);
            });
            // Automatically query Identify to cache supported protocols
            try {
                StreamPromise<IdentifyController> sp =
                        conn.muxerSession().createStream(identifyBinding);
                sp.getController().thenCompose(ctrl -> ctrl.id()).thenAccept(idMsg -> {
                    List<String> protos = idMsg.getProtocolsList().stream()
                            .map(Object::toString).toList();
                    peerProtocols.put(pid, protos);
                    String agent = idMsg.getAgentVersion();
                    if (agent != null && !agent.isEmpty()) {
                        peerAgentVersions.put(pid, agent);
                    }
                    long lcCount = protos.stream().filter(p -> p.contains("light_client")).count();
                    log.debug("[beacon-p2p] Identify auto-query for {}: agent={}, {} protocols ({} light_client)",
                            pid, agent, protos.size(), lcCount);
                }).exceptionally(ex -> {
                    log.debug("[beacon-p2p] Identify auto-query failed for {}: {}", pid, ex.getMessage());
                    return null;
                });
            } catch (Exception e) {
                log.debug("[beacon-p2p] Failed to start Identify for {}: {}", pid, e.getMessage());
            }

            // CL p2p spec: Status MUST be the first req/resp on every new connection.
            // Skipping it makes Lighthouse/Teku drop subsequent requests
            // (light_client_bootstrap, light_client_updates_by_range, …) almost
            // immediately. Kick off an initiator Status exchange as soon as the
            // connection is up — fire-and-forget, result is informational.
            autoStatus(conn, pid);
        });

        // Register identify protocol to query remote peer capabilities
        identifyBinding = new Identify();
        host.addProtocolHandler(identifyBinding);

        // Register protocol bindings before starting.
        //
        // Each binding is "initiator+responder" when a handler is provided.
        // We fulfil responder roles for every protocol a good network
        // citizen should answer (status, ping, metadata, goodbye) plus the
        // fork-dependent light-client read protocols — relayed from our own
        // cache, so a peer that asks us for a recent finality update gets
        // whatever upstream peer just gave us instead of a dead stream.
        registerBinding(STATUS, /*has ctx*/ false, /*req size*/ 92,
                statusHandler(/*v2*/ true));
        registerBinding(STATUS_V1, false, 84, statusHandler(false));
        registerBinding(PING, false, 8, pingHandler());
        registerBinding(METADATA, false, 0, metadataHandler());
        registerBinding(GOODBYE, false, 8, goodbyeHandler());
        registerBinding(FINALITY, true, 0, relayHandler(FINALITY));
        registerBinding(OPTIMISTIC, true, 0, relayHandler(OPTIMISTIC));
        registerBinding(BOOTSTRAP, true, 32, bootstrapHandler());
        registerBinding(UPDATES, true, 16, null); // multi-chunk relay deferred
        registerBinding(BLOCKS_BY_RANGE, true, 16, null); // we never serve blocks

        host.start().join();
        log.info("[beacon-p2p] libp2p host started, peerId={}, listenAddrs={}",
                host.getPeerId(), host.listenAddresses());

        // Keepalive: periodically Ping every connected peer. This is what
        // the CL spec expects of a well-behaved peer on idle connections;
        // without it we look dead and peers trim us on their next scoring
        // cycle.
        keepaliveExecutor = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "beacon-p2p-keepalive");
            t.setDaemon(true);
            return t;
        });
        keepaliveExecutor.scheduleAtFixedRate(this::pingAllConnections,
                PING_INTERVAL_SECS, PING_INTERVAL_SECS, java.util.concurrent.TimeUnit.SECONDS);

        if (gossipsubEnabled) {
            subscribeLightClientGossipTopics();
        }
    }

    /**
     * Subscribe to the light-client gossipsub topics in observation mode:
     * log every message, always return {@link
     * io.libp2p.core.pubsub.ValidationResult#Ignore}. We make no judgement
     * about validity yet, so we don't forward to our mesh peers — PR 2
     * will add full BLS validation on top.
     *
     * <p>Topics are named with the current {@code fork_digest}, which we
     * pull from {@link #localStatusSupplier}. When a hard fork activates,
     * the digest changes and we'd need to unsubscribe+resubscribe; that's
     * a known TODO (plan §4).
     */
    private void subscribeLightClientGossipTopics() {
        if (gossip == null || localStatusSupplier == null) return;
        byte[] forkDigest;
        try {
            forkDigest = localStatusSupplier.get().forkDigest();
        } catch (Exception e) {
            log.warn("[beacon-p2p] gossip subscribe skipped: no fork_digest ({})", e.getMessage());
            return;
        }
        String fdHex = bytesToHex(forkDigest, 4);
        String finalityTopic = "/eth2/" + fdHex + "/light_client_finality_update/ssz_snappy";
        String optimisticTopic = "/eth2/" + fdHex + "/light_client_optimistic_update/ssz_snappy";

        try {
            // Explicit typed variable disambiguates the Gossip#subscribe
            // overloads — the Consumer one is fire-and-forget, the Function
            // one returns our ValidationResult (what we want).
            java.util.function.Function<io.libp2p.core.pubsub.MessageApi,
                    java.util.concurrent.CompletableFuture<io.libp2p.core.pubsub.ValidationResult>> finalityFn =
                    msg -> handleGossipMessage(finalityTopic, msg);
            java.util.function.Function<io.libp2p.core.pubsub.MessageApi,
                    java.util.concurrent.CompletableFuture<io.libp2p.core.pubsub.ValidationResult>> optimisticFn =
                    msg -> handleGossipMessage(optimisticTopic, msg);
            gossip.subscribe(finalityFn, new io.libp2p.core.pubsub.Topic(finalityTopic));
            gossip.subscribe(optimisticFn, new io.libp2p.core.pubsub.Topic(optimisticTopic));
            log.info("[beacon-p2p] gossipsub subscribed (observation-only) to: {} and {}",
                    finalityTopic, optimisticTopic);
        } catch (Exception e) {
            log.warn("[beacon-p2p] gossip subscribe failed: {}", e.getMessage());
        }
    }

    /**
     * Observation-only gossipsub message handler. Logs sender, topic and
     * payload size, always returns {@code Ignore} — no relay, no scoring
     * effect on the sender. We'll graduate to validating/forwarding in PR 2.
     */
    private java.util.concurrent.CompletableFuture<io.libp2p.core.pubsub.ValidationResult>
            handleGossipMessage(String expectedTopic, io.libp2p.core.pubsub.MessageApi msg) {
        try {
            io.netty.buffer.ByteBuf data = msg.getData();
            int size = data == null ? 0 : data.readableBytes();
            byte[] from = msg.getFrom();
            String fromHex = from == null ? "?" : bytesToHex(from, 8);
            log.info("[beacon-p2p] gossip msg topic={} from={} size={}B",
                    expectedTopic, fromHex, size);
        } catch (Exception e) {
            log.debug("[beacon-p2p] gossip msg log failed: {}", e.getMessage());
        }
        return java.util.concurrent.CompletableFuture.completedFuture(
                io.libp2p.core.pubsub.ValidationResult.Ignore);
    }

    @Override
    public void close() {
        if (keepaliveExecutor != null) {
            keepaliveExecutor.shutdownNow();
            keepaliveExecutor = null;
        }
        Host h = host;
        if (h != null) {
            h.stop().join();
            log.info("[beacon-p2p] libp2p host stopped");
        }
    }

    // -------------------------------------------------------------------------
    // Protocol binding registration + responder handlers
    // -------------------------------------------------------------------------

    private void registerBinding(String protoId, boolean hasContextBytes,
                                 int expectedRequestSize, ReqRespHandler handler) {
        QueuedReqRespBinding binding = new QueuedReqRespBinding(
                protoId, peerAgentVersions, handler, hasContextBytes, expectedRequestSize,
                this::currentForkDigest);
        bindings.put(protoId, binding);
        // Only advertise the protocol (make it appear in our Identify response)
        // when we actually have a responder. Advertising protocols we can't
        // serve (UPDATES, BLOCKS_BY_RANGE) makes CL peers like Lighthouse
        // treat us as misbehaving and goodbye us immediately — observed
        // durationMs=1 closes in the wild. We can still OPEN streams for
        // those protocols as initiator because we hold the binding reference.
        if (handler != null) {
            host.addProtocolHandler(binding);
        }
    }

    /** The 4-byte fork_digest we tag context-bearing responses with. */
    private byte[] currentForkDigest() {
        if (localStatusSupplier == null) return new byte[4];
        try {
            return localStatusSupplier.get().forkDigest();
        } catch (Exception e) {
            return new byte[4];
        }
    }

    private ReqRespHandler statusHandler(boolean v2) {
        return (req, peerId) -> {
            if (localStatusSupplier == null) {
                throw new IllegalStateException("no local status supplier");
            }
            if (req != null && req.length > 0) {
                try {
                    StatusMessage peer = v2 ? StatusMessage.decode(req) : StatusMessage.decodeV1(req);
                    log.debug("[beacon-p2p] status responder received peer status from {}: {}", peerId, peer);
                } catch (Exception ignored) {}
            }
            StatusMessage local = localStatusSupplier.get();
            return v2 ? local.encode() : local.encodeV1();
        };
    }

    /** Ping: echo the peer's seq_number back — cheap keepalive. */
    private ReqRespHandler pingHandler() {
        return (req, peerId) -> {
            if (req != null && req.length == 8) return req;
            return new byte[8];
        };
    }

    /** Metadata v2: tell the peer we're a pure light client with no subscriptions. */
    private ReqRespHandler metadataHandler() {
        return (req, peerId) -> {
            MetadataMessage md = new MetadataMessage(metadataSeqNumber.get(), new byte[8], new byte[1]);
            return md.encode();
        };
    }

    /**
     * Goodbye: peer told us they're closing. Echo the reason back so they
     * see an ack. Record a cooldown only for <em>behavioral</em> reasons
     * (Lighthouse-style application codes &ge; 128, plus spec's FaultError
     * (3) and ClientShutdown (1) where reconnecting doesn't help). For the
     * spec's IrrelevantNetwork (2) we do <em>not</em> cooldown: that's a
     * static-capability mismatch (we don't advertise gossipsub, so we stay
     * "irrelevant" until we subscribe), and cooldowning locks us out of
     * every peer at once without reducing abuse — the peer already decided
     * based on Identify, they won't be angrier if we re-dial.
     */
    private ReqRespHandler goodbyeHandler() {
        return (req, peerId) -> {
            long code = 0L;
            if (req != null && req.length == 8) {
                code = ByteBuffer.wrap(req).order(ByteOrder.LITTLE_ENDIAN).getLong();
            }
            boolean shouldCooldown = code == 1 || code == 3 || code >= 128;
            if (shouldCooldown) {
                long until = System.currentTimeMillis() + GOODBYE_COOLDOWN_MS;
                goodbyeUntilMs.put(peerId, until);
                log.info("[beacon-p2p] peer sent Goodbye reason={} — {} in cooldown for {}s",
                        code, peerId, GOODBYE_COOLDOWN_MS / 1000);
            } else {
                log.info("[beacon-p2p] peer sent Goodbye reason={} — {} (no cooldown, static mismatch)",
                        code, peerId);
            }
            return req != null && req.length == 8 ? req : new byte[8];
        };
    }

    /**
     * Serve {@code /light_client_finality_update/1} or
     * {@code /light_client_optimistic_update/1} from whatever we most
     * recently received upstream. Returns null (ResourceUnavailable) when
     * the cache is empty or stale; peers interpret that as "ask someone else".
     */
    private ReqRespHandler relayHandler(String protoId) {
        return (req, peerId) -> {
            byte[] cached = freshRelay(protoId);
            if (cached == null) {
                log.debug("[beacon-p2p] relay miss for {}, returning ResourceUnavailable", protoId);
                return null;
            }
            return cached;
        };
    }

    /**
     * Serve {@code /light_client_bootstrap/1} only if the peer asks for
     * exactly the block root we bootstrapped from. That's the only root we
     * have verified branches for, so anything else must be ResourceUnavailable.
     */
    private ReqRespHandler bootstrapHandler() {
        return (req, peerId) -> {
            byte[] cached = freshRelay(BOOTSTRAP);
            byte[] expectedRoot = bootstrapBlockRoot;
            if (cached == null || expectedRoot == null) return null;
            if (req == null || req.length != 32) {
                throw new IllegalArgumentException("InvalidRequest: bootstrap root must be 32 bytes");
            }
            if (!java.util.Arrays.equals(req, expectedRoot)) {
                log.debug("[beacon-p2p] bootstrap request for unknown root, returning ResourceUnavailable");
                return null;
            }
            return cached;
        };
    }

    /**
     * Walk every live libp2p connection and fire an outbound /req/ping/1
     * so the peer's liveness tracker stays green. Called from a scheduled
     * thread every {@link #PING_INTERVAL_SECS}s.
     */
    private void pingAllConnections() {
        Host h = host;
        if (h == null) return;
        try {
            for (io.libp2p.core.Connection conn : h.getNetwork().getConnections()) {
                pingConnection(conn);
            }
        } catch (Exception e) {
            log.debug("[beacon-p2p] keepalive loop error: {}", e.getMessage());
        }
    }

    /** Fire a single /req/ping/1 on an already-open connection. */
    private void pingConnection(io.libp2p.core.Connection conn) {
        QueuedReqRespBinding binding = bindings.get(PING);
        if (binding == null) return;
        String pid;
        try {
            pid = conn.secureSession().getRemoteId().toString();
        } catch (Exception e) {
            return;
        }
        byte[] requestPayload;
        try {
            byte[] sszSeq = new byte[8]; // our seq_number stays 0
            requestPayload = ReqRespCodec.encodeRequest(sszSeq);
        } catch (IOException e) {
            return;
        }
        CompletableFuture<byte[]> responseFuture = new CompletableFuture<>();
        responseFuture.whenComplete((raw, ex) -> {
            if (ex != null) {
                log.debug("[beacon-p2p] ping failed with {}: {}", pid, ex.getMessage());
            } else {
                log.debug("[beacon-p2p] ping ok with {} ({} bytes)", pid, raw == null ? 0 : raw.length);
            }
        });
        binding.enqueue(requestPayload, responseFuture);
        try {
            StreamPromise<?> sp = conn.muxerSession().createStream(binding);
            sp.getStream().whenComplete((s, e) -> {
                if (e != null && !responseFuture.isDone()) {
                    responseFuture.completeExceptionally(e);
                }
            });
        } catch (Exception e) {
            if (!responseFuture.isDone()) responseFuture.completeExceptionally(e);
        }
    }

    /**
     * Fire-and-forget Status handshake on a freshly-established connection.
     *
     * <p>The eth2 p2p-interface spec says Status MUST be the first req/resp
     * exchanged after a connection is opened, and modern CL clients (Lighthouse
     * v8+, Teku, Prysm) enforce this by dropping any subsequent stream
     * (light_client_bootstrap / light_client_updates_by_range / …) that
     * arrives before Status has completed. Calling this from the connection
     * handler makes every outbound connection spec-compliant without
     * requiring the caller to remember to exchange Status first.
     */
    private void autoStatus(io.libp2p.core.Connection conn, String pid) {
        if (localStatusSupplier == null) return;
        QueuedReqRespBinding statusBinding = bindings.get(STATUS);
        if (statusBinding == null) return;
        try {
            StatusMessage local = localStatusSupplier.get();
            byte[] requestPayload = ReqRespCodec.encodeRequest(local.encode());
            CompletableFuture<byte[]> responseFuture = new CompletableFuture<>();
            responseFuture.whenComplete((raw, ex) -> {
                if (ex != null) {
                    log.debug("[beacon-p2p] auto-Status failed with {}: {}", pid, ex.getMessage());
                } else {
                    try {
                        ReqRespCodec.DecodeResult decoded = ReqRespCodec.decodeResponse(raw, false);
                        StatusMessage peer = StatusMessage.decode(decoded.sszPayload());
                        log.info("[beacon-p2p] auto-Status with {} (agent={}): peer={}",
                                pid, peerAgentVersions.getOrDefault(pid, "?"), peer);
                    } catch (Exception e) {
                        log.debug("[beacon-p2p] auto-Status decode failed with {}: {} ({} bytes)",
                                pid, e.getMessage(), raw != null ? raw.length : -1);
                    }
                }
            });
            statusBinding.enqueue(requestPayload, responseFuture);
            StreamPromise<?> sp = conn.muxerSession().createStream(statusBinding);
            sp.getStream().whenComplete((s, e) -> {
                if (e != null && !responseFuture.isDone()) {
                    responseFuture.completeExceptionally(e);
                }
            });
        } catch (Exception e) {
            log.debug("[beacon-p2p] auto-Status init failed for {}: {}", pid, e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /** Info about a connected CL peer. */
    public record PeerInfo(String peerId, String remoteAddress, List<String> protocols, String agentVersion) {
        /** Whether this peer advertises any light_client protocol. */
        public boolean supportsLightClient() {
            return protocols != null && protocols.stream()
                    .anyMatch(p -> p.contains("light_client"));
        }
    }

    /**
     * Return the cached agent string for a peer if Identify has completed.
     * Accepts either a libp2p multiaddr (we'll extract the {@code /p2p/<peerId>})
     * or a raw peerId string. Returns {@code null} if unknown.
     */
    public String cachedAgent(String multiaddrOrPeerId) {
        if (multiaddrOrPeerId == null) return null;
        String peerId = multiaddrOrPeerId;
        int idx = multiaddrOrPeerId.indexOf("/p2p/");
        if (idx >= 0) {
            peerId = multiaddrOrPeerId.substring(idx + "/p2p/".length());
            int slash = peerId.indexOf('/');
            if (slash >= 0) peerId = peerId.substring(0, slash);
        }
        return peerAgentVersions.get(peerId);
    }

    /**
     * Return info about all currently connected CL peers.
     * For each peer, attempts to retrieve cached Identify protocol lists.
     */
    public List<PeerInfo> getConnectedPeers() {
        Host h = host;
        if (h == null) return List.of();
        List<PeerInfo> result = new ArrayList<>();
        for (io.libp2p.core.Connection conn : h.getNetwork().getConnections()) {
            String peerId = conn.secureSession().getRemoteId().toString();
            String remote = conn.remoteAddress().toString();
            List<String> protocols = peerProtocols.get(peerId);
            String agent = peerAgentVersions.get(peerId);
            result.add(new PeerInfo(peerId, remote,
                    protocols != null ? protocols : List.of(),
                    agent));
        }
        return result;
    }

    /**
     * Disconnect all existing connections to a peer, forcing fresh connections
     * on subsequent requests. This is needed when a stale connection causes
     * "Failed to open stream" errors (e.g. after a bootstrap empty response).
     */
    public void disconnectPeer(String peerMultiaddr) {
        Host h = host;
        if (h == null) return;
        try {
            PeerId peerId = new Multiaddr(peerMultiaddr).getPeerId();
            if (peerId == null) return;
            for (io.libp2p.core.Connection conn : h.getNetwork().getConnections()) {
                if (peerId.equals(conn.secureSession().getRemoteId())) {
                    log.debug("[beacon-p2p] Disconnecting stale connection to {}", peerMultiaddr);
                    h.getNetwork().disconnect(conn);
                }
            }
        } catch (Exception e) {
            log.debug("[beacon-p2p] Error disconnecting {}: {}", peerMultiaddr, e.getMessage());
        }
    }

    /**
     * Query a peer's supported protocols via the libp2p Identify protocol.
     * Logs all protocols the peer advertises — diagnostic tool.
     */
    public CompletableFuture<Void> queryIdentify(String peerMultiaddr) {
        Host h = host;
        if (h == null) return CompletableFuture.failedFuture(new IllegalStateException("not started"));

        try {
            Multiaddr peerAddr = new Multiaddr(peerMultiaddr);
            PeerId peerId = peerAddr.getPeerId();
            if (peerId == null) return CompletableFuture.failedFuture(new IllegalArgumentException("no peer id"));

            CompletableFuture<io.libp2p.core.Connection> connFuture = findOrConnect(h, peerId, peerAddr);
            return connFuture.thenCompose(conn -> {
                StreamPromise<IdentifyController> streamPromise =
                        conn.muxerSession().createStream(identifyBinding);
                return streamPromise.getController().thenCompose(ctrl -> ctrl.id());
            }).thenAccept(idMsg -> {
                List<?> protocols = idMsg.getProtocolsList();
                List<String> protoStrings = protocols.stream()
                        .map(Object::toString).toList();
                // Cache protocol list and agent version keyed by peer ID
                try {
                    PeerId pid = new Multiaddr(peerMultiaddr).getPeerId();
                    if (pid != null) {
                        peerProtocols.put(pid.toString(), protoStrings);
                        String agent = idMsg.getAgentVersion();
                        if (agent != null && !agent.isEmpty()) {
                            peerAgentVersions.put(pid.toString(), agent);
                        }
                    }
                } catch (Exception ignored) {}
                log.info("[beacon-p2p] Identify response from {}: {} protocols", peerMultiaddr, protoStrings.size());
                for (String protoStr : protoStrings) {
                    if (protoStr.contains("light_client") || protoStr.contains("eth2")) {
                        log.info("[beacon-p2p]   MATCH: {}", protoStr);
                    }
                }
                // Log all protocols at debug level
                for (String protoStr : protoStrings) {
                    log.debug("[beacon-p2p]   proto: {}", protoStr);
                }
            }).exceptionally(ex -> {
                log.warn("[beacon-p2p] Identify failed for {}: {}", peerMultiaddr, ex.getMessage());
                return null;
            });
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Send the CL Status handshake and return the peer's Status response.
     *
     * <p>Modern CL clients (Lighthouse v8+, recent Teku / Prysm) enforce the
     * {@code /req/status/1} handshake: a peer that doesn't send Status within
     * a few seconds is disconnected. Calling this immediately after Identify
     * keeps bootstrap-capable peers from RST'ing our stream before we can
     * ask for {@code light_client_bootstrap}.
     *
     * <p>The resulting Status from the peer is mostly informative for a light
     * client — we don't yet build a view of the chain head from it — but
     * completing the exchange is what the peer actually requires.
     *
     * @return the decoded peer Status, or a failed future if the exchange fails
     */
    public CompletableFuture<StatusMessage> exchangeStatus(String peerMultiaddr, StatusMessage local) {
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(local.encode());
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        dumpOutgoingStatus(peerMultiaddr, "v2", local, requestPayload);
        return doReqResp(peerMultiaddr, STATUS, requestPayload)
                .thenApply(raw -> dumpStatusResponse(peerMultiaddr, "v2", raw))
                .thenApply(raw -> decodeSingleResponse(raw, false))
                .thenApply(StatusMessage::decode);
    }

    /** Legacy {@code /status/1} variant (84-byte payload, no earliest_available_slot). */
    public CompletableFuture<StatusMessage> exchangeStatusV1(String peerMultiaddr, StatusMessage local) {
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(local.encodeV1());
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        dumpOutgoingStatus(peerMultiaddr, "v1", local, requestPayload);
        return doReqResp(peerMultiaddr, STATUS_V1, requestPayload)
                .thenApply(raw -> dumpStatusResponse(peerMultiaddr, "v1", raw))
                .thenApply(raw -> decodeSingleResponse(raw, false))
                .thenApply(StatusMessage::decodeV1);
    }

    /**
     * Diagnostic: log the Status message we're about to send, both as the
     * decoded fields (so it's easy to compare against the peer's response) and
     * as the wire bytes (so anything the codec is mis-framing is visible).
     * INFO level so it's visible without enabling debug.
     */
    private static void dumpOutgoingStatus(String peer, String version,
                                           StatusMessage local, byte[] wire) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(wire.length, 24); i++) {
            hex.append(String.format("%02x", wire[i]));
        }
        log.info("[beacon-p2p] status/{} REQUEST to {}: local={} wire={}B hex={}{}",
                version, peer, local, wire.length, hex,
                wire.length > 24 ? "…" : "");
    }

    /**
     * Diagnostic: log the wire-format bytes of a Status response before they
     * go through the codec. Reveals when Lighthouse/Teku send a non-zero
     * result code (Goodbye / InvalidRequest / ServerError) vs. an empty
     * SSZ body vs. a short truncated frame. Runs unconditionally but at
     * INFO so we can see it without enabling debug.
     */
    private static byte[] dumpStatusResponse(String peer, String version, byte[] raw) {
        if (raw == null || raw.length == 0) {
            log.info("[beacon-p2p] status/{} response from {}: (0 bytes)", version, peer);
            return raw;
        }
        byte resultCode = raw[0];
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(raw.length, 24); i++) {
            sb.append(String.format("%02x", raw[i]));
        }
        log.info("[beacon-p2p] status/{} response from {}: {} bytes, result=0x{} hex={}{}",
                version, peer, raw.length,
                String.format("%02x", resultCode & 0xff),
                sb,
                raw.length > 24 ? "…" : "");
        return raw;
    }

    public CompletableFuture<byte[]> requestBootstrap(String peerMultiaddr, byte[] blockRoot32) {
        if (blockRoot32 == null || blockRoot32.length != 32) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("blockRoot32 must be exactly 32 bytes"));
        }
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(blockRoot32);
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        return doReqResp(peerMultiaddr, BOOTSTRAP, requestPayload)
                .thenApply(BeaconP2PService::decodeSingleResponse);
    }

    public CompletableFuture<byte[]> requestFinalityUpdate(String peerMultiaddr) {
        // No request body for finality_update — send nothing, just close write side
        return doReqResp(peerMultiaddr, FINALITY, new byte[0])
                .thenApply(BeaconP2PService::decodeSingleResponse);
    }

    public CompletableFuture<byte[]> requestOptimisticUpdate(String peerMultiaddr) {
        // No request body for optimistic_update — send nothing, just close write side
        return doReqResp(peerMultiaddr, OPTIMISTIC, new byte[0])
                .thenApply(BeaconP2PService::decodeSingleResponse);
    }

    public CompletableFuture<List<byte[]>> requestUpdatesByRange(
            String peerMultiaddr, long startPeriod, int count) {
        byte[] sszRequest = encodeUpdatesByRangeRequest(startPeriod, count);
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(sszRequest);
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        return doReqResp(peerMultiaddr, UPDATES, requestPayload)
                .thenApply(raw -> {
                    try {
                        return decodeUpdatesByRangeResponse(raw, count);
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to decode updates_by_range response", e);
                    }
                });
    }

    /**
     * Request beacon blocks by slot range from a CL peer.
     * Returns a list of SSZ-decoded SignedBeaconBlock payloads.
     */
    public CompletableFuture<List<byte[]>> requestBlocksByRange(
            String peerMultiaddr, long startSlot, long count) {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(startSlot);
        buf.putLong(count);
        byte[] requestPayload;
        try {
            requestPayload = ReqRespCodec.encodeRequest(buf.array());
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
        return doReqResp(peerMultiaddr, BLOCKS_BY_RANGE, requestPayload)
                .thenApply(raw -> {
                    try {
                        return decodeMultiChunkResponse(raw, count);
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to decode blocks_by_range response", e);
                    }
                });
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private static byte[] decodeSingleResponse(byte[] raw) {
        return decodeSingleResponse(raw, true);
    }

    /**
     * @param hasContextBytes whether the response includes 4 bytes of
     *     context (fork_digest) after the result byte. True for
     *     fork-dependent protocols (light_client_*, beacon_blocks_by_*,
     *     blob_sidecars_by_*); false for fixed-type protocols
     *     (status, ping, metadata, goodbye).
     */
    private static byte[] decodeSingleResponse(byte[] raw, boolean hasContextBytes) {
        try {
            ReqRespCodec.DecodeResult result = ReqRespCodec.decodeResponse(raw, hasContextBytes);
            return result.sszPayload();
        } catch (Exception e) {
            log.warn("[beacon-p2p] Failed to decode response ({} bytes): {} — first 20 bytes: {}",
                    raw.length, e.getMessage(), bytesToHex(raw, 20));
            throw new RuntimeException("Failed to decode response: " + e.getMessage(), e);
        }
    }

    private static String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, limit); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }

    /**
     * Find or create a connection to the peer, then open a muxed stream for the
     * given protocol — matching Teku's pattern of reusing connections. If the
     * existing connection is dying (peer just sent FIN, mux stream fails with
     * "Channel closed"), we force-disconnect and retry once with a fresh
     * connection instead of failing the request. Without this, a peer like
     * Lodestar that closes after every single request would fail every
     * follow-up request even though dialing again would work fine.
     */
    private CompletableFuture<byte[]> doReqResp(
            String peerMultiaddr, String protocolId, byte[] requestBytes) {
        return doReqRespAttempt(peerMultiaddr, protocolId, requestBytes, true);
    }

    private CompletableFuture<byte[]> doReqRespAttempt(
            String peerMultiaddr, String protocolId, byte[] requestBytes, boolean allowRetry) {

        Host h = host;
        if (h == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("BeaconP2PService not started"));
        }

        CompletableFuture<byte[]> responseFuture = new CompletableFuture<>();

        QueuedReqRespBinding binding = bindings.get(protocolId);
        if (binding == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("No binding registered for " + protocolId));
        }

        try {
            Multiaddr peerAddr = new Multiaddr(peerMultiaddr);
            PeerId peerId = peerAddr.getPeerId();
            if (peerId == null) {
                return CompletableFuture.failedFuture(
                        new IllegalArgumentException("Cannot extract PeerId from: " + peerMultiaddr));
            }

            // Goodbye cooldown: if the peer recently sent us Goodbye, skip.
            // Re-dialing right after a Goodbye is exactly the signal that
            // gets us scored down across the network; honoring it is how
            // we stay a good citizen.
            Long cooldownUntil = goodbyeUntilMs.get(peerId.toString());
            if (cooldownUntil != null) {
                long remaining = cooldownUntil - System.currentTimeMillis();
                if (remaining > 0) {
                    return CompletableFuture.failedFuture(
                            new RuntimeException("peer " + peerId + " in Goodbye cooldown for "
                                    + remaining + "ms"));
                }
                goodbyeUntilMs.remove(peerId.toString());
            }

            log.debug("[beacon-p2p] Opening stream {} to {}", protocolId, peerMultiaddr);

            // Step 1: Find existing connection or establish a new one
            CompletableFuture<io.libp2p.core.Connection> connFuture = findOrConnect(h, peerId, peerAddr);

            connFuture.whenComplete((conn, connEx) -> {
                if (connEx != null) {
                    log.debug("[beacon-p2p] Connection failed to {}: {} ({})",
                            peerMultiaddr, connEx.getMessage(), connEx.getClass().getSimpleName());
                    responseFuture.completeExceptionally(
                            new RuntimeException("Failed to connect to " + peerMultiaddr, connEx));
                    return;
                }

                // Step 2: Enqueue request state, then open a stream on the muxer
                log.debug("[beacon-p2p] Connection ready for {}, enqueueing and creating stream for {}",
                        peerMultiaddr, protocolId);
                binding.enqueue(requestBytes, responseFuture);

                try {
                    StreamPromise<?> streamPromise =
                            conn.muxerSession().createStream(binding);
                    log.debug("[beacon-p2p] createStream() returned for {} to {}", protocolId, peerMultiaddr);

                    streamPromise.getStream().whenComplete((stream, ex) -> {
                        if (ex != null && !responseFuture.isDone()) {
                            log.debug("[beacon-p2p] Stream open failed to {}: {} ({})",
                                    peerMultiaddr, ex.getMessage(), ex.getClass().getSimpleName());
                            Throwable cause = ex;
                            while (cause.getCause() != null) cause = cause.getCause();
                            if (cause != ex) {
                                log.debug("[beacon-p2p]   root cause: {} ({})",
                                        cause.getMessage(), cause.getClass().getSimpleName());
                            }
                            if (allowRetry && isStaleConnectionError(cause)) {
                                // Dying connection: force-disconnect and retry once with a fresh dial.
                                log.debug("[beacon-p2p] Stale connection to {} — retrying with fresh dial",
                                        peerMultiaddr);
                                disconnectPeer(peerMultiaddr);
                                doReqRespAttempt(peerMultiaddr, protocolId, requestBytes, false)
                                        .whenComplete((r, e) -> {
                                            if (e != null) responseFuture.completeExceptionally(e);
                                            else responseFuture.complete(r);
                                        });
                            } else {
                                responseFuture.completeExceptionally(
                                        new RuntimeException("Failed to open stream to " + peerMultiaddr, ex));
                            }
                        }
                    });

                    streamPromise.getController().whenComplete((ctrl, ex) -> {
                        if (ex != null && !responseFuture.isDone()) {
                            log.debug("[beacon-p2p] Protocol negotiation failed for {} to {}: {}",
                                    protocolId, peerMultiaddr, ex.getMessage());
                            responseFuture.completeExceptionally(
                                    new RuntimeException("Protocol negotiation failed", ex));
                        }
                    });
                } catch (Exception e) {
                    if (!responseFuture.isDone()) {
                        responseFuture.completeExceptionally(
                                new RuntimeException("Failed to create stream to " + peerMultiaddr, e));
                    }
                }
            });

        } catch (Exception e) {
            log.debug("[beacon-p2p] Connection init failed to {}: {}", peerMultiaddr, e.getMessage());
            responseFuture.completeExceptionally(
                    new RuntimeException("Failed to initiate connection to " + peerMultiaddr, e));
        }

        return responseFuture;
    }

    /**
     * True if the given exception looks like we tried to use a connection
     * the peer just closed — so retrying with a fresh dial is the right
     * remedy. Covers the two patterns libp2p-jvm produces: a mux-level
     * {@code ConnectionClosedException} wrapping "Channel closed" and a
     * plain {@code ClosedChannelException} from the underlying socket.
     */
    private static boolean isStaleConnectionError(Throwable cause) {
        if (cause == null) return false;
        String name = cause.getClass().getSimpleName();
        String msg = cause.getMessage() != null ? cause.getMessage() : "";
        return name.equals("ConnectionClosedException")
                || name.equals("ClosedChannelException")
                || msg.contains("Channel closed")
                || msg.contains("Connection reset");
    }

    /**
     * Find an existing connection to the peer, or establish a new one.
     */
    private CompletableFuture<io.libp2p.core.Connection> findOrConnect(
            Host h, PeerId peerId, Multiaddr peerAddr) {
        // Check for an existing connection first
        for (io.libp2p.core.Connection conn : h.getNetwork().getConnections()) {
            if (peerId.equals(conn.secureSession().getRemoteId())) {
                return CompletableFuture.completedFuture(conn);
            }
        }
        // No existing connection — establish a new one
        return h.getNetwork().connect(peerId, peerAddr);
    }

    private static byte[] encodeUpdatesByRangeRequest(long startPeriod, int count) {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(startPeriod);
        buf.putLong(count);
        return buf.array();
    }

    private static List<byte[]> decodeUpdatesByRangeResponse(byte[] raw, int expectedCount)
            throws IOException {
        return decodeMultiChunkResponse(raw, expectedCount);
    }

    /**
     * Decode a multi-chunk eth2 req/resp response (used by both updates_by_range
     * and blocks_by_range). Each chunk: 1B result + 4B fork_digest + varint(uncompressed_len) + snappy data.
     * The varint is the uncompressed SSZ length, NOT the compressed length.
     * We scan snappy frames to find chunk boundaries, using the expected uncompressed
     * length to resolve ambiguity between snappy compressed frames (type 0x00) and
     * the next chunk's result code (also 0x00).
     */
    private static List<byte[]> decodeMultiChunkResponse(byte[] raw, long expectedCount)
            throws IOException {
        List<byte[]> items = new ArrayList<>();
        int pos = 0;
        while (pos < raw.length && items.size() < expectedCount) {
            byte resultCode = raw[pos];
            if (resultCode != 0) {
                log.warn("[beacon-p2p] Multi-chunk response item {} error code {}", items.size(), resultCode);
                break;
            }
            pos++;
            if (pos + 4 > raw.length) break;
            pos += 4; // skip fork digest
            ReqRespCodec.VarintResult varint = ReqRespCodec.readVarint(raw, pos);
            pos = varint.nextPos();
            int uncompressedLength = varint.value();
            if (uncompressedLength == 0) { items.add(new byte[0]); continue; }

            // Scan snappy frames to find the end of this chunk's compressed data
            int snappyStart = pos;
            pos = skipSnappyFrames(raw, pos, uncompressedLength);
            int compressedLength = pos - snappyStart;
            if (compressedLength <= 0) break;
            byte[] compressed = new byte[compressedLength];
            System.arraycopy(raw, snappyStart, compressed, 0, compressedLength);
            items.add(ReqRespCodec.snappyDecompress(compressed));
        }
        return items;
    }

    /**
     * Skip past one complete snappy framed stream. Snappy frames:
     * - Stream identifier: 0xff + 3-byte LE length (always 6) + "sNaPpY"
     * - Compressed: 0x00 + 3-byte LE length + data
     * - Uncompressed: 0x01 + 3-byte LE length + data
     *
     * Tracks decompressed output to stop when the expected uncompressed length
     * is reached, preventing ambiguity between snappy compressed frames (0x00)
     * and the next response chunk's result code (also 0x00).
     *
     * @param data              raw response bytes
     * @param pos               start position of the snappy stream
     * @param uncompressedLength expected total decompressed output for this chunk
     * @return position after the last frame belonging to this chunk
     */
    private static int skipSnappyFrames(byte[] data, int pos, int uncompressedLength) {
        int decompressedSoFar = 0;
        while (pos < data.length) {
            int chunkType = data[pos] & 0xFF;
            if (chunkType != 0xFF && chunkType != 0x00 && chunkType != 0x01) {
                // Not a snappy frame — this is the start of the next chunk's result code
                break;
            }
            if (pos + 4 > data.length) break;
            int frameLen = (data[pos + 1] & 0xFF)
                    | ((data[pos + 2] & 0xFF) << 8)
                    | ((data[pos + 3] & 0xFF) << 16);
            // Bounds check: frame must fit within the data
            if (pos + 4 + frameLen > data.length) {
                // Truncated frame — consume remaining data
                pos = data.length;
                break;
            }

            // Track decompressed output to know when this chunk is complete
            if (chunkType == 0x01 && frameLen > 4) {
                // Uncompressed frame: 4 bytes CRC32C + raw data
                decompressedSoFar += frameLen - 4;
            } else if (chunkType == 0x00 && frameLen > 4) {
                // Compressed frame: 4 bytes CRC32C + snappy block
                // Snappy block starts with a varint for uncompressed block length
                try {
                    int snappyBlockStart = pos + 4 + 4; // frame header (4) + CRC32C (4)
                    ReqRespCodec.VarintResult blockSize =
                            ReqRespCodec.readVarint(data, snappyBlockStart);
                    decompressedSoFar += blockSize.value();
                } catch (Exception e) {
                    // Can't read varint — likely not a real snappy frame
                    break;
                }
            }
            // 0xFF is stream identifier — contributes 0 decompressed bytes

            pos += 4 + frameLen;

            // Stop when we've accounted for all expected decompressed bytes
            if (decompressedSoFar >= uncompressedLength && uncompressedLength > 0) {
                break;
            }
        }
        return pos;
    }

    // =========================================================================
    // Queued protocol binding: registered once, handles multiple requests
    // =========================================================================

    /**
     * A reusable ProtocolBinding registered with the host. Per-request state
     * (request bytes + response future) is passed through a FIFO queue.
     */
    static class QueuedReqRespBinding implements ProtocolBinding<ReqRespController> {

        private final String protocolId;
        private final ConcurrentLinkedQueue<PendingRequest> pendingRequests = new ConcurrentLinkedQueue<>();
        private final Map<String, String> peerAgentsRef;
        /** When non-null, the binding serves peer-initiated streams with this handler. */
        private final ReqRespHandler responderHandler;
        /** Whether the response includes 4 context bytes (fork_digest) after the result code. */
        private final boolean hasContextBytes;
        /**
         * SSZ size of the request body. 0 means the request has no body
         * (e.g. metadata, finality_update, optimistic_update); -1 means we
         * don't know / variable size. Used to detect when we've received a
         * complete request and can respond.
         */
        private final int expectedRequestSize;
        /** Supplier for current fork digest (only consulted when {@code hasContextBytes}). */
        private final Supplier<byte[]> forkDigestSupplier;

        record PendingRequest(byte[] requestBytes, CompletableFuture<byte[]> responseFuture) {}

        QueuedReqRespBinding(String protocolId, Map<String, String> peerAgentsRef) {
            this(protocolId, peerAgentsRef, null, false, -1, () -> new byte[4]);
        }

        QueuedReqRespBinding(String protocolId, Map<String, String> peerAgentsRef,
                             ReqRespHandler responderHandler, boolean hasContextBytes,
                             int expectedRequestSize, Supplier<byte[]> forkDigestSupplier) {
            this.protocolId = protocolId;
            this.peerAgentsRef = peerAgentsRef;
            this.responderHandler = responderHandler;
            this.hasContextBytes = hasContextBytes;
            this.expectedRequestSize = expectedRequestSize;
            this.forkDigestSupplier = forkDigestSupplier;
        }

        void enqueue(byte[] requestBytes, CompletableFuture<byte[]> responseFuture) {
            pendingRequests.add(new PendingRequest(requestBytes, responseFuture));
        }

        @Override
        public ProtocolDescriptor getProtocolDescriptor() {
            return new ProtocolDescriptor(protocolId);
        }

        @Override
        public CompletableFuture<ReqRespController> initChannel(P2PChannel channel, String negotiatedProtocol) {
            io.libp2p.core.Stream stream = (io.libp2p.core.Stream) channel;

            // Peer-initiated streams (symmetric CL protocols like /req/status/2
            // are opened by either side) must NOT drain the outgoing pending-request
            // queue — that queue belongs to streams WE opened. Draining it here
            // steals the PendingRequest intended for a concurrent outgoing stream
            // and that stream then fails with "No pending request" masquerading
            // as "Protocol negotiation failed".
            if (!stream.isInitiator()) {
                String agent = "?";
                String pid = "?";
                try {
                    pid = stream.getConnection().secureSession().getRemoteId().toString();
                    String a = peerAgentsRef.get(pid);
                    if (a != null) agent = a;
                } catch (Exception ignored) {}

                if (responderHandler != null) {
                    log.debug("[beacon-p2p] Peer-initiated {} stream from {} (agent={}) — responding",
                            protocolId, pid, agent);
                    ResponderController responder = new ResponderController(
                            stream, responderHandler, hasContextBytes,
                            forkDigestSupplier, expectedRequestSize,
                            protocolId, pid, agent);
                    channel.pushHandler(responder.nettyHandler());
                    return CompletableFuture.completedFuture(null);
                }

                log.debug("[beacon-p2p] Peer-initiated {} stream from {} (agent={}) — no responder, closing",
                        protocolId, pid, agent);
                try { stream.close(); } catch (Exception ignored) {}
                return CompletableFuture.failedFuture(
                        new IllegalStateException("Responder role not implemented for " + protocolId));
            }

            // Outgoing stream: drain stale (already-timed-out) requests from the queue.
            PendingRequest pending = null;
            while (true) {
                pending = pendingRequests.poll();
                if (pending == null) {
                    log.warn("[beacon-p2p] No pending request for outgoing {} — queue was empty!", protocolId);
                    return CompletableFuture.failedFuture(
                            new IllegalStateException("No pending request for " + protocolId));
                }
                if (!pending.responseFuture.isDone()) break;
                log.debug("[beacon-p2p] Skipping stale request for {}", protocolId);
            }

            ReqRespController controller = new ReqRespController(
                    pending.requestBytes, pending.responseFuture, stream);
            channel.pushHandler(controller.nettyHandler());
            return controller.getReadyFuture();
        }
    }

    // =========================================================================
    // Controller: handles a single stream's I/O
    // =========================================================================

    static class ReqRespController {

        private final byte[] requestBytes;
        private final CompletableFuture<byte[]> responseFuture;
        private final CompletableFuture<ReqRespController> readyFuture = new CompletableFuture<>();
        private final ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream();
        private final io.libp2p.core.Stream stream;
        private volatile boolean writeClosedOnly;
        private volatile boolean dataReceived;
        private volatile boolean channelFullyClosed;
        private volatile java.util.concurrent.ScheduledFuture<?> completionTimer;

        ReqRespController(byte[] requestBytes, CompletableFuture<byte[]> responseFuture,
                          io.libp2p.core.Stream stream) {
            this.requestBytes = requestBytes;
            this.responseFuture = responseFuture;
            this.stream = stream;
        }

        CompletableFuture<ReqRespController> getReadyFuture() {
            return readyFuture;
        }

        ChannelHandler nettyHandler() {
            return new SimpleChannelInboundHandler<ByteBuf>() {

                @Override
                public void channelActive(ChannelHandlerContext ctx) throws Exception {
                    log.debug("[beacon-p2p] channelActive fired, writing {} request bytes",
                            requestBytes != null ? requestBytes.length : 0);
                    // Send request bytes then half-close write side per eth2 req/resp spec.
                    writeClosedOnly = true;  // Mark that next channelInactive is from our closeWrite
                    if (requestBytes != null && requestBytes.length > 0) {
                        ctx.writeAndFlush(Unpooled.wrappedBuffer(requestBytes)).addListener(f -> {
                            log.debug("[beacon-p2p] Request write complete, success={}", f.isSuccess());
                            stream.closeWrite();
                            log.debug("[beacon-p2p] closeWrite() called");
                        });
                    } else {
                        stream.closeWrite();
                        log.debug("[beacon-p2p] closeWrite() called (empty request)");
                    }
                    readyFuture.complete(ReqRespController.this);
                    super.channelActive(ctx);
                }

                @Override
                protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                    int readable = msg.readableBytes();
                    dataReceived = true;
                    byte[] bytes = new byte[readable];
                    msg.readBytes(bytes);
                    responseBuffer.write(bytes, 0, bytes.length);
                    log.debug("[beacon-p2p] channelRead0: {} bytes received, total={}, channelClosed={}",
                            readable, responseBuffer.size(), channelFullyClosed);
                }

                @Override
                public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
                    if (!dataReceived || responseFuture.isDone()) {
                        super.channelReadComplete(ctx);
                        return;
                    }

                    if (channelFullyClosed) {
                        // Channel is inactive but buffered data is still being delivered
                        // in multiple batches (e.g., 1+4+3+10 bytes, then 25680 bytes
                        // arriving ~40ms later). Use a short delay to accumulate all
                        // buffered reads before completing.
                        var prevClosed = completionTimer;
                        if (prevClosed != null) prevClosed.cancel(false);
                        completionTimer = ctx.executor().schedule(() -> {
                            if (!responseFuture.isDone() && responseBuffer.size() > 0) {
                                log.debug("[beacon-p2p] Completing response (post-close timer): {} bytes",
                                        responseBuffer.size());
                                responseFuture.complete(responseBuffer.toByteArray());
                            }
                        }, 150, java.util.concurrent.TimeUnit.MILLISECONDS);
                        super.channelReadComplete(ctx);
                        return;
                    }

                    // Don't use a short timer — large responses (e.g. bootstrap ~25KB)
                    // can arrive in multiple TCP segments spaced >200ms apart, which
                    // would cause premature completion with truncated data.
                    // Instead, rely on channelInactive (stream close) to complete.
                    // Use a long safety timer (5s) only as a fallback for muxer
                    // implementations that don't reliably fire channelInactive.
                    var prev = completionTimer;
                    if (prev != null) prev.cancel(false);
                    completionTimer = ctx.executor().schedule(() -> {
                        if (!responseFuture.isDone() && responseBuffer.size() > 0) {
                            log.debug("[beacon-p2p] Completing response (safety timer): {} bytes",
                                    responseBuffer.size());
                            responseFuture.complete(responseBuffer.toByteArray());
                        }
                    }, 5000, java.util.concurrent.TimeUnit.MILLISECONDS);
                    super.channelReadComplete(ctx);
                }

                @Override
                public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                    log.debug("[beacon-p2p] channelInactive fired, buffer size={}, dataReceived={}, writeClosedOnly={}",
                            responseBuffer.size(), dataReceived, writeClosedOnly);
                    if (writeClosedOnly && !dataReceived) {
                        // This channelInactive is from our closeWrite(), not a full close.
                        // Ignore it — data may still arrive on the read side.
                        // Only ignore if no data received yet — if data already arrived,
                        // the remote has responded and this is a real close.
                        writeClosedOnly = false;
                        super.channelInactive(ctx);
                        return;
                    }
                    writeClosedOnly = false;
                    // Mark channel as fully closed — any subsequent channelRead0
                    // calls are delivering buffered data and should complete immediately.
                    channelFullyClosed = true;
                    if (!dataReceived && responseBuffer.size() == 0) {
                        // No data arrived yet. On well-behaved peers, buffered data
                        // sometimes trickles in right after the close event (see the
                        // `channelFullyClosed`-gated path in channelReadComplete). On
                        // peers that goodbye/reset us mid-handshake (Lighthouse on a
                        // fork_digest mismatch, for example) no further data EVER
                        // arrives. Wait a short grace window for trailing buffered
                        // reads, then complete the future exceptionally so the caller
                        // learns about the close instead of hanging forever.
                        log.debug("[beacon-p2p] Channel closed with no data; scheduling 1s grace timer");
                        ctx.executor().schedule(() -> {
                            if (responseFuture.isDone()) return;
                            if (responseBuffer.size() > 0) {
                                log.debug("[beacon-p2p] Grace timer: completing with {} late bytes",
                                        responseBuffer.size());
                                responseFuture.complete(responseBuffer.toByteArray());
                            } else {
                                log.debug("[beacon-p2p] Grace timer: no data arrived, failing future");
                                responseFuture.completeExceptionally(
                                        new RuntimeException("Stream closed by peer with no response"));
                            }
                        }, 1_000, java.util.concurrent.TimeUnit.MILLISECONDS);
                        super.channelInactive(ctx);
                        return;
                    }
                    if (!responseFuture.isDone()) {
                        byte[] response = responseBuffer.toByteArray();
                        if (response.length == 0) {
                            responseFuture.completeExceptionally(
                                    new RuntimeException("Empty response (stream closed without data)"));
                        } else {
                            responseFuture.complete(response);
                        }
                    }
                    super.channelInactive(ctx);
                }

                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                    log.debug("[beacon-p2p] exceptionCaught: {}", cause.getMessage());
                    if (!responseFuture.isDone()) {
                        responseFuture.completeExceptionally(cause);
                    }
                    if (!readyFuture.isDone()) {
                        readyFuture.completeExceptionally(cause);
                    }
                    ctx.close();
                }
            };
        }
    }

    // =========================================================================
     // Responder: serves any peer-initiated stream for which the binding has
     // a ReqRespHandler registered (status, ping, metadata, goodbye, plus the
     // relayed light_client_* read protocols).
    // =========================================================================

    /**
     * Generic responder: reads the peer's request body (if any), decodes the
     * SSZ, delegates to a {@link ReqRespHandler}, and writes the response back
     * in the standard eth2 req/resp wire format:
     * <pre>
     *   0x00 || [fork_digest (4)] || varint(ssz_len) || snappy_framed(ssz_payload)
     * </pre>
     * Errors map to the spec's result codes:
     * <ul>
     *   <li>handler returns null → {@code ResourceUnavailable} (0x03)</li>
     *   <li>handler throws {@code IllegalArgumentException} → {@code InvalidRequest} (0x01)</li>
     *   <li>handler throws anything else → {@code ServerError} (0x02)</li>
     * </ul>
     */
    static class ResponderController {

        private final io.libp2p.core.Stream stream;
        private final ReqRespHandler handler;
        private final boolean hasContextBytes;
        private final Supplier<byte[]> forkDigestSupplier;
        private final int expectedRequestSize;
        private final String protocolId;
        private final String peerId;
        private final String agent;
        private final ByteArrayOutputStream incoming = new ByteArrayOutputStream();
        private volatile boolean responded;
        private volatile java.util.concurrent.ScheduledFuture<?> respondTimer;
        private final long startMs = System.currentTimeMillis();

        ResponderController(io.libp2p.core.Stream stream,
                            ReqRespHandler handler,
                            boolean hasContextBytes,
                            Supplier<byte[]> forkDigestSupplier,
                            int expectedRequestSize,
                            String protocolId,
                            String peerId,
                            String agent) {
            this.stream = stream;
            this.handler = handler;
            this.hasContextBytes = hasContextBytes;
            this.forkDigestSupplier = forkDigestSupplier;
            this.expectedRequestSize = expectedRequestSize;
            this.protocolId = protocolId;
            this.peerId = peerId;
            this.agent = agent;
        }

        ChannelHandler nettyHandler() {
            return new SimpleChannelInboundHandler<ByteBuf>() {

                @Override
                public void channelActive(ChannelHandlerContext ctx) throws Exception {
                    if (expectedRequestSize == 0) {
                        // No request body expected — respond right away.
                        tryRespond(ctx);
                        super.channelActive(ctx);
                        return;
                    }
                    // RESP_TIMEOUT safety: if we never see the full request,
                    // respond (or reject) after 1 s so the peer doesn't time us out.
                    respondTimer = ctx.executor().schedule(
                            () -> tryRespond(ctx),
                            1_000, java.util.concurrent.TimeUnit.MILLISECONDS);
                    super.channelActive(ctx);
                }

                @Override
                protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                    int readable = msg.readableBytes();
                    byte[] bytes = new byte[readable];
                    msg.readBytes(bytes);
                    incoming.write(bytes, 0, bytes.length);
                    if (!responded && canDecodeRequest()) {
                        var prev = respondTimer;
                        if (prev != null) prev.cancel(false);
                        tryRespond(ctx);
                    }
                }

                @Override
                public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
                    if (!responded && incoming.size() > 0) {
                        var prev = respondTimer;
                        if (prev != null) prev.cancel(false);
                        respondTimer = ctx.executor().schedule(
                                () -> tryRespond(ctx),
                                150, java.util.concurrent.TimeUnit.MILLISECONDS);
                    }
                    super.channelReadComplete(ctx);
                }

                @Override
                public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                    if (!responded) {
                        var prev = respondTimer;
                        if (prev != null) prev.cancel(false);
                        tryRespond(ctx);
                    }
                    super.channelInactive(ctx);
                }

                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                    log.debug("[beacon-p2p] responder exception proto={} peer={}: {}",
                            protocolId, peerId, cause.getMessage());
                    ctx.close();
                }
            };
        }

        private boolean canDecodeRequest() {
            if (expectedRequestSize <= 0) return true;
            byte[] raw = incoming.toByteArray();
            if (raw.length < 2) return false;
            try {
                ReqRespCodec.VarintResult v = ReqRespCodec.readVarint(raw, 0);
                if (v.value() != expectedRequestSize) return false;
                // Need at least the snappy stream-identifier frame (10 B) + a
                // compressed chunk header (4 B) before we can decompress.
                return raw.length - v.nextPos() >= 14;
            } catch (Exception e) {
                return false;
            }
        }

        private void tryRespond(ChannelHandlerContext ctx) {
            if (responded) return;
            responded = true;

            byte[] reqSsz = null;
            if (expectedRequestSize > 0) {
                reqSsz = parseRequestSsz(incoming.toByteArray());
                if (reqSsz == null) {
                    writeError(ctx, (byte) 0x01, "InvalidRequest: unparseable body");
                    return;
                }
            } else {
                reqSsz = new byte[0];
            }

            byte[] responseSsz;
            try {
                responseSsz = handler.handle(reqSsz, peerId);
            } catch (IllegalArgumentException e) {
                writeError(ctx, (byte) 0x01, "InvalidRequest: " + e.getMessage());
                return;
            } catch (Exception e) {
                log.debug("[beacon-p2p] responder handler for {} raised {}: {}",
                        protocolId, e.getClass().getSimpleName(), e.getMessage());
                writeError(ctx, (byte) 0x02, "ServerError");
                return;
            }

            if (responseSsz == null) {
                writeError(ctx, (byte) 0x03, "ResourceUnavailable");
                return;
            }

            try {
                byte[] response = encodeSuccessResponse(responseSsz);
                ctx.writeAndFlush(Unpooled.wrappedBuffer(response)).addListener(f -> {
                    long dur = System.currentTimeMillis() - startMs;
                    log.debug("[beacon-p2p] responder proto={} peer={} agent={} wrote {}B success={} durMs={}",
                            protocolId, peerId, agent, response.length, f.isSuccess(), dur);
                    try { stream.closeWrite(); } catch (Exception ignored) {}
                });
            } catch (Exception e) {
                log.warn("[beacon-p2p] responder encode/write failed proto={} peer={}: {}",
                        protocolId, peerId, e.getMessage());
                ctx.close();
            }
        }

        private void writeError(ChannelHandlerContext ctx, byte resultCode, String msg) {
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(resultCode);
                // Error body: SSZ ErrorMessage is a List[uint8, MAX=256]. We
                // emit the minimum compatible encoding: varint(len) + utf-8.
                byte[] utf8 = msg.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                ReqRespCodec.writeVarint(out, utf8.length);
                byte[] compressed = ReqRespCodec.snappyCompress(utf8);
                out.write(compressed);
                ctx.writeAndFlush(Unpooled.wrappedBuffer(out.toByteArray())).addListener(f -> {
                    try { stream.closeWrite(); } catch (Exception ignored) {}
                });
            } catch (Exception e) {
                ctx.close();
            }
        }

        private byte[] encodeSuccessResponse(byte[] ssz) throws IOException {
            byte[] compressed = ReqRespCodec.snappyCompress(ssz);
            ByteArrayOutputStream out = new ByteArrayOutputStream(compressed.length + 16);
            out.write(0x00);
            if (hasContextBytes) {
                byte[] fd = forkDigestSupplier.get();
                if (fd == null || fd.length != 4) fd = new byte[4];
                out.write(fd);
            }
            ReqRespCodec.writeVarint(out, ssz.length);
            out.write(compressed);
            return out.toByteArray();
        }

        private static byte[] parseRequestSsz(byte[] raw) {
            if (raw == null || raw.length < 2) return null;
            try {
                ReqRespCodec.VarintResult v = ReqRespCodec.readVarint(raw, 0);
                int uncompressedLen = v.value();
                int snappyStart = v.nextPos();
                if (uncompressedLen <= 0 || snappyStart >= raw.length) return null;
                byte[] compressed = new byte[raw.length - snappyStart];
                System.arraycopy(raw, snappyStart, compressed, 0, compressed.length);
                return ReqRespCodec.snappyDecompress(compressed);
            } catch (Exception e) {
                return null;
            }
        }
    }
}
