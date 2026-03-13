package com.jaeckel.ethp2p.consensus.libp2p;

import io.libp2p.core.Host;
import io.libp2p.core.PeerId;
import io.libp2p.core.StreamPromise;
import io.libp2p.core.crypto.PrivKey;
import io.libp2p.core.dsl.BuilderJKt;
import io.libp2p.core.dsl.Builder;
import io.libp2p.core.dsl.HostBuilder;
import io.libp2p.core.multiformats.Multiaddr;
import io.libp2p.core.multistream.ProtocolBinding;
import io.libp2p.core.multistream.ProtocolDescriptor;
import io.libp2p.core.mux.StreamMuxerProtocol;
import io.libp2p.core.P2PChannel;
import io.libp2p.core.crypto.KeyType;
import io.libp2p.crypto.keys.Secp256k1Kt;
import io.libp2p.crypto.keys.Ed25519Kt;
import io.libp2p.security.noise.NoiseXXSecureChannel;
import io.libp2p.security.tls.TlsSecureChannel;
import io.libp2p.transport.tcp.TcpTransport;
import io.netty.handler.logging.LogLevel;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Debug test: attempt a Noise XX handshake to a local Lighthouse node.
 * Run with: ./gradlew :consensus:test --tests "com.jaeckel.ethp2p.consensus.libp2p.NoiseHandshakeDebugTest"
 */
@Disabled("Manual/debug harness requiring a local Lighthouse node — not for CI")
class NoiseHandshakeDebugTest {

    private static final Logger log = LoggerFactory.getLogger(NoiseHandshakeDebugTest.class);

    // Local Lighthouse
    static final String PEER_MULTIADDR =
            "/ip4/172.17.0.1/tcp/9100/p2p/16Uiu2HAm5AH9YsNjHqLsQofyd1WUBVxyPY5cPC8Sec3gVwJPU7wD";

    // Simple ping protocol just to test connectivity
    static final String PROTOCOL = "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy";

    @Test
    void testNoiseHandshakeWithHostBuilder() throws Exception {
        log.info("=== Test 1: HostBuilder with BiFunction, Ed25519, yamux+mplex ===");
        PrivKey privKey = Ed25519Kt.generateEd25519KeyPair().component1();
        log.info("Generated Ed25519 identity key, peerId={}", PeerId.fromPubKey(privKey.publicKey()));

        Host host = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> {
                    log.info("SecureChannel factory called with key type={}, muxers={}",
                            key.getClass().getSimpleName(), muxers);
                    return new NoiseXXSecureChannel(key, muxers);
                })
                .muxer(StreamMuxerProtocol::getYamux)
                .muxer(StreamMuxerProtocol::getMplex)
                .builderModifier(b -> {
                    // Override identity to Ed25519 (default is ECDSA P-256 which Lighthouse may reject)
                    b.getIdentity().random(KeyType.ED25519);
                    b.getDebug().getAfterSecureHandler().addLogger(LogLevel.ERROR, "after-secure");
                })
                .build();

        try {
            host.start().join();
            log.info("Host started, peerId={}", host.getPeerId());

            connectAndTest(host, "HostBuilder-Ed25519");
        } finally {
            host.stop().join();
        }
    }

    @Test
    void testNoiseHandshakeWithSecp256k1() throws Exception {
        log.info("=== Test 2: HostBuilder with BiFunction, Secp256k1, yamux+mplex ===");
        PrivKey privKey = Secp256k1Kt.generateSecp256k1KeyPair().component1();
        log.info("Generated Secp256k1 identity key, peerId={}", PeerId.fromPubKey(privKey.publicKey()));

        Host host = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> {
                    log.info("SecureChannel factory called with key type={}, muxers={}",
                            key.getClass().getSimpleName(), muxers);
                    return new NoiseXXSecureChannel(key, muxers);
                })
                .muxer(StreamMuxerProtocol::getYamux)
                .muxer(StreamMuxerProtocol::getMplex)
                .build();

        try {
            host.start().join();
            log.info("Host started, peerId={}", host.getPeerId());

            connectAndTest(host, "HostBuilder-Secp256k1");
        } finally {
            host.stop().join();
        }
    }

    @Test
    void testNoiseHandshakeYamuxOnly() throws Exception {
        log.info("=== Test 3: HostBuilder with BiFunction, Ed25519, yamux ONLY ===");
        PrivKey privKey = Ed25519Kt.generateEd25519KeyPair().component1();

        Host host = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> {
                    log.info("SecureChannel factory called with key type={}, muxers={}",
                            key.getClass().getSimpleName(), muxers);
                    return new NoiseXXSecureChannel(key, muxers);
                })
                .muxer(StreamMuxerProtocol::getYamux)
                .build();

        try {
            host.start().join();
            log.info("Host started, peerId={}", host.getPeerId());

            connectAndTest(host, "HostBuilder-YamuxOnly");
        } finally {
            host.stop().join();
        }
    }

    @Test
    void testTlsSecureChannel() throws Exception {
        log.info("=== Test 5: TLS secure channel with early muxer negotiation ===");
        Host host = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> {
                    log.info("TLS SecureChannel factory called, key type={}, muxers={}",
                            key.getClass().getSimpleName(), muxers);
                    return new TlsSecureChannel(key, muxers);
                })
                .muxer(StreamMuxerProtocol::getYamux)
                .muxer(StreamMuxerProtocol::getMplex)
                .build();

        try {
            host.start().join();
            log.info("Host started, peerId={}", host.getPeerId());

            connectAndTest(host, "TLS");
        } finally {
            host.stop().join();
        }
    }

    @Test
    void testBothNoiseAndTls() throws Exception {
        log.info("=== Test 6: Both Noise + TLS secure channels ===");
        Host host = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> {
                    log.info("Noise SecureChannel factory called");
                    return new NoiseXXSecureChannel(key, muxers);
                })
                .secureChannel((key, muxers) -> {
                    log.info("TLS SecureChannel factory called");
                    return new TlsSecureChannel(key, muxers);
                })
                .muxer(StreamMuxerProtocol::getYamux)
                .muxer(StreamMuxerProtocol::getMplex)
                .build();

        try {
            host.start().join();
            log.info("Host started, peerId={}", host.getPeerId());

            connectAndTest(host, "Noise+TLS");
        } finally {
            host.stop().join();
        }
    }

    @Test
    void testNoiseHandshakeSingleArgConstructor() throws Exception {
        log.info("=== Test 4: HostBuilder with single-arg NoiseXXSecureChannel ===");
        Host host = new HostBuilder()
                .transport(TcpTransport::new)
                .secureChannel((key, muxers) -> {
                    log.info("SecureChannel factory called (ignoring muxers), key type={}",
                            key.getClass().getSimpleName());
                    return new NoiseXXSecureChannel(key);
                })
                .muxer(StreamMuxerProtocol::getYamux)
                .muxer(StreamMuxerProtocol::getMplex)
                .build();

        try {
            host.start().join();
            log.info("Host started, peerId={}", host.getPeerId());

            connectAndTest(host, "SingleArg");
        } finally {
            host.stop().join();
        }
    }

    private void connectAndTest(Host host, String label) {
        try {
            Multiaddr peerAddr = new Multiaddr(PEER_MULTIADDR);
            PeerId peerId = peerAddr.getPeerId();
            log.info("[{}] Connecting to peer={} at {}", label, peerId, PEER_MULTIADDR);

            CompletableFuture<String> result = new CompletableFuture<>();

            SimpleBinding binding = new SimpleBinding(PROTOCOL, result);
            host.addProtocolHandler(binding);

            StreamPromise<?> promise = host.newStream(List.of(PROTOCOL), peerId, peerAddr);

            promise.getStream().whenComplete((stream, ex) -> {
                if (ex != null) {
                    log.error("[{}] Stream open failed: {}", label, ex.getMessage(), ex);
                    result.completeExceptionally(ex);
                } else {
                    log.info("[{}] Stream opened successfully!", label);
                }
            });

            promise.getController().whenComplete((ctrl, ex) -> {
                if (ex != null) {
                    log.error("[{}] Controller failed: {}", label, ex.getMessage(), ex);
                    if (!result.isDone()) result.completeExceptionally(ex);
                } else {
                    log.info("[{}] Controller obtained: {}", label, ctrl);
                }
            });

            try {
                String res = result.get(15, TimeUnit.SECONDS);
                log.info("[{}] Result: {}", label, res);
            } catch (Exception e) {
                log.error("[{}] Test failed: {}", label, e.getMessage());
            }
        } catch (Exception e) {
            log.error("[{}] Connection error: {}", label, e.getMessage(), e);
        }
    }

    static class SimpleBinding implements ProtocolBinding<Object> {
        private final String protocol;
        private final CompletableFuture<String> result;

        SimpleBinding(String protocol, CompletableFuture<String> result) {
            this.protocol = protocol;
            this.result = result;
        }

        @Override
        public ProtocolDescriptor getProtocolDescriptor() {
            return new ProtocolDescriptor(protocol);
        }

        @Override
        public CompletableFuture<Object> initChannel(P2PChannel channel, String negotiatedProtocol) {
            log.info("initChannel called for protocol={}", negotiatedProtocol);
            CompletableFuture<Object> ready = new CompletableFuture<>();

            channel.pushHandler(new SimpleChannelInboundHandler<ByteBuf>() {
                @Override
                public void channelActive(ChannelHandlerContext ctx) throws Exception {
                    log.info("Protocol channel active, sending empty request");
                    // For finality_update, send an empty request (just the snappy-framed empty payload)
                    ctx.writeAndFlush(io.netty.buffer.Unpooled.wrappedBuffer(
                            ReqRespCodec.encodeEmptyRequest()));
                    ready.complete(new Object());
                    super.channelActive(ctx);
                }

                @Override
                protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                    int readable = msg.readableBytes();
                    log.info("Received {} bytes from peer", readable);
                    if (!result.isDone()) {
                        result.complete("Received " + readable + " bytes");
                    }
                }

                @Override
                public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                    log.info("Protocol channel inactive");
                    if (!result.isDone()) {
                        result.complete("Channel closed (no data)");
                    }
                    super.channelInactive(ctx);
                }

                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                    log.error("Protocol channel error: {}", cause.getMessage());
                    if (!result.isDone()) {
                        result.completeExceptionally(cause);
                    }
                }
            });

            return ready;
        }
    }
}
