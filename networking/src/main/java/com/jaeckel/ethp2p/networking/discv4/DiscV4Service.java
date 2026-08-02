package com.jaeckel.ethp2p.networking.discv4;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * discv4 peer discovery service.
 *
 * Runs a UDP Netty channel, bootstraps from mainnet bootnodes,
 * and continuously looks up random nodes to populate the routing table.
 */
public final class DiscV4Service implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(DiscV4Service.class);

    private final NodeKey nodeKey;
    private final List<InetSocketAddress> bootnodes;
    private final KademliaTable table;
    private final NioEventLoopGroup group;
    private Channel channel;
    private DiscV4Handler handler;
    private ScheduledExecutorService scheduler;
    private final Consumer<KademliaTable.Entry> onPeerDiscovered;

    /** Endpoint ("ip:port") → last probe millis (see {@link #probeEndpoint}). */
    private final ConcurrentHashMap<String, Long> probedEndpoints = new ConcurrentHashMap<>();
    private static final long PROBE_MIN_INTERVAL_MS = 60 * 60 * 1000L; // 1h per endpoint
    private static final int PROBE_MAP_MAX = 1024;

    public DiscV4Service(NodeKey nodeKey, List<InetSocketAddress> bootnodes,
                         Consumer<KademliaTable.Entry> onPeerDiscovered) {
        this.nodeKey = nodeKey;
        this.bootnodes = bootnodes;
        this.table = new KademliaTable(nodeKey.nodeId());
        this.group = new NioEventLoopGroup(1);
        this.onPeerDiscovered = onPeerDiscovered;
    }

    public void start(int udpPort) throws InterruptedException {
        handler = new DiscV4Handler(nodeKey, table, onPeerDiscovered);

        Bootstrap b = new Bootstrap()
            .group(group)
            .channel(NioDatagramChannel.class)
            // discv4 NEIGHBORS packets are large (~1.2KB, up to the 1280B spec
            // cap). Netty's default datagram recv allocator can hand back a
            // buffer smaller than the datagram on some stacks (observed on
            // Android/ART: Ping/Pong arrive but NEIGHBORS never does), which
            // truncates the read so the packet is silently dropped. Pin a recv
            // buffer comfortably above the spec max so neighbors always fit.
            .option(ChannelOption.RCVBUF_ALLOCATOR, new FixedRecvByteBufAllocator(4096))
            .option(ChannelOption.SO_RCVBUF, 1 << 20)
            .handler(new ChannelInitializer<NioDatagramChannel>() {
                @Override
                protected void initChannel(NioDatagramChannel ch) {
                    ch.pipeline().addLast(handler);
                }
            });

        channel = b.bind(udpPort).sync().channel();
        log.info("[discv4] Listening on UDP port {}", udpPort);

        // Bootstrap: ping all bootnodes
        InetSocketAddress localAddr = new InetSocketAddress("0.0.0.0", udpPort);
        for (InetSocketAddress bootnode : bootnodes) {
            sendPing(localAddr, bootnode);
        }

        // Periodic refresh: ping random peers to cascade Kademlia discovery every 15s
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "discv4-refresh");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::refreshTable, 10, 15, TimeUnit.SECONDS);
    }

    /** Send a FindNode for our own ID to a specific peer. */
    public void findNode(InetSocketAddress target, Bytes nodeId) {
        Bytes packet = Packet.encodeFindNode(nodeKey, nodeId);
        sendRaw(packet, target);
    }

    /**
     * Bond with a specific UDP endpoint so its neighbourhood enters the walk —
     * used for peers PROVEN over TCP (reached eth READY) whose UDP side the
     * table may never have seen (e.g. DNS-ENR-pool peers): the periodic refresh
     * only FindNodes peers already in the table, so without this nudge a proven
     * peer's neighbours are never asked for. The ping establishes the bond and
     * (on pong) lands the peer in the table, where {@link #refreshTable} then
     * samples it; the immediate FindNode is a best-effort head start (peers may
     * ignore it until the bond completes — the refresh loop retries later).
     * Per-address rate limit so repeated READY events don't re-probe.
     */
    public void probeEndpoint(InetSocketAddress udpAddr) {
        if (channel == null || !channel.isActive()) return;
        String key = udpAddr.getHostString() + ":" + udpAddr.getPort();
        if (!shouldProbe(key, System.currentTimeMillis())) return;
        log.debug("[discv4] probing proven peer endpoint {}", udpAddr);
        sendPing((InetSocketAddress) channel.localAddress(), udpAddr);
        findNode(udpAddr, nodeKey.publicKeyBytes());
    }

    /** Dedup/rate-limit decision for {@link #probeEndpoint} (package-private for
     *  tests). Bounded, coarse: the map is dropped wholesale when oversized —
     *  probes are a nudge, not bookkeeping, so losing history just allows an
     *  early re-probe. Races between concurrent READY events are benign for the
     *  same reason (worst case one duplicate ping+FindNode). */
    boolean shouldProbe(String key, long now) {
        if (probedEndpoints.size() > PROBE_MAP_MAX) probedEndpoints.clear();
        Long last = probedEndpoints.putIfAbsent(key, now);
        if (last == null) return true;
        if (now - last < PROBE_MIN_INTERVAL_MS) return false;
        probedEndpoints.put(key, now);
        return true;
    }

    public KademliaTable table() {
        return table;
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------
    private void sendPing(InetSocketAddress from, InetSocketAddress to) {
        Bytes pingPacket = Packet.encodePing(nodeKey, from, to);
        // Store ping hash (first 32 bytes) for pong verification
        Bytes32 pingHash = Bytes32.wrap(pingPacket, 0);
        handler.recordPingSent(to, pingHash);
        sendRaw(pingPacket, to);
        log.debug("[discv4] Ping → {}", to);
    }

    private void sendRaw(Bytes packet, InetSocketAddress dest) {
        if (channel == null || !channel.isActive()) return;
        ByteBuf buf = channel.alloc().buffer(packet.size());
        buf.writeBytes(packet.toArrayUnsafe());
        channel.writeAndFlush(new DatagramPacket(buf, dest));
    }

    private void refreshTable() {
        List<KademliaTable.Entry> peers = table.allPeers();
        log.debug("[discv4] Refresh: table size = {}", peers.size());
        InetSocketAddress localAddr = (InetSocketAddress) channel.localAddress();
        if (peers.isEmpty()) {
            // Re-ping bootnodes if table is empty
            for (InetSocketAddress bootnode : bootnodes) {
                sendPing(localAddr, bootnode);
            }
            return;
        }
        // Send FindNode to bootnodes (they have our bond cached from previous runs).
        for (InetSocketAddress bootnode : bootnodes) {
            findNode(bootnode, nodeKey.publicKeyBytes());
        }
        // Send FindNode to random discovered peers to traverse deeper into the network.
        // We ping first (to establish bond), then send FindNode.
        List<KademliaTable.Entry> sample = new ArrayList<>(peers);
        Collections.shuffle(sample);
        int count = Math.min(10, sample.size());
        // Use a random target to discover diverse peers across the keyspace
        Bytes randomTarget = Bytes.random(64);
        for (int i = 0; i < count; i++) {
            InetSocketAddress peerAddr = sample.get(i).udpAddr();
            sendPing(localAddr, peerAddr);
            findNode(peerAddr, randomTarget);
        }
    }

    @Override
    public void close() {
        if (scheduler != null) scheduler.shutdownNow();
        if (channel != null) channel.close();
        group.shutdownGracefully();
        log.info("[discv4] Stopped");
    }
}
