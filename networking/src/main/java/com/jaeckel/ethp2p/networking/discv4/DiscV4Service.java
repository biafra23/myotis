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
