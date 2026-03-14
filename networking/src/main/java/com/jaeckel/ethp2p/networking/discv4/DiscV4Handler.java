package com.jaeckel.ethp2p.networking.discv4;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.function.Consumer;

/**
 * Netty UDP handler for discv4.
 *
 * Processes incoming Ping/Pong/FindNode/Neighbors packets and
 * notifies the DiscV4Service of new peers.
 */
public final class DiscV4Handler extends SimpleChannelInboundHandler<DatagramPacket> {

    private static final Logger log = LoggerFactory.getLogger(DiscV4Handler.class);

    private final NodeKey nodeKey;
    private final KademliaTable table;
    private final Consumer<KademliaTable.Entry> onPeerDiscovered;

    // Track pending ping → expected pong hash
    private final ConcurrentHashMap<InetSocketAddress, Bytes32> pendingPings = new ConcurrentHashMap<>();

    public DiscV4Handler(NodeKey nodeKey, KademliaTable table,
                         Consumer<KademliaTable.Entry> onPeerDiscovered) {
        this.nodeKey = nodeKey;
        this.table = table;
        this.onPeerDiscovered = onPeerDiscovered;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket msg) {
        ByteBuf buf = msg.content();
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        Bytes raw = Bytes.wrap(bytes);
        InetSocketAddress sender = msg.sender();

        try {
            Packet.Parsed parsed = Packet.parse(raw);
            handlePacket(ctx, parsed, sender);
        } catch (Exception e) {
            log.debug("Discarding invalid packet from {}: {}", sender, e.getMessage());
        }
    }

    private void handlePacket(ChannelHandlerContext ctx, Packet.Parsed p, InetSocketAddress sender) {
        switch (p.type()) {
            case Packet.TYPE_PING -> handlePing(ctx, p, sender);
            case Packet.TYPE_PONG -> handlePong(ctx, p, sender);
            case Packet.TYPE_NEIGHBORS -> handleNeighbors(p, sender);
            default -> log.trace("Unknown packet type 0x{:02x} from {}", p.type(), sender);
        }
    }

    private void handlePing(ChannelHandlerContext ctx, Packet.Parsed p, InetSocketAddress sender) {
        log.debug("[discv4] Ping from {}", sender);
        // Respond with Pong
        InetSocketAddress localAddr = (InetSocketAddress) ctx.channel().localAddress();
        Bytes pong = Packet.encodePong(nodeKey, sender, p.hash());
        sendPacket(ctx, pong, sender);
        // Extract TCP port from Ping FROM endpoint
        int tcpPort = sender.getPort(); // default same as UDP
        try {
            int[] ports = Packet.decodePingFromTcpPort(p.data());
            if (ports[1] > 0) tcpPort = ports[1];
        } catch (Exception ignored) {}
        // Add to routing table with TCP port
        Bytes nodeId = p.senderKey().bytes();
        KademliaTable.Entry entry = new KademliaTable.Entry(
            sender, tcpPort, nodeId, System.currentTimeMillis());
        table.add(entry);
        onPeerDiscovered.accept(entry);
    }

    private void handlePong(ChannelHandlerContext ctx, Packet.Parsed p, InetSocketAddress sender) {
        Bytes32 pingHash = Packet.decodePongPingHash(p.data());
        Bytes32 expected = pendingPings.remove(sender);
        if (expected != null && expected.equals(pingHash)) {
            log.info("[discv4] Pong from {} (verified)", sender);
            Bytes nodeId = p.senderKey().bytes();
            KademliaTable.Entry entry = new KademliaTable.Entry(
                sender, sender.getPort(), nodeId, System.currentTimeMillis());
            table.add(entry);
            onPeerDiscovered.accept(entry);
            // NOTE: Do NOT send FindNode here. go-ethereum requires "LastPongReceived"
            // from us before answering FindNode. We must first respond to the bootnode's
            // return Ping before initiating any FindNode requests.
        } else {
            log.debug("[discv4] Unsolicited/mismatched pong from {}", sender);
        }
    }

    private void handleNeighbors(Packet.Parsed p, InetSocketAddress sender) {
        try {
            java.util.List<Packet.DiscoveredPeer> peers = Packet.decodeNeighbors(p.data());
            log.info("[discv4] {} neighbors from {} (table={} before)", peers.size(), sender, table.size());
            for (Packet.DiscoveredPeer peer : peers) {
                if (peer == null) continue;
                log.debug("[discv4]   neighbor {}:{} tcp={} nodeId={}...",
                    peer.udpAddr().getAddress().getHostAddress(), peer.udpAddr().getPort(),
                    peer.tcpPort(), peer.nodeId().toHexString().substring(0, 8));
                KademliaTable.Entry entry = new KademliaTable.Entry(
                    peer.udpAddr(), peer.tcpPort(), peer.nodeId(),
                    System.currentTimeMillis());
                table.add(entry);
                onPeerDiscovered.accept(entry);
            }
        } catch (Exception e) {
            log.info("Failed to decode Neighbors from {}: {}", sender, e.getMessage());
        }
    }

    private void addToTable(Packet.Parsed p, InetSocketAddress sender) {
        Bytes nodeId = p.senderKey().bytes();
        KademliaTable.Entry entry = new KademliaTable.Entry(
            sender, 0, nodeId, System.currentTimeMillis());
        table.add(entry);
        onPeerDiscovered.accept(entry);
    }

    /** Record that we sent a ping; store its hash so we can verify the pong. */
    public void recordPingSent(InetSocketAddress target, Bytes32 pingHash) {
        pendingPings.put(target, pingHash);
    }

    private void sendPacket(ChannelHandlerContext ctx, Bytes packet, InetSocketAddress dest) {
        ByteBuf buf = ctx.alloc().buffer(packet.size());
        buf.writeBytes(packet.toArrayUnsafe());
        ctx.writeAndFlush(new DatagramPacket(buf, dest));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("[discv4] Channel error", cause);
    }
}
