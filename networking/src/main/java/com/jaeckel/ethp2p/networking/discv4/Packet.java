package com.jaeckel.ethp2p.networking.discv4;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.rlp.RLP;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;

/**
 * discv4 wire packets.
 *
 * Packet format: hash(32) || signature(65) || packet-type(1) || packet-data(RLP)
 *   hash = keccak256(signature || packet-type || packet-data)
 *   signature = secp256k1 sign(keccak256(packet-type || packet-data))
 *
 * Packet types:
 *   0x01 = Ping
 *   0x02 = Pong
 *   0x03 = FindNode
 *   0x04 = Neighbors
 *   0x05 = ENRRequest
 *   0x06 = ENRResponse
 */
public final class Packet {

    public static final byte TYPE_PING = 0x01;
    public static final byte TYPE_PONG = 0x02;
    public static final byte TYPE_FIND_NODE = 0x03;
    public static final byte TYPE_NEIGHBORS = 0x04;

    // Protocol version for Ping/Pong
    private static final int VERSION = 4;

    // Expiry: 20 seconds from now
    private static long expiry() {
        return Instant.now().getEpochSecond() + 20;
    }

    /** Encode an endpoint as [ip(bytes), udpPort(int), tcpPort(int)] */
    private static Bytes encodeEndpoint(InetSocketAddress addr, int tcpPort) {
        return RLP.encodeList(writer -> {
            writer.writeValue(Bytes.wrap(addr.getAddress().getAddress())); // 4 or 16 bytes
            writer.writeInt(addr.getPort()); // UDP port
            writer.writeInt(tcpPort);        // TCP port (0 if unknown)
        });
    }

    // -------------------------------------------------------------------------
    // Ping (0x01): [version, from, to, expiry, enr-seq?]
    // -------------------------------------------------------------------------
    public static Bytes encodePing(NodeKey key, InetSocketAddress from, InetSocketAddress to) {
        Bytes data = RLP.encodeList(writer -> {
            writer.writeInt(VERSION);
            writer.writeRLP(encodeEndpoint(from, from.getPort()));
            writer.writeRLP(encodeEndpoint(to, 0));
            writer.writeLong(expiry());
        });
        return encode(key, TYPE_PING, data);
    }

    // -------------------------------------------------------------------------
    // Pong (0x02): [to, ping-hash, expiry, enr-seq?]
    // -------------------------------------------------------------------------
    public static Bytes encodePong(NodeKey key, InetSocketAddress to, Bytes32 pingHash) {
        Bytes data = RLP.encodeList(writer -> {
            writer.writeRLP(encodeEndpoint(to, 0));
            writer.writeValue(pingHash);
            writer.writeLong(expiry());
        });
        return encode(key, TYPE_PONG, data);
    }

    // -------------------------------------------------------------------------
    // FindNode (0x03): [target(64 bytes), expiry]
    // -------------------------------------------------------------------------
    public static Bytes encodeFindNode(NodeKey key, Bytes target) {
        Bytes data = RLP.encodeList(writer -> {
            writer.writeValue(target);
            writer.writeLong(expiry());
        });
        return encode(key, TYPE_FIND_NODE, data);
    }

    // -------------------------------------------------------------------------
    // Wire encoding
    // -------------------------------------------------------------------------
    private static Bytes encode(NodeKey key, byte type, Bytes data) {
        // 1. Hash input = type || data
        Bytes typeAndData = Bytes.concatenate(Bytes.of(type), data);
        Bytes32 sigHash = Hash.keccak256(typeAndData);

        // 2. Sign
        SECP256K1.Signature sig = key.sign(sigHash);
        // Recovery id + r + s → 65 bytes: [r(32) | s(32) | v(1)]
        byte[] sigBytes = new byte[65];
        byte[] r = sig.r().toByteArray();
        byte[] s = sig.s().toByteArray();
        // r and s may have leading zero padding from BigInteger
        int rOff = Math.max(0, r.length - 32);
        int sOff = Math.max(0, s.length - 32);
        System.arraycopy(r, rOff, sigBytes, 32 - Math.min(r.length, 32), Math.min(r.length, 32));
        System.arraycopy(s, sOff, sigBytes, 64 - Math.min(s.length, 32), Math.min(s.length, 32));
        sigBytes[64] = (byte) sig.v(); // recovery id (0 or 1)

        // 3. Hash = keccak256(signature || type || data)
        Bytes sigAndPayload = Bytes.concatenate(Bytes.wrap(sigBytes), typeAndData);
        Bytes32 hash = Hash.keccak256(sigAndPayload);

        // 4. Final packet: hash(32) || sig(65) || type(1) || data
        return Bytes.concatenate(hash, Bytes.wrap(sigBytes), typeAndData);
    }

    // -------------------------------------------------------------------------
    // Parsing
    // -------------------------------------------------------------------------
    public record Parsed(Bytes32 hash, byte type, Bytes data, SECP256K1.PublicKey senderKey) {}

    public static Parsed parse(Bytes packet) {
        if (packet.size() < 98) {
            throw new IllegalArgumentException("Packet too short: " + packet.size());
        }
        Bytes32 hash = Bytes32.wrap(packet, 0);
        Bytes sigBytes = packet.slice(32, 65);
        byte type = packet.get(97);
        Bytes data = packet.slice(98);

        // Verify hash
        Bytes32 expectedHash = Hash.keccak256(packet.slice(32));
        if (!hash.equals(expectedHash)) {
            throw new IllegalArgumentException("Packet hash mismatch");
        }

        // Recover sender public key
        Bytes32 msgHash = Hash.keccak256(packet.slice(97)); // type || data
        SECP256K1.Signature sig = recoverSignature(sigBytes);
        SECP256K1.PublicKey senderKey = SECP256K1.PublicKey.recoverFromHashAndSignature(msgHash, sig);
        if (senderKey == null) {
            throw new IllegalArgumentException("Cannot recover public key from signature");
        }

        return new Parsed(hash, type, data, senderKey);
    }

    private static SECP256K1.Signature recoverSignature(Bytes sigBytes) {
        // sigBytes: r(32) | s(32) | v(1)
        java.math.BigInteger r = new java.math.BigInteger(1, sigBytes.slice(0, 32).toArrayUnsafe());
        java.math.BigInteger s = new java.math.BigInteger(1, sigBytes.slice(32, 32).toArrayUnsafe());
        int v = sigBytes.get(64) & 0xFF;
        return SECP256K1.Signature.create((byte) v, r, s);
    }

    // -------------------------------------------------------------------------
    // Decoders for packet data
    // -------------------------------------------------------------------------
    public static InetSocketAddress decodePingDestination(Bytes data) {
        return RLP.decodeList(data, reader -> {
            reader.skipNext(); // version
            reader.skipNext(); // from endpoint
            return decodeEndpoint(reader);
        });
    }

    /** Decode the FROM endpoint (with TCP port) from a Ping packet. */
    public static int[] decodePingFromTcpPort(Bytes data) {
        // Returns [udpPort, tcpPort] of the sender's self-reported endpoint
        return RLP.decodeList(data, reader -> {
            reader.skipNext(); // version
            return reader.readList(r -> {
                r.readValue(); // ip
                int udp = r.readInt();
                int tcp = r.readInt();
                return new int[]{udp, tcp};
            });
        });
    }

    public static Bytes32 decodePongPingHash(Bytes data) {
        return RLP.decodeList(data, reader -> {
            reader.skipNext(); // to endpoint
            return Bytes32.wrap(reader.readValue());
        });
    }

    public static Bytes decodeFindNodeTarget(Bytes data) {
        return RLP.decodeList(data, reader -> reader.readValue());
    }

    public static List<DiscoveredPeer> decodeNeighbors(Bytes data) {
        return RLP.decodeList(data, outerReader -> {
            // Neighbors: [[node, node, ...], expiry]
            // Each node: [ip, udp-port, tcp-port, node-id]
            List<DiscoveredPeer> peers = new java.util.ArrayList<>();
            outerReader.readList(nodesReader -> {
                while (!nodesReader.isComplete()) {
                    try {
                        nodesReader.readList(peerReader -> {
                            Bytes ip = peerReader.readValue();
                            int udpPort = peerReader.readInt();
                            int tcpPort = peerReader.readInt();
                            Bytes nodeId = peerReader.readValue();
                            try {
                                InetAddress addr = InetAddress.getByAddress(ip.toArrayUnsafe());
                                peers.add(new DiscoveredPeer(
                                    new InetSocketAddress(addr, udpPort), tcpPort, nodeId));
                            } catch (Exception ignored) {}
                            return null;
                        });
                    } catch (Exception ignored) { break; }
                }
                return null;
            });
            return peers;
        });
    }

    private static InetSocketAddress decodeEndpoint(org.apache.tuweni.rlp.RLPReader reader) {
        return reader.readList(r -> {
            Bytes ip = r.readValue();
            int udpPort = r.readInt();
            r.skipNext(); // tcp port
            try {
                return new InetSocketAddress(InetAddress.getByAddress(ip.toArrayUnsafe()), udpPort);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public record DiscoveredPeer(InetSocketAddress udpAddr, int tcpPort, Bytes nodeId) {}
}
