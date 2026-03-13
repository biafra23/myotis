package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;

import java.util.List;

/**
 * p2p/Hello (message code 0x00).
 *
 * RLP: [protocolVersion, clientId, [[capName, capVersion], ...], listenPort, nodeId(64)]
 */
public final class HelloMessage {

    public static final int CODE = 0x00;

    private static final int PROTOCOL_VERSION = 5;

    public record Capability(String name, int version) {}

    public final int protocolVersion;
    public final String clientId;
    public final List<Capability> capabilities;
    public final int listenPort;
    public final Bytes nodeId; // 64-byte public key

    private HelloMessage(int protocolVersion, String clientId,
                         List<Capability> capabilities, int listenPort, Bytes nodeId) {
        this.protocolVersion = protocolVersion;
        this.clientId = clientId;
        this.capabilities = capabilities;
        this.listenPort = listenPort;
        this.nodeId = nodeId;
    }

    public static byte[] encode(Bytes nodePublicKey, int tcpPort) {
        return RLP.encodeList(writer -> {
            writer.writeInt(PROTOCOL_VERSION);
            writer.writeString("ethp2p/0.1.0");
            writer.writeList(capWriter -> {
                // eth/67
                capWriter.writeList(cap -> {
                    cap.writeString("eth");
                    cap.writeInt(67);
                });
                // eth/68
                capWriter.writeList(cap -> {
                    cap.writeString("eth");
                    cap.writeInt(68);
                });
                // eth/69
                capWriter.writeList(cap -> {
                    cap.writeString("eth");
                    cap.writeInt(69);
                });
                // snap/1
                capWriter.writeList(cap -> {
                    cap.writeString("snap");
                    cap.writeInt(1);
                });
            });
            writer.writeInt(tcpPort);
            writer.writeValue(nodePublicKey); // 64-byte uncompressed public key
        }).toArrayUnsafe();
    }

    public static HelloMessage decode(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> {
            int protoVer = reader.readInt();
            String clientId = reader.readString();
            List<Capability> caps = reader.readListContents(
                capReader -> capReader.readList(cap -> new Capability(cap.readString(), cap.readInt())));
            int port = reader.readInt();
            Bytes nodeId = reader.readValue();
            return new HelloMessage(protoVer, clientId, caps, port, nodeId);
        });
    }

    @Override
    public String toString() {
        return "Hello{client=" + clientId + ", caps=" + capabilities + "}";
    }
}
