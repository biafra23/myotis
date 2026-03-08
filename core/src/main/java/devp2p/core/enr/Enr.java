package devp2p.core.enr;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPReader;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Ethereum Node Record (ENR) as defined in EIP-778.
 *
 * Format: RLP([signature, seq, k, v, k, v, ...])
 * Keys relevant to devp2p: "id", "ip", "tcp", "udp", "secp256k1"
 */
public final class Enr {

    private final long seq;
    private final Map<String, Bytes> pairs;
    private final Bytes rawRlp;

    private Enr(long seq, Map<String, Bytes> pairs, Bytes rawRlp) {
        this.seq = seq;
        this.pairs = pairs;
        this.rawRlp = rawRlp;
    }

    /**
     * Decode an ENR from raw RLP bytes (as received in discv4 Neighbors or discv5).
     * Skips signature verification for now.
     */
    public static Enr decode(Bytes rlpBytes) {
        Map<String, Bytes> pairs = new HashMap<>();
        long[] seqHolder = {0};
        RLP.decodeList(rlpBytes, reader -> {
            // First element: signature (skip)
            reader.skipNext(); // signature
            // Second element: sequence number
            seqHolder[0] = reader.readLong();
            // Remaining: key-value pairs
            while (!reader.isComplete()) {
                String key = reader.readString();
                Bytes value = reader.readValue();
                pairs.put(key, value);
            }
            return null;
        });
        return new Enr(seqHolder[0], pairs, rlpBytes);
    }

    /** Node's secp256k1 public key (64 bytes uncompressed, without 0x04 prefix). */
    public Optional<SECP256K1.PublicKey> publicKey() {
        Bytes keyBytes = pairs.get("secp256k1");
        if (keyBytes == null) return Optional.empty();
        // ENR stores compressed 33-byte public key; decompress to 64-byte uncompressed
        try {
            // BouncyCastle: decompress secp256k1 point
            org.bouncycastle.crypto.params.ECDomainParameters params =
                new org.bouncycastle.crypto.params.ECDomainParameters(
                    org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1").getCurve(),
                    org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1").getG(),
                    org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1").getN()
                );
            org.bouncycastle.math.ec.ECPoint point =
                params.getCurve().decodePoint(keyBytes.toArrayUnsafe());
            byte[] encoded = point.getEncoded(false); // uncompressed: 0x04 || x || y
            // Strip the 0x04 prefix -> 64 bytes
            Bytes uncompressed = Bytes.wrap(encoded, 1, 64);
            return Optional.of(SECP256K1.PublicKey.fromBytes(uncompressed));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public Optional<InetSocketAddress> tcpAddress() {
        return address("ip", "tcp");
    }

    public Optional<InetSocketAddress> udpAddress() {
        return address("ip", "udp");
    }

    private Optional<InetSocketAddress> address(String ipKey, String portKey) {
        Bytes ipBytes = pairs.get(ipKey);
        Bytes portBytes = pairs.get(portKey);
        if (ipBytes == null || portBytes == null) return Optional.empty();
        try {
            InetAddress addr = InetAddress.getByAddress(ipBytes.toArrayUnsafe());
            int port = portBytes.toInt();
            return Optional.of(new InetSocketAddress(addr, port));
        } catch (UnknownHostException e) {
            return Optional.empty();
        }
    }

    public long seq() { return seq; }
    public Map<String, Bytes> pairs() { return Map.copyOf(pairs); }
    public Bytes rawRlp() { return rawRlp; }

    @Override
    public String toString() {
        return "ENR{seq=" + seq + ", udp=" + udpAddress().orElse(null) +
               ", tcp=" + tcpAddress().orElse(null) + "}";
    }
}
