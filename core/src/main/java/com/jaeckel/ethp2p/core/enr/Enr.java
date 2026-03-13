package com.jaeckel.ethp2p.core.enr;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPReader;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Base64;
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
     * Decode an ENR from an "enr:..." base64url-encoded string (EIP-778 text form).
     */
    public static Enr fromEnrString(String enrString) {
        String data = enrString.startsWith("enr:") ? enrString.substring(4) : enrString;
        byte[] rlpBytes = Base64.getUrlDecoder().decode(data);
        return decode(Bytes.wrap(rlpBytes));
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

    /** Raw compressed secp256k1 public key (33 bytes) from the ENR, if present. */
    public Optional<byte[]> compressedSecp256k1() {
        Bytes keyBytes = pairs.get("secp256k1");
        return keyBytes != null ? Optional.of(keyBytes.toArrayUnsafe()) : Optional.empty();
    }

    /**
     * Derive a libp2p multiaddr string from this ENR.
     * Format: {@code /ip4/<ip>/tcp/<port>/p2p/<peer-id>}
     *
     * <p>The PeerId is derived from the secp256k1 compressed public key using
     * the libp2p identity multihash convention (protobuf-wrapped key ≤ 42 bytes).
     *
     * @return the multiaddr, or empty if the ENR lacks ip, tcp, or secp256k1 fields
     */
    public Optional<String> toLibp2pMultiaddr() {
        // Prefer explicit TCP address; fall back to UDP port (CL convention: same port for both)
        var addr = tcpAddress().or(this::udpAddress);
        var keyOpt = compressedSecp256k1();
        if (addr.isEmpty() || keyOpt.isEmpty()) return Optional.empty();

        byte[] compressedKey = keyOpt.get();
        String peerId = derivePeerId(compressedKey);

        String ip = addr.get().getAddress().getHostAddress();
        int port = addr.get().getPort();
        return Optional.of("/ip4/" + ip + "/tcp/" + port + "/p2p/" + peerId);
    }

    /**
     * Derive a libp2p PeerId (base58-encoded multihash) from a compressed secp256k1 key.
     *
     * <p>Steps:
     * <ol>
     *   <li>Wrap key in libp2p crypto protobuf: KeyType=Secp256k1(2), Data=compressed_key</li>
     *   <li>Since the protobuf (37 bytes) ≤ 42, use identity multihash</li>
     *   <li>Base58-encode the multihash bytes</li>
     * </ol>
     */
    static String derivePeerId(byte[] compressedSecp256k1Key) {
        // Protobuf: field 1 (KeyType, varint) = 2, field 2 (Data, bytes) = key
        byte[] protobuf = new byte[4 + compressedSecp256k1Key.length];
        protobuf[0] = 0x08; // field 1, wire type 0 (varint)
        protobuf[1] = 0x02; // Secp256k1
        protobuf[2] = 0x12; // field 2, wire type 2 (length-delimited)
        protobuf[3] = (byte) compressedSecp256k1Key.length;
        System.arraycopy(compressedSecp256k1Key, 0, protobuf, 4, compressedSecp256k1Key.length);

        // Identity multihash: code=0x00, length, data
        byte[] multihash = new byte[2 + protobuf.length];
        multihash[0] = 0x00; // identity hash function
        multihash[1] = (byte) protobuf.length;
        System.arraycopy(protobuf, 0, multihash, 2, protobuf.length);

        return base58Encode(multihash);
    }

    private static final String BASE58_ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    static String base58Encode(byte[] input) {
        if (input.length == 0) return "";

        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) zeros++;

        BigInteger value = BigInteger.ZERO;
        for (byte b : input) {
            value = value.multiply(BigInteger.valueOf(256))
                         .add(BigInteger.valueOf(b & 0xFF));
        }

        StringBuilder sb = new StringBuilder();
        BigInteger fiftyEight = BigInteger.valueOf(58);
        while (value.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divmod = value.divideAndRemainder(fiftyEight);
            value = divmod[0];
            sb.append(BASE58_ALPHABET.charAt(divmod[1].intValue()));
        }

        for (int i = 0; i < zeros; i++) sb.append('1');
        return sb.reverse().toString();
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
