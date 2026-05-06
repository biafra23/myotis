package io.myotis.evm.abi;

import io.myotis.evm.Address;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal Solidity ABI encoder for the types this module emits.
 *
 * <p>Supported types (head/tail layout per Solidity spec):
 * <ul>
 *   <li>{@code uint256} (BigInteger, must be non-negative and fit in 256 bits)
 *   <li>{@code address}
 *   <li>{@code bool}
 *   <li>{@code bytes32} (fixed; passed as 32-byte array)
 *   <li>{@code bytes} (dynamic)
 *   <li>{@code string} (dynamic; UTF-8)
 *   <li>{@code uint256[]}, {@code bytes[]}, {@code string[]} (dynamic arrays — minimal subset)
 * </ul>
 *
 * <p>Tuples/structs are not supported. If a future caller needs one, encode
 * the head and tail explicitly via {@link #encodeRaw}.
 *
 * <p>Web3j is intentionally not used: the surface needed by this module is
 * tiny, the spec is stable, and rolling it in-house keeps the dependency
 * footprint of an Android wallet down.
 */
public final class AbiEncoder {

    private AbiEncoder() {}

    /**
     * Encode a function call: 4-byte selector concatenated with the head/tail
     * encoding of {@code args}.
     */
    public static byte[] encodeCall(FunctionSignature signature, AbiValue... args) {
        byte[] body = encodeRaw(args);
        ByteArrayOutputStream out = new ByteArrayOutputStream(4 + body.length);
        out.write(signature.selector(), 0, 4);
        out.write(body, 0, body.length);
        return out.toByteArray();
    }

    /**
     * Encode {@code args} per Solidity's head/tail layout, without a selector.
     * Useful for constructing calldata fragments (e.g. CCIP-Read callback inputs).
     */
    public static byte[] encodeRaw(AbiValue... args) {
        // Solidity head/tail: head is exactly 32 * args.length bytes. For dynamic
        // values the head holds an offset (in bytes from the start of head/tail
        // section) into the tail. The tail concatenates the dynamic encodings.
        int headSize = args.length * 32;
        ByteArrayOutputStream tail = new ByteArrayOutputStream();
        byte[][] heads = new byte[args.length][];
        for (int i = 0; i < args.length; i++) {
            AbiValue v = args[i];
            if (v.dynamic()) {
                heads[i] = encodeUint256(BigInteger.valueOf(headSize + tail.size()));
                byte[] enc = v.encode();
                tail.write(enc, 0, enc.length);
            } else {
                heads[i] = v.encode();
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(headSize + tail.size());
        for (byte[] h : heads) out.write(h, 0, h.length);
        byte[] t = tail.toByteArray();
        out.write(t, 0, t.length);
        return out.toByteArray();
    }

    // ---- Value constructors -------------------------------------------------

    public static AbiValue uint256(BigInteger v) {
        if (v.signum() < 0) {
            throw new IllegalArgumentException("uint256 must be non-negative");
        }
        if (v.bitLength() > 256) {
            throw new IllegalArgumentException("uint256 overflow");
        }
        byte[] enc = encodeUint256(v);
        return new AbiValue(false, enc);
    }

    public static AbiValue uint256(long v) {
        return uint256(BigInteger.valueOf(v));
    }

    public static AbiValue address(Address a) {
        byte[] padded = new byte[32];
        byte[] addr = a.toByteArray();
        System.arraycopy(addr, 0, padded, 12, 20);
        return new AbiValue(false, padded);
    }

    public static AbiValue bool(boolean b) {
        byte[] padded = new byte[32];
        padded[31] = b ? (byte) 1 : (byte) 0;
        return new AbiValue(false, padded);
    }

    public static AbiValue bytes32(byte[] v) {
        if (v.length != 32) throw new IllegalArgumentException("bytes32 must be 32 bytes");
        return new AbiValue(false, v.clone());
    }

    public static AbiValue bytes(byte[] v) {
        return new AbiValue(true, encodeDynamicBytes(v));
    }

    public static AbiValue string(String v) {
        return new AbiValue(true, encodeDynamicBytes(v.getBytes(StandardCharsets.UTF_8)));
    }

    /** Dynamic uint256 array. */
    public static AbiValue uint256Array(List<BigInteger> values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] len = encodeUint256(BigInteger.valueOf(values.size()));
        out.write(len, 0, len.length);
        for (BigInteger v : values) {
            byte[] enc = encodeUint256(v);
            out.write(enc, 0, enc.length);
        }
        return new AbiValue(true, out.toByteArray());
    }

    /** Dynamic string array. Per spec, the inner strings are encoded head/tail relative to the array body. */
    public static AbiValue stringArray(List<String> values) {
        return dynamicArrayOfDynamic(values, s -> encodeDynamicBytes(s.getBytes(StandardCharsets.UTF_8)));
    }

    /** Dynamic bytes array. */
    public static AbiValue bytesArray(List<byte[]> values) {
        return dynamicArrayOfDynamic(values, AbiEncoder::encodeDynamicBytes);
    }

    private static <T> AbiValue dynamicArrayOfDynamic(
            List<T> values, java.util.function.Function<T, byte[]> encodeOne) {
        // Layout: length || head[0..n-1] || tail. head[i] is the offset (from start
        // of head section) of element i's encoding inside tail.
        int n = values.size();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] len = encodeUint256(BigInteger.valueOf(n));
        out.write(len, 0, len.length);

        List<byte[]> encoded = new ArrayList<>(n);
        for (T v : values) encoded.add(encodeOne.apply(v));

        int headBytes = 32 * n;
        int tailOffset = 0;
        for (int i = 0; i < n; i++) {
            byte[] off = encodeUint256(BigInteger.valueOf(headBytes + tailOffset));
            out.write(off, 0, off.length);
            tailOffset += encoded.get(i).length;
        }
        for (byte[] enc : encoded) out.write(enc, 0, enc.length);
        return new AbiValue(true, out.toByteArray());
    }

    // ---- Internals ----------------------------------------------------------

    static byte[] encodeUint256(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] padded = new byte[32];
        if (raw.length > 32) {
            // BigInteger may include a sign byte; strip a leading zero if present.
            if (raw.length == 33 && raw[0] == 0) {
                System.arraycopy(raw, 1, padded, 0, 32);
                return padded;
            }
            throw new IllegalArgumentException("uint256 overflow");
        }
        System.arraycopy(raw, 0, padded, 32 - raw.length, raw.length);
        return padded;
    }

    static byte[] encodeDynamicBytes(byte[] data) {
        // Layout: length (uint256) || data padded to a 32-byte boundary.
        int padded = ((data.length + 31) / 32) * 32;
        ByteArrayOutputStream out = new ByteArrayOutputStream(32 + padded);
        byte[] len = encodeUint256(BigInteger.valueOf(data.length));
        out.write(len, 0, len.length);
        out.write(data, 0, data.length);
        for (int i = data.length; i < padded; i++) out.write(0);
        return out.toByteArray();
    }
}
