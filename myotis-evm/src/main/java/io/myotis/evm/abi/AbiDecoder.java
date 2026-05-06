package io.myotis.evm.abi;

import io.myotis.evm.Address;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Decoder counterpart to {@link AbiEncoder}.
 *
 * <p>The decoder is positional — callers know the expected return shape and
 * walk the buffer left-to-right. It does not attempt to validate that buffer
 * length matches the declared types; the caller is responsible.
 */
public final class AbiDecoder {

    private AbiDecoder() {}

    public static BigInteger uint256(byte[] data, int offset) {
        if (offset + 32 > data.length) {
            throw new IllegalArgumentException("not enough bytes for uint256 at offset " + offset);
        }
        // Always positive: BigInteger(int signum, byte[] magnitude).
        return new BigInteger(1, Arrays.copyOfRange(data, offset, offset + 32));
    }

    public static Address address(byte[] data, int offset) {
        if (offset + 32 > data.length) {
            throw new IllegalArgumentException("not enough bytes for address at offset " + offset);
        }
        // Address is right-aligned in a 32-byte slot; the upper 12 bytes must be zero
        // for valid encodings, but we accept any input and slice the trailing 20.
        byte[] addr = Arrays.copyOfRange(data, offset + 12, offset + 32);
        return Address.of(addr);
    }

    public static boolean bool(byte[] data, int offset) {
        return uint256(data, offset).signum() != 0;
    }

    public static byte[] bytes32(byte[] data, int offset) {
        if (offset + 32 > data.length) {
            throw new IllegalArgumentException("not enough bytes for bytes32 at offset " + offset);
        }
        return Arrays.copyOfRange(data, offset, offset + 32);
    }

    /**
     * Read a dynamic {@code bytes} value. {@code headOffset} points at the
     * 32-byte slot in the head that holds the tail offset.
     */
    public static byte[] dynamicBytes(byte[] data, int headOffset) {
        int tailOffset = uint256(data, headOffset).intValueExact();
        int len = uint256(data, tailOffset).intValueExact();
        if (tailOffset + 32 + len > data.length) {
            throw new IllegalArgumentException("dynamic bytes runs past buffer");
        }
        return Arrays.copyOfRange(data, tailOffset + 32, tailOffset + 32 + len);
    }

    public static String string(byte[] data, int headOffset) {
        return new String(dynamicBytes(data, headOffset), StandardCharsets.UTF_8);
    }
}
