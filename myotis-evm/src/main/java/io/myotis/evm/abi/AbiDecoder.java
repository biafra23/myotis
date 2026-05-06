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
 *
 * <p>Inputs are typically untrusted (peer-supplied SNAP responses, contract
 * revert payloads, calldata). Where we read offsets/lengths and downcast to
 * {@code int}, we use {@link #toIntStrict} to fail with a clean
 * {@link IllegalArgumentException} instead of an unchecked
 * {@link ArithmeticException}, which is the wrong type to leak through to
 * the executor and would otherwise be a small DoS surface.
 */
public final class AbiDecoder {

    /**
     * Hard upper bound on any in-buffer index we accept from network data.
     * 64 MiB is well beyond any realistic ABI return value while still small
     * enough that allocating a buffer of that size is bounded and cheap to
     * detect early. The actual buffer cap is enforced by the caller.
     */
    public static final int MAX_INDEX = 64 * 1024 * 1024;

    private AbiDecoder() {}

    public static BigInteger uint256(byte[] data, int offset) {
        if (offset < 0 || offset + 32 > data.length) {
            throw new IllegalArgumentException("not enough bytes for uint256 at offset " + offset);
        }
        // Always positive: BigInteger(int signum, byte[] magnitude).
        return new BigInteger(1, Arrays.copyOfRange(data, offset, offset + 32));
    }

    public static Address address(byte[] data, int offset) {
        if (offset < 0 || offset + 32 > data.length) {
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
        if (offset < 0 || offset + 32 > data.length) {
            throw new IllegalArgumentException("not enough bytes for bytes32 at offset " + offset);
        }
        return Arrays.copyOfRange(data, offset, offset + 32);
    }

    /**
     * Read a dynamic {@code bytes} value. {@code headOffset} points at the
     * 32-byte slot in the head that holds the tail offset.
     */
    public static byte[] dynamicBytes(byte[] data, int headOffset) {
        int tailOffset = toIntStrict(uint256(data, headOffset), "tail offset");
        int len = toIntStrict(uint256(data, tailOffset), "dynamic-bytes length");
        // Guard against integer overflow on tailOffset+32+len before doing
        // the bounds check; the caller's data could specify lengths that
        // overflow when added.
        if (tailOffset > data.length - 32 || len > data.length - tailOffset - 32) {
            throw new IllegalArgumentException(
                    "dynamic bytes runs past buffer (offset=" + tailOffset + " len=" + len
                            + " buffer=" + data.length + ")");
        }
        return Arrays.copyOfRange(data, tailOffset + 32, tailOffset + 32 + len);
    }

    public static String string(byte[] data, int headOffset) {
        return new String(dynamicBytes(data, headOffset), StandardCharsets.UTF_8);
    }

    /**
     * Strict {@code BigInteger} → {@code int} conversion for offsets and
     * lengths read from untrusted bytes. Rejects negatives and values above
     * {@link #MAX_INDEX}, throwing {@link IllegalArgumentException} so the
     * executor surfaces a clean {@code Reverted} rather than a raw
     * {@code ArithmeticException} bubbling out of the decoder.
     */
    public static int toIntStrict(BigInteger v, String name) {
        if (v.signum() < 0) {
            throw new IllegalArgumentException(name + " is negative: " + v);
        }
        if (v.bitLength() > 31 || v.intValue() > MAX_INDEX) {
            throw new IllegalArgumentException(
                    name + " exceeds MAX_INDEX (" + MAX_INDEX + "): " + v);
        }
        return v.intValueExact();
    }
}
