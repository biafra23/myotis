package io.myotis.evm.ccipread;

import io.myotis.evm.Address;
import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.FunctionSignature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Parser for the ERC-3668 {@code OffchainLookup} custom error.
 *
 * <p>Solidity declaration:
 * <pre>
 *   error OffchainLookup(
 *       address sender,
 *       string[] urls,
 *       bytes callData,
 *       bytes4 callbackFunction,
 *       bytes extraData
 *   );
 * </pre>
 *
 * <p>The four-byte selector is {@code keccak256("OffchainLookup(address,string[],bytes,bytes4,bytes)")[:4]}.
 * Revert payloads from contracts that opt into CCIP-Read start with this
 * selector and are followed by the ABI-encoded args.
 */
public record OffchainLookupRevert(
        Address sender,
        List<String> urls,
        byte[] callData,
        byte[] callbackSelector,
        byte[] extraData) {

    /** Cached selector for the {@code OffchainLookup} error. */
    public static final byte[] SELECTOR =
            FunctionSignature.of("OffchainLookup(address,string[],bytes,bytes4,bytes)").selector();

    /** Returns the parsed revert if {@code revertData} carries the OffchainLookup selector. */
    public static Optional<OffchainLookupRevert> tryParse(byte[] revertData) {
        if (revertData.length < 4) return Optional.empty();
        if (!Arrays.equals(Arrays.copyOf(revertData, 4), SELECTOR)) return Optional.empty();
        byte[] body = Arrays.copyOfRange(revertData, 4, revertData.length);
        return Optional.of(parseBody(body));
    }

    /** Minimum bytes for the static portion of the args (5 head slots). */
    static final int MIN_BODY_SIZE = 5 * 32;

    /** Cap on the number of URLs in a single revert; defends against length-bomb payloads. */
    static final int MAX_URLS = 32;

    /** Parse the args region (after the 4-byte selector). */
    static OffchainLookupRevert parseBody(byte[] body) {
        // Truncated payloads from a hostile or malformed revert would otherwise
        // AIOOBE / NumberFormatException out of the AbiDecoder. Reject early
        // with a clean error type the executor can map to Reverted.
        if (body.length < MIN_BODY_SIZE) {
            throw new IllegalArgumentException(
                    "OffchainLookup body too short: " + body.length + " < " + MIN_BODY_SIZE);
        }
        // Head layout: sender (static, slot 0), urls (offset, slot 1),
        // callData (offset, slot 2), callbackFunction (static, slot 3),
        // extraData (offset, slot 4).
        Address sender = AbiDecoder.address(body, 0);
        // bytes4 is left-aligned in its 32-byte slot per Solidity spec.
        byte[] callbackSelector = Arrays.copyOfRange(body, 32 * 3, 32 * 3 + 4);
        byte[] callData = AbiDecoder.dynamicBytes(body, 32 * 2);
        byte[] extraData = AbiDecoder.dynamicBytes(body, 32 * 4);

        // urls: dynamic string[]. Layout at urlsOffset:
        //   length || head[0..n-1] (each is an offset relative to the start of
        //   the array body's head section) || tail (each entry is a length-prefixed
        //   utf-8 payload, padded to a 32-byte boundary).
        int urlsOffset = AbiDecoder.toIntStrict(
                AbiDecoder.uint256(body, 32), "urls offset");
        int n = AbiDecoder.toIntStrict(
                AbiDecoder.uint256(body, urlsOffset), "urls length");
        if (n > MAX_URLS) {
            throw new IllegalArgumentException(
                    "OffchainLookup urls length " + n + " exceeds cap " + MAX_URLS);
        }
        int urlsHeadStart = urlsOffset + 32;
        List<String> urls = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            int relOffset = AbiDecoder.toIntStrict(
                    AbiDecoder.uint256(body, urlsHeadStart + i * 32), "url[" + i + "] offset");
            int strStart = urlsHeadStart + relOffset;
            int strLen = AbiDecoder.toIntStrict(
                    AbiDecoder.uint256(body, strStart), "url[" + i + "] length");
            if (strStart > body.length - 32 || strLen > body.length - strStart - 32) {
                throw new IllegalArgumentException(
                        "url[" + i + "] runs past buffer (start=" + strStart + " len=" + strLen + ")");
            }
            urls.add(new String(
                    Arrays.copyOfRange(body, strStart + 32, strStart + 32 + strLen),
                    java.nio.charset.StandardCharsets.UTF_8));
        }

        return new OffchainLookupRevert(sender, urls, callData, callbackSelector, extraData);
    }
}
