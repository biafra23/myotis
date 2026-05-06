package io.myotis.evm.abi;

import io.myotis.evm.CryptoProviders;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Solidity function signature with the Keccak-256 four-byte selector.
 *
 * <p>The signature string is the canonical form used by the ABI spec, e.g.
 * {@code "balanceOf(address)"} or {@code "transfer(address,uint256)"}.
 * Spaces are not permitted; types must use their canonical names
 * ({@code uint256}, not {@code uint}).
 *
 * <p>This is intentionally a thin wrapper. The full ABI grammar — tuples,
 * arrays of arrays, fixed-point types — is not modelled. The codec only
 * supports the types this module actually emits or consumes
 * (uint256, address, bool, bytes, bytes32, string, dynamic arrays of those).
 */
public record FunctionSignature(String signature, byte[] selector) {

    public FunctionSignature {
        Objects.requireNonNull(signature);
        Objects.requireNonNull(selector);
        if (selector.length != 4) {
            throw new IllegalArgumentException("selector must be 4 bytes");
        }
    }

    public static FunctionSignature of(String canonicalSignature) {
        CryptoProviders.ensureRegistered();
        if (canonicalSignature.indexOf(' ') >= 0) {
            throw new IllegalArgumentException(
                    "function signature must not contain spaces: '" + canonicalSignature + "'");
        }
        Bytes hash = Hash.keccak256(Bytes.wrap(canonicalSignature.getBytes(StandardCharsets.UTF_8)));
        byte[] sel = new byte[4];
        System.arraycopy(hash.toArrayUnsafe(), 0, sel, 0, 4);
        return new FunctionSignature(canonicalSignature, sel);
    }
}
