package com.jaeckel.ethp2p.consensus.bls;

import java.util.List;

/**
 * A pluggable BLS12-381 fast-aggregate-verify backend. The seam lets the host pick the
 * fastest implementation available for the platform — the pure-Java Milagro path
 * (works everywhere, slow) today, and a native blst path (jblst on desktop JVM, an
 * NDK-built blst on Android) once wired — without the light-client verification code
 * caring which is in use.
 *
 * <p>Ethereum's "minimal-pubkey-size" variant: 48-byte compressed G1 pubkeys, 96-byte
 * compressed G2 signatures, POP ciphersuite DST.
 */
public interface BlsBackend {

    /**
     * Ethereum 2.0 fast_aggregate_verify: aggregate the G1 pubkeys, then check
     * {@code e(aggPk, H(message)) == e(G1, signature)} under the POP ciphersuite.
     *
     * @param pubkeys   48-byte compressed G1 pubkeys (the participating committee members)
     * @param message   the signed message (a 32-byte signing root)
     * @param signature 96-byte compressed G2 aggregate signature
     * @return true iff valid
     */
    boolean fastAggregateVerify(List<byte[]> pubkeys, byte[] message, byte[] signature);

    /** Human-readable backend name (for logs / benchmarks). */
    default String name() { return getClass().getSimpleName(); }
}
