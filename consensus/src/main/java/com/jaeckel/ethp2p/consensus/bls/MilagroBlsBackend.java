package com.jaeckel.ethp2p.consensus.bls;

import java.util.List;

/**
 * The default {@link BlsBackend}: the pure-Java Milagro AMCL path in {@link BlsVerifier}.
 * Works on every platform (no native libs) but is slow — a cold sync-committee verify
 * (~512 G1 decompressions) is what the cache + bounded decompress pool in
 * {@link BlsVerifier} exist to survive. Kept as the portable fallback.
 */
public final class MilagroBlsBackend implements BlsBackend {

    @Override
    public boolean fastAggregateVerify(List<byte[]> pubkeys, byte[] message, byte[] signature) {
        return BlsVerifier.fastAggregateVerify(pubkeys, message, signature);
    }

    @Override
    public void warmPubkeyCache(List<byte[]> pubkeys) {
        BlsVerifier.warmPubkeyCache(pubkeys);
    }

    @Override
    public String name() { return "Milagro (pure-Java)"; }
}
