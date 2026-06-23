package com.jaeckel.ethp2p.consensus.bls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Runs two backends on every verify and logs a head-to-head — a direct A/B of native vs
 * pure-Java in one process/run. **Returns the {@code trusted} backend's verdict**, so
 * enabling compare mode never changes verification behavior; the {@code candidate} is
 * measured and cross-checked only. A disagreement is logged loudly (a candidate bug).
 *
 * <p>Doubles BLS cost while enabled — for evaluation, not steady state. Select via
 * {@code -Dmyotis.bls.backend=compare} (see {@link BlsBackends}).
 */
public final class ComparingBlsBackend implements BlsBackend {

    private static final Logger log = LoggerFactory.getLogger(ComparingBlsBackend.class);

    private final BlsBackend trusted;
    private final BlsBackend candidate;

    public ComparingBlsBackend(BlsBackend trusted, BlsBackend candidate) {
        this.trusted = trusted;
        this.candidate = candidate;
    }

    @Override
    public boolean fastAggregateVerify(List<byte[]> pubkeys, byte[] message, byte[] signature) {
        long t0 = System.nanoTime();
        boolean trustedOk = trusted.fastAggregateVerify(pubkeys, message, signature);
        long trustedNs = System.nanoTime() - t0;

        // The candidate is UNTRUSTED here — a native/JNI backend could throw
        // (UnsatisfiedLinkError, a native panic, a device-specific linkage error). It must
        // never disrupt the trusted verification flow, which is the whole point of this
        // backend. Isolate it: on any Throwable, treat the candidate as failed and keep going.
        long t1 = System.nanoTime();
        boolean candOk = false;
        long candNs = 0;
        try {
            candOk = candidate.fastAggregateVerify(pubkeys, message, signature);
            candNs = System.nanoTime() - t1;
        } catch (Throwable t) {
            log.error("[bls-compare] Candidate backend {} threw during verification",
                    candidate.name(), t);
        }

        int pk = pubkeys == null ? 0 : pubkeys.size();
        double tMs = trustedNs / 1e6, cMs = candNs / 1e6;
        log.info("[bls-compare] pubkeys={} {}={}ms {}={}ms speedup={}x agree={}",
                pk, trusted.name(), String.format("%.2f", tMs),
                candidate.name(), String.format("%.2f", cMs),
                String.format("%.1f", cMs == 0 ? 0 : tMs / cMs), trustedOk == candOk);
        if (trustedOk != candOk) {
            log.error("[bls-compare] DISAGREEMENT: {}={} {}={} — candidate backend is buggy!",
                    trusted.name(), trustedOk, candidate.name(), candOk);
        }
        return trustedOk;
    }

    @Override
    public void warmPubkeyCache(List<byte[]> pubkeys) {
        trusted.warmPubkeyCache(pubkeys);
        candidate.warmPubkeyCache(pubkeys);
    }

    @Override
    public String name() { return "compare(" + trusted.name() + " vs " + candidate.name() + ")"; }
}
