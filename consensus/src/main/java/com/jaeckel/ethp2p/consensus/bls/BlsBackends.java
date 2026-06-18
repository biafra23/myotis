package com.jaeckel.ethp2p.consensus.bls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Process-wide selection of the active {@link BlsBackend}, always wrapped in a
 * {@link TimingBlsBackend} so the cost is visible on any platform. Selection (system
 * property {@code myotis.bls.backend}, default {@code auto}):
 *
 * <ul>
 *   <li>{@code auto}    — native blst if its library loaded for this platform, else Milagro.</li>
 *   <li>{@code milagro} — force the pure-Java path.</li>
 *   <li>{@code native}  — force native blst (falls back to Milagro if it didn't load).</li>
 *   <li>{@code compare} — run Milagro AND native on every verify and log a head-to-head
 *                         (returns Milagro's verdict; for evaluation only).</li>
 * </ul>
 *
 * A host may also call {@link #set(BlsBackend)} to inject a backend explicitly (e.g. the
 * Android app after confirming its bundled native lib loaded).
 */
public final class BlsBackends {

    private static final Logger log = LoggerFactory.getLogger(BlsBackends.class);
    public static final String PROP = "myotis.bls.backend";

    private static volatile BlsBackend active;

    private BlsBackends() {}

    public static BlsBackend active() {
        BlsBackend a = active;
        if (a == null) {
            synchronized (BlsBackends.class) {
                if (active == null) active = build(System.getProperty(PROP, "auto"));
                a = active;
            }
        }
        return a;
    }

    /** Explicitly set the active backend (wrapped in timing). Overrides the property. */
    public static synchronized void set(BlsBackend backend) {
        active = backend instanceof TimingBlsBackend ? backend : new TimingBlsBackend(backend);
        log.info("[bls] active backend set to {}", active.name());
    }

    static synchronized BlsBackend build(String choice) {
        BlsBackend milagro = new MilagroBlsBackend();
        boolean nativeOk = NativeBlsBackend.isAvailable();
        BlsBackend chosen;
        switch (choice == null ? "auto" : choice.trim().toLowerCase()) {
            case "milagro" -> chosen = milagro;
            case "native"  -> chosen = nativeOk ? new NativeBlsBackend() : milagro;
            case "compare" -> chosen = nativeOk
                    ? new ComparingBlsBackend(milagro, new NativeBlsBackend())
                    : milagro;
            default /* auto */ -> chosen = nativeOk ? new NativeBlsBackend() : milagro;
        }
        log.info("[bls] backend selection: choice={} nativeAvailable={} -> {}",
                choice, nativeOk, chosen.name());
        return new TimingBlsBackend(chosen);
    }

    /** Timing snapshot of the active backend, or null if it isn't a timing wrapper. */
    public static TimingBlsBackend.Stats stats() {
        BlsBackend a = active();
        return a instanceof TimingBlsBackend t ? t.snapshot() : null;
    }
}
