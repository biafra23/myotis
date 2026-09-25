package com.jaeckel.ethp2p.android;

/**
 * Which engines this Android device can run, by API level. Pure (no Android imports) so
 * the policy is unit-testable on the JVM; {@link NodeService} feeds it
 * {@code Build.VERSION.SDK_INT}.
 *
 * <p>The Java engine is disabled below {@link #JAVA_ENGINE_MIN_SDK}. Verified on an
 * Android 10 (API 29) emulator, 2026-09-11: Besu's {@code UInt256} static initializer
 * links {@code MethodHandles.byteArrayViewVarHandle}, and the JRE variant of Guava (forced
 * for Besu) links {@code VarHandle.get/set} in {@code AbstractFutureState$VarHandleAtomicHelper}.
 * Android 10-12 keep those APIs hidden, and ART refuses to link them for an app targeting
 * a current SDK ("greylist-max-o" / "blacklist, linking, denied"). The result: every
 * Java-engine eth_call / ENS lookup fails, its discv5 never starts, and the failed Guava
 * class poisons every later Guava future in the process. The VarHandle APIs became public
 * in API 33 (Android 13).
 *
 * <p>The Rust engine runs these devices fine, so below the gate every network runs on it
 * with NO Java fallback: the selector's hard {@code rust} choice fails a boot visibly
 * instead of handing the network to an engine that cannot work. See issue #402.
 */
final class EngineGate {

    /** Android 13 (TIRAMISU): the first API level where the Java engine's VarHandle users link. */
    static final int JAVA_ENGINE_MIN_SDK = 33;

    private EngineGate() {}

    static boolean javaEngineSupported(int sdkInt) {
        return sdkInt >= JAVA_ENGINE_MIN_SDK;
    }

    /**
     * The {@code Engines} selector choice for this device: a hard {@code rust} (no Java
     * fallback) below the gate, whatever the stored preference; otherwise {@code java} when
     * the user prefers it, else {@code auto}.
     */
    static String engineChoice(int sdkInt, boolean preferJava) {
        if (!javaEngineSupported(sdkInt)) return "rust";
        return preferJava ? "java" : "auto";
    }

    /** Why the Java engine is unavailable on this device (shown in Settings), or null when it is available. */
    static String javaEngineUnavailableReason(int sdkInt) {
        if (javaEngineSupported(sdkInt)) return null;
        return "This device runs Android API " + sdkInt + ". The Java engine needs API "
                + JAVA_ENGINE_MIN_SDK + " (Android 13) or newer, so every network runs on the Rust "
                + "engine, with no Java fallback. The Query tab's transaction-history scan, which "
                + "only the Java engine serves, is not available here.";
    }
}
