package com.jaeckel.ethp2p.consensus.bls;

import java.util.List;

/**
 * {@link BlsBackend} backed by Supranational's blst (C + assembly) through a thin Rust
 * JNI shim ({@code rust/myotis-bls} → {@code libmyotis_bls}). One crate builds the native
 * library for every platform: a desktop {@code .so}/{@code .dylib}/{@code .dll} for the
 * JVM daemon, and per-ABI {@code .so}s (via cargo-ndk) bundled in the Android app's
 * jniLibs. Same Java code, different binary per target — see docs/bls-rust-acceleration.md.
 *
 * <p>Falls back gracefully: if the native library can't be loaded (no binary for this
 * platform), {@link #isAvailable()} is false and {@link BlsBackends} keeps the pure-Java
 * Milagro path.
 */
public final class NativeBlsBackend implements BlsBackend {

    private static final boolean AVAILABLE = tryLoad();

    private static boolean tryLoad() {
        try {
            System.loadLibrary("myotis_bls");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** True iff the native blst library loaded for this platform. */
    public static boolean isAvailable() { return AVAILABLE; }

    @Override
    public boolean fastAggregateVerify(List<byte[]> pubkeys, byte[] message, byte[] signature) {
        if (pubkeys == null || pubkeys.isEmpty()) return false;
        // Validate message (32-byte signing root) and signature (96-byte compressed G2)
        // before the work below — fail fast instead of allocating the ~24KB flat buffer and
        // crossing the JNI boundary just to be rejected by native validation.
        if (message == null || message.length != 32) return false;
        if (signature == null || signature.length != 96) return false;
        // Flatten the committee into one contiguous 48*N buffer so the whole verify is a
        // SINGLE JNI crossing (decompress + aggregate + pairing all happen in native code),
        // instead of one boundary hop per pubkey.
        int n = pubkeys.size();
        byte[] flat = new byte[n * 48];
        for (int i = 0; i < n; i++) {
            byte[] pk = pubkeys.get(i);
            if (pk == null || pk.length != 48) return false;
            System.arraycopy(pk, 0, flat, i * 48, 48);
        }
        try {
            return nativeFastAggregateVerify(flat, n, message, signature);
        } catch (Throwable t) {
            return false;
        }
    }

    private static native boolean nativeFastAggregateVerify(
            byte[] pubkeys48xN, int count, byte[] message, byte[] signature);

    @Override
    public String name() { return "blst (native/rust)"; }
}
