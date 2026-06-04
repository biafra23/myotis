package org.hyperledger.besu.crypto;

import java.security.Provider;

/**
 * Android-compatible drop-in replacement for Besu's {@code BesuProvider}.
 *
 * <h2>Why this file exists</h2>
 * Besu's own {@code org.hyperledger.besu.crypto.BesuProvider} (shipped in
 * {@code org.hyperledger.besu.internal:algorithms:24.12.2}) calls the
 * three-{@code String} JCA constructor:
 * <pre>{@code super("Besu", "1.0", "Besu Security Provider v1.0");  // Provider(String, String, String)}</pre>
 * That {@code java.security.Provider(String name, String versionStr, String info)}
 * overload was added to the JDK in Java 9. It is present in the Android
 * <em>compile</em> stubs ({@code android.jar} from API 34 up), so Besu compiles
 * fine — but it is <em>absent from the ART runtime</em> ({@code core-oj.jar})
 * even on API 35/36 emulator images. So at runtime, constructing the upstream
 * BesuProvider throws:
 * <pre>{@code NoSuchMethodError: No direct method <init>(String,String,String) in class java.security.Provider}</pre>
 * This fires the first time any Besu code hashes (e.g. {@code Hash.keccak256}
 * via {@code MessageDigestFactory}), which on the ENS path happens during EVM
 * opcode execution (EXTCODEHASH, etc.). A minSdk bump does not help — the gap is
 * in the runtime build, not gated by API level.
 *
 * <h2>What this changes</h2>
 * Exactly one thing: it calls the legacy {@code Provider(String name, double
 * version, String info)} constructor (present since Android API 1) instead of
 * the {@code String}-version overload. Behaviour is otherwise identical — it
 * registers the {@code Blake2bf} message digest (EIP-152 BLAKE2 F compression),
 * the only algorithm the upstream provider contributes. Keccak/SHA still come
 * from BouncyCastle, which {@code MessageDigestFactory} registers right after.
 *
 * <h2>How it takes effect</h2>
 * This class has the same fully-qualified name as the upstream one. To avoid a
 * duplicate-class error at dex time, the {@code stripBesuProvider} Gradle
 * artifact transform in {@code android-app/build.gradle.kts} deletes the single
 * {@code BesuProvider.class} entry from the algorithms jar before dexing (a
 * zip-entry removal — it does not rewrite any bytecode). Every other class in
 * that jar, including {@link Blake2bfMessageDigest} referenced below, is left
 * untouched, so this compiles and links against the real artifact.
 *
 * <p>Remove this file (and the transform) if/when Besu is upgraded to a release
 * whose BesuProvider uses an Android-runtime-safe constructor, or if minSdk is
 * raised to a level whose runtime ships {@code Provider(String,String,String)}.
 */
public final class BesuProvider extends Provider {

    /** Matches the upstream constant; some Besu code looks the provider up by this name. */
    public static final String PROVIDER_NAME = "Besu";

    private static final String INFO = "Besu Security Provider v1.0";

    /**
     * The implementation class the upstream registers via
     * {@code Blake2bfMessageDigest.class.getName()}. We reference it by name
     * rather than by {@code .class} because Besu's {@code :algorithms} jar is a
     * transitive {@code implementation} dependency (visible on android-app's
     * runtime classpath but not its compile classpath). JCA resolves the
     * provider's implementation classes lazily by name when the algorithm is
     * first requested, at which point the class is present at runtime.
     */
    private static final String BLAKE2BF_IMPL =
            "org.hyperledger.besu.crypto.Blake2bfMessageDigest";

    public BesuProvider() {
        // (String, double, String) — Android API 1. The upstream uses the
        // (String, String, String) overload, which the ART runtime lacks.
        super(PROVIDER_NAME, 1.0, INFO);
        // Upstream wraps this put in AccessController.doPrivileged. Android has
        // no SecurityManager (it's a no-op and deprecated for removal), so a
        // direct put is equivalent and avoids the deprecated API.
        put("MessageDigest.Blake2bf", BLAKE2BF_IMPL);
    }
}
