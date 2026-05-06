package io.myotis.evm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * One-time JCA registration for BouncyCastle.
 *
 * <p>Tuweni's {@code Hash.keccak256} dispatches through JCA and silently
 * fails with {@code NoSuchAlgorithmException} until BouncyCastle is added
 * as a provider. The other Myotis modules register it inside their public
 * entry points; this module mirrors that pattern via a static initialiser
 * referenced from each public-facing class that touches Keccak.
 *
 * <p>This is intentionally a no-arg class with a public static method:
 * Java guarantees the static initialiser runs exactly once per
 * classloader, so callers can invoke {@link #ensureRegistered()} freely
 * without worrying about ordering or duplication.
 */
public final class CryptoProviders {

    private static final boolean REGISTERED;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        REGISTERED = true;
    }

    private CryptoProviders() {}

    public static void ensureRegistered() {
        // Reading the field is enough to force class initialisation.
        if (!REGISTERED) throw new IllegalStateException("BouncyCastle registration failed");
    }
}
