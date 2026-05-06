package io.myotis.evm.ens;

import io.myotis.evm.CryptoProviders;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;

import java.nio.charset.StandardCharsets;

/**
 * ENS namehash per the ENSIP-1 specification.
 *
 * <p>Recursive Keccak-256 hashing of dot-separated, lowercased UTF-8 labels:
 * <pre>{@code
 *   namehash([])              = 32 zero bytes
 *   namehash([label, ...])    = keccak256(namehash(...) || keccak256(label))
 * }</pre>
 *
 * <p>Names are decoded right-to-left: {@code "vitalik.eth"} hashes the
 * {@code "eth"} label first, then {@code "vitalik"} on top of that.
 *
 * <p>The plan (Phase 3) lives in a separate {@code myotis-ens} module that
 * depends on {@code myotis-evm}. This helper is parked here for now because
 * it is small and the full ENS module is a Phase 3 deliverable. When that
 * module lands, this class can be relocated without API impact — only the
 * package import changes.
 */
public final class Namehash {

    private static final byte[] ROOT = new byte[32];

    private Namehash() {}

    /** Compute the namehash of {@code name}. Empty string returns 32 zero bytes. */
    public static byte[] of(String name) {
        CryptoProviders.ensureRegistered();
        if (name == null || name.isEmpty()) return ROOT.clone();
        // Lowercase per ENSIP-1; full UTS-46 normalisation is a Phase 3 concern.
        // Most production names are already canonical lowercase ASCII; documenting
        // the simplification here so the gap is visible.
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        String[] labels = lower.split("\\.", -1);
        byte[] node = ROOT.clone();
        for (int i = labels.length - 1; i >= 0; i--) {
            byte[] labelHash = Hash.keccak256(
                    Bytes.wrap(labels[i].getBytes(StandardCharsets.UTF_8))).toArrayUnsafe();
            byte[] combined = new byte[64];
            System.arraycopy(node, 0, combined, 0, 32);
            System.arraycopy(labelHash, 0, combined, 32, 32);
            node = Hash.keccak256(Bytes.wrap(combined)).toArrayUnsafe();
        }
        return node;
    }
}
