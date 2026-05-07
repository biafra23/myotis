package io.myotis.ens;

import java.nio.charset.StandardCharsets;

/**
 * DNS wire-format encoder for ENS names per ENSIP-10.
 *
 * <p>The Universal Resolver and ENSIP-10 wildcard resolvers consume names
 * in the canonical DNS wire format: each label is preceded by its
 * one-byte length, terminated by a zero-length root label. Labels
 * themselves must be ≤ 63 bytes (DNS label limit).
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code "vitalik.eth"} → {@code 07 76 69 74 61 6c 69 6b 03 65 74 68 00}
 *   <li>{@code ""} → {@code 00}
 *   <li>{@code "a.b.c"} → {@code 01 61 01 62 01 63 00}
 * </ul>
 *
 * <p>Per ENSIP-10, dots in a label (escaped via the encoded form
 * {@code "..."}) are out of scope for now — the encoder splits on
 * literal dots and assumes labels contain none.
 */
public final class DnsEncoder {

    private static final int MAX_LABEL_LENGTH = 63;

    private DnsEncoder() {}

    /**
     * Encode {@code name} into DNS wire format. Returns a single null byte
     * for the empty string (the root domain).
     *
     * <p>Rejects names with empty labels — {@code "a..b"}, {@code "..eth"},
     * etc. The trailing-dot form {@code "vitalik.eth."} (FQDN-style) is
     * accepted by stripping the trailing dot, since it's a common convention
     * and unambiguously equivalent to the bare form.
     *
     * @throws IllegalArgumentException if any label is empty (other than the
     *         implicit root) or exceeds 63 bytes.
     */
    public static byte[] encode(String name) {
        if (name == null || name.isEmpty()) {
            return new byte[]{0x00};
        }
        // Lower-case for consistency with Namehash; ENSIP-1 normalisation
        // is a separate concern (UTS-46 / IDNA) tracked elsewhere.
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        // FQDN form ("vitalik.eth.") is accepted by stripping the trailing
        // dot — semantically equivalent to the bare form, but the split
        // would otherwise produce a spurious empty label and an invalid
        // double-zero terminator on the wire.
        if (lower.endsWith(".")) {
            lower = lower.substring(0, lower.length() - 1);
        }
        if (lower.isEmpty()) {
            return new byte[]{0x00};
        }
        String[] labels = lower.split("\\.", -1);

        // Compute total size: each label is 1 byte length + N bytes of UTF-8,
        // plus the final zero terminator.
        int total = 1; // terminator
        byte[][] encodedLabels = new byte[labels.length][];
        for (int i = 0; i < labels.length; i++) {
            String label = labels[i];
            if (label.isEmpty()) {
                // Per RFC 1035, only the final root label may be zero-length.
                // Empty labels in the middle / start come from inputs like
                // "a..b" or ".eth"; both are not valid DNS names.
                throw new IllegalArgumentException(
                        "DNS name contains an empty label: " + name);
            }
            byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);
            if (labelBytes.length > MAX_LABEL_LENGTH) {
                throw new IllegalArgumentException(
                        "DNS label exceeds " + MAX_LABEL_LENGTH + " bytes: " + label);
            }
            encodedLabels[i] = labelBytes;
            total += 1 + labelBytes.length;
        }

        byte[] out = new byte[total];
        int p = 0;
        for (byte[] labelBytes : encodedLabels) {
            out[p++] = (byte) labelBytes.length;
            System.arraycopy(labelBytes, 0, out, p, labelBytes.length);
            p += labelBytes.length;
        }
        out[p] = 0x00;
        return out;
    }
}
