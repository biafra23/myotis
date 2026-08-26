package io.myotis.evm;

import java.util.Objects;

/**
 * 20-byte Ethereum address.
 *
 * <p>Distinct from Besu's {@code org.hyperledger.besu.datatypes.Address} so the
 * public API of this module does not leak the Besu type. The {@link #toBesu()}
 * conversion lives only in the internal Besu adapter package.
 */
public final class Address {

    public static final int SIZE = 20;
    public static final Address ZERO = new Address(new byte[SIZE]);

    private final byte[] bytes;

    private Address(byte[] bytes) {
        this.bytes = bytes;
    }

    public static Address of(byte[] bytes) {
        if (bytes.length != SIZE) {
            throw new IllegalArgumentException("Address must be " + SIZE + " bytes, got " + bytes.length);
        }
        return new Address(bytes.clone());
    }

    public static Address fromHex(String hex) {
        String s = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        if (s.length() != SIZE * 2) {
            throw new IllegalArgumentException("Address hex must be " + (SIZE * 2) + " chars, got " + s.length());
        }
        return new Address(Hex.parseHex(s));
    }

    public byte[] toByteArray() {
        return bytes.clone();
    }

    public String toHex() {
        return "0x" + Hex.formatHex(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Address other)) return false;
        return java.util.Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return toHex();
    }
}
