package io.myotis.ens;

import io.myotis.evm.Address;
import io.myotis.evm.Hex;

/**
 * Builds the reverse-lookup namehash input for an Ethereum address per
 * ENSIP-3.
 *
 * <p>Reverse records live under the {@code .addr.reverse} subdomain, with
 * each address holding a record at the namehash of
 * {@code "<lowercase-addr-hex-no-0x>.addr.reverse"}. For example,
 * {@code 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045}'s reverse-lookup name
 * is {@code "d8da6bf26964af9d7eed9e03e53415d37aa96045.addr.reverse"}.
 *
 * <p>The address hex must be lowercase and without the {@code 0x} prefix —
 * mixed-case (EIP-55 checksum) addresses produce a different namehash and
 * won't match the reverse record. This helper enforces the format.
 */
public final class ReverseLookup {

    private ReverseLookup() {}

    /** ENS reverse-lookup parent: {@code addr.reverse}. */
    public static final String PARENT = "addr.reverse";

    /**
     * Build the reverse-lookup name for {@code address}. The result is
     * {@code "<lowercase-hex>.addr.reverse"} suitable for passing to
     * {@code Namehash.of(...)}.
     */
    public static String nameFor(Address address) {
        String hex = Hex.formatHex(address.toByteArray());
        return hex + "." + PARENT;
    }
}
