package io.myotis.ens;

import io.myotis.evm.Address;

/**
 * Canonical ENS contract addresses on mainnet.
 *
 * <p>The Registry has been at the same address since EIP-137 was deployed
 * and is unlikely to ever move. Resolver addresses are not pinned here —
 * each name's resolver is looked up dynamically from the Registry.
 */
public final class EnsAddresses {

    private EnsAddresses() {}

    /**
     * Mainnet ENS Registry. Mapping {@code (node) → (owner, resolver, ttl)}
     * exposed via standard accessors. The Registry's address is fixed at
     * deployment and a known constant of the Ethereum ecosystem.
     */
    public static final Address MAINNET_REGISTRY =
            Address.fromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
}
