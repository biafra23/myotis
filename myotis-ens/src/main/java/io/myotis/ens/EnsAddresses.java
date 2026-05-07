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

    /**
     * Mainnet ENS Universal Resolver (ENSIP-10 + CCIP-Read aware). The UR
     * walks the registry/resolver chain in a single call and supports
     * wildcard resolution, which is what most modern ENS surfaces (Coinbase
     * names, Uniswap names, Base subnames) rely on. Without it,
     * step-by-step calls to {@code resolver.addr(node)} return zero for
     * wildcard names because the wildcard resolver only implements
     * {@code resolve(bytes name, bytes data)}, not the per-name accessors.
     *
     * <p>The address pinned here is the ENS Labs deployment current at the
     * time of writing. The UR is occasionally redeployed when new ENSIPs
     * land; consumers can pass a different address via
     * {@link EnsResolver#EnsResolver(io.myotis.evm.EvmExecutor,
     * io.myotis.evm.Address, io.myotis.evm.Address) the three-arg
     * constructor}.
     */
    public static final Address MAINNET_UNIVERSAL_RESOLVER =
            Address.fromHex("0xce01f8eee7E479C928F8919abD53E553a36CeF67");
}
