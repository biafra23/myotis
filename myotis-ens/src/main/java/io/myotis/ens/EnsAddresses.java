package io.myotis.ens;

import io.myotis.evm.Address;

/**
 * Canonical ENS contract addresses per network.
 *
 * <p>Sourced from the {@code ensdomains/ens-contracts} repository's
 * {@code deployments/{network}/{ENSRegistry,UniversalResolver}.json}
 * files at the time these constants were pinned. The Registry on every
 * EVM network ENS supports lives at the same address since EIP-137; the
 * Universal Resolver is redeployed independently per network and is
 * occasionally re-pinned when new ENSIPs land. Consumers that need a
 * different deployment can pass overrides via the three-arg
 * {@link EnsResolver} constructor.
 *
 * <p>Resolver addresses (per name) are not pinned here — each name's
 * resolver is looked up dynamically from the Registry.
 */
public final class EnsAddresses {

    private EnsAddresses() {}

    // ---- Mainnet (chainId 1) ---------------------------------------------

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
     */
    public static final Address MAINNET_UNIVERSAL_RESOLVER =
            Address.fromHex("0xce01f8eee7E479C928F8919abD53E553a36CeF67");

    // ---- Sepolia (chainId 11155111) --------------------------------------

    /**
     * Sepolia ENS Registry — same address as mainnet (the Registry deploys
     * to a deterministic address on every network ENS is set up on).
     */
    public static final Address SEPOLIA_REGISTRY =
            Address.fromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");

    /** Sepolia Universal Resolver. */
    public static final Address SEPOLIA_UNIVERSAL_RESOLVER =
            Address.fromHex("0x3c85752a5d47DD09D677C645Ff2A938B38fbFEbA");

    // ---- Holesky (chainId 17000) -----------------------------------------

    /** Holesky ENS Registry — same canonical address as mainnet/sepolia. */
    public static final Address HOLESKY_REGISTRY =
            Address.fromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");

    /**
     * Holesky Universal Resolver. Note that ENS has signalled holesky is
     * being phased out in favour of sepolia, so this pin may stop being
     * useful before sepolia's does.
     */
    public static final Address HOLESKY_UNIVERSAL_RESOLVER =
            Address.fromHex("0x9b37980C10bc0A31Bb61d740De46444853fe2359");
}
