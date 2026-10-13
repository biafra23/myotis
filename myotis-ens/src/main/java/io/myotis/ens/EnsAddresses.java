package io.myotis.ens;

import io.myotis.evm.Address;

/**
 * Canonical ENS contract addresses per network.
 *
 * <p>Sourced from the {@code ensdomains/ens-contracts} repository's
 * {@code deployments/{network}/{ENSRegistry,UniversalResolver}.json}
 * files at the time these constants were pinned. The Registry on every
 * EVM network ENS supports lives at the same address since EIP-137.
 * Consumers that need a different deployment can pass overrides via the
 * three-arg {@link EnsResolver} constructor.
 *
 * <p>Resolver addresses (per name) are not pinned here — each name's
 * resolver is looked up dynamically from the Registry (the ENSIP-10 walk:
 * the exact node, then each parent).
 *
 * <p>The Universal Resolver pins are no longer read by anything:
 * {@link EnsResolver} resolves forward by walking the Registry itself and
 * calling the resolver it finds directly, so no UR (and no shared CCIP
 * batch gateway) sits in the path. They are kept because the constructors
 * still take a UR address.
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
     * Mainnet ENS Universal Resolver. Not read: wildcard names (Coinbase,
     * Uniswap, Base subnames), whose resolvers implement only
     * {@code resolve(bytes name, bytes data)}, are served by
     * {@link EnsResolver}'s own ENSIP-10 walk, which calls that method on
     * the resolver directly.
     */
    public static final Address MAINNET_UNIVERSAL_RESOLVER =
            Address.fromHex("0xce01f8eee7E479C928F8919abD53E553a36CeF67");

    /** The {@code .eth} BaseRegistrar (ERC-721 of the second-level names) — the same
     *  address on mainnet and Sepolia (verified against both chains' {@code ens()}). */
    public static final Address BASE_REGISTRAR =
            Address.fromHex("0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85");

    /** The NameWrapper a wrapped name's registry owner points at; its
     *  {@code ownerOf(uint256(node))} is the user behind it. */
    public static final Address MAINNET_NAME_WRAPPER =
            Address.fromHex("0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401");

    // ---- Sepolia (chainId 11155111) --------------------------------------

    /**
     * Sepolia ENS Registry — same address as mainnet (the Registry deploys
     * to a deterministic address on every network ENS is set up on).
     */
    public static final Address SEPOLIA_REGISTRY =
            Address.fromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");

    /** Sepolia Universal Resolver. Not read (see the class doc). */
    public static final Address SEPOLIA_UNIVERSAL_RESOLVER =
            Address.fromHex("0x3c85752a5d47DD09D677C645Ff2A938B38fbFEbA");

    public static final Address SEPOLIA_NAME_WRAPPER =
            Address.fromHex("0x0635513f179D50A207757E05759CbD106d7dFcE8");

    // ---- Holesky (chainId 17000) -----------------------------------------

    /** Holesky ENS Registry — same canonical address as mainnet/sepolia. */
    public static final Address HOLESKY_REGISTRY =
            Address.fromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");

    /**
     * Holesky Universal Resolver. Not read (see the class doc); holesky
     * itself was retired by the EF in Oct 2025.
     */
    public static final Address HOLESKY_UNIVERSAL_RESOLVER =
            Address.fromHex("0x9b37980C10bc0A31Bb61d740De46444853fe2359");
}
