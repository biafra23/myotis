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

    // ---- Gnosis Chain (chainId 100): Genome .gno names -------------------

    /**
     * The TLD Genome serves on Gnosis Chain. Genome is a SPACE ID deployment, an ENS
     * fork: the same {@code owner/resolver(bytes32)} registry and resolver interfaces,
     * but every name hashes under {@link #gnosisGenomeRoot()} rather than ENS's zero
     * root, so a {@code .gno} name is NOT in the ENS tree — it resolves against
     * Gnosis Chain state, read and verified by the Gnosis node like any other
     * {@code eth_call}, with no mainnet involved.
     *
     * <p>Sources for the three pins: the {@code genome-subgraph} deployment and the
     * {@code genome} protocol entry ({@code empty_label_hash}, {@code native_token_contract})
     * in Blockscout's ENS service ({@code blockscout/blockscout-rs}, {@code blockscout-ens});
     * eth.limo's gateway resolves {@code *.gno.limo} the same way, through SPACE ID's
     * {@code @web3-name-sdk/core} ({@code tldNamehash}). The hashing scheme is checked
     * against Blockscout fixtures in {@code EnsResolverTest}; the pins themselves are
     * cross-checked on chain by {@code scripts/check_genome_pins.py} against a Gnosis
     * node (the registrar's own {@code baseNode()} and {@code sidRegistry()} must equal
     * them, and the registry must list the registrar as the {@code gno} node's owner).
     */
    public static final String GENOME_TLD = "gno";

    /** Genome's SID registry on Gnosis Chain ({@code owner/resolver(bytes32)}). */
    public static final Address GNOSIS_GENOME_REGISTRY =
            Address.fromHex("0x5dC881dDA4e4a8d312be3544AD13118D1a04Cb17");

    /** Genome's {@code .gno} registrar ("Base", ERC-721 of the second-level names, token
     *  id = labelhash): {@code ownerOf}, {@code nameExpires}, {@code GRACE_PERIOD}, like
     *  the {@code .eth} BaseRegistrar. */
    public static final Address GNOSIS_GENOME_REGISTRAR =
            Address.fromHex("0x942fcaf68a0c264d5447b03a2011b395a899f2d3");

    /** The node every Genome name hashes under — {@code namehash("")} in that tree,
     *  i.e. {@code keccak256(0x00…00 ‖ identifier)} for the {@code .gno} TLD's SPACE ID
     *  identifier. {@code namehash("gno")} there is this, then {@code keccak256("gno")}. */
    public static byte[] gnosisGenomeRoot() {
        return com.jaeckel.ethp2p.core.encoding.Hex.parseHex(GNOSIS_GENOME_ROOT_HEX);
    }

    static final String GNOSIS_GENOME_ROOT_HEX =
            "c4a8c56f9b0096f720f38bd557d30306dbd78f7751d277e05f062d1b85912a63";
}
