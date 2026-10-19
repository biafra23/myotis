package io.myotis.ens;

import com.jaeckel.ethp2p.core.math.BigIntegers;
import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ccipread.OffchainLookupRevert;
import io.myotis.evm.ens.Namehash;

import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;

/**
 * Forward + reverse + record-type resolver for ENS names.
 *
 * <p>Forward record-type calls resolve <b>directly</b> — no UniversalResolver
 * and, crucially, no shared CCIP batch gateway (e.g. {@code ccip-v2.ens.xyz}).
 * We discover the resolver via the Registry over snap (an ENSIP-10 walk: exact
 * node, then each parent), then call it directly: {@code resolve(bytes,bytes)}
 * for ENSIP-10 (wildcard / offchain) resolvers, or the record method directly
 * for a legacy resolver. For an offchain name the ERC-3668 OffchainLookup we
 * follow is the resolver's OWN gateway (e.g. Coinbase for cb.id) — so a
 * {@code CcipReadEvmExecutor} wrapping the executor fetches it with no
 * third-party relay in the path. Resolver discovery is cached per registry+name.
 *
 * <p>Supported records:
 * <ul>
 *   <li>{@code addr(bytes32)} — {@link #resolveAddress}
 *   <li>{@code addr(bytes32, uint256)} — {@link #resolveMultiCoinAddress} (ENSIP-9, SLIP-44)
 *   <li>{@code text(bytes32, string)} — {@link #resolveText} (ENSIP-5)
 *   <li>{@code contenthash(bytes32)} — {@link #resolveContenthash} (ENSIP-7)
 *   <li>{@code pubkey(bytes32)} — {@link #resolvePubkey} (EIP-619)
 *   <li>{@code ABI(bytes32, uint256)} — {@link #resolveAbi} (EIP-205)
 *   <li>{@code dnsRecord(bytes32, bytes, uint16)} — {@link #resolveDnsRecord} (ENSIP-8)
 *   <li>{@code interfaceImplementer(bytes32, bytes4)} — {@link #resolveInterfaceImplementer} (EIP-1820 over ENS)
 * </ul>
 *
 * <p>Reverse resolution ({@code address → name}) uses the step-by-step
 * Registry → reverse-resolver path with a mandatory ENSIP-3 forward
 * verification round-trip — the resolver's claim is only accepted if a
 * forward lookup of the claimed name returns the original address.
 *
 * <p>For modern ENS surfaces (Coinbase IDs, Uniswap names, Base
 * subdomains, etc.) to work, callers must wrap the executor in
 * {@code io.myotis.evm.CcipReadEvmExecutor}. Without that, those names
 * surface as {@code Reverted} errors carrying the {@code OffchainLookup}
 * selector — distinct from "name not found", so callers can tell whether
 * they forgot to wrap vs. whether the name is genuinely unregistered.
 * A name with no resolver anywhere up the Registry walk, and any other revert
 * from its resolver, map to {@link Optional#empty()}.
 */
public final class EnsResolver {

    private static final FunctionSignature RESOLVE =
            FunctionSignature.of("resolve(bytes,bytes)");
    private static final FunctionSignature ADDR =
            FunctionSignature.of("addr(bytes32)");
    private static final FunctionSignature ADDR_COIN =
            FunctionSignature.of("addr(bytes32,uint256)");
    private static final FunctionSignature TEXT =
            FunctionSignature.of("text(bytes32,string)");
    private static final FunctionSignature CONTENTHASH =
            FunctionSignature.of("contenthash(bytes32)");
    private static final FunctionSignature PUBKEY =
            FunctionSignature.of("pubkey(bytes32)");
    private static final FunctionSignature ABI =
            FunctionSignature.of("ABI(bytes32,uint256)");
    private static final FunctionSignature DNS_RECORD =
            FunctionSignature.of("dnsRecord(bytes32,bytes,uint16)");
    private static final FunctionSignature OWNER =
            FunctionSignature.of("owner(bytes32)");
    private static final FunctionSignature OWNER_OF =
            FunctionSignature.of("ownerOf(uint256)");
    private static final FunctionSignature NAME_EXPIRES =
            FunctionSignature.of("nameExpires(uint256)");
    private static final FunctionSignature GRACE_PERIOD =
            FunctionSignature.of("GRACE_PERIOD()");
    private static final FunctionSignature INTERFACE_IMPLEMENTER =
            FunctionSignature.of("interfaceImplementer(bytes32,bytes4)");
    private static final FunctionSignature RESOLVER =
            FunctionSignature.of("resolver(bytes32)");
    private static final FunctionSignature NAME =
            FunctionSignature.of("name(bytes32)");
    private static final FunctionSignature SUPPORTS_INTERFACE =
            FunctionSignature.of("supportsInterface(bytes4)");
    private static final FunctionSignature ROOT_REGISTRY =
            FunctionSignature.of("ROOT_REGISTRY()");
    private static final FunctionSignature FIND_RESOLVER =
            FunctionSignature.of("findResolver(bytes)");
    private static final FunctionSignature REGISTRY_V1 =
            FunctionSignature.of("REGISTRY_V1()");

    /** The ownership refusal for a name ENSv2 decides (#671; Rust {@code ENSV2_OWNERSHIP}). */
    public static final String ENSV2_OWNERSHIP =
            "ENSv2 decides this name's ownership, and this engine does not read ENSv2 yet";

    private final EvmExecutor executor;
    private final Address registry;
    /** Asked only whether ENSv2 decides a name ({@link #v1Decides}, for
     *  {@link #resolveOwnership}); no record is read through it. Null = no ENSv2 on this
     *  tree (Genome). */
    private final Address universalResolver;
    /** ENSv2's v1 mirror on this chain, pinned ({@link EnsAddresses#SEPOLIA_ENSV1_MIRROR});
     *  null = none known, so where ENSv2 is live no name is v1's. */
    private final Address ensv1Mirror;
    /** The {@code .eth} registrar and the NameWrapper for {@link #resolveOwnership};
     *  null = not known for this chain (ownership then stops at the registry). */
    private final Address baseRegistrar;
    private final Address nameWrapper;
    /** {@code namehash("")} of this name tree: zero for ENS, a per-TLD node for a SPACE ID
     *  namespace (Genome {@code .gno}). Every node this resolver computes starts here. */
    private final byte[] rootNode;
    /** The TLD whose second-level names {@link #baseRegistrar} registers ({@code eth}, {@code gno}). */
    private final String registrarTld;
    /** Non-null = the only TLD this resolver serves (Genome: {@code gno}); any other name is
     *  refused instead of being hashed into a tree it does not belong to. Null = any (ENS). */
    private final String requiredTld;

    /** Default constructor: the mainnet contracts. */
    public EnsResolver(EvmExecutor executor) {
        this(executor, EnsAddresses.MAINNET_REGISTRY, EnsAddresses.MAINNET_UNIVERSAL_RESOLVER,
                EnsAddresses.BASE_REGISTRAR, EnsAddresses.MAINNET_NAME_WRAPPER);
    }

    /**
     * Construct against non-default contract addresses. Useful for
     * testnets and for unit tests that mock the resolver chain.
     * {@code universalResolver} resolves no record (reads walk the Registry, ENSIP-10);
     * ownership asks it whether ENSv2 decides the name. The {@code .eth}
     * registrar is one address on every ENS chain; the NameWrapper is not known here
     * (a wrapped name's holders then read as the wrapper contract itself).
     */
    public EnsResolver(EvmExecutor executor, Address registry, Address universalResolver) {
        this(executor, registry, universalResolver, EnsAddresses.BASE_REGISTRAR, null);
    }

    /** With the chain's {@code .eth} registrar and NameWrapper, for {@link #resolveOwnership}. */
    public EnsResolver(EvmExecutor executor, Address registry, Address universalResolver,
                       Address baseRegistrar, Address nameWrapper) {
        this(executor, registry, universalResolver, baseRegistrar, nameWrapper, null);
    }

    /** With the chain's ENSv2 v1 mirror too ({@link #v1Decides}); null = none known. */
    public EnsResolver(EvmExecutor executor, Address registry, Address universalResolver,
                       Address baseRegistrar, Address nameWrapper, Address ensv1Mirror) {
        this(executor, registry, universalResolver, baseRegistrar, nameWrapper, ensv1Mirror,
                new byte[32], "eth", null);
    }

    private EnsResolver(EvmExecutor executor, Address registry, Address universalResolver,
                        Address baseRegistrar, Address nameWrapper, Address ensv1Mirror,
                        byte[] rootNode, String registrarTld, String requiredTld) {
        this.executor = executor;
        this.registry = registry;
        this.universalResolver = universalResolver;
        this.ensv1Mirror = ensv1Mirror;
        this.baseRegistrar = baseRegistrar;
        this.nameWrapper = nameWrapper;
        this.rootNode = rootNode.clone();
        this.registrarTld = registrarTld;
        this.requiredTld = requiredTld;
    }

    /**
     * Genome's {@code .gno} names on Gnosis Chain (chainId 100): a SPACE ID registry with the
     * ENS interfaces, rooted at {@link EnsAddresses#gnosisGenomeRoot()} instead of zero.
     * Serves {@code .gno} names only — any other name is refused with an
     * {@link IllegalArgumentException}, the same way a malformed name is. There is no
     * NameWrapper; the registrar is Genome's {@code .gno} Base.
     */
    public static EnsResolver gnosisGenome(EvmExecutor executor) {
        return new EnsResolver(executor, EnsAddresses.GNOSIS_GENOME_REGISTRY, null,
                EnsAddresses.GNOSIS_GENOME_REGISTRAR, null, null,
                EnsAddresses.gnosisGenomeRoot(), EnsAddresses.GENOME_TLD, EnsAddresses.GENOME_TLD);
    }

    /** The refusal for a non-{@code .gno} name on Gnosis Chain (Rust {@code ONLY_GNO_NAMES}). */
    public static final String ONLY_GNO_NAMES = "only .gno names resolve on Gnosis Chain";
    /** The refusal for a reverse lookup on Gnosis Chain (Rust {@code NO_GNO_REVERSE}). */
    public static final String NO_GNO_REVERSE = "reverse resolution is not supported for .gno names";

    /**
     * Why a query on {@code chainId} is refused before any state is read, or null when it
     * can be tried: a name outside the chain's tree ({@code name}), or a reverse lookup
     * ({@code name} = null) where the tree has none — on Gnosis, anything but a forward
     * {@code .gno} lookup. Callers check it first so a refused query costs no peer probe,
     * no EVM setup and no AUTO retry. Rust twin: {@code myotis_evm::ens::refusal}.
     */
    public static String refusal(long chainId, String name) {
        // Derived from the same forChainId table the resolution itself uses, so a tree
        // added there is refused here by construction (the Rust twin reads
        // Namespace::for_chain for both). The executor is never touched.
        final EnsResolver tree;
        try {
            tree = forChainId(null, chainId);
        } catch (IllegalArgumentException noTree) {
            return null;   // no pinned tree: the caller reports that itself
        }
        if (tree.requiredTld == null) return null;
        if (name == null) return NO_GNO_REVERSE;
        return tree.servesName(name) ? null : ONLY_GNO_NAMES;
    }

    private static boolean servesUnderTld(String tld, String name) {
        if (name == null) return false;
        String n = name.toLowerCase(java.util.Locale.ROOT);
        if (n.endsWith(".")) n = n.substring(0, n.length() - 1);
        return n.endsWith("." + tld) && n.length() > tld.length() + 1;
    }

    /** Whether this resolver serves {@code name}: any name for ENS, only names under its
     *  TLD for a single-TLD namespace (Genome: {@code x.gno}, one trailing root dot allowed). */
    public boolean servesName(String name) {
        return requiredTld == null || servesUnderTld(requiredTld, name);
    }

    /**
     * The node of {@code name} in this resolver's tree. Throws {@link IllegalArgumentException}
     * for a name outside a single-TLD namespace — a {@code vitalik.eth} hashed under the
     * Genome root is not a name anyone registered, and "no record" would hide the mistake.
     */
    private byte[] node(String name) {
        if (!servesName(name)) {
            throw new IllegalArgumentException(ONLY_GNO_NAMES);
        }
        return Namehash.of(name, rootNode);
    }

    /**
     * Network-aware factory keyed on the EVM chain ID: picks the
     * canonical Registry (and the chain's NameWrapper, where pinned) for
     * the given network. Throws {@link IllegalArgumentException} for networks
     * where ENS is not pinned (callers that need to override can use
     * the three-arg constructor directly).
     *
     * <p>Keeping this on chain-id (not on a {@code NetworkConfig}) keeps
     * {@code :myotis-ens} from depending on {@code :networking} — the
     * ENS module needs to remain Android-friendly and the networking
     * module pulls in Netty + discv5 transitively.
     *
     * @param chainId EVM chain id: 1 = mainnet, 11155111 = sepolia, 100 = Gnosis Chain
     *                (Genome {@code .gno} names, {@link #gnosisGenome}),
     *                17000 = holesky — dead code: the EF retired the network in
     *                Oct 2025, {@code NetworkConfig.byName} rejects it and
     *                {@code NetworkConfig.hasEns} never admits it, so no production
     *                caller reaches that branch
     */
    public static EnsResolver forChainId(EvmExecutor executor, long chainId) {
        // Java's switch statement only accepts int-promotable types, so a
        // `switch ((int) chainId)` would truncate large chain ids — a
        // mainnet-shaped id like 4_294_967_297L would wrap to 1 and
        // silently pick the mainnet contracts. Compare on the long.
        if (chainId == 1L) {
            return new EnsResolver(executor,
                    EnsAddresses.MAINNET_REGISTRY, EnsAddresses.MAINNET_UNIVERSAL_RESOLVER,
                    EnsAddresses.BASE_REGISTRAR, EnsAddresses.MAINNET_NAME_WRAPPER);
        }
        if (chainId == 11155111L) {
            return new EnsResolver(executor,
                    EnsAddresses.SEPOLIA_REGISTRY, EnsAddresses.SEPOLIA_UNIVERSAL_RESOLVER,
                    EnsAddresses.BASE_REGISTRAR, EnsAddresses.SEPOLIA_NAME_WRAPPER,
                    EnsAddresses.SEPOLIA_ENSV1_MIRROR);
        }
        if (chainId == 17000L) {
            return new EnsResolver(executor,
                    EnsAddresses.HOLESKY_REGISTRY, EnsAddresses.HOLESKY_UNIVERSAL_RESOLVER,
                    EnsAddresses.BASE_REGISTRAR, null);
        }
        if (chainId == 100L) {
            return gnosisGenome(executor);
        }
        throw new IllegalArgumentException("ENS not pinned for chain id " + chainId);
    }

    // ---- Forward record-type calls ----------------------------------------

    /**
     * Forward resolution: {@code name → address}.
     *
     * <p>Returns {@link Optional#empty()} when no resolver can answer for
     * the name (none set anywhere up the Registry walk, or only an
     * ancestor's that does not implement ENSIP-10), when the record is
     * unset (a zero address), or when the resolver reverts.
     * {@code OffchainLookup} reverts are rethrown for the
     * {@code CcipReadEvmExecutor} wrapper to catch.
     */
    public CompletableFuture<Optional<Address>> resolveAddress(String name, BlockContext blockContext) {
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(ADDR, AbiEncoder.bytes32(node));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeAddrResult);
    }

    /**
     * Multi-coin address (ENSIP-9 / SLIP-44):
     * {@code addr(node, coinType) → bytes}.
     *
     * <p>{@code coinType} is the SLIP-44 coin type for the chain whose
     * address we want (e.g. {@code 0} for Bitcoin, {@code 60} for ETH).
     * The return is the chain-specific address bytes; for Bitcoin that
     * is the script payload, for EVM chains it is the 20-byte address.
     * Decoding the bytes for a given chain is the caller's responsibility.
     */
    public CompletableFuture<Optional<byte[]>> resolveMultiCoinAddress(
            String name, long coinType, BlockContext blockContext) {
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(
                ADDR_COIN, AbiEncoder.bytes32(node), AbiEncoder.uint256(coinType));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeNonEmptyBytes);
    }

    /**
     * Text record (ENSIP-5):
     * {@code text(node, key) → string}. Common keys: {@code "avatar"},
     * {@code "url"}, {@code "description"}, {@code "email"},
     * {@code "com.twitter"}, {@code "com.github"}, {@code "org.telegram"}.
     */
    public CompletableFuture<Optional<String>> resolveText(
            String name, String key, BlockContext blockContext) {
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(
                TEXT, AbiEncoder.bytes32(node), AbiEncoder.string(key));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeStringResult);
    }

    /**
     * Content hash (ENSIP-7):
     * {@code contenthash(node) → bytes}. The return is a multicodec-
     * encoded pointer (IPFS / Swarm / IPNS / Arweave); see
     * <a href="https://github.com/multiformats/multicodec">multicodec</a>.
     * Decoding the multicodec is the caller's responsibility.
     */
    public CompletableFuture<Optional<byte[]>> resolveContenthash(
            String name, BlockContext blockContext) {
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(CONTENTHASH, AbiEncoder.bytes32(node));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeNonEmptyBytes);
    }

    /**
     * Public key record (EIP-619):
     * {@code pubkey(node) → (bytes32 x, bytes32 y)} — secp256k1 public-
     * key coordinates. Returns {@link Optional#empty()} when both
     * coordinates are zero (no record set).
     */
    public CompletableFuture<Optional<Pubkey>> resolvePubkey(
            String name, BlockContext blockContext) {
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(PUBKEY, AbiEncoder.bytes32(node));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodePubkeyResult);
    }

    /**
     * ABI record (EIP-205):
     * {@code ABI(node, contentTypes) → (uint256 contentType, bytes data)}.
     * {@code contentTypes} is a bitmask of supported encodings: 1 =
     * Solidity ABI JSON, 2 = zlib-compressed JSON, 4 = CBOR, 8 = URI
     * (resolver may return any of those it has, with the chosen
     * {@code contentType} echoed back).
     */
    public CompletableFuture<Optional<AbiRecord>> resolveAbi(
            String name, long contentTypes, BlockContext blockContext) {
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(
                ABI, AbiEncoder.bytes32(node), AbiEncoder.uint256(contentTypes));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeAbiResult);
    }

    /**
     * DNS record (ENSIP-8):
     * {@code dnsRecord(node, dnsName, resource) → bytes}. The return is
     * the raw DNS RDATA the resolver has stored for that
     * (name, resource-type) pair, including any DNSSEC signing. The
     * caller is responsible for parsing and (if desired) DNSSEC-
     * verifying the bytes.
     *
     * @param dnsName  DNS-wire-encoded name (use {@link DnsEncoder#encode})
     * @param resource DNS resource type (e.g. 1 = A, 28 = AAAA, 16 = TXT)
     */
    public CompletableFuture<Optional<byte[]>> resolveDnsRecord(
            String name, byte[] dnsName, int resource, BlockContext blockContext) {
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(
                DNS_RECORD,
                AbiEncoder.bytes32(node),
                AbiEncoder.bytes(dnsName),
                AbiEncoder.uint256(resource & 0xFFFFL));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeNonEmptyBytes);
    }

    /**
     * Interface implementer (EIP-1820 over ENS):
     * {@code interfaceImplementer(node, interfaceId) → address}. Returns
     * the address of a contract that implements the given EIP-165
     * interface for this name's owner.
     *
     * @param interfaceId 4-byte EIP-165 interface selector
     */
    public CompletableFuture<Optional<Address>> resolveInterfaceImplementer(
            String name, byte[] interfaceId, BlockContext blockContext) {
        if (interfaceId == null || interfaceId.length != 4) {
            throw new IllegalArgumentException("interfaceId must be 4 bytes");
        }
        byte[] padded = new byte[32];
        System.arraycopy(interfaceId, 0, padded, 0, 4);
        byte[] node = node(name);
        byte[] innerCall = AbiEncoder.encodeCall(
                INTERFACE_IMPLEMENTER,
                AbiEncoder.bytes32(node),
                AbiEncoder.bytes32(padded));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeAddrResult);
    }

    /**
     * Reverse resolution: {@code address → name}, with ENSIP-3 verification.
     *
     * <p>Step-by-step path against the Registry: the reverse node's
     * {@code resolver(bytes32)}, then that resolver's {@code name(bytes32)}, called
     * directly — the old reverse resolvers predate ERC-165 and halt on a
     * {@code supportsInterface} probe. That covers classic on-chain reverse records. An
     * address with no reverse resolver of its own is asked of an ancestor's ENSIP-10
     * resolver ({@link #ancestorReverseName}). The verification round-trip is
     * {@link #resolveAddress} — the same Registry walk every forward read takes.
     *
     * <p>Returns {@link Optional#empty()} when the address has no reverse
     * record OR when the resolver's claim fails ENSIP-3 verification (a
     * forward lookup of the claimed name doesn't point back at the
     * original address).
     */
    public CompletableFuture<Optional<String>> resolveName(Address address, BlockContext blockContext) {
        if (requiredTld != null) {
            // Genome keeps its reverse records in SPACE ID's own reverse scheme (an
            // addr.reverse node read through tldName/name with the TLD's identifier),
            // which this resolver does not implement. Refuse: "no primary name" would
            // look like a real answer.
            return com.jaeckel.ethp2p.core.concurrent.Futures.failedFuture(
                    new UnsupportedOperationException(NO_GNO_REVERSE));
        }
        String reverseName = ReverseLookup.nameFor(address);
        byte[] reverseNode = Namehash.of(reverseName);
        return getReverseResolver(reverseNode, blockContext)
                .thenCompose(resolver -> resolver.isPresent()
                        ? getName(resolver.get(), reverseNode, blockContext)
                        : ancestorReverseName(reverseName, reverseNode, blockContext))
                .thenCompose(claimed -> verifyForward(claimed, address, blockContext));
    }

    /**
     * The claim for an address WITHOUT a reverse resolver of its own (#671): the nearest
     * resolver of {@code addr.reverse} or {@code reverse}, when it is an ENSIP-10 wildcard
     * one, asked through {@code resolve(bytes,bytes)}. A primary name set through ENSv2 on
     * Sepolia is answered that way, and so, on mainnet, is one the {@code reverse} node's
     * wildcard resolver keeps for an address. Rust twin: the walk-up branch of
     * {@code reverse_resolve}.
     */
    private CompletableFuture<Optional<String>> ancestorReverseName(
            String reverseName, byte[] reverseNode, BlockContext ctx) {
        return findResolver("addr.reverse", ctx).thenCompose(found -> {
            if (found.isEmpty() || !found.get().extended()) {
                return CompletableFuture.completedFuture(Optional.<String>empty());
            }
            byte[] nameCall = AbiEncoder.encodeCall(NAME, AbiEncoder.bytes32(reverseNode));
            byte[] calldata = AbiEncoder.encodeCall(RESOLVE,
                    AbiEncoder.bytes(DnsEncoder.encode(reverseName)), AbiEncoder.bytes(nameCall));
            return executor.callView(found.get().resolver(), calldata, ctx)
                    .handle((result, error) ->
                            decodeOutcome(result, error, /* wrapped */ true, EnsResolver::decodeStringResult));
        });
    }

    // ---- Ownership ---------------------------------------------------------

    /** Who holds a name; see {@link #resolveOwnership}. {@code expiresAt} / {@code gracePeriod}
     *  are -1 where there is no registrar entry (a subname, an unregistered name). */
    public record Ownership(Address registrant, Address manager, boolean wrapped,
                            Address resolver, long expiresAt, long gracePeriod) {}

    /**
     * Who holds {@code name}: the registry's {@code owner(node)} and {@code resolver(node)},
     * then for a second-level name of the registrar's TLD ({@code x.eth}; {@code x.gno} on
     * Gnosis Chain, whose Genome registrar has the same interface) the registrar's
     * {@code ownerOf}, {@code nameExpires} and {@code GRACE_PERIOD}, each unwrapped through
     * the chain's NameWrapper where it is the holder (Gnosis has none). Empty = nothing
     * on chain for the name (no registry owner or resolver, no registrar token, no expiry). A reverting
     * {@code ownerOf} (an expired or never registered token) is "no registrant", never a
     * failure; any other failure propagates. The name is validated and hashed exactly as
     * the record reads validate and hash it ({@link DnsEncoder#encode}, {@link Namehash#of}),
     * so this read and the record reads of one input answer about the same node. A name
     * ENSv2 decides fails with {@link #ENSV2_OWNERSHIP} (#671): v1's registry and registrar
     * would read it as unowned or name a stale holder. Rust twin: {@code resolve_ownership}.
     */
    public CompletableFuture<Optional<Ownership>> resolveOwnership(String name, BlockContext ctx) {
        // The record reads' own validation (an empty label, more than one trailing dot)
        // and their node: Namehash.of lowercases as it hashes and keeps a trailing dot as
        // an empty label — so "x.eth." is the three-label node the records look at, not
        // the 2LD's, and the registrar is asked only for a two-label name of its TLD.
        try {
            DnsEncoder.encode(name);
        } catch (IllegalArgumentException e) {
            return com.jaeckel.ethp2p.core.concurrent.Futures.failedFuture(e);
        }
        String[] labels = name.toLowerCase(java.util.Locale.ROOT).split("\\.", -1);
        byte[] node;
        try {
            node = node(name);
        } catch (IllegalArgumentException e) {
            return com.jaeckel.ethp2p.core.concurrent.Futures.failedFuture(e);
        }
        if (baseRegistrar == null) {
            return com.jaeckel.ethp2p.core.concurrent.Futures.failedFuture(
                    new IllegalStateException("the ." + registrarTld + " registrar is not pinned for this chain"));
        }
        CompletableFuture<Boolean> v1 = universalResolver == null
                ? CompletableFuture.completedFuture(true)
                : v1Decides(DnsEncoder.encode(name), ctx);
        return v1.thenCompose(decides -> decides
                ? readOwnership(labels, node, ctx)
                : com.jaeckel.ethp2p.core.concurrent.Futures.<Optional<Ownership>>failedFuture(
                        new UnsupportedOperationException(ENSV2_OWNERSHIP)));
    }

    /**
     * Whether the v1 registry still decides the name {@code dnsName} encodes (#671).
     * ENSv2 is live on a chain when its Universal Resolver names a root registry
     * ({@code ROOT_REGISTRY()}: Sepolia since the ENSv2 beta; a revert on mainnet until
     * activation). Where it is not, v1 decides everything. Where it is, v1 decides only a
     * name the Universal Resolver hands to this chain's pinned v1 mirror ({@link #ensv1Mirror}),
     * which ENSv2 sets for names not migrated yet; its {@code REGISTRY_V1()} must still name
     * this registry. Any other answer, no resolver included, belongs to ENSv2; and where no
     * mirror is pinned, no name is v1's. Rust twin: {@code v1_decides}.
     */
    private CompletableFuture<Boolean> v1Decides(byte[] dnsName, BlockContext ctx) {
        return callAddress(universalResolver, AbiEncoder.encodeCall(ROOT_REGISTRY), ctx).thenCompose(root -> {
            if (root.isEmpty()) return CompletableFuture.completedFuture(true);
            if (ensv1Mirror == null) return CompletableFuture.completedFuture(false);
            byte[] find = AbiEncoder.encodeCall(FIND_RESOLVER, AbiEncoder.bytes(dnsName));
            return callAddress(universalResolver, find, ctx).thenCompose(resolver ->
                    resolver.isEmpty() || !resolver.get().equals(ensv1Mirror)
                            ? CompletableFuture.completedFuture(false)
                            : callAddress(resolver.get(), AbiEncoder.encodeCall(REGISTRY_V1), ctx)
                                    .thenApply(v1 -> v1.isPresent() && v1.get().equals(registry)));
        });
    }

    /** The v1 reads of {@link #resolveOwnership}, once v1 is known to decide the name. */
    private CompletableFuture<Optional<Ownership>> readOwnership(String[] labels, byte[] node, BlockContext ctx) {
        boolean secondLevel = labels.length == 2 && labels[1].equals(registrarTld);
        byte[] labelHash = secondLevel ? Namehash.labelhash(labels[0]) : null;

        CompletableFuture<Optional<Address>> owner =
                callAddress(registry, AbiEncoder.encodeCall(OWNER, AbiEncoder.bytes32(node)), ctx);
        CompletableFuture<Optional<Address>> resolver =
                callAddress(registry, AbiEncoder.encodeCall(RESOLVER, AbiEncoder.bytes32(node)), ctx);
        CompletableFuture<Optional<Address>> tokenOwner = secondLevel
                ? callAddress(baseRegistrar, AbiEncoder.encodeCall(OWNER_OF, AbiEncoder.bytes32(labelHash)), ctx)
                : CompletableFuture.completedFuture(Optional.empty());
        CompletableFuture<Optional<Long>> expires = secondLevel
                ? callUint(baseRegistrar, AbiEncoder.encodeCall(NAME_EXPIRES, AbiEncoder.bytes32(labelHash)), ctx)
                : CompletableFuture.completedFuture(Optional.empty());
        CompletableFuture<Optional<Long>> grace = expires.thenCompose(e -> e.isPresent()
                ? callUint(baseRegistrar, AbiEncoder.encodeCall(GRACE_PERIOD), ctx)
                : CompletableFuture.completedFuture(Optional.empty()));
        CompletableFuture<Optional<Address>> manager = owner.thenCompose(o -> {
            boolean wrapped = o.isPresent() && nameWrapper != null && o.get().equals(nameWrapper);
            return wrapped
                    ? callAddress(nameWrapper, AbiEncoder.encodeCall(OWNER_OF, AbiEncoder.bytes32(node)), ctx)
                    : CompletableFuture.completedFuture(o);
        });

        return CompletableFuture.allOf(owner, resolver, tokenOwner, expires, grace, manager)
                .thenApply(v -> {
                    Optional<Address> o = owner.join();
                    boolean wrapped = o.isPresent() && nameWrapper != null && o.get().equals(nameWrapper);
                    Optional<Address> t = tokenOwner.join();
                    Optional<Address> registrant =
                            (t.isPresent() && nameWrapper != null && t.get().equals(nameWrapper))
                                    ? manager.join() : t;
                    Optional<Long> exp = expires.join();
                    if (o.isEmpty() && resolver.join().isEmpty() && registrant.isEmpty() && exp.isEmpty()) {
                        return Optional.empty();
                    }
                    return Optional.of(new Ownership(
                            registrant.orElse(null), manager.join().orElse(null), wrapped,
                            resolver.join().orElse(null),
                            exp.orElse(-1L), grace.join().orElse(-1L)));
                });
    }

    /** One {@code address}-returning view: the zero address and a revert are both empty;
     *  any other failure propagates (a well-formed wrong answer is worse than none). */
    private CompletableFuture<Optional<Address>> callAddress(Address target, byte[] calldata, BlockContext ctx) {
        return executor.callView(target, calldata, ctx).handle((res, err) -> {
            if (err == null) return decodeAddressOrEmpty(res);
            if (isRevert(err)) return Optional.<Address>empty();
            throw new CompletionException(unwrap(err));
        });
    }

    /** One {@code uint256}-returning view that must fit a {@code long}; zero and a revert are empty. */
    private CompletableFuture<Optional<Long>> callUint(Address target, byte[] calldata, BlockContext ctx) {
        return executor.callView(target, calldata, ctx).handle((res, err) -> {
            if (err == null) return decodeUintOrEmpty(res);
            if (isRevert(err)) return Optional.<Long>empty();
            throw new CompletionException(unwrap(err));
        });
    }

    private static Optional<Long> decodeUintOrEmpty(byte[] result) {
        if (result == null || result.length < 32) return Optional.empty();
        for (int i = 0; i < 24; i++) {
            if (result[i] != 0) return Optional.empty();   // above Long.MAX_VALUE: unusable here
        }
        long v = 0;
        for (int i = 24; i < 32; i++) v = (v << 8) | (result[i] & 0xff);
        if (v < 0) return Optional.empty();
        return v == 0 ? Optional.empty() : Optional.of(v);
    }

    // ---- Record dispatch (Registry walk, ENSIP-10) -------------------------

    /**
     * Find the resolver for {@code name} ({@link #findResolver}: the Registry
     * walk of ENSIP-10) and run {@code innerCall} against it through
     * {@link EvmExecutor#callView}: wrapped in the resolver's own
     * {@code resolve(bytes,bytes)} when it implements ENSIP-10, or sent as is
     * to a legacy resolver set on the exact node. A legacy resolver found only
     * on an ancestor cannot answer for the name, which is then empty. The
     * outcome goes through the revert taxonomy below, and the inner-call
     * return bytes into {@code innerResultDecoder}.
     *
     * <p>Revert taxonomy:
     * <ul>
     *   <li>{@code OffchainLookup} (ERC-3668) — rethrown so the
     *       {@code CcipReadEvmExecutor} wrapper can fetch the gateway
     *       response and re-enter the EVM with the resolver's callback.
     *   <li>Any other revert — mapped to {@link Optional#empty()}. The
     *       caller's intent is "look up this record" and the reasonable
     *       answer for an unregistered name or missing record is "no
     *       result," not a propagated failure.
     *   <li>Non-revert failure (oracle issue, network problem) —
     *       propagated as a failed future.
     * </ul>
     *
     * <p>Decoding:
     * <ul>
     *   <li>An ENSIP-10 {@code resolve()} returns {@code bytes} wrapping
     *       the inner call's return, pulled out via
     *       {@code AbiDecoder.dynamicBytes(result, 0)}; a legacy resolver's
     *       return IS the inner call's return.
     *   <li>The decoder receives {@code innerResult} and returns
     *       {@link Optional#empty()} for any "missing record" condition
     *       (zero address, empty bytes, etc.) and the value otherwise.
     *   <li>A {@link RuntimeException} from the decoder (malformed
     *       buffer) is also folded to {@link Optional#empty()} — same
     *       reasoning as a plain revert.
     * </ul>
     */
    private <T> CompletableFuture<Optional<T>> dispatchResolve(
            String name, byte[] innerCall, BlockContext blockContext,
            Function<byte[], Optional<T>> innerResultDecoder) {
        byte[] dnsName = DnsEncoder.encode(name);
        return findResolver(name, blockContext).thenCompose(found -> {
            if (found.isEmpty()) {
                // No resolver set anywhere up the chain → unregistered / no record.
                return CompletableFuture.completedFuture(Optional.<T>empty());
            }
            ResolverInfo ri = found.get();
            if (ri.extended()) {
                // ENSIP-10: call the resolver's resolve(name, data) DIRECTLY. For an
                // offchain resolver this throws OffchainLookup pointing at the
                // resolver's OWN gateway (e.g. Coinbase for cb.id), so
                // CcipReadEvmExecutor fetches it with no third-party batch relay.
                byte[] calldata = AbiEncoder.encodeCall(
                        RESOLVE, AbiEncoder.bytes(dnsName), AbiEncoder.bytes(innerCall));
                return executor.callView(ri.resolver(), calldata, blockContext)
                        .handle((result, error) ->
                                decodeOutcome(result, error, /* wrapped */ true, innerResultDecoder));
            }
            if (ri.exact()) {
                // Legacy resolver (e.g. the ENS Public Resolver) that doesn't
                // implement ENSIP-10: call the record method directly.
                return executor.callView(ri.resolver(), innerCall, blockContext)
                        .handle((result, error) ->
                                decodeOutcome(result, error, /* wrapped */ false, innerResultDecoder));
            }
            // Resolver exists only on an ancestor and isn't ENSIP-10 wildcard-aware,
            // so it cannot answer for this subname.
            return CompletableFuture.completedFuture(Optional.<T>empty());
        });
    }

    /**
     * Shared outcome decoder. {@code wrapped} is true for ENSIP-10
     * {@code resolve()} (whose return is {@code bytes} wrapping the inner-call
     * return) and false for a direct legacy record call (the return IS the
     * inner-call return). OffchainLookup is normally consumed by
     * {@link io.myotis.evm.CcipReadEvmExecutor}; a plain revert maps to empty;
     * any other failure propagates.
     */
    private static <T> Optional<T> decodeOutcome(
            byte[] result, Throwable error, boolean wrapped,
            Function<byte[], Optional<T>> innerResultDecoder) {
        if (error != null) {
            Throwable cause = unwrap(error);
            if (cause instanceof EvmExecutionException eee
                    && eee.error() instanceof EvmExecutionError.Reverted r
                    && OffchainLookupRevert.tryParse(r.data()).isPresent()) {
                throw new CompletionException(cause);
            }
            if (cause instanceof EvmExecutionException eee
                    && eee.error() instanceof EvmExecutionError.Reverted) {
                return Optional.empty();
            }
            throw new CompletionException(cause);
        }
        if (result == null) return Optional.empty();
        if (wrapped && result.length < 64) return Optional.empty();
        try {
            byte[] inner = wrapped ? AbiDecoder.dynamicBytes(result, 0) : result;
            return innerResultDecoder.apply(inner);
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    // ---- Resolver discovery (direct: no UniversalResolver, no batch gateway) --

    private record ResolverInfo(Address resolver, boolean exact, boolean extended) {}
    private record CachedResolver(ResolverInfo info, long expiresAtMs) {}
    private record Found(Address resolver, boolean exact) {}

    /** IExtendedResolver (ENSIP-10) interface id — {@code resolve(bytes,bytes)} support. */
    private static final byte[] EXTENDED_RESOLVER_INTERFACE_ID = {(byte) 0x90, 0x61, (byte) 0xb9, 0x23};
    private static final long RESOLVER_CACHE_TTL_MS = 5 * 60 * 1000L;
    /** Per (chain,registry,name) resolver-discovery cache so repeated lookups skip the walk.
     *  The chain is part of the key: mainnet and Sepolia share the registry address, and one
     *  process can serve both. */
    private static final java.util.concurrent.ConcurrentHashMap<String, CachedResolver> RESOLVER_CACHE =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** Test hook: drop cached resolver discovery so tests don't see each other's state. */
    static void clearResolverCache() { RESOLVER_CACHE.clear(); }

    /**
     * Find the resolver responsible for {@code name} via the registry (ENSIP-10
     * walk: exact node, then each parent, until a resolver is set) and detect
     * whether it implements ENSIP-10. All reads are snap/EVM — no gateway.
     * Cached per chain+registry+name for a few minutes. Empty when no resolver is set
     * anywhere up the chain.
     */
    private CompletableFuture<Optional<ResolverInfo>> findResolver(String name, BlockContext ctx) {
        String cacheKey = ctx.chainId() + ":" + registry.toHex() + ':'
                + name.toLowerCase(java.util.Locale.ROOT);
        CachedResolver cached = RESOLVER_CACHE.get(cacheKey);
        if (cached != null && cached.expiresAtMs() > System.currentTimeMillis()) {
            return CompletableFuture.completedFuture(Optional.of(cached.info()));
        }
        String[] labels = name.isEmpty() ? new String[0] : name.split("\\.");
        return walkResolver(labels, 0, ctx).thenCompose(found -> {
            if (found.isEmpty()) {
                return CompletableFuture.completedFuture(Optional.<ResolverInfo>empty());
            }
            Address resolver = found.get().resolver();
            boolean exact = found.get().exact();
            byte[] arg = new byte[32];
            System.arraycopy(EXTENDED_RESOLVER_INTERFACE_ID, 0, arg, 0, 4);
            byte[] supportsCall = AbiEncoder.encodeCall(SUPPORTS_INTERFACE, AbiEncoder.bytes32(arg));
            return executor.callView(resolver, supportsCall, ctx)
                    .handle(EnsResolver::decodeSupportsInterface)
                    .thenApply(extended -> {
                        ResolverInfo info = new ResolverInfo(resolver, exact, extended);
                        RESOLVER_CACHE.put(cacheKey, new CachedResolver(
                                info, System.currentTimeMillis() + RESOLVER_CACHE_TTL_MS));
                        return Optional.of(info);
                    });
        });
    }

    /**
     * Try {@code registry.resolver(namehash(labels[i:]))}; recurse to the parent on a zero
     * address or a revert. Any other failure — an oracle or network error, a block the EVM
     * refuses to run (Sepolia past Amsterdam on Besu 26.4) — fails the walk instead: its
     * empty result means "unregistered", a definitive answer, and a failure read as one is
     * a well-formed wrong answer (every name "does not resolve"). Rust twin:
     * {@code find_resolver}, which continues only on a revert.
     */
    private CompletableFuture<Optional<Found>> walkResolver(String[] labels, int i, BlockContext ctx) {
        if (i >= labels.length) return CompletableFuture.completedFuture(Optional.empty());
        String suffix = String.join(".", java.util.Arrays.asList(labels).subList(i, labels.length));
        byte[] node = Namehash.of(suffix, rootNode);
        byte[] calldata = AbiEncoder.encodeCall(RESOLVER, AbiEncoder.bytes32(node));
        return executor.callView(registry, calldata, ctx)
                .handle((res, err) -> {
                    if (err == null) return decodeAddressOrEmpty(res);
                    if (isRevert(err)) return Optional.<Address>empty();
                    throw new CompletionException(unwrap(err));
                })
                .thenCompose(addr -> addr.isPresent()
                        ? CompletableFuture.completedFuture(Optional.of(new Found(addr.get(), i == 0)))
                        : walkResolver(labels, i + 1, ctx));
    }

    /**
     * ERC-165 {@code supportsInterface}: false on a revert (a resolver without ERC-165); any
     * other failure propagates rather than silently choosing the legacy path, which would
     * then be cached for {@link #RESOLVER_CACHE_TTL_MS}. Rust twin: {@code supports_interface}.
     */
    private static boolean decodeSupportsInterface(byte[] result, Throwable error) {
        if (error != null) {
            if (isRevert(error)) return false;
            throw new CompletionException(unwrap(error));
        }
        return result != null && result.length >= 32 && result[31] != 0;
    }

    /** Whether {@code error} is an EVM revert — a contract's answer, unlike every other failure. */
    private static boolean isRevert(Throwable error) {
        return unwrap(error) instanceof EvmExecutionException eee
                && eee.error() instanceof EvmExecutionError.Reverted;
    }

    // ---- Reverse-path step-by-step calls ----------------------------------

    /** Registry call: {@code resolver(bytes32) → address}. Used only for the reverse path. */
    private CompletableFuture<Optional<Address>> getReverseResolver(byte[] node, BlockContext ctx) {
        byte[] calldata = AbiEncoder.encodeCall(RESOLVER, AbiEncoder.bytes32(node));
        return executor.callView(registry, calldata, ctx)
                .thenApply(EnsResolver::decodeAddressOrEmpty);
    }

    /** Resolver call: {@code name(bytes32) → string}. */
    private CompletableFuture<Optional<String>> getName(Address resolver, byte[] node, BlockContext ctx) {
        byte[] calldata = AbiEncoder.encodeCall(NAME, AbiEncoder.bytes32(node));
        return executor.callView(resolver, calldata, ctx)
                .thenApply(EnsResolver::decodeStringOrEmpty);
    }

    // ---- Decoders ---------------------------------------------------------

    /**
     * Inner-call return for {@code addr(bytes32)} and
     * {@code interfaceImplementer(bytes32, bytes4)}: a single 32-byte
     * slot holding an address. Zero address → empty.
     */
    private static Optional<Address> decodeAddrResult(byte[] inner) {
        if (inner.length < 32) return Optional.empty();
        Address addr = AbiDecoder.address(inner, 0);
        return addr.equals(Address.ZERO) ? Optional.<Address>empty() : Optional.of(addr);
    }

    /**
     * Inner-call return for {@code text(bytes32, string)}: dynamic
     * UTF-8 string. Empty string → empty.
     */
    private static Optional<String> decodeStringResult(byte[] inner) {
        if (inner.length < 64) return Optional.empty();
        String s = AbiDecoder.string(inner, 0);
        return s.isEmpty() ? Optional.<String>empty() : Optional.of(s);
    }

    /**
     * Inner-call return for {@code addr(bytes32, uint256)},
     * {@code contenthash(bytes32)}, and
     * {@code dnsRecord(bytes32, bytes, uint16)}: dynamic bytes. Empty
     * bytes → empty.
     */
    private static Optional<byte[]> decodeNonEmptyBytes(byte[] inner) {
        if (inner.length < 32) return Optional.empty();
        byte[] payload = AbiDecoder.dynamicBytes(inner, 0);
        return payload.length == 0 ? Optional.<byte[]>empty() : Optional.of(payload);
    }

    /**
     * Inner-call return for {@code pubkey(bytes32)}: fixed
     * {@code (bytes32 x, bytes32 y)} tuple. Both-zero → empty.
     */
    private static Optional<Pubkey> decodePubkeyResult(byte[] inner) {
        if (inner.length < 64) return Optional.empty();
        byte[] x = AbiDecoder.bytes32(inner, 0);
        byte[] y = AbiDecoder.bytes32(inner, 32);
        if (isAllZero(x) && isAllZero(y)) return Optional.empty();
        return Optional.of(new Pubkey(x, y));
    }

    /**
     * Inner-call return for {@code ABI(bytes32, uint256)}:
     * {@code (uint256 contentType, bytes data)}. Empty data → empty.
     */
    private static Optional<AbiRecord> decodeAbiResult(byte[] inner) {
        if (inner.length < 64) return Optional.empty();
        BigInteger contentType = AbiDecoder.uint256(inner, 0);
        byte[] data = AbiDecoder.dynamicBytes(inner, 32);
        if (data.length == 0) return Optional.empty();
        // contentType is a small bitmask in practice (1, 2, 4, 8) — long is plenty.
        return Optional.of(new AbiRecord(BigIntegers.longValueExact(contentType), data));
    }

    /** Decode a single 32-byte address with empty/short fallback. */
    private static Optional<Address> decodeAddressOrEmpty(byte[] result) {
        if (result == null || result.length < 32) return Optional.empty();
        Address addr = AbiDecoder.address(result, 0);
        return addr.equals(Address.ZERO) ? Optional.<Address>empty() : Optional.of(addr);
    }

    /** Decode a single dynamic string with empty/short/malformed fallback. */
    private static Optional<String> decodeStringOrEmpty(byte[] result) {
        if (result == null || result.length < 64) return Optional.empty();
        try {
            String s = AbiDecoder.string(result, 0);
            return s.isEmpty() ? Optional.<String>empty() : Optional.of(s);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * ENSIP-3 verification: confirm the resolver's name claim by resolving
     * it forward and checking it points back at the original address.
     */
    private CompletableFuture<Optional<String>> verifyForward(
            Optional<String> claimed, Address address, BlockContext ctx) {
        if (claimed.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
        return resolveAddress(claimed.get(), ctx).thenApply(forward ->
                forward.filter(a -> a.equals(address)).map(a -> claimed.get()));
    }

    private static boolean isAllZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    private static Throwable unwrap(Throwable t) {
        while (t instanceof CompletionException && t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }

    // ---- Value records ----------------------------------------------------

    /** {@code (bytes32 x, bytes32 y)} — secp256k1 public-key coordinates per EIP-619. */
    public record Pubkey(byte[] x, byte[] y) {
        public Pubkey {
            if (x == null || x.length != 32) throw new IllegalArgumentException("x must be 32 bytes");
            if (y == null || y.length != 32) throw new IllegalArgumentException("y must be 32 bytes");
        }
    }

    /** {@code (uint256 contentType, bytes data)} — ABI record per EIP-205. */
    public record AbiRecord(long contentType, byte[] data) {
        public AbiRecord {
            if (data == null) throw new IllegalArgumentException("data must not be null");
        }
    }
}
