package io.myotis.ens;

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
 * Generic UR reverts (ResolverNotFound and friends) still map to
 * {@link Optional#empty()}.
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
    private static final FunctionSignature INTERFACE_IMPLEMENTER =
            FunctionSignature.of("interfaceImplementer(bytes32,bytes4)");
    private static final FunctionSignature RESOLVER =
            FunctionSignature.of("resolver(bytes32)");
    private static final FunctionSignature NAME =
            FunctionSignature.of("name(bytes32)");
    private static final FunctionSignature SUPPORTS_INTERFACE =
            FunctionSignature.of("supportsInterface(bytes4)");

    private final EvmExecutor executor;
    private final Address registry;
    private final Address universalResolver;

    /** Default constructor: mainnet Registry + Universal Resolver. */
    public EnsResolver(EvmExecutor executor) {
        this(executor, EnsAddresses.MAINNET_REGISTRY, EnsAddresses.MAINNET_UNIVERSAL_RESOLVER);
    }

    /**
     * Construct against non-default contract addresses. Useful for
     * testnets and for unit tests that mock the resolver chain.
     */
    public EnsResolver(EvmExecutor executor, Address registry, Address universalResolver) {
        this.executor = executor;
        this.registry = registry;
        this.universalResolver = universalResolver;
    }

    /**
     * Network-aware factory keyed on the EVM chain ID: picks the
     * canonical Registry + Universal Resolver pair for the given
     * network. Throws {@link IllegalArgumentException} for networks
     * where ENS is not pinned (callers that need to override can use
     * the three-arg constructor directly).
     *
     * <p>Keeping this on chain-id (not on a {@code NetworkConfig}) keeps
     * {@code :myotis-ens} from depending on {@code :networking} — the
     * ENS module needs to remain Android-friendly and the networking
     * module pulls in Netty + discv5 transitively.
     *
     * @param chainId EVM chain id: 1 = mainnet, 11155111 = sepolia,
     *                17000 = holesky
     */
    public static EnsResolver forChainId(EvmExecutor executor, long chainId) {
        // Java's switch statement only accepts int-promotable types, so a
        // `switch ((int) chainId)` would truncate large chain ids — a
        // mainnet-shaped id like 4_294_967_297L would wrap to 1 and
        // silently pick the mainnet contracts. Compare on the long.
        if (chainId == 1L) {
            return new EnsResolver(executor,
                    EnsAddresses.MAINNET_REGISTRY, EnsAddresses.MAINNET_UNIVERSAL_RESOLVER);
        }
        if (chainId == 11155111L) {
            return new EnsResolver(executor,
                    EnsAddresses.SEPOLIA_REGISTRY, EnsAddresses.SEPOLIA_UNIVERSAL_RESOLVER);
        }
        if (chainId == 17000L) {
            return new EnsResolver(executor,
                    EnsAddresses.HOLESKY_REGISTRY, EnsAddresses.HOLESKY_UNIVERSAL_RESOLVER);
        }
        throw new IllegalArgumentException("ENS not pinned for chain id " + chainId);
    }

    // ---- Forward record-type calls ----------------------------------------

    /**
     * Forward resolution: {@code name → address}.
     *
     * <p>Returns {@link Optional#empty()} when the UR returns empty/zero
     * bytes for the inner call (no record set) or when the UR reverts
     * with a known "not found" condition. {@code OffchainLookup} reverts
     * are rethrown for the {@code CcipReadEvmExecutor} wrapper to catch.
     */
    public CompletableFuture<Optional<Address>> resolveAddress(String name, BlockContext blockContext) {
        byte[] node = Namehash.of(name);
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
        byte[] node = Namehash.of(name);
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
        byte[] node = Namehash.of(name);
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
        byte[] node = Namehash.of(name);
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
        byte[] node = Namehash.of(name);
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
        byte[] node = Namehash.of(name);
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
        byte[] node = Namehash.of(name);
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
        byte[] node = Namehash.of(name);
        byte[] innerCall = AbiEncoder.encodeCall(
                INTERFACE_IMPLEMENTER,
                AbiEncoder.bytes32(node),
                AbiEncoder.bytes32(padded));
        return dispatchResolve(name, innerCall, blockContext, EnsResolver::decodeAddrResult);
    }

    /**
     * Reverse resolution: {@code address → name}, with ENSIP-3 verification.
     *
     * <p>Step-by-step path against the Registry. The plan calls out
     * switching to the UR's {@code reverse()} method as a future
     * refinement; the step-by-step path is correct for classic on-chain
     * reverse records and the verification round-trip uses the new UR-
     * based forward path under the hood.
     *
     * <p>Returns {@link Optional#empty()} when the address has no reverse
     * record OR when the resolver's claim fails ENSIP-3 verification (a
     * forward lookup of the claimed name doesn't point back at the
     * original address).
     */
    public CompletableFuture<Optional<String>> resolveName(Address address, BlockContext blockContext) {
        byte[] reverseNode = Namehash.of(ReverseLookup.nameFor(address));
        return getReverseResolver(reverseNode, blockContext)
                .thenCompose(resolver -> {
                    if (resolver.isEmpty()) return CompletableFuture.completedFuture(Optional.<String>empty());
                    return getName(resolver.get(), reverseNode, blockContext)
                            .thenCompose(claimed -> verifyForward(claimed, address, blockContext));
                });
    }

    // ---- Universal-Resolver dispatch helper -------------------------------

    /**
     * Wrap {@code innerCall} in a UR {@code resolve(bytes,bytes)} call,
     * route through {@link EvmExecutor#callView}, handle the standard
     * revert taxonomy, and feed the inner-call return bytes into
     * {@code innerResultDecoder}.
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
     *   <li>UR return is {@code (bytes innerResult, address resolver)}.
     *       We pull {@code innerResult} via
     *       {@code AbiDecoder.dynamicBytes(urReturn, 0)}.
     *   <li>The decoder receives {@code innerResult} and returns
     *       {@link Optional#empty()} for any "missing record" condition
     *       (zero address, empty bytes, etc.) and the value otherwise.
     *   <li>A {@link RuntimeException} from the decoder (malformed
     *       buffer) is also folded to {@link Optional#empty()} — same
     *       reasoning as a generic UR revert.
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
    /** Per (registry,name) resolver-discovery cache so repeated lookups skip the walk. */
    private static final java.util.concurrent.ConcurrentHashMap<String, CachedResolver> RESOLVER_CACHE =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** Test hook: drop cached resolver discovery so tests don't see each other's state. */
    static void clearResolverCache() { RESOLVER_CACHE.clear(); }

    /**
     * Find the resolver responsible for {@code name} via the registry (ENSIP-10
     * walk: exact node, then each parent, until a resolver is set) and detect
     * whether it implements ENSIP-10. All reads are snap/EVM — no gateway.
     * Cached per registry+name for a few minutes. Empty when no resolver is set
     * anywhere up the chain.
     */
    private CompletableFuture<Optional<ResolverInfo>> findResolver(String name, BlockContext ctx) {
        String cacheKey = registry.toHex() + ':' + name.toLowerCase(java.util.Locale.ROOT);
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
                    .handle(EnsResolver::decodeBool)
                    .thenApply(extended -> {
                        ResolverInfo info = new ResolverInfo(resolver, exact, extended);
                        RESOLVER_CACHE.put(cacheKey, new CachedResolver(
                                info, System.currentTimeMillis() + RESOLVER_CACHE_TTL_MS));
                        return Optional.of(info);
                    });
        });
    }

    /** Try {@code registry.resolver(namehash(labels[i:]))}; recurse to the parent on zero/error. */
    private CompletableFuture<Optional<Found>> walkResolver(String[] labels, int i, BlockContext ctx) {
        if (i >= labels.length) return CompletableFuture.completedFuture(Optional.empty());
        String suffix = String.join(".", java.util.Arrays.asList(labels).subList(i, labels.length));
        byte[] node = Namehash.of(suffix);
        byte[] calldata = AbiEncoder.encodeCall(RESOLVER, AbiEncoder.bytes32(node));
        return executor.callView(registry, calldata, ctx)
                .handle((res, err) -> err == null ? decodeAddressOrEmpty(res) : Optional.<Address>empty())
                .thenCompose(addr -> addr.isPresent()
                        ? CompletableFuture.completedFuture(Optional.of(new Found(addr.get(), i == 0)))
                        : walkResolver(labels, i + 1, ctx));
    }

    private static boolean decodeBool(byte[] result, Throwable error) {
        return error == null && result != null && result.length >= 32 && result[31] != 0;
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
        return Optional.of(new AbiRecord(longValueExact(contentType), data));
    }

    /** {@code BigInteger.longValueExact} (Android API 31) replacement — minSdk is 29. */
    private static long longValueExact(BigInteger v) {
        if (v.bitLength() > 63) throw new ArithmeticException("BigInteger out of long range");
        return v.longValue();
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
