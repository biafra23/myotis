package io.myotis.ens;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ens.Namehash;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * Forward + reverse resolver for ENS names.
 *
 * <p>Forward resolution ({@code name → address}) goes through the
 * Universal Resolver: a single {@code resolve(bytes name, bytes data)}
 * call that walks the registry/resolver chain, handles wildcard names
 * (ENSIP-10), and surfaces ERC-3668 OffchainLookup reverts at the call
 * boundary so a {@code CcipReadEvmExecutor} wrapping the supplied
 * executor can fetch the off-chain response transparently.
 *
 * <p>Reverse resolution ({@code address → name}) uses the step-by-step
 * Registry → reverse-resolver path with a mandatory ENSIP-3 forward
 * verification round-trip — the resolver's claim is only accepted if a
 * forward lookup of the claimed name returns the original address.
 *
 * <p>For modern ENS surfaces (Coinbase IDs, Uniswap names, Base
 * subdomains, etc.) to work, callers must wrap the executor in
 * {@code io.myotis.evm.CcipReadEvmExecutor}. Without that, those names
 * surface as {@code Reverted} errors when the wildcard resolver issues
 * its OffchainLookup revert.
 */
public final class EnsResolver {

    private static final FunctionSignature RESOLVE =
            FunctionSignature.of("resolve(bytes,bytes)");
    private static final FunctionSignature ADDR =
            FunctionSignature.of("addr(bytes32)");
    private static final FunctionSignature RESOLVER =
            FunctionSignature.of("resolver(bytes32)");
    private static final FunctionSignature NAME =
            FunctionSignature.of("name(bytes32)");

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
     * Forward resolution: {@code name → address}.
     *
     * <p>Returns {@link Optional#empty()} when:
     * <ul>
     *   <li>The Universal Resolver returns empty / zero bytes for the
     *       inner call (no record set).
     *   <li>The UR reverts with a known "not found" condition. Most UR
     *       implementations revert with {@code ResolverNotFound} or
     *       similar custom errors when the name has no resolver; we
     *       map any revert from the UR to {@code Optional.empty()}
     *       rather than propagate it as a call failure, since the
     *       wallet's intent is "look up this name" and the reasonable
     *       answer for an unregistered name is "no result."
     * </ul>
     *
     * <p>OffchainLookup reverts from the UR's nested resolver call are
     * <em>not</em> surfaced here — they're caught one layer up by the
     * {@code CcipReadEvmExecutor} wrapping {@code executor}. If the
     * caller hasn't wrapped, those reverts propagate as
     * {@code Reverted} errors.
     */
    public CompletableFuture<Optional<Address>> resolveAddress(String name, BlockContext blockContext) {
        byte[] dnsName = DnsEncoder.encode(name);
        byte[] node = Namehash.of(name);
        // Inner call: addr(bytes32) with the namehash. The UR will dispatch
        // this against the right resolver internally.
        byte[] innerCall = AbiEncoder.encodeCall(ADDR, AbiEncoder.bytes32(node));
        // Outer call: resolve(bytes name, bytes data) on the UR.
        byte[] resolveCalldata = AbiEncoder.encodeCall(
                RESOLVE,
                AbiEncoder.bytes(dnsName),
                AbiEncoder.bytes(innerCall));

        return executor.callView(universalResolver, resolveCalldata, blockContext)
                .handle((result, error) -> {
                    if (error != null) {
                        // The UR may revert with custom errors for unregistered
                        // names. Treat all reverts the same for the wallet: no
                        // answer. CCIP-Read reverts are caught upstream by the
                        // CcipReadEvmExecutor decorator before they reach here,
                        // so anything that escapes is a genuine "not resolvable."
                        Throwable cause = unwrap(error);
                        if (cause instanceof EvmExecutionException eee
                                && eee.error() instanceof EvmExecutionError.Reverted) {
                            return Optional.<Address>empty();
                        }
                        // Not a revert: bubble the real failure (oracle issue,
                        // network problem, etc.). Wrap in a CompletionException
                        // so the caller sees the original cause.
                        if (cause instanceof RuntimeException re) throw re;
                        throw new CompletionException(cause);
                    }
                    return decodeUrAddrResult(result);
                });
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
     * Decode the Universal Resolver's {@code resolve(...)} return.
     *
     * <p>Wire shape: {@code (bytes result, address resolver)}. For an
     * {@code addr(bytes32)} inner call, {@code result} is the 32-byte
     * ABI-encoded address (or empty if no record).
     */
    private static Optional<Address> decodeUrAddrResult(byte[] urReturn) {
        if (urReturn == null || urReturn.length < 64) return Optional.empty();
        try {
            byte[] resultBytes = AbiDecoder.dynamicBytes(urReturn, 0);
            if (resultBytes.length < 32) return Optional.empty();
            Address addr = AbiDecoder.address(resultBytes, 0);
            return addr.equals(Address.ZERO) ? Optional.<Address>empty() : Optional.of(addr);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
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

    private static Throwable unwrap(Throwable t) {
        while (t instanceof CompletionException && t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }
}
