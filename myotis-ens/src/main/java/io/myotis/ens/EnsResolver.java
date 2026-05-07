package io.myotis.ens;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ens.Namehash;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Forward + reverse resolver for classic on-chain ENS names.
 *
 * <p>Forward (`name → address`) chains two {@link EvmExecutor#callView}
 * invocations: first the Registry to find the name's resolver, then the
 * resolver itself for the {@code addr(bytes32)} record. Reverse
 * (`address → name`) does the same for the {@code .addr.reverse} subdomain
 * plus a mandatory ENSIP-3 verification round-trip — the resolver's claim
 * is only accepted if a forward lookup of the claimed name returns the
 * original address.
 *
 * <p>CCIP-Read (ERC-3668) is <strong>not</strong> handled here. Names that
 * resolve via off-chain gateways (Coinbase IDs, Base subnames, etc.) will
 * cause the underlying {@code callView} to revert with the
 * {@code OffchainLookup} selector; the caller will see a
 * {@code Reverted} error. Phase 4 wires CCIP-Read into the executor and
 * makes those calls work transparently.
 */
public final class EnsResolver {

    private static final FunctionSignature RESOLVER =
            FunctionSignature.of("resolver(bytes32)");
    private static final FunctionSignature ADDR =
            FunctionSignature.of("addr(bytes32)");
    private static final FunctionSignature NAME =
            FunctionSignature.of("name(bytes32)");

    private final EvmExecutor executor;
    private final Address registry;

    /** Default constructor: mainnet Registry at the canonical address. */
    public EnsResolver(EvmExecutor executor) {
        this(executor, EnsAddresses.MAINNET_REGISTRY);
    }

    /**
     * Construct against a non-default Registry. Useful for testnets and for
     * unit tests that mock a custom registry address.
     */
    public EnsResolver(EvmExecutor executor, Address registry) {
        this.executor = executor;
        this.registry = registry;
    }

    /**
     * Forward resolution: {@code name → address}.
     *
     * <p>Returns {@link Optional#empty()} when:
     * <ul>
     *   <li>The Registry has no resolver for the name (returns the zero address).
     *   <li>The resolver returns the zero address for the name's
     *       {@code addr} record.
     * </ul>
     */
    public CompletableFuture<Optional<Address>> resolveAddress(String name, BlockContext blockContext) {
        byte[] node = Namehash.of(name);
        return getResolver(node, blockContext)
                .thenCompose(resolver -> {
                    if (resolver.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
                    return getAddress(resolver.get(), node, blockContext);
                });
    }

    /**
     * Reverse resolution: {@code address → name}, with ENSIP-3 verification.
     *
     * <p>Returns {@link Optional#empty()} when:
     * <ul>
     *   <li>The address has no reverse record (no resolver, or resolver
     *       returns the empty string).
     *   <li>The resolver claims a name but a forward lookup of that name
     *       does <em>not</em> point back at the original address — the
     *       claim is unverifiable and rejected (defends against
     *       impersonation, since anyone can write any string into their
     *       reverse record).
     * </ul>
     */
    public CompletableFuture<Optional<String>> resolveName(Address address, BlockContext blockContext) {
        byte[] reverseNode = Namehash.of(ReverseLookup.nameFor(address));
        return getResolver(reverseNode, blockContext)
                .thenCompose(resolver -> {
                    if (resolver.isEmpty()) return CompletableFuture.completedFuture(Optional.<String>empty());
                    return getName(resolver.get(), reverseNode, blockContext)
                            .thenCompose(claimed -> verifyForward(claimed, address, blockContext));
                });
    }

    /** Registry call: {@code resolver(bytes32) → address}. */
    private CompletableFuture<Optional<Address>> getResolver(byte[] node, BlockContext ctx) {
        byte[] calldata = AbiEncoder.encodeCall(RESOLVER, AbiEncoder.bytes32(node));
        return executor.callView(registry, calldata, ctx)
                .thenApply(result -> {
                    Address resolver = AbiDecoder.address(result, 0);
                    return resolver.equals(Address.ZERO) ? Optional.<Address>empty() : Optional.of(resolver);
                });
    }

    /** Resolver call: {@code addr(bytes32) → address}. */
    private CompletableFuture<Optional<Address>> getAddress(Address resolver, byte[] node, BlockContext ctx) {
        byte[] calldata = AbiEncoder.encodeCall(ADDR, AbiEncoder.bytes32(node));
        return executor.callView(resolver, calldata, ctx)
                .thenApply(result -> {
                    Address addr = AbiDecoder.address(result, 0);
                    return addr.equals(Address.ZERO) ? Optional.<Address>empty() : Optional.of(addr);
                });
    }

    /** Resolver call: {@code name(bytes32) → string}. */
    private CompletableFuture<Optional<String>> getName(Address resolver, byte[] node, BlockContext ctx) {
        byte[] calldata = AbiEncoder.encodeCall(NAME, AbiEncoder.bytes32(node));
        return executor.callView(resolver, calldata, ctx)
                .thenApply(result -> {
                    String s = AbiDecoder.string(result, 0);
                    return s.isEmpty() ? Optional.<String>empty() : Optional.of(s);
                });
    }

    /**
     * ENSIP-3 verification: confirm the resolver's name claim by resolving
     * it forward and checking it points back at the original address.
     * Returns {@code Optional.of(name)} only if the round-trip succeeds.
     */
    private CompletableFuture<Optional<String>> verifyForward(
            Optional<String> claimed, Address address, BlockContext ctx) {
        if (claimed.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
        return resolveAddress(claimed.get(), ctx).thenApply(forward ->
                forward.filter(a -> a.equals(address)).map(a -> claimed.get()));
    }
}
