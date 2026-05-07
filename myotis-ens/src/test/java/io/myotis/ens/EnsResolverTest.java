package io.myotis.ens;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ens.Namehash;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link EnsResolver}.
 *
 * <p>Forward tests mock the Universal Resolver's
 * {@code resolve(bytes name, bytes data)} call. Reverse tests still mock
 * the step-by-step Registry → reverse-resolver path (the resolver's
 * reverse path stayed step-by-step in Phase 4).
 *
 * <p>The {@link MockExecutor} maps {@code (target, calldata) → response}
 * deterministically, with a separate channel for "this call should fail
 * with EvmExecutionException(Reverted)" to test the UR-revert-as-empty
 * pathway.
 */
class EnsResolverTest {

    private static final Address REGISTRY = Address.fromHex(
            "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
    private static final Address UR = Address.fromHex(
            "0xce01f8eee7E479C928F8919abD53E553a36CeF67");
    private static final Address PUBLIC_RESOLVER = Address.fromHex(
            "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63");
    private static final Address VITALIK = Address.fromHex(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    // ---- Forward resolution (UR path) -------------------------------------

    @Test
    void resolveAddressVitalikEth() throws Exception {
        var mock = new MockExecutor();
        mock.respond(UR, callUrResolveAddr("vitalik.eth"),
                encodeUrAddrResponse(VITALIK, PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("vitalik.eth", ctx()).get();
        assertEquals(Optional.of(VITALIK), result);
        assertEquals(1, mock.callCount(),
                "UR-based forward resolution issues exactly one callView");
    }

    @Test
    void resolveAddressUrRevertReturnsEmpty() throws Exception {
        // The Universal Resolver may revert with a custom error
        // (ResolverNotFound, etc.) for unregistered names. Treat as
        // "no answer" rather than propagate the revert.
        var mock = new MockExecutor();
        mock.revertOn(UR, callUrResolveAddr("not-registered.eth"),
                /* revert data = empty */ new byte[0]);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("not-registered.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveAddressEmptyResultBytesReturnsEmpty() throws Exception {
        // The UR returns successfully but with an empty inner-call result
        // (resolver returned no addr record).
        var mock = new MockExecutor();
        mock.respond(UR, callUrResolveAddr("ghost.eth"),
                encodeUrAddrResponse(Address.ZERO, PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("ghost.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveAddressShortResponseReturnsEmpty() throws Exception {
        // UR returned non-conforming bytes (less than the 64 head bytes
        // a (bytes, address) tuple needs). Treat as no answer.
        var mock = new MockExecutor();
        mock.respond(UR, callUrResolveAddr("weird.eth"),
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8});

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("weird.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    // ---- Reverse resolution (step-by-step path) ---------------------------

    @Test
    void resolveNameVerifiesForwardRoundTrip() throws Exception {
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);

        // Reverse path: Registry.resolver(reverseNode) → PUBLIC_RESOLVER
        mock.respond(REGISTRY, callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        // Resolver.name(reverseNode) → "vitalik.eth"
        mock.respond(PUBLIC_RESOLVER, callResolverName(reverseName),
                encodeString("vitalik.eth"));
        // Forward verification: now via UR
        mock.respond(UR, callUrResolveAddr("vitalik.eth"),
                encodeUrAddrResponse(VITALIK, PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertEquals(Optional.of("vitalik.eth"), result);
    }

    @Test
    void resolveNameRejectsImpersonationAttempt() throws Exception {
        // Reverse resolver claims someone else's address resolves to
        // vitalik.eth, but a forward UR call for vitalik.eth returns
        // VITALIK's address — not the impersonator. ENSIP-3 says reject.
        var mock = new MockExecutor();
        Address impersonator = Address.fromHex(
                "0x9999999999999999999999999999999999999999");
        String reverseName = ReverseLookup.nameFor(impersonator);

        mock.respond(REGISTRY, callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER, callResolverName(reverseName),
                encodeString("vitalik.eth"));
        // Forward verification: vitalik.eth → VITALIK (NOT impersonator)
        mock.respond(UR, callUrResolveAddr("vitalik.eth"),
                encodeUrAddrResponse(VITALIK, PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveName(impersonator, ctx()).get();
        assertTrue(result.isEmpty(),
                "ENSIP-3 verification must reject claims that don't round-trip");
    }

    @Test
    void resolveNameMissingReverseRecordReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);
        mock.respond(REGISTRY, callRegistryResolver(reverseName),
                encodeAddress(Address.ZERO));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertTrue(result.isEmpty());
        assertEquals(1, mock.callCount(),
                "absence of reverse resolver short-circuits before any other call");
    }

    @Test
    void emptyResponseFromReverseResolverReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);
        mock.respond(REGISTRY, callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        // Resolver returns empty data for name(bytes32).
        mock.respond(PUBLIC_RESOLVER, callResolverName(reverseName), new byte[0]);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertTrue(result.isEmpty());
    }

    // ---- Calldata builders ------------------------------------------------

    private static byte[] callUrResolveAddr(String name) {
        byte[] dnsName = DnsEncoder.encode(name);
        byte[] node = Namehash.of(name);
        byte[] innerCall = AbiEncoder.encodeCall(
                FunctionSignature.of("addr(bytes32)"),
                AbiEncoder.bytes32(node));
        return AbiEncoder.encodeCall(
                FunctionSignature.of("resolve(bytes,bytes)"),
                AbiEncoder.bytes(dnsName),
                AbiEncoder.bytes(innerCall));
    }

    private static byte[] callRegistryResolver(String name) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("resolver(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
    }

    private static byte[] callResolverName(String reverseName) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("name(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(reverseName)));
    }

    /** ABI-encode a single address as a 32-byte uint256. */
    private static byte[] encodeAddress(Address a) {
        return AbiEncoder.encodeRaw(AbiEncoder.address(a));
    }

    /** ABI-encode a single dynamic string. */
    private static byte[] encodeString(String s) {
        return AbiEncoder.encodeRaw(AbiEncoder.string(s));
    }

    /**
     * Encode the Universal Resolver's {@code resolve()} return for an
     * {@code addr(bytes32)} inner call: {@code (bytes result, address resolver)}.
     * The {@code result} bytes are themselves the 32-byte ABI encoding of
     * the resolved address.
     */
    private static byte[] encodeUrAddrResponse(Address resolved, Address resolver) {
        byte[] innerReturn = encodeAddress(resolved);
        return AbiEncoder.encodeRaw(
                AbiEncoder.bytes(innerReturn),
                AbiEncoder.address(resolver));
    }

    private static BlockContext ctx() {
        return new BlockContext(
                new byte[32],
                19_500_000L,
                io.myotis.evm.besu.EvmFactory.CANCUN_TIME + 1,
                BigInteger.valueOf(1_000_000_000L),
                Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                30_000_000L);
    }

    /**
     * Programmable {@link EvmExecutor}: callers register
     * {@code (target, calldata) → returnBytes} mappings, and {@code callView}
     * looks them up. Also supports {@code revertOn(...)} to fail a specific
     * call with {@link EvmExecutionException}.
     */
    private static final class MockExecutor implements EvmExecutor {
        private final Map<Key, byte[]> responses = new HashMap<>();
        private final Map<Key, byte[]> reverts = new HashMap<>();
        private int callCount = 0;

        void respond(Address target, byte[] calldata, byte[] returnBytes) {
            responses.put(new Key(target, HexFormat.of().formatHex(calldata)), returnBytes);
        }

        void revertOn(Address target, byte[] calldata, byte[] revertData) {
            reverts.put(new Key(target, HexFormat.of().formatHex(calldata)), revertData);
        }

        int callCount() { return callCount; }

        @Override
        public CompletableFuture<byte[]> callView(Address target, byte[] calldata, BlockContext blockContext) {
            callCount++;
            Key key = new Key(target, HexFormat.of().formatHex(calldata));
            byte[] revertData = reverts.get(key);
            if (revertData != null) {
                return CompletableFuture.failedFuture(new EvmExecutionException(
                        new EvmExecutionError.Reverted(revertData)));
            }
            byte[] response = responses.get(key);
            if (response == null) {
                return CompletableFuture.failedFuture(new AssertionError(
                        "MockExecutor: no response programmed for callView(target="
                                + target + ", calldata=0x"
                                + HexFormat.of().formatHex(calldata) + ")"));
            }
            return CompletableFuture.completedFuture(response);
        }

        private record Key(Address target, String calldataHex) {
            Key {
                Objects.requireNonNull(target);
                Objects.requireNonNull(calldataHex);
            }
        }
    }
}
