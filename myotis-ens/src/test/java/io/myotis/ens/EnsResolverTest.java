package io.myotis.ens;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ens.Namehash;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
 * <p>The tests substitute a {@link MockExecutor} for the real
 * {@link EvmExecutor}, programming it with the exact (target, calldata)
 * → return-bytes mappings the resolver should issue. This proves:
 * <ul>
 *   <li>The Registry call uses the right selector and namehash.
 *   <li>The Resolver call uses the right selector and namehash.
 *   <li>Forward + reverse resolution chain correctly.
 *   <li>ENSIP-3 verification round-trip rejects unverifiable claims.
 * </ul>
 *
 * <p>Concrete EVM execution against fixture state is exercised by Phase 0's
 * {@code EvmFactoryTest}; the resolver is just orchestration on top, so
 * mocking the executor is the right level of test isolation.
 */
class EnsResolverTest {

    private static final Address REGISTRY = Address.fromHex(
            "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
    private static final Address PUBLIC_RESOLVER = Address.fromHex(
            "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63");
    private static final Address VITALIK = Address.fromHex(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    @Test
    void resolveAddressVitalikEth() throws Exception {
        var mock = new MockExecutor();
        // Registry.resolver(namehash("vitalik.eth")) → PUBLIC_RESOLVER
        mock.respond(REGISTRY,
                callRegistryResolver("vitalik.eth"),
                encodeAddress(PUBLIC_RESOLVER));
        // PublicResolver.addr(namehash("vitalik.eth")) → VITALIK
        mock.respond(PUBLIC_RESOLVER,
                callResolverAddr("vitalik.eth"),
                encodeAddress(VITALIK));

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<Address> result = resolver.resolveAddress("vitalik.eth", ctx()).get();
        assertEquals(Optional.of(VITALIK), result);
    }

    @Test
    void resolveAddressMissingResolverReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        // Registry returns address(0) — no resolver registered for the name.
        mock.respond(REGISTRY,
                callRegistryResolver("not-registered.eth"),
                encodeAddress(Address.ZERO));

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<Address> result = resolver.resolveAddress("not-registered.eth", ctx()).get();
        assertTrue(result.isEmpty());
        // Resolver wasn't called — only the Registry.
        assertEquals(1, mock.callCount());
    }

    @Test
    void resolveAddressEmptyAddrRecordReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        mock.respond(REGISTRY,
                callRegistryResolver("ghost.eth"),
                encodeAddress(PUBLIC_RESOLVER));
        // Resolver knows the name but has no addr record for it.
        mock.respond(PUBLIC_RESOLVER,
                callResolverAddr("ghost.eth"),
                encodeAddress(Address.ZERO));

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<Address> result = resolver.resolveAddress("ghost.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveNameVerifiesForwardRoundTrip() throws Exception {
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);

        // Reverse path: Registry.resolver(reverseNode) → PUBLIC_RESOLVER
        mock.respond(REGISTRY,
                callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        // Resolver.name(reverseNode) → "vitalik.eth"
        mock.respond(PUBLIC_RESOLVER,
                callResolverName(reverseName),
                encodeString("vitalik.eth"));

        // Forward verification path: same as resolveAddress test.
        mock.respond(REGISTRY,
                callRegistryResolver("vitalik.eth"),
                encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER,
                callResolverAddr("vitalik.eth"),
                encodeAddress(VITALIK));

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertEquals(Optional.of("vitalik.eth"), result);
    }

    @Test
    void resolveNameRejectsImpersonationAttempt() throws Exception {
        // The reverse resolver claims vitalik owns "vitalik.eth", but the
        // forward lookup of "vitalik.eth" returns a DIFFERENT address — so
        // someone has tampered with the reverse record. ENSIP-3 says reject.
        var mock = new MockExecutor();
        Address impersonator = Address.fromHex(
                "0x9999999999999999999999999999999999999999");
        String reverseName = ReverseLookup.nameFor(impersonator);

        mock.respond(REGISTRY,
                callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER,
                callResolverName(reverseName),
                encodeString("vitalik.eth"));
        // Forward verification: vitalik.eth resolves to vitalik's real
        // address, NOT the impersonator. Mismatch → reject the claim.
        mock.respond(REGISTRY,
                callRegistryResolver("vitalik.eth"),
                encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER,
                callResolverAddr("vitalik.eth"),
                encodeAddress(VITALIK));

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<String> result = resolver.resolveName(impersonator, ctx()).get();
        assertTrue(result.isEmpty(),
                "ENSIP-3 verification must reject claims that don't round-trip");
    }

    @Test
    void resolveNameMissingReverseRecordReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);
        // No resolver registered for the reverse subdomain.
        mock.respond(REGISTRY,
                callRegistryResolver(reverseName),
                encodeAddress(Address.ZERO));

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertTrue(result.isEmpty());
        // Did not consult the resolver or attempt forward verification.
        assertEquals(1, mock.callCount());
    }

    /**
     * The Registry address in an offline / misconfigured wallet might point
     * at an EOA (no code). The EVM returns empty bytes for a successful
     * call against a code-less account. The resolver must surface this as
     * {@code Optional.empty()} rather than throwing in the ABI decoder.
     */
    @Test
    void emptyResponseFromRegistryReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        mock.respond(REGISTRY,
                callRegistryResolver("anything.eth"),
                new byte[0]);

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<Address> result = resolver.resolveAddress("anything.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    /**
     * A non-conforming resolver might return short or malformed data instead
     * of a 32-byte address. The resolver must treat this as "no answer"
     * rather than crash the call.
     */
    @Test
    void shortResponseFromResolverReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        mock.respond(REGISTRY,
                callRegistryResolver("weird.eth"),
                encodeAddress(PUBLIC_RESOLVER));
        // Resolver returns 16 bytes — not a valid uint256/address encoding.
        mock.respond(PUBLIC_RESOLVER,
                callResolverAddr("weird.eth"),
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<Address> result = resolver.resolveAddress("weird.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    /** Symmetric short/empty handling for the reverse-name decoder. */
    @Test
    void emptyResponseFromReverseResolverReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);
        mock.respond(REGISTRY,
                callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        // Resolver returns nothing for the name(bytes32) call.
        mock.respond(PUBLIC_RESOLVER,
                callResolverName(reverseName),
                new byte[0]);

        var resolver = new EnsResolver(mock, REGISTRY);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertTrue(result.isEmpty());
    }

    // ---- Calldata builders mirroring what EnsResolver should issue --------

    private static byte[] callRegistryResolver(String name) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("resolver(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
    }

    private static byte[] callResolverAddr(String name) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("addr(bytes32)"),
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
     * looks them up. Unmatched calls fail loudly so the test catches any
     * unexpected calldata shape.
     */
    private static final class MockExecutor implements EvmExecutor {
        private final Map<Key, byte[]> responses = new HashMap<>();
        private int callCount = 0;

        void respond(Address target, byte[] calldata, byte[] returnBytes) {
            responses.put(new Key(target, HexFormat.of().formatHex(calldata)), returnBytes);
        }

        int callCount() { return callCount; }

        @Override
        public CompletableFuture<byte[]> callView(Address target, byte[] calldata, BlockContext blockContext) {
            callCount++;
            byte[] response = responses.get(
                    new Key(target, HexFormat.of().formatHex(calldata)));
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
