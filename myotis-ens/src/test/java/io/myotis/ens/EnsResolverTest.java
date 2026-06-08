package io.myotis.ens;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ens.Namehash;
import org.junit.jupiter.api.BeforeEach;
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
 * <p>Forward resolution is <b>direct</b>: no UniversalResolver and no shared CCIP
 * batch gateway. The resolver is discovered via the Registry (ENSIP-10 walk),
 * then called directly — {@code resolve(bytes,bytes)} for ENSIP-10 (wildcard /
 * offchain) resolvers, or the record method directly for a legacy resolver. So
 * these tests mock that exact sequence: {@code registry.resolver(node)} →
 * {@code resolver.supportsInterface(0x9061b923)} → the record call.
 *
 * <p>The {@link MockExecutor} maps {@code (target, calldata) → response}
 * deterministically, with a separate channel for reverts.
 */
class EnsResolverTest {

    private static final Address REGISTRY = Address.fromHex(
            "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
    private static final Address UR = Address.fromHex(
            "0xce01f8eee7E479C928F8919abD53E553a36CeF67");
    private static final Address PUBLIC_RESOLVER = Address.fromHex(
            "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63");
    private static final Address WILDCARD_RESOLVER = Address.fromHex(
            "0xce01f8eee7E479C928F8919abD53E553a36CeF67");
    private static final Address VITALIK = Address.fromHex(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    /** IExtendedResolver (ENSIP-10) interface id. */
    private static final byte[] EXTENDED_ID = {(byte) 0x90, 0x61, (byte) 0xb9, 0x23};

    @BeforeEach
    void resetCache() {
        // The resolver-discovery cache is process-static (it must survive the
        // per-resolution EnsResolver instances in production); clear it so tests
        // don't inherit each other's mocked discovery.
        EnsResolver.clearResolverCache();
    }

    // ---- Forward resolution: legacy (direct record call) ------------------

    @Test
    void resolveAddressVitalikEth() throws Exception {
        var mock = new MockExecutor();
        programLegacy(mock, "vitalik.eth", innerAddr("vitalik.eth"), encodeAddress(VITALIK));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("vitalik.eth", ctx()).get();
        assertEquals(Optional.of(VITALIK), result);
    }

    @Test
    void resolveAddressNoResolverReturnsEmpty() throws Exception {
        // No resolver set on the name or any parent → unregistered → empty.
        var mock = new MockExecutor();
        mock.respond(REGISTRY, callRegistryResolver("not-registered.eth"), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("eth"), encodeAddress(Address.ZERO));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("not-registered.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveAddressZeroAddrReturnsEmpty() throws Exception {
        // Resolver exists but addr() returns the zero address (no record).
        var mock = new MockExecutor();
        programLegacy(mock, "ghost.eth", innerAddr("ghost.eth"), encodeAddress(Address.ZERO));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("ghost.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveAddressShortResponseReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        programLegacy(mock, "weird.eth", innerAddr("weird.eth"), new byte[]{1, 2, 3, 4, 5, 6, 7, 8});

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("weird.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    // ---- Forward resolution: wildcard (ENSIP-10 resolve()) ----------------

    @Test
    void resolveAddressWildcardViaExtendedResolver() throws Exception {
        // jesse.cb.id: resolver lives on the parent (cb.id) and implements
        // ENSIP-10, so we call resolve(name, addr-call) directly on it.
        var mock = new MockExecutor();
        Address resolved = Address.fromHex("0x849151d7D0bF1F34b70d5caD5149D28CC2308bf1");
        // resolver found at the parent "cb.id" (wildcard), not the exact node.
        mock.respond(REGISTRY, callRegistryResolver("jesse.cb.id"), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("cb.id"), encodeAddress(WILDCARD_RESOLVER));
        mock.respond(WILDCARD_RESOLVER, callSupportsExtended(), encodeBool(true));
        mock.respond(WILDCARD_RESOLVER, resolveCalldata("jesse.cb.id", innerAddr("jesse.cb.id")),
                encodeBytes(encodeAddress(resolved)));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result = resolver.resolveAddress("jesse.cb.id", ctx()).get();
        assertEquals(Optional.of(resolved), result);
    }

    @Test
    void resolveAddressOffchainLookupRevertIsRethrown() {
        // An ENSIP-10 resolver may revert with an ERC-3668 OffchainLookup. With no
        // CcipReadEvmExecutor wrapping, that must surface as a distinct error.
        var mock = new MockExecutor();
        programExtendedRevert(mock, "ccip-read.eth",
                resolveCalldata("ccip-read.eth", innerAddr("ccip-read.eth")), offchainLookupPayload());

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        try {
            resolver.resolveAddress("ccip-read.eth", ctx()).get();
            org.junit.jupiter.api.Assertions.fail(
                    "OffchainLookup reverts must propagate so the caller learns "
                            + "they need CcipReadEvmExecutor — not be swallowed as empty");
        } catch (Exception e) {
            Throwable cause = e instanceof java.util.concurrent.ExecutionException
                    ? e.getCause() : e;
            var eee = org.junit.jupiter.api.Assertions.assertInstanceOf(
                    EvmExecutionException.class, cause);
            org.junit.jupiter.api.Assertions.assertInstanceOf(
                    EvmExecutionError.Reverted.class, eee.error());
        }
    }

    // ---- Extended record types (direct legacy path) ----------------------

    @Test
    void resolveTextHappyPath() throws Exception {
        var mock = new MockExecutor();
        programLegacy(mock, "vitalik.eth", innerText("vitalik.eth", "avatar"),
                encodeString("ipfs://Qm..."));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveText("vitalik.eth", "avatar", ctx()).get();
        assertEquals(Optional.of("ipfs://Qm..."), result);
    }

    @Test
    void resolveTextEmptyResultReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        programLegacy(mock, "vitalik.eth", innerText("vitalik.eth", "no-such-key"),
                encodeString(""));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveText("vitalik.eth", "no-such-key", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveContenthashHappyPath() throws Exception {
        var mock = new MockExecutor();
        byte[] expected = HexFormat.of().parseHex("e30101701220deadbeef");
        programLegacy(mock, "vitalik.eth", innerContenthash("vitalik.eth"), encodeBytes(expected));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<byte[]> result = resolver.resolveContenthash("vitalik.eth", ctx()).get();
        assertTrue(result.isPresent());
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, result.get());
    }

    @Test
    void resolveContenthashEmptyReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        programLegacy(mock, "ghost.eth", innerContenthash("ghost.eth"), encodeBytes(new byte[0]));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<byte[]> result = resolver.resolveContenthash("ghost.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveMultiCoinAddressBitcoin() throws Exception {
        var mock = new MockExecutor();
        byte[] btcPayload = HexFormat.of().parseHex(
                "76a914f3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a388ac");
        programLegacy(mock, "vitalik.eth", innerAddrCoin("vitalik.eth", 0L), encodeBytes(btcPayload));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<byte[]> result =
                resolver.resolveMultiCoinAddress("vitalik.eth", 0L, ctx()).get();
        assertTrue(result.isPresent());
        org.junit.jupiter.api.Assertions.assertArrayEquals(btcPayload, result.get());
    }

    @Test
    void resolvePubkeyHappyPath() throws Exception {
        var mock = new MockExecutor();
        byte[] x = HexFormat.of().parseHex(
                "1111111111111111111111111111111111111111111111111111111111111111");
        byte[] y = HexFormat.of().parseHex(
                "2222222222222222222222222222222222222222222222222222222222222222");
        byte[] innerReturn = new byte[64];
        System.arraycopy(x, 0, innerReturn, 0, 32);
        System.arraycopy(y, 0, innerReturn, 32, 32);
        programLegacy(mock, "vitalik.eth", innerPubkey("vitalik.eth"), innerReturn);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<EnsResolver.Pubkey> result = resolver.resolvePubkey("vitalik.eth", ctx()).get();
        assertTrue(result.isPresent());
        org.junit.jupiter.api.Assertions.assertArrayEquals(x, result.get().x());
        org.junit.jupiter.api.Assertions.assertArrayEquals(y, result.get().y());
    }

    @Test
    void resolvePubkeyAllZeroReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        programLegacy(mock, "ghost.eth", innerPubkey("ghost.eth"), new byte[64]);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<EnsResolver.Pubkey> result = resolver.resolvePubkey("ghost.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveAbiHappyPath() throws Exception {
        var mock = new MockExecutor();
        byte[] data = HexFormat.of().parseHex("deadbeefcafebabe");
        byte[] innerReturn = AbiEncoder.encodeRaw(
                AbiEncoder.uint256(1L),
                AbiEncoder.bytes(data));
        programLegacy(mock, "vitalik.eth", innerAbi("vitalik.eth", 0xFL), innerReturn);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<EnsResolver.AbiRecord> result =
                resolver.resolveAbi("vitalik.eth", 0xFL, ctx()).get();
        assertTrue(result.isPresent());
        assertEquals(1L, result.get().contentType());
        org.junit.jupiter.api.Assertions.assertArrayEquals(data, result.get().data());
    }

    @Test
    void resolveAbiEmptyDataReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        byte[] innerReturn = AbiEncoder.encodeRaw(
                AbiEncoder.uint256(0L),
                AbiEncoder.bytes(new byte[0]));
        programLegacy(mock, "ghost.eth", innerAbi("ghost.eth", 0xFL), innerReturn);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<EnsResolver.AbiRecord> result =
                resolver.resolveAbi("ghost.eth", 0xFL, ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveDnsRecordHappyPath() throws Exception {
        var mock = new MockExecutor();
        byte[] dnsNameWire = DnsEncoder.encode("example.com");
        byte[] rdata = HexFormat.of().parseHex("c0a80101");
        programLegacy(mock, "vitalik.eth", innerDnsRecord("vitalik.eth", dnsNameWire, 1),
                encodeBytes(rdata));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<byte[]> result =
                resolver.resolveDnsRecord("vitalik.eth", dnsNameWire, 1, ctx()).get();
        assertTrue(result.isPresent());
        org.junit.jupiter.api.Assertions.assertArrayEquals(rdata, result.get());
    }

    @Test
    void resolveInterfaceImplementerHappyPath() throws Exception {
        var mock = new MockExecutor();
        Address impl = Address.fromHex("0x4242424242424242424242424242424242424242");
        byte[] interfaceId = HexFormat.of().parseHex("5b5e139f");
        programLegacy(mock, "vitalik.eth", innerInterface("vitalik.eth", interfaceId),
                encodeAddress(impl));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<Address> result =
                resolver.resolveInterfaceImplementer("vitalik.eth", interfaceId, ctx()).get();
        assertEquals(Optional.of(impl), result);
    }

    @Test
    void resolveInterfaceImplementerRejectsWrongLengthInterfaceId() {
        var resolver = new EnsResolver(new MockExecutor(), REGISTRY, UR);
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> resolver.resolveInterfaceImplementer(
                        "vitalik.eth", new byte[3], ctx()));
    }

    @Test
    void offchainLookupRevertIsRethrownForEveryRecordType() {
        // The OffchainLookup-rethrow gate applies to all record types; text here.
        var mock = new MockExecutor();
        programExtendedRevert(mock, "ccip-read.eth",
                resolveCalldata("ccip-read.eth", innerText("ccip-read.eth", "avatar")),
                offchainLookupPayload());

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        try {
            resolver.resolveText("ccip-read.eth", "avatar", ctx()).get();
            org.junit.jupiter.api.Assertions.fail("OffchainLookup must propagate");
        } catch (Exception e) {
            Throwable cause = e instanceof java.util.concurrent.ExecutionException
                    ? e.getCause() : e;
            org.junit.jupiter.api.Assertions.assertInstanceOf(
                    EvmExecutionException.class, cause);
        }
    }

    // ---- forChainId factory -----------------------------------------------

    @Test
    void forChainIdMainnet() {
        var r = EnsResolver.forChainId(new MockExecutor(), 1);
        org.junit.jupiter.api.Assertions.assertNotNull(r);
    }

    @Test
    void forChainIdSepolia() {
        var r = EnsResolver.forChainId(new MockExecutor(), 11155111L);
        org.junit.jupiter.api.Assertions.assertNotNull(r);
    }

    @Test
    void forChainIdHolesky() {
        var r = EnsResolver.forChainId(new MockExecutor(), 17000L);
        org.junit.jupiter.api.Assertions.assertNotNull(r);
    }

    @Test
    void forChainIdUnknownThrows() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> EnsResolver.forChainId(new MockExecutor(), 999_999L));
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
        // Forward verification of vitalik.eth — now via the direct path.
        programLegacy(mock, "vitalik.eth", innerAddr("vitalik.eth"), encodeAddress(VITALIK));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertEquals(Optional.of("vitalik.eth"), result);
    }

    @Test
    void resolveNameRejectsImpersonationAttempt() throws Exception {
        var mock = new MockExecutor();
        Address impersonator = Address.fromHex(
                "0x9999999999999999999999999999999999999999");
        String reverseName = ReverseLookup.nameFor(impersonator);

        mock.respond(REGISTRY, callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER, callResolverName(reverseName),
                encodeString("vitalik.eth"));
        // Forward verification: vitalik.eth → VITALIK (NOT impersonator)
        programLegacy(mock, "vitalik.eth", innerAddr("vitalik.eth"), encodeAddress(VITALIK));

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
        mock.respond(PUBLIC_RESOLVER, callResolverName(reverseName), new byte[0]);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertTrue(result.isEmpty());
    }

    // ---- Direct-path programming helpers ----------------------------------

    /** Program an exact-match legacy resolver: registry → resolver, supportsInterface=false, direct record call. */
    private static void programLegacy(MockExecutor mock, String name, byte[] innerCalldata, byte[] innerReturn) {
        mock.respond(REGISTRY, callRegistryResolver(name), encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER, callSupportsExtended(), encodeBool(false));
        mock.respond(PUBLIC_RESOLVER, innerCalldata, innerReturn);
    }

    /** Program an exact-match ENSIP-10 resolver whose resolve() reverts with the given data. */
    private static void programExtendedRevert(MockExecutor mock, String name, byte[] resolveCalldata, byte[] revertData) {
        mock.respond(REGISTRY, callRegistryResolver(name), encodeAddress(WILDCARD_RESOLVER));
        mock.respond(WILDCARD_RESOLVER, callSupportsExtended(), encodeBool(true));
        mock.revertOn(WILDCARD_RESOLVER, resolveCalldata, revertData);
    }

    private static byte[] offchainLookupPayload() {
        byte[] body = AbiEncoder.encodeRaw(
                AbiEncoder.address(Address.ZERO),
                AbiEncoder.stringArray(java.util.List.of("test://gateway")),
                AbiEncoder.bytes(new byte[0]),
                new io.myotis.evm.abi.AbiValue(false, new byte[32]),
                AbiEncoder.bytes(new byte[0]));
        byte[] full = new byte[4 + body.length];
        System.arraycopy(io.myotis.evm.ccipread.OffchainLookupRevert.SELECTOR, 0, full, 0, 4);
        System.arraycopy(body, 0, full, 4, body.length);
        return full;
    }

    // ---- Calldata builders: discovery + inner record calls ---------------

    private static byte[] callRegistryResolver(String name) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("resolver(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
    }

    private static byte[] callSupportsExtended() {
        byte[] padded = new byte[32];
        System.arraycopy(EXTENDED_ID, 0, padded, 0, 4);
        return AbiEncoder.encodeCall(
                FunctionSignature.of("supportsInterface(bytes4)"),
                AbiEncoder.bytes32(padded));
    }

    private static byte[] callResolverName(String reverseName) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("name(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(reverseName)));
    }

    private static byte[] innerAddr(String name) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("addr(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
    }

    private static byte[] innerText(String name, String key) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("text(bytes32,string)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.string(key));
    }

    private static byte[] innerContenthash(String name) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("contenthash(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
    }

    private static byte[] innerAddrCoin(String name, long coinType) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("addr(bytes32,uint256)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.uint256(coinType));
    }

    private static byte[] innerPubkey(String name) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("pubkey(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
    }

    private static byte[] innerAbi(String name, long contentTypes) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("ABI(bytes32,uint256)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.uint256(contentTypes));
    }

    private static byte[] innerDnsRecord(String name, byte[] dnsNameWire, int resource) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("dnsRecord(bytes32,bytes,uint16)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.bytes(dnsNameWire),
                AbiEncoder.uint256(resource));
    }

    private static byte[] innerInterface(String name, byte[] interfaceId) {
        byte[] padded = new byte[32];
        System.arraycopy(interfaceId, 0, padded, 0, 4);
        return AbiEncoder.encodeCall(
                FunctionSignature.of("interfaceImplementer(bytes32,bytes4)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.bytes32(padded));
    }

    /** ENSIP-10 resolve(name, innerCall) calldata sent to a wildcard resolver. */
    private static byte[] resolveCalldata(String name, byte[] innerCall) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("resolve(bytes,bytes)"),
                AbiEncoder.bytes(DnsEncoder.encode(name)),
                AbiEncoder.bytes(innerCall));
    }

    // ---- ABI encoders for mock return values ------------------------------

    private static byte[] encodeAddress(Address a) {
        return AbiEncoder.encodeRaw(AbiEncoder.address(a));
    }

    private static byte[] encodeString(String s) {
        return AbiEncoder.encodeRaw(AbiEncoder.string(s));
    }

    private static byte[] encodeBytes(byte[] data) {
        return AbiEncoder.encodeRaw(AbiEncoder.bytes(data));
    }

    private static byte[] encodeBool(boolean v) {
        byte[] word = new byte[32];
        word[31] = (byte) (v ? 1 : 0);
        return word;
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
