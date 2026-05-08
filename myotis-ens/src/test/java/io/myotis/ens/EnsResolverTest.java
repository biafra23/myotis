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
    void resolveAddressOffchainLookupRevertIsRethrown() {
        // The Universal Resolver's wildcard resolver may revert with an
        // ERC-3668 OffchainLookup. When the caller hasn't wrapped the
        // executor in CcipReadEvmExecutor, that revert must surface as a
        // distinct error — not be swallowed as "name not found." This
        // distinguishes "you forgot CCIP-Read wiring" from "the name
        // genuinely doesn't resolve."
        var mock = new MockExecutor();
        // Build a minimal, valid OffchainLookup payload so
        // OffchainLookupRevert.tryParse() recognises it.
        byte[] offchainLookupPayload = io.myotis.evm.ccipread.OffchainLookupRevert.SELECTOR;
        // The selector alone isn't a valid full payload, but we need a
        // representative payload that the parser recognises. Build one via
        // AbiEncoder so it round-trips:
        byte[] body = AbiEncoder.encodeRaw(
                AbiEncoder.address(io.myotis.evm.Address.ZERO),                  // sender
                AbiEncoder.stringArray(java.util.List.of("test://gateway")),     // urls
                AbiEncoder.bytes(new byte[0]),                                   // callData
                new io.myotis.evm.abi.AbiValue(false, new byte[32]),             // callbackFunction
                AbiEncoder.bytes(new byte[0]));                                  // extraData
        byte[] full = new byte[4 + body.length];
        System.arraycopy(offchainLookupPayload, 0, full, 0, 4);
        System.arraycopy(body, 0, full, 4, body.length);

        mock.revertOn(UR, callUrResolveAddr("ccip-read.eth"), full);

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

    // ---- Extended record types (UR path) ----------------------------------

    @Test
    void resolveTextHappyPath() throws Exception {
        var mock = new MockExecutor();
        mock.respond(UR, callUrResolveText("vitalik.eth", "avatar"),
                encodeUrDynamicResponse(encodeString("ipfs://Qm..."), PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveText("vitalik.eth", "avatar", ctx()).get();
        assertEquals(Optional.of("ipfs://Qm..."), result);
    }

    @Test
    void resolveTextEmptyResultReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        // Inner result decodes to an empty string (length=0).
        mock.respond(UR, callUrResolveText("vitalik.eth", "no-such-key"),
                encodeUrDynamicResponse(encodeString(""), PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveText("vitalik.eth", "no-such-key", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveTextUrRevertReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        mock.revertOn(UR, callUrResolveText("ghost.eth", "avatar"), new byte[0]);

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveText("ghost.eth", "avatar", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveContenthashHappyPath() throws Exception {
        var mock = new MockExecutor();
        // multicodec for ipfs is 0xe3 0x01 0x01 0x70 ...; we don't validate
        // the prefix here, just that the bytes round-trip unchanged.
        byte[] expected = HexFormat.of().parseHex("e30101701220deadbeef");
        mock.respond(UR, callUrResolveContenthash("vitalik.eth"),
                encodeUrDynamicResponse(encodeBytes(expected), PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<byte[]> result = resolver.resolveContenthash("vitalik.eth", ctx()).get();
        assertTrue(result.isPresent());
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, result.get());
    }

    @Test
    void resolveContenthashEmptyReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        mock.respond(UR, callUrResolveContenthash("ghost.eth"),
                encodeUrDynamicResponse(encodeBytes(new byte[0]), PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<byte[]> result = resolver.resolveContenthash("ghost.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveMultiCoinAddressBitcoin() throws Exception {
        var mock = new MockExecutor();
        // SLIP-44 coinType 0 = Bitcoin. The "address" is the script payload
        // bytes; we don't validate format here, just round-trip.
        byte[] btcPayload = HexFormat.of().parseHex(
                "76a914f3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a388ac");
        mock.respond(UR, callUrResolveAddrCoin("vitalik.eth", 0L),
                encodeUrDynamicResponse(encodeBytes(btcPayload), PUBLIC_RESOLVER));

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
        // Pubkey returns (bytes32 x, bytes32 y) — 64 bytes head, no tail.
        byte[] innerReturn = new byte[64];
        System.arraycopy(x, 0, innerReturn, 0, 32);
        System.arraycopy(y, 0, innerReturn, 32, 32);
        mock.respond(UR, callUrResolvePubkey("vitalik.eth"),
                encodeUrDynamicResponse(innerReturn, PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<EnsResolver.Pubkey> result = resolver.resolvePubkey("vitalik.eth", ctx()).get();
        assertTrue(result.isPresent());
        org.junit.jupiter.api.Assertions.assertArrayEquals(x, result.get().x());
        org.junit.jupiter.api.Assertions.assertArrayEquals(y, result.get().y());
    }

    @Test
    void resolvePubkeyAllZeroReturnsEmpty() throws Exception {
        var mock = new MockExecutor();
        // Both coordinates zero → no pubkey set.
        mock.respond(UR, callUrResolvePubkey("ghost.eth"),
                encodeUrDynamicResponse(new byte[64], PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<EnsResolver.Pubkey> result = resolver.resolvePubkey("ghost.eth", ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveAbiHappyPath() throws Exception {
        var mock = new MockExecutor();
        // ABI returns (uint256 contentType, bytes data). Build the head/tail
        // by hand: head[0]=contentType (32 bytes), head[1]=offset to tail.
        byte[] data = HexFormat.of().parseHex("deadbeefcafebabe");
        byte[] innerReturn = AbiEncoder.encodeRaw(
                AbiEncoder.uint256(1L),       // contentType = Solidity ABI JSON
                AbiEncoder.bytes(data));
        mock.respond(UR, callUrResolveAbi("vitalik.eth", 0xFL),
                encodeUrDynamicResponse(innerReturn, PUBLIC_RESOLVER));

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
        mock.respond(UR, callUrResolveAbi("ghost.eth", 0xFL),
                encodeUrDynamicResponse(innerReturn, PUBLIC_RESOLVER));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<EnsResolver.AbiRecord> result =
                resolver.resolveAbi("ghost.eth", 0xFL, ctx()).get();
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveDnsRecordHappyPath() throws Exception {
        var mock = new MockExecutor();
        byte[] dnsNameWire = DnsEncoder.encode("example.com");
        byte[] rdata = HexFormat.of().parseHex("c0a80101"); // 192.168.1.1 (A record)
        mock.respond(UR, callUrResolveDnsRecord("vitalik.eth", dnsNameWire, 1),
                encodeUrDynamicResponse(encodeBytes(rdata), PUBLIC_RESOLVER));

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
        // EIP-165 selector for ERC-721 Metadata: 0x5b5e139f
        byte[] interfaceId = HexFormat.of().parseHex("5b5e139f");
        mock.respond(UR, callUrResolveInterface("vitalik.eth", interfaceId),
                encodeUrDynamicResponse(encodeAddress(impl), PUBLIC_RESOLVER));

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
        // Sanity: the OffchainLookup-rethrow gate in dispatchUR applies to
        // all record types, not just addr. Pick text as the representative.
        var mock = new MockExecutor();
        byte[] body = AbiEncoder.encodeRaw(
                AbiEncoder.address(io.myotis.evm.Address.ZERO),
                AbiEncoder.stringArray(java.util.List.of("test://gateway")),
                AbiEncoder.bytes(new byte[0]),
                new io.myotis.evm.abi.AbiValue(false, new byte[32]),
                AbiEncoder.bytes(new byte[0]));
        byte[] full = new byte[4 + body.length];
        System.arraycopy(io.myotis.evm.ccipread.OffchainLookupRevert.SELECTOR, 0, full, 0, 4);
        System.arraycopy(body, 0, full, 4, body.length);
        mock.revertOn(UR, callUrResolveText("ccip-read.eth", "avatar"), full);

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

    private static byte[] callUrResolveText(String name, String key) {
        byte[] inner = AbiEncoder.encodeCall(
                FunctionSignature.of("text(bytes32,string)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.string(key));
        return wrapInUrResolve(name, inner);
    }

    private static byte[] callUrResolveContenthash(String name) {
        byte[] inner = AbiEncoder.encodeCall(
                FunctionSignature.of("contenthash(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
        return wrapInUrResolve(name, inner);
    }

    private static byte[] callUrResolveAddrCoin(String name, long coinType) {
        byte[] inner = AbiEncoder.encodeCall(
                FunctionSignature.of("addr(bytes32,uint256)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.uint256(coinType));
        return wrapInUrResolve(name, inner);
    }

    private static byte[] callUrResolvePubkey(String name) {
        byte[] inner = AbiEncoder.encodeCall(
                FunctionSignature.of("pubkey(bytes32)"),
                AbiEncoder.bytes32(Namehash.of(name)));
        return wrapInUrResolve(name, inner);
    }

    private static byte[] callUrResolveAbi(String name, long contentTypes) {
        byte[] inner = AbiEncoder.encodeCall(
                FunctionSignature.of("ABI(bytes32,uint256)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.uint256(contentTypes));
        return wrapInUrResolve(name, inner);
    }

    private static byte[] callUrResolveDnsRecord(String name, byte[] dnsNameWire, int resource) {
        byte[] inner = AbiEncoder.encodeCall(
                FunctionSignature.of("dnsRecord(bytes32,bytes,uint16)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.bytes(dnsNameWire),
                AbiEncoder.uint256(resource));
        return wrapInUrResolve(name, inner);
    }

    private static byte[] callUrResolveInterface(String name, byte[] interfaceId) {
        byte[] padded = new byte[32];
        System.arraycopy(interfaceId, 0, padded, 0, 4);
        byte[] inner = AbiEncoder.encodeCall(
                FunctionSignature.of("interfaceImplementer(bytes32,bytes4)"),
                AbiEncoder.bytes32(Namehash.of(name)),
                AbiEncoder.bytes32(padded));
        return wrapInUrResolve(name, inner);
    }

    private static byte[] wrapInUrResolve(String name, byte[] innerCall) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("resolve(bytes,bytes)"),
                AbiEncoder.bytes(DnsEncoder.encode(name)),
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

    /** ABI-encode a single dynamic bytes value. */
    private static byte[] encodeBytes(byte[] data) {
        return AbiEncoder.encodeRaw(AbiEncoder.bytes(data));
    }

    /**
     * Encode the Universal Resolver's {@code resolve()} return for any
     * dynamic-typed inner call:
     * {@code (bytes innerReturn, address resolver)} — the {@code innerReturn}
     * payload is whatever the inner function returned, supplied raw.
     */
    private static byte[] encodeUrDynamicResponse(byte[] innerReturn, Address resolver) {
        return AbiEncoder.encodeRaw(
                AbiEncoder.bytes(innerReturn),
                AbiEncoder.address(resolver));
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
