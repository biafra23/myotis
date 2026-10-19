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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    // ---- Ownership (registry + .eth registrar, through the NameWrapper) ----

    private static final Address USER = Address.fromHex("0x" + "51".repeat(20));
    private static final Address BASE_REGISTRAR = EnsAddresses.BASE_REGISTRAR;
    private static final Address NAME_WRAPPER = EnsAddresses.MAINNET_NAME_WRAPPER;

    private static byte[] registryCall(String fn, String name) {
        return AbiEncoder.encodeCall(FunctionSignature.of(fn), AbiEncoder.bytes32(Namehash.of(name)));
    }

    private static byte[] registrarCall(String fn, String label) {
        return AbiEncoder.encodeCall(FunctionSignature.of(fn), AbiEncoder.bytes32(Namehash.labelhash(label)));
    }

    private static byte[] gracePeriodCall() {
        return AbiEncoder.encodeCall(FunctionSignature.of("GRACE_PERIOD()"));
    }

    private static byte[] encodeUint(long v) {
        return AbiEncoder.encodeRaw(AbiEncoder.uint256(v));
    }

    /** Mainnet today: the Universal Resolver names no ENSv2 root, so v1 decides every name. */
    private static EnsResolver ownershipResolver(MockExecutor mock) {
        mock.revertOn(UR, AbiEncoder.encodeCall(FunctionSignature.of("ROOT_REGISTRY()")), new byte[0]);
        return new EnsResolver(mock, REGISTRY, UR, BASE_REGISTRAR, NAME_WRAPPER);
    }

    // ---- ENSv2 (#671): whether v1 still decides a name's ownership ---------

    private static final Address ROOT_V2 = Address.fromHex("0x" + "b4".repeat(20));
    private static final Address V2_RESOLVER = Address.fromHex("0x" + "5e".repeat(20));
    private static final Address MIRROR = Address.fromHex("0x" + "32".repeat(20));

    /**
     * An ENSv2 chain: the Universal Resolver names a root registry and finds {@code found}
     * for {@code name}. MIRROR is the v1 mirror ({@code REGISTRY_V1()} = the v1 registry);
     * V2_RESOLVER has no such getter.
     */
    private static EnsResolver ensv2Resolver(MockExecutor mock, String name, Address found) {
        mock.respond(UR, AbiEncoder.encodeCall(FunctionSignature.of("ROOT_REGISTRY()")), encodeAddress(ROOT_V2));
        mock.respond(UR, AbiEncoder.encodeCall(FunctionSignature.of("findResolver(bytes)"),
                        AbiEncoder.bytes(DnsEncoder.encode(name))),
                AbiEncoder.encodeRaw(AbiEncoder.address(found), AbiEncoder.bytes32(new byte[32]),
                        AbiEncoder.uint256(0)));
        byte[] registryV1 = AbiEncoder.encodeCall(FunctionSignature.of("REGISTRY_V1()"));
        mock.respond(MIRROR, registryV1, encodeAddress(REGISTRY));
        mock.revertOn(V2_RESOLVER, registryV1, new byte[0]);
        return new EnsResolver(mock, REGISTRY, UR, BASE_REGISTRAR, NAME_WRAPPER);
    }

    private static void assertEnsv2Refusal(java.util.concurrent.CompletableFuture<?> f) {
        var e = assertThrows(java.util.concurrent.ExecutionException.class, f::get);
        assertTrue(e.getCause() instanceof UnsupportedOperationException, String.valueOf(e.getCause()));
        assertEquals(EnsResolver.ENSV2_OWNERSHIP, e.getCause().getMessage());
    }

    @Test
    void ownershipOfANameEnsv2DecidesIsRefusedBeforeAnyV1Read() {
        // myotis.eth on Sepolia: registered in ENSv2 only; v1 would read it as unowned.
        // No v1 call is programmed, so any v1 read would fail the test with an
        // AssertionError instead of the refusal. The name reaches the UR lowercased.
        var mock = new MockExecutor();
        assertEnsv2Refusal(ensv2Resolver(mock, "myotis.eth", V2_RESOLVER)
                .resolveOwnership("Myotis.eth", ctx()));
    }

    @Test
    void aNameEnsv2HandsToItsV1MirrorKeepsItsV1Ownership() throws Exception {
        // Not migrated (ens.eth on Sepolia): ENSv2 resolves it through the v1 mirror.
        var mock = new MockExecutor();
        mock.respond(REGISTRY, registryCall("owner(bytes32)", "ens.eth"), encodeAddress(USER));
        mock.respond(REGISTRY, registryCall("resolver(bytes32)", "ens.eth"), encodeAddress(PUBLIC_RESOLVER));
        mock.respond(BASE_REGISTRAR, registrarCall("ownerOf(uint256)", "ens"), encodeAddress(USER));
        mock.respond(BASE_REGISTRAR, registrarCall("nameExpires(uint256)", "ens"), encodeUint(1_823_155_031L));
        mock.respond(BASE_REGISTRAR, gracePeriodCall(), encodeUint(7_776_000L));
        var o = ensv2Resolver(mock, "ens.eth", MIRROR).resolveOwnership("ens.eth", ctx()).get().orElseThrow();
        assertEquals(USER, o.registrant());
        assertEquals(PUBLIC_RESOLVER, o.resolver());
        assertEquals(1_823_155_031L, o.expiresAt());
    }

    @Test
    void anOwnershipCheckThatCannotRunFailsInsteadOfReadingV1() {
        // ENSv2 check (#671): state the Universal Resolver needs but cannot get is not
        // "no ENSv2 root" — answering from v1 then would put back the unowned reading.
        var mock = new MockExecutor();
        mock.failOn(UR, AbiEncoder.encodeCall(FunctionSignature.of("ROOT_REGISTRY()")),
                new IllegalStateException("state unavailable"));
        var e = assertThrows(java.util.concurrent.ExecutionException.class,
                () -> new EnsResolver(mock, REGISTRY, UR, BASE_REGISTRAR, NAME_WRAPPER)
                        .resolveOwnership("myotis.eth", ctx()).get());
        assertTrue(e.getCause() instanceof IllegalStateException, String.valueOf(e.getCause()));
    }

    @Test
    void aStaleV1EntryEnsv2KnowsNoResolverForIsRefused() {
        // alice.eth on Sepolia: expired, still holding a v1 resolver, unknown to ENSv2.
        var mock = new MockExecutor();
        assertEnsv2Refusal(ensv2Resolver(mock, "alice.eth", Address.ZERO)
                .resolveOwnership("alice.eth", ctx()));
    }

    @Test
    void ownershipOfAnUnwrappedEthName() throws Exception {
        var mock = new MockExecutor();
        mock.respond(REGISTRY, registryCall("owner(bytes32)", "myotis.eth"), encodeAddress(USER));
        mock.respond(REGISTRY, registryCall("resolver(bytes32)", "myotis.eth"), encodeAddress(PUBLIC_RESOLVER));
        mock.respond(BASE_REGISTRAR, registrarCall("ownerOf(uint256)", "myotis"), encodeAddress(USER));
        mock.respond(BASE_REGISTRAR, registrarCall("nameExpires(uint256)", "myotis"), encodeUint(1_823_155_031L));
        mock.respond(BASE_REGISTRAR, gracePeriodCall(), encodeUint(7_776_000L));

        // Lowercased before hashing: the registrar hashes the normalized label.
        var o = ownershipResolver(mock).resolveOwnership("Myotis.eth", ctx()).get().orElseThrow();
        assertEquals(USER, o.registrant());
        assertEquals(USER, o.manager());
        assertFalse(o.wrapped());
        assertEquals(PUBLIC_RESOLVER, o.resolver());
        assertEquals(1_823_155_031L, o.expiresAt());
        assertEquals(7_776_000L, o.gracePeriod());
    }

    @Test
    void ownershipOfAWrappedEthNameIsSeenThroughTheWrapper() throws Exception {
        var mock = new MockExecutor();
        mock.respond(REGISTRY, registryCall("owner(bytes32)", "myotis.eth"), encodeAddress(NAME_WRAPPER));
        mock.respond(REGISTRY, registryCall("resolver(bytes32)", "myotis.eth"), encodeAddress(PUBLIC_RESOLVER));
        mock.respond(NAME_WRAPPER, registryCall("ownerOf(uint256)", "myotis.eth"), encodeAddress(USER));
        mock.respond(BASE_REGISTRAR, registrarCall("ownerOf(uint256)", "myotis"), encodeAddress(NAME_WRAPPER));
        mock.respond(BASE_REGISTRAR, registrarCall("nameExpires(uint256)", "myotis"), encodeUint(1_823_155_031L));
        mock.respond(BASE_REGISTRAR, gracePeriodCall(), encodeUint(7_776_000L));

        var o = ownershipResolver(mock).resolveOwnership("myotis.eth", ctx()).get().orElseThrow();
        assertTrue(o.wrapped());
        assertEquals(USER, o.manager());
        assertEquals(USER, o.registrant());
    }

    @Test
    void ownershipOfAnExpiredNameInGraceAndOfASubname() throws Exception {
        var mock = new MockExecutor();
        // Expired: ownerOf reverts, the registry still lists the old owner, nameExpires is past.
        mock.respond(REGISTRY, registryCall("owner(bytes32)", "old.eth"), encodeAddress(USER));
        mock.respond(REGISTRY, registryCall("resolver(bytes32)", "old.eth"), encodeAddress(Address.ZERO));
        mock.revertOn(BASE_REGISTRAR, registrarCall("ownerOf(uint256)", "old"), new byte[0]);
        mock.respond(BASE_REGISTRAR, registrarCall("nameExpires(uint256)", "old"), encodeUint(1_700_000_000L));
        mock.respond(BASE_REGISTRAR, gracePeriodCall(), encodeUint(7_776_000L));
        var expired = ownershipResolver(mock).resolveOwnership("old.eth", ctx()).get().orElseThrow();
        assertNull(expired.registrant());
        assertEquals(USER, expired.manager());
        assertNull(expired.resolver());
        assertEquals(1_700_000_000L, expired.expiresAt());
        // A subname: the Universal Resolver (no ENSv2 root) and the registry only, no
        // registrar calls at all.
        var sub = new MockExecutor();
        sub.respond(REGISTRY, registryCall("owner(bytes32)", "sub.myotis.eth"), encodeAddress(USER));
        sub.respond(REGISTRY, registryCall("resolver(bytes32)", "sub.myotis.eth"), encodeAddress(PUBLIC_RESOLVER));
        var s = ownershipResolver(sub).resolveOwnership("sub.myotis.eth", ctx()).get().orElseThrow();
        assertEquals(USER, s.manager());
        assertNull(s.registrant());
        assertEquals(-1L, s.expiresAt());
        assertEquals(3, sub.callCount());
    }

    @Test
    void ownershipOfAnUnregisteredNameIsEmpty() throws Exception {
        var mock = new MockExecutor();
        mock.respond(REGISTRY, registryCall("owner(bytes32)", "nobody.eth"), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, registryCall("resolver(bytes32)", "nobody.eth"), encodeAddress(Address.ZERO));
        mock.revertOn(BASE_REGISTRAR, registrarCall("ownerOf(uint256)", "nobody"), new byte[0]);
        mock.respond(BASE_REGISTRAR, registrarCall("nameExpires(uint256)", "nobody"), encodeUint(0L));
        assertTrue(ownershipResolver(mock).resolveOwnership("nobody.eth", ctx()).get().isEmpty());
        // What the record reads reject (DnsEncoder), this rejects.
        var bad = assertThrows(java.util.concurrent.ExecutionException.class,
                () -> ownershipResolver(mock).resolveOwnership("x..eth", ctx()).get());
        assertTrue(bad.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void aNameWhoseOwnerWasBurnedButKeepsAResolverIsOnChain() throws Exception {
        // setOwner(node, 0) after setting the resolver — immutable records: the records
        // still resolve, so "nothing on chain" would contradict them.
        var mock = new MockExecutor();
        mock.respond(REGISTRY, registryCall("owner(bytes32)", "fixed.myotis.eth"), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, registryCall("resolver(bytes32)", "fixed.myotis.eth"), encodeAddress(PUBLIC_RESOLVER));
        var o = ownershipResolver(mock).resolveOwnership("fixed.myotis.eth", ctx()).get().orElseThrow();
        assertNull(o.manager());
        assertNull(o.registrant());
        assertEquals(PUBLIC_RESOLVER, o.resolver());
        assertEquals(-1L, o.expiresAt());
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

    // ---- Resolver discovery: only a revert means "no resolver here" -------

    /** A refused fork, as the Java EVM reports Sepolia past Amsterdam (Besu 26.4). */
    private static EvmExecutionException refusedFork() {
        return new EvmExecutionException(new EvmExecutionError.UnsupportedFork(
                "Sepolia past Amsterdam: this engine's EVM cannot run it"));
    }

    private static EvmExecutionException causeOf(java.util.concurrent.Future<?> f) {
        var e = org.junit.jupiter.api.Assertions.assertThrows(
                java.util.concurrent.ExecutionException.class, f::get);
        return org.junit.jupiter.api.Assertions.assertInstanceOf(
                EvmExecutionException.class, e.getCause());
    }

    @Test
    void aRegistryLookupThatCannotRunFailsTheWalkInsteadOfReadingUnregistered() {
        // Every Sepolia name would otherwise "not resolve" past Amsterdam on the Java
        // engine: the walk read each refused level as "no resolver here". The parent
        // ("eth") is left unprogrammed — continuing to it would surface the mock's
        // AssertionError instead of the refusal.
        var mock = new MockExecutor();
        mock.failOn(REGISTRY, callRegistryResolver("vitalik.eth"), refusedFork());

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        EvmExecutionException eee = causeOf(resolver.resolveAddress("vitalik.eth", ctx()));
        org.junit.jupiter.api.Assertions.assertInstanceOf(
                EvmExecutionError.UnsupportedFork.class, eee.error());
        assertEquals(1, mock.callCount(), "the walk stops at the failure");
        // Every record lookup shares the walk.
        eee = causeOf(resolver.resolveText("vitalik.eth", "url", ctx()));
        org.junit.jupiter.api.Assertions.assertInstanceOf(
                EvmExecutionError.UnsupportedFork.class, eee.error());
    }

    @Test
    void aRegistryLevelThatRevertsIsSkipped() throws Exception {
        // A revert IS the registry's answer for that level: walk on to the parent.
        var mock = new MockExecutor();
        Address resolved = Address.fromHex("0x849151d7D0bF1F34b70d5caD5149D28CC2308bf1");
        mock.revertOn(REGISTRY, callRegistryResolver("jesse.cb.id"), new byte[0]);
        mock.respond(REGISTRY, callRegistryResolver("cb.id"), encodeAddress(WILDCARD_RESOLVER));
        mock.respond(WILDCARD_RESOLVER, callSupportsExtended(), encodeBool(true));
        mock.respond(WILDCARD_RESOLVER, resolveCalldata("jesse.cb.id", innerAddr("jesse.cb.id")),
                encodeBytes(encodeAddress(resolved)));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        assertEquals(Optional.of(resolved), resolver.resolveAddress("jesse.cb.id", ctx()).get());
    }

    @Test
    void theErc165ProbeReadsOnlyARevertAsNotExtended() throws Exception {
        // A resolver without ERC-165 reverts on supportsInterface: legacy path.
        var mock = new MockExecutor();
        mock.respond(REGISTRY, callRegistryResolver("vitalik.eth"), encodeAddress(PUBLIC_RESOLVER));
        mock.revertOn(PUBLIC_RESOLVER, callSupportsExtended(), new byte[0]);
        mock.respond(PUBLIC_RESOLVER, innerAddr("vitalik.eth"), encodeAddress(VITALIK));
        var resolver = new EnsResolver(mock, REGISTRY, UR);
        assertEquals(Optional.of(VITALIK), resolver.resolveAddress("vitalik.eth", ctx()).get());

        // Any other failure propagates — not a silent (and cached) legacy choice.
        EnsResolver.clearResolverCache();
        var failing = new MockExecutor();
        failing.respond(REGISTRY, callRegistryResolver("vitalik.eth"), encodeAddress(PUBLIC_RESOLVER));
        failing.failOn(PUBLIC_RESOLVER, callSupportsExtended(), refusedFork());
        EvmExecutionException eee = causeOf(
                new EnsResolver(failing, REGISTRY, UR).resolveAddress("vitalik.eth", ctx()));
        org.junit.jupiter.api.Assertions.assertInstanceOf(
                EvmExecutionError.UnsupportedFork.class, eee.error());
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

    // ---- Reverse resolution (step-by-step path, ENSIP-10 above it) ----------

    @Test
    void resolveNameVerifiesForwardRoundTrip() throws Exception {
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);

        // Reverse path: Registry.resolver(reverseNode) → PUBLIC_RESOLVER
        mock.respond(REGISTRY, callRegistryResolver(reverseName),
                encodeAddress(PUBLIC_RESOLVER));
        // Resolver.name(reverseNode) → "vitalik.eth", asked directly: no supportsInterface
        // probe is programmed for the reverse lookup, so probing would fail the test (the
        // old reverse resolvers halt on it — vitalik's 0x5fBb…F358 on mainnet).
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
        mock.respond(REGISTRY, callRegistryResolver(reverseName), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("addr.reverse"), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("reverse"), encodeAddress(Address.ZERO));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        Optional<String> result = resolver.resolveName(VITALIK, ctx()).get();
        assertTrue(result.isEmpty());
        assertEquals(3, mock.callCount(),
                "no resolver up the reverse tree ends after the three registry reads");
    }

    @Test
    void resolveNameWalksUpToAWildcardResolverOnTheReverseNode() throws Exception {
        // A primary name set through ENSv2 on Sepolia (#671): no resolver at
        // <hex>.addr.reverse or addr.reverse; the `reverse` node's ENSIP-10 resolver
        // answers name() through resolve(bytes,bytes).
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);
        mock.respond(REGISTRY, callRegistryResolver(reverseName), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("addr.reverse"), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("reverse"), encodeAddress(WILDCARD_RESOLVER));
        mock.respond(WILDCARD_RESOLVER, callSupportsExtended(), encodeBool(true));
        mock.respond(WILDCARD_RESOLVER, resolveCalldata(reverseName, callResolverName(reverseName)),
                encodeBytes(encodeString("myotis.eth")));
        programLegacy(mock, "myotis.eth", innerAddr("myotis.eth"), encodeAddress(VITALIK));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        assertEquals(Optional.of("myotis.eth"), resolver.resolveName(VITALIK, ctx()).get());
    }

    @Test
    void resolveNameDoesNotAskAnAncestorsLegacyResolver() throws Exception {
        // A resolver on `reverse` without ENSIP-10 cannot answer for a subname; its
        // name() is not programmed, so asking it would fail the test.
        var mock = new MockExecutor();
        String reverseName = ReverseLookup.nameFor(VITALIK);
        mock.respond(REGISTRY, callRegistryResolver(reverseName), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("addr.reverse"), encodeAddress(Address.ZERO));
        mock.respond(REGISTRY, callRegistryResolver("reverse"), encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER, callSupportsExtended(), encodeBool(false));

        var resolver = new EnsResolver(mock, REGISTRY, UR);
        assertTrue(resolver.resolveName(VITALIK, ctx()).get().isEmpty());
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

    // ---- Genome .gno names on Gnosis Chain ----------------------------------

    private static final Address GNO_REGISTRY = EnsAddresses.GNOSIS_GENOME_REGISTRY;
    private static final Address GNO_REGISTRAR = EnsAddresses.GNOSIS_GENOME_REGISTRAR;

    private static byte[] gno(String name) {
        return Namehash.of(name, EnsAddresses.gnosisGenomeRoot());
    }

    private static byte[] gnoCall(String fn, String name) {
        return AbiEncoder.encodeCall(FunctionSignature.of(fn), AbiEncoder.bytes32(gno(name)));
    }

    @Test
    void genomeNamesHashUnderTheirTldRootNotTheEnsRoot() {
        // The scheme, pinned by an independent implementation: Blockscout's ENS service
        // test (blockscout-rs, bens-logic hash_name / domain_name tests) hashes
        // "levvv.gno" under an empty-label hash of 0x6cbb… to 0x79e0….
        byte[] fixtureRoot = HexFormat.of().parseHex(
                "6cbb71e02aa156be31c9be2644cd7e3fe375b291d0786c825495af35fe98ee72");
        assertEquals("79e028f97b232b1600b2ed68cc7d9811c28595c3ab859b166d13980bcfcece9d",
                HexFormat.of().formatHex(Namehash.of("levvv.gno", fixtureRoot)));
        // …and Blockscout's Chiado fixture: levvv.gno's domain id under Chiado Genome's root.
        byte[] chiadoRoot = HexFormat.of().parseHex(
                "1a13b687a5ff1d8ab1a9e189e1507a6abe834a9296cc8cff937905e3dee0c4f6");
        assertEquals("a3504cdec527495c69c760c85d5be9996252f853b91fd0df04c5b6aa2deb3347",
                HexFormat.of().formatHex(Namehash.of("levvv.gno", chiadoRoot)));
        // The empty name IS the root; a zero root is plain ENSIP-1.
        assertEquals(EnsAddresses.GNOSIS_GENOME_ROOT_HEX,
                HexFormat.of().formatHex(gno("")));
        assertEquals(HexFormat.of().formatHex(Namehash.of("vitalik.eth")),
                HexFormat.of().formatHex(Namehash.of("vitalik.eth", new byte[32])));
        // Gnosis mainnet's .gno node — what Genome's registrar must report as baseNode().
        assertEquals("b610db9c8c31e1a841d7e46f0184e3ae40589639b590138de0de5df028245ce2",
                HexFormat.of().formatHex(gno("gno")));
    }

    @Test
    void forChainId100IsTheGenomeRegistry() throws Exception {
        var mock = new MockExecutor();
        Address resolverAddr = Address.fromHex("0x6D3B3F99177FB2A5de7F9E928a9BD807bF7b5BAD");
        mock.respond(GNO_REGISTRY, gnoCall("resolver(bytes32)", "levvv.gno"), encodeAddress(resolverAddr));
        mock.respond(resolverAddr, callSupportsExtended(), encodeBool(false));
        mock.respond(resolverAddr, gnoCall("addr(bytes32)", "levvv.gno"), encodeAddress(USER));

        var r = EnsResolver.forChainId(mock, 100L);
        assertEquals(Optional.of(USER), r.resolveAddress("Levvv.GNO", ctx()).get());
    }

    @Test
    void genomeWalksUpUnderTheGenomeRoot() throws Exception {
        var mock = new MockExecutor();
        // No resolver on the subname: the walk asks for "gno" next, under the Genome root,
        // and never for a zero-rooted node.
        mock.respond(GNO_REGISTRY, gnoCall("resolver(bytes32)", "a.levvv.gno"), encodeAddress(Address.ZERO));
        mock.respond(GNO_REGISTRY, gnoCall("resolver(bytes32)", "levvv.gno"), encodeAddress(Address.ZERO));
        mock.respond(GNO_REGISTRY, gnoCall("resolver(bytes32)", "gno"), encodeAddress(PUBLIC_RESOLVER));
        mock.respond(PUBLIC_RESOLVER, callSupportsExtended(), encodeBool(false));

        // A legacy resolver on an ancestor cannot answer for the subname: no record.
        assertTrue(EnsResolver.gnosisGenome(mock).resolveAddress("a.levvv.gno", ctx()).get().isEmpty());
    }

    @Test
    void genomeRefusesNamesOutsideGno() {
        var r = EnsResolver.gnosisGenome(new MockExecutor());
        assertTrue(r.servesName("levvv.gno"));
        assertTrue(r.servesName("a.levvv.gno."));
        assertFalse(r.servesName("gno"));
        assertFalse(r.servesName("vitalik.eth"));
        assertFalse(r.servesName("levvv.gno.eth"));
        // Refused before any call: "vitalik.eth" hashed under the Genome root is no one's name.
        var e = assertThrows(IllegalArgumentException.class,
                () -> r.resolveAddress("vitalik.eth", ctx()));
        assertEquals(EnsResolver.ONLY_GNO_NAMES, e.getMessage());
        var own = r.resolveOwnership("vitalik.eth", ctx());
        assertTrue(assertThrows(java.util.concurrent.ExecutionException.class, own::get).getCause()
                instanceof IllegalArgumentException);
        // ENS serves any name, .gno included (it simply has none registered).
        assertTrue(new EnsResolver(new MockExecutor()).servesName("levvv.gno"));
    }

    @Test
    void genomeOwnershipReadsTheGnoRegistrar() throws Exception {
        var mock = new MockExecutor();
        mock.respond(GNO_REGISTRY, gnoCall("owner(bytes32)", "levvv.gno"), encodeAddress(USER));
        mock.respond(GNO_REGISTRY, gnoCall("resolver(bytes32)", "levvv.gno"), encodeAddress(PUBLIC_RESOLVER));
        // Token id = labelhash, as on the .eth registrar (Blockscout's levvv.gno fixture:
        // token 0x1a8247ca… = keccak256("levvv")).
        assertEquals("1a8247ca2a4190d90c748b31fa6517e5560c1b7a680f03ff73dbbc3ed2c0ed66",
                HexFormat.of().formatHex(Namehash.labelhash("levvv")));
        mock.respond(GNO_REGISTRAR, registrarCall("ownerOf(uint256)", "levvv"), encodeAddress(USER));
        mock.respond(GNO_REGISTRAR, registrarCall("nameExpires(uint256)", "levvv"), encodeUint(1_900_000_000L));
        mock.respond(GNO_REGISTRAR, gracePeriodCall(), encodeUint(7_776_000L));

        var o = EnsResolver.gnosisGenome(mock).resolveOwnership("levvv.gno", ctx()).get().orElseThrow();
        assertEquals(USER, o.registrant());
        assertEquals(USER, o.manager());
        assertFalse(o.wrapped());
        assertEquals(PUBLIC_RESOLVER, o.resolver());
        assertEquals(1_900_000_000L, o.expiresAt());
        assertEquals(7_776_000L, o.gracePeriod());
    }

    @Test
    void genomeRefusesReverseResolution() {
        var mock = new MockExecutor();
        // Refused, not "no primary name" — and before any call.
        var f = EnsResolver.gnosisGenome(mock).resolveName(VITALIK, ctx());
        var cause = assertThrows(java.util.concurrent.ExecutionException.class, f::get).getCause();
        assertTrue(cause instanceof UnsupportedOperationException, String.valueOf(cause));
        assertEquals(EnsResolver.NO_GNO_REVERSE, cause.getMessage());
        assertEquals(0, mock.callCount());
    }

    @Test
    void refusalIsDecidedPerChainBeforeAnyState() {
        assertNull(EnsResolver.refusal(1L, "vitalik.eth"));
        assertNull(EnsResolver.refusal(1L, "levvv.gno"));   // ENS serves any name
        assertNull(EnsResolver.refusal(1L, null));          // reverse on ENS
        assertNull(EnsResolver.refusal(100L, "levvv.gno"));
        assertEquals(EnsResolver.ONLY_GNO_NAMES, EnsResolver.refusal(100L, "vitalik.eth"));
        assertEquals(EnsResolver.NO_GNO_REVERSE, EnsResolver.refusal(100L, null));
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
        private final Map<Key, Throwable> failures = new HashMap<>();
        private int callCount = 0;

        void respond(Address target, byte[] calldata, byte[] returnBytes) {
            responses.put(new Key(target, HexFormat.of().formatHex(calldata)), returnBytes);
        }

        void revertOn(Address target, byte[] calldata, byte[] revertData) {
            reverts.put(new Key(target, HexFormat.of().formatHex(calldata)), revertData);
        }

        /** Fail a specific call with a NON-revert error (an oracle failure, a refused fork). */
        void failOn(Address target, byte[] calldata, Throwable error) {
            failures.put(new Key(target, HexFormat.of().formatHex(calldata)), error);
        }

        int callCount() { return callCount; }

        @Override
        public CompletableFuture<byte[]> callView(Address target, byte[] calldata, BlockContext blockContext) {
            callCount++;
            Key key = new Key(target, HexFormat.of().formatHex(calldata));
            Throwable failure = failures.get(key);
            if (failure != null) return CompletableFuture.failedFuture(failure);
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
