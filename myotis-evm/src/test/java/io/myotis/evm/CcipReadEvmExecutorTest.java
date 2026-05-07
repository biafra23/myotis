package io.myotis.evm;

import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.AbiValue;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.besu.EvmFactory;
import io.myotis.evm.ccipread.CcipGateway;
import io.myotis.evm.ccipread.CcipReadHandler;
import io.myotis.evm.ccipread.OffchainLookupRevert;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.FixtureSnapStateOracle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * End-to-end tests for {@link CcipReadEvmExecutor}.
 *
 * <p>The tests build hand-crafted bytecode that reverts with the
 * {@code OffchainLookup} payload, then verify the executor catches the
 * revert, calls the {@link MockGateway} to fetch the response, and
 * re-enters the EVM against the resolver-supplied {@code sender} address
 * with the proper callback calldata.
 */
class CcipReadEvmExecutorTest {

    private static final Address RESOLVER_CONTRACT = Address.fromHex(
            "0x1111111111111111111111111111111111111111");
    /** Where the OffchainLookup directs the wallet to call back. */
    private static final Address CALLBACK_CONTRACT = Address.fromHex(
            "0x2222222222222222222222222222222222222222");
    /** Selector the resolver will ask the wallet to invoke on the callback contract. */
    private static final byte[] CALLBACK_SELECTOR = hex("aabbccdd");
    /** Arbitrary opaque blob the resolver puts in {@code extraData}. */
    private static final byte[] EXTRA_DATA = hex("c0ffee");

    /** Returns 32 bytes ending in 0xff regardless of calldata. */
    private static final byte[] RETURN_FF_BYTECODE = hex("60ff60005260206000f3");

    /** A contract that reverts with empty data — used for the passthrough test. */
    private static final byte[] EMPTY_REVERT_BYTECODE = hex("60006000fd");

    @Test
    void offchainLookupRevertTriggersGatewayCallAndCallback() throws Exception {
        // Resolver bytecode reverts with OffchainLookup pointing at CALLBACK_CONTRACT.
        // Callback bytecode returns 32 bytes ending in 0xff.
        byte[] resolverCode = revertWithOffchainLookup(
                CALLBACK_CONTRACT,
                List.of("test://gateway/{sender}/{data}"),
                hex("01020304"),  // callData
                CALLBACK_SELECTOR,
                EXTRA_DATA);

        var oracle = oracleWithContracts(
                Map.of(
                        RESOLVER_CONTRACT, resolverCode,
                        CALLBACK_CONTRACT, RETURN_FF_BYTECODE));

        // Gateway returns a hardcoded JSON {"data":"0xdeadbeef"} for any URL/body.
        // The bytes here become the `response` argument to the callback.
        MockGateway gateway = new MockGateway();
        gateway.respondWith("{\"data\":\"0xdeadbeef\"}");

        var handler = new CcipReadHandler(gateway);
        var executor = new CcipReadEvmExecutor(new DefaultEvmExecutor(oracle), handler);

        byte[] result = executor.callView(RESOLVER_CONTRACT, hex("12345678"), ctx()).get();
        // The callback contract returned 0xff in slot 0 of a 32-byte uint.
        assertEquals(BigInteger.valueOf(255), AbiDecoder.uint256(result, 0));

        // Gateway was called exactly once.
        assertEquals(1, gateway.callCount());
        // Substituted URL contained both placeholders' values.
        assertEquals("test://gateway/" + CALLBACK_CONTRACT.toHex() + "/0x01020304",
                gateway.lastUrl());
        // It was a GET (because the URL template had {data}).
        assertEquals(CcipGateway.Method.GET, gateway.lastMethod());
    }

    @Test
    void postRoutedWhenUrlOmitsDataPlaceholder() throws Exception {
        // URL has only {sender}; per ERC-3668 §6.1 this means POST with the
        // (sender, data) JSON body.
        byte[] resolverCode = revertWithOffchainLookup(
                CALLBACK_CONTRACT,
                List.of("https://example/{sender}"),
                hex("99"),
                CALLBACK_SELECTOR,
                hex(""));

        var oracle = oracleWithContracts(
                Map.of(
                        RESOLVER_CONTRACT, resolverCode,
                        CALLBACK_CONTRACT, RETURN_FF_BYTECODE));

        MockGateway gateway = new MockGateway();
        gateway.respondWith("{\"data\":\"0x00\"}");

        var handler = new CcipReadHandler(gateway);
        var executor = new CcipReadEvmExecutor(new DefaultEvmExecutor(oracle), handler);

        executor.callView(RESOLVER_CONTRACT, hex(""), ctx()).get();
        assertEquals(CcipGateway.Method.POST, gateway.lastMethod());
        // POST body carries (sender, data) JSON.
        assertEquals(
                "{\"sender\":\"" + CALLBACK_CONTRACT.toHex() + "\",\"data\":\"0x99\"}",
                gateway.lastBody());
    }

    @Test
    void allGatewaysFailingPropagatesCcipGatewayFailed() {
        byte[] resolverCode = revertWithOffchainLookup(
                CALLBACK_CONTRACT,
                List.of("test://gateway-1/{sender}/{data}", "test://gateway-2/{sender}/{data}"),
                hex(""),
                CALLBACK_SELECTOR,
                hex(""));

        var oracle = oracleWithContracts(
                Map.of(
                        RESOLVER_CONTRACT, resolverCode,
                        CALLBACK_CONTRACT, RETURN_FF_BYTECODE));

        // Gateway throws on every request — every URL in the list fails.
        MockGateway gateway = new MockGateway();
        gateway.respondWithFailure(new RuntimeException("gateway unreachable"));

        var handler = new CcipReadHandler(gateway);
        var executor = new CcipReadEvmExecutor(new DefaultEvmExecutor(oracle), handler);

        try {
            executor.callView(RESOLVER_CONTRACT, hex(""), ctx()).get();
            fail("expected CcipGatewayFailed");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            var failed = assertInstanceOf(EvmExecutionError.CcipGatewayFailed.class, eee.error());
            assertEquals(2, failed.urls().size(),
                    "both URLs must be reported in the failure");
        }
    }

    @Test
    void nonCcipReadRevertPassesThrough() {
        // A regular revert (no OffchainLookup selector) must reach the
        // caller unchanged — the CCIP-Read decorator only intercepts
        // OffchainLookup-shaped payloads.
        var oracle = oracleWithContracts(
                Map.of(RESOLVER_CONTRACT, EMPTY_REVERT_BYTECODE));

        MockGateway gateway = new MockGateway(); // never called
        var executor = new CcipReadEvmExecutor(
                new DefaultEvmExecutor(oracle),
                new CcipReadHandler(gateway));

        try {
            executor.callView(RESOLVER_CONTRACT, hex(""), ctx()).get();
            fail("expected the underlying revert to surface");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.Reverted.class, eee.error());
        }
        assertEquals(0, gateway.callCount(),
                "non-CCIP-Read revert must not invoke the gateway");
    }

    @Test
    void recursiveCcipReadCappedAtOneHop() {
        // Resolver A reverts with OffchainLookup pointing at Resolver A's
        // own address. The callback re-enters A, which reverts again. The
        // second OffchainLookup exceeds the depth cap (1) and surfaces as
        // CcipGatewayFailed.
        byte[] selfReferentialRevert = revertWithOffchainLookup(
                RESOLVER_CONTRACT,  // sender = self
                List.of("test://gateway/{sender}/{data}"),
                hex(""),
                CALLBACK_SELECTOR,
                hex(""));

        var oracle = oracleWithContracts(Map.of(RESOLVER_CONTRACT, selfReferentialRevert));

        MockGateway gateway = new MockGateway();
        gateway.respondWith("{\"data\":\"0x\"}");

        var handler = new CcipReadHandler(gateway);
        var executor = new CcipReadEvmExecutor(new DefaultEvmExecutor(oracle), handler);

        try {
            executor.callView(RESOLVER_CONTRACT, hex(""), ctx()).get();
            fail("expected CcipGatewayFailed for recursion-cap breach");
        } catch (Exception e) {
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.CcipGatewayFailed.class, eee.error());
        }
        // First call hit the gateway, second call (after depth cap) should not.
        assertEquals(1, gateway.callCount());
    }

    // ---- Bytecode helpers --------------------------------------------------

    /**
     * Build bytecode that reverts with an ERC-3668 {@code OffchainLookup}
     * payload. The strategy: pre-compute the entire revert payload as a
     * static byte array, append it to the code section, and prepend a
     * tiny stub that {@code CODECOPY}s the payload into memory and
     * {@code REVERT}s with it.
     */
    private static byte[] revertWithOffchainLookup(
            Address sender, List<String> urls, byte[] callData,
            byte[] callbackSelector4, byte[] extraData) {
        if (callbackSelector4.length != 4) {
            throw new IllegalArgumentException("callbackSelector must be 4 bytes");
        }
        // ABI-encode the body: (address sender, string[] urls, bytes callData,
        // bytes4 callbackFunction, bytes extraData). bytes4 is left-aligned
        // in its 32-byte slot.
        byte[] callbackPadded = new byte[32];
        System.arraycopy(callbackSelector4, 0, callbackPadded, 0, 4);
        byte[] body = AbiEncoder.encodeRaw(
                AbiEncoder.address(sender),
                AbiEncoder.stringArray(urls),
                AbiEncoder.bytes(callData),
                new AbiValue(false, callbackPadded),
                AbiEncoder.bytes(extraData));
        byte[] selector = OffchainLookupRevert.SELECTOR;
        byte[] payload = new byte[selector.length + body.length];
        System.arraycopy(selector, 0, payload, 0, selector.length);
        System.arraycopy(body, 0, payload, selector.length, body.length);

        // Stub: CODECOPY payload from offset 15 (== prefix length) into
        // memory[0..len], then REVERT memory[0..len].
        //   PUSH2 length    (0x61 LL HH)        3 bytes
        //   PUSH2 offset    (0x61 LL HH)        3 bytes
        //   PUSH1 0         (0x60 0x00)         2 bytes
        //   CODECOPY        (0x39)              1 byte
        //   PUSH2 length    (0x61 LL HH)        3 bytes
        //   PUSH1 0         (0x60 0x00)         2 bytes
        //   REVERT          (0xfd)              1 byte
        // Total = 15 bytes.
        int len = payload.length;
        int codeOffset = 15;
        byte[] prefix = {
                0x61, hi(len), lo(len),
                0x61, hi(codeOffset), lo(codeOffset),
                0x60, 0x00,
                0x39,
                0x61, hi(len), lo(len),
                0x60, 0x00,
                (byte) 0xfd,
        };
        byte[] result = new byte[prefix.length + payload.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(payload, 0, result, prefix.length, payload.length);
        return result;
    }

    private static byte hi(int n) { return (byte) ((n >>> 8) & 0xff); }
    private static byte lo(int n) { return (byte) (n & 0xff); }

    private static FixtureSnapStateOracle oracleWithContracts(Map<Address, byte[]> contracts) {
        var b = FixtureSnapStateOracle.builder();
        for (var entry : contracts.entrySet()) {
            byte[] codeHash = FixtureSnapStateOracle.codeHashOf(entry.getValue());
            b.account(new AccountState(entry.getKey(), 0L, BigInteger.ZERO, codeHash));
            b.bytecode(entry.getValue());
        }
        return b.build();
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static BlockContext ctx() {
        return new BlockContext(
                new byte[32],
                19_500_000L,
                EvmFactory.CANCUN_TIME + 1,
                BigInteger.valueOf(1_000_000_000L),
                Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                30_000_000L);
    }

    /** Programmable {@link CcipGateway} for tests. */
    private static final class MockGateway implements CcipGateway {
        private String responseBody;
        private RuntimeException failure;
        private int callCount;
        private String lastUrl;
        private String lastBody;
        private Method lastMethod;

        void respondWith(String body) {
            this.responseBody = body;
            this.failure = null;
        }

        void respondWithFailure(RuntimeException e) {
            this.failure = e;
            this.responseBody = null;
        }

        int callCount() { return callCount; }
        String lastUrl() { return lastUrl; }
        String lastBody() { return lastBody; }
        Method lastMethod() { return lastMethod; }

        @Override
        public CompletableFuture<String> request(Method method, String url, String body) {
            callCount++;
            lastMethod = method;
            lastUrl = url;
            lastBody = body;
            if (failure != null) {
                return CompletableFuture.failedFuture(failure);
            }
            return CompletableFuture.completedFuture(Objects.requireNonNull(responseBody));
        }
    }
}
