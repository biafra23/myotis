package io.myotis.evm.besu;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.DefaultEvmExecutor;
import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.FixtureSnapStateOracle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Phase 0 acceptance test: drive Besu's EVM end-to-end against fixture state
 * for a hand-written {@code balanceOf(address)} contract that returns a known
 * value from a known storage slot.
 *
 * <p>Real USDC bytecode is too large to embed here cleanly; this contract
 * exercises the same code path (calldata decoding → SLOAD → return) and
 * proves the integration:
 * <ul>
 *   <li>{@link EvmFactory} builds a Cancun EVM
 *   <li>{@link io.myotis.evm.world.SnapWorldUpdater} reads from
 *       {@link FixtureSnapStateOracle}
 *   <li>{@link DefaultEvmExecutor#callView} runs the message-call, returns
 *       the expected ABI-encoded uint256
 * </ul>
 */
class EvmFactoryTest {

    /**
     * Minimal bytecode: ignore calldata, push the value at storage slot 0
     * onto the stack, return its 32-byte representation.
     *
     * <pre>
     *   60 00            PUSH1 0x00         // slot
     *   54               SLOAD              // value
     *   60 00            PUSH1 0x00         // mem offset
     *   52               MSTORE             // store value at memory[0..32]
     *   60 20            PUSH1 0x20         // length
     *   60 00            PUSH1 0x00         // offset
     *   f3               RETURN
     * </pre>
     */
    private static final byte[] STORAGE_LOAD_BYTECODE =
            HexFormat.of().parseHex("60005460005260206000f3");

    private static final BigInteger EXPECTED_BALANCE = new BigInteger("12345678900000000000000");

    @Test
    void returnsValueFromFixtureStorage() throws Exception {
        Address contract = Address.fromHex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

        byte[] codeHash = FixtureSnapStateOracle.codeHashOf(STORAGE_LOAD_BYTECODE);
        AccountState contractAccount = new AccountState(contract, 0L, BigInteger.ZERO, codeHash);

        FixtureSnapStateOracle oracle = FixtureSnapStateOracle.builder()
                .account(contractAccount)
                .bytecode(STORAGE_LOAD_BYTECODE)
                .storage(contract, BigInteger.ZERO, EXPECTED_BALANCE)
                .build();

        DefaultEvmExecutor executor = new DefaultEvmExecutor(oracle);

        FunctionSignature sig = FunctionSignature.of("balanceOf(address)");
        byte[] calldata = AbiEncoder.encodeCall(sig,
                AbiEncoder.address(Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")));

        byte[] zeroRoot = new byte[32];
        BlockContext ctx = new BlockContext(
                zeroRoot,
                /* blockNumber */ 19_500_000L,
                /* timestamp   */ EvmFactory.CANCUN_TIME + 1,
                /* baseFee     */ BigInteger.valueOf(1_000_000_000L),
                /* coinbase    */ Address.ZERO,
                /* prevRandao  */ new byte[32],
                /* chainId     */ BigInteger.ONE,
                /* gasLimit    */ 30_000_000L);

        byte[] returnData;
        try {
            returnData = executor.callView(contract, calldata, ctx).get();
        } catch (java.util.concurrent.ExecutionException e) {
            if (e.getCause() instanceof io.myotis.evm.EvmExecutionException eee
                    && eee.error() instanceof io.myotis.evm.EvmExecutionError.Reverted r) {
                throw new AssertionError(
                        "EVM did not return success. Halt detail: "
                                + new String(r.data(), java.nio.charset.StandardCharsets.UTF_8),
                        e);
            }
            throw e;
        }
        assertEquals(32, returnData.length, "balanceOf must return a single uint256");
        assertEquals(EXPECTED_BALANCE, AbiDecoder.uint256(returnData, 0));
    }
}
