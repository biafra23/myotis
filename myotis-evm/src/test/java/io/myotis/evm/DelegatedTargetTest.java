package io.myotis.evm;

import io.myotis.evm.besu.EvmFactory;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.FixtureSnapStateOracle;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A call into an account that holds an EIP-7702 delegation designator runs the
 * delegate's code, and starts with the delegate warm, as the execution specs,
 * geth and revm start it. RelayAdapt7702's multicall calls back into its own
 * account, and with a cold delegate this engine charged 2500 gas more than the
 * Rust engine for the RAILGUN shield (#509; {@link RelayAdapt7702ShieldFixtureTest}).
 * The Rust executor's {@code a_delegated_targets_delegate_starts_warm} pins the
 * same number.
 */
class DelegatedTargetTest {

    private static final Address SENDER = Address.fromHex("0x1111111111111111111111111111111111111111");
    private static final Address TARGET = Address.fromHex("0x2222222222222222222222222222222222222222");
    private static final Address DELEGATE = Address.fromHex("0x3333333333333333333333333333333333333333");
    private static final Address OTHER = Address.fromHex("0x4444444444444444444444444444444444444444");

    @Test
    void theDelegateOfTheTargetStartsWarm() {
        // The delegate's code: BALANCE of itself (warm: 100), then of an
        // untouched account (cold: 2600), then STOP.
        byte[] code = Bytes.concatenate(
                Bytes.fromHexString("0x73"), Bytes.wrap(DELEGATE.toByteArray()), Bytes.fromHexString("0x3150"),
                Bytes.fromHexString("0x73"), Bytes.wrap(OTHER.toByteArray()), Bytes.fromHexString("0x3150"),
                Bytes.fromHexString("0x00")).toArrayUnsafe();
        byte[] designator = Bytes.concatenate(Bytes.fromHexString("0xef0100"), Bytes.wrap(DELEGATE.toByteArray()))
                .toArrayUnsafe();
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L, BigInteger.TEN.pow(18), FixtureSnapStateOracle.codeHashOf(new byte[0])))
                .account(new AccountState(TARGET, 1L, BigInteger.ZERO, FixtureSnapStateOracle.codeHashOf(designator)))
                .bytecode(designator)
                .account(new AccountState(DELEGATE, 1L, BigInteger.ZERO, FixtureSnapStateOracle.codeHashOf(code)))
                .bytecode(code)
                .build();
        var tx = new UnsignedTransaction(SENDER, TARGET, BigInteger.ZERO, new byte[0], null);
        BlockContext prague = new BlockContext(new byte[32], 22_500_000L, EvmFactory.PRAGUE_TIME + 1,
                BigInteger.ONE, Address.ZERO, new byte[32], BigInteger.ONE, 30_000_000L);

        // 21000 + PUSH20 3 + BALANCE (warm) 100 + POP 2 + PUSH20 3 + BALANCE (cold) 2600 + POP 2.
        assertEquals(21_000L + 3 + 100 + 2 + 3 + 2_600 + 2,
                new DefaultEvmExecutor(oracle).drawnAt(tx, prague, 1_000_000L));
    }
}
