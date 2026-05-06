package io.myotis.evm.world;

import io.myotis.evm.Address;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FixtureSnapStateOracleTest {

    private static final byte[] FAKE_ROOT = new byte[32];

    @Test
    void absentAccountReturnsEmptyDefault() throws Exception {
        FixtureSnapStateOracle oracle = FixtureSnapStateOracle.builder().build();
        Address a = Address.fromHex("0x0000000000000000000000000000000000000001");
        AccountState s = oracle.fetchAccount(FAKE_ROOT, a).get();
        assertEquals(0L, s.nonce());
        assertEquals(BigInteger.ZERO, s.balance());
        // Empty-code keccak256 hash.
        assertArrayEquals(
                java.util.HexFormat.of().parseHex(
                        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
                s.codeHash());
    }

    @Test
    void storedBytecodeIsRetrievableByHash() throws Exception {
        byte[] code = new byte[]{0x60, 0x00};
        byte[] hash = FixtureSnapStateOracle.codeHashOf(code);
        FixtureSnapStateOracle oracle = FixtureSnapStateOracle.builder()
                .bytecode(code)
                .build();
        byte[] retrieved = oracle.fetchBytecode(hash).get();
        assertArrayEquals(code, retrieved);
    }

    @Test
    void storageMissReturnsZero() throws Exception {
        FixtureSnapStateOracle oracle = FixtureSnapStateOracle.builder().build();
        Address a = Address.fromHex("0x0000000000000000000000000000000000000002");
        BigInteger v = oracle.fetchStorage(FAKE_ROOT, a, BigInteger.valueOf(7)).get();
        assertEquals(BigInteger.ZERO, v);
    }
}
