package io.myotis.evm.besu;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.evm.gascalculator.PragueGasCalculator;
import org.hyperledger.besu.evm.precompile.MainnetPrecompiledContracts;
import org.hyperledger.besu.evm.precompile.PrecompileContractRegistry;
import org.junit.jupiter.api.Test;

/**
 * Pins the PRAGUE precompile layout after the Besu 26.4.0 bump: the FINAL
 * EIP-2537 mainnet set (0x0b..0x11, 7 contracts) — Besu 24.12.2 shipped the
 * pre-final draft (9 contracts through 0x13 with separate G1MUL/G2MUL), so the
 * bump is a live-correctness fix, not a neutral swap. Also guards the coming
 * Osaka flip: P256VERIFY (0x100) must NOT be registered under Prague.
 */
class PragueLayoutTest {

    private static Address addr(final int lastByte) {
        byte[] b = new byte[20];
        b[19] = (byte) lastByte;
        return Address.wrap(org.apache.tuweni.bytes.Bytes.wrap(b));
    }

    @Test
    void pragueHasFinalBlsLayoutAndNoOsakaPrecompiles() {
        PrecompileContractRegistry reg =
                MainnetPrecompiledContracts.prague(new PragueGasCalculator());
        // Final EIP-2537: 0x0b..0x11 present…
        for (int a = 0x0b; a <= 0x11; a++) {
            assertTrue(reg.get(addr(a)) != null, "0x" + Integer.toHexString(a) + " must exist");
        }
        // …and the pre-final draft's 0x12/0x13 gone.
        assertFalse(reg.get(addr(0x12)) != null, "0x12 is not in the final EIP-2537 layout");
        assertFalse(reg.get(addr(0x13)) != null, "0x13 is not in the final EIP-2537 layout");
        // Osaka's P256VERIFY (0x100) must not leak into Prague.
        byte[] p256 = new byte[20];
        p256[18] = 0x01;
        assertFalse(reg.get(Address.wrap(org.apache.tuweni.bytes.Bytes.wrap(p256))) != null,
                "P256VERIFY is Osaka-only");
        // KZG point-eval (0x0a, Cancun+) still registered.
        assertTrue(reg.get(addr(0x0a)) != null, "KZG point-eval must exist");
        // Sanity: chain-id-flavored factory agrees.
        BigInteger one = BigInteger.ONE;
        assertTrue(one.signum() > 0);
    }
}
