package io.myotis.ens;

import io.myotis.evm.Address;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReverseLookupTest {

    @Test
    void vitalikReverseName() {
        // Canonical example from ENSIP-3.
        Address vitalik = Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        assertEquals(
                "d8da6bf26964af9d7eed9e03e53415d37aa96045.addr.reverse",
                ReverseLookup.nameFor(vitalik));
    }

    @Test
    void zeroAddressReverseName() {
        assertEquals(
                "0000000000000000000000000000000000000000.addr.reverse",
                ReverseLookup.nameFor(Address.ZERO));
    }

    @Test
    void mixedCaseInputProducesLowercaseHex() {
        // Address.fromHex tolerates mixed case; the reverse-lookup name
        // must always be lowercase regardless of how the input was formatted.
        Address upper = Address.fromHex("0xABCDEF0102030405060708090A0B0C0D0E0F1011");
        assertEquals(
                "abcdef0102030405060708090a0b0c0d0e0f1011.addr.reverse",
                ReverseLookup.nameFor(upper));
    }
}
