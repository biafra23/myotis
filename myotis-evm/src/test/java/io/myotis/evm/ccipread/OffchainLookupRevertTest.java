package io.myotis.evm.ccipread;

import io.myotis.evm.Address;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.AbiValue;
import io.myotis.evm.abi.FunctionSignature;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OffchainLookupRevertTest {

    @Test
    void roundTripsThroughEncoder() {
        // Construct a synthetic OffchainLookup payload via the encoder and
        // verify the parser recovers every field.
        Address sender = Address.fromHex("0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63");
        List<String> urls = List.of(
                "https://gateway-1.example.com/{sender}/{data}.json",
                "https://gateway-2.example.com/lookup");
        byte[] callData = HexFormat.of().parseHex("deadbeef");
        byte[] callbackSelector = HexFormat.of().parseHex("aabbccdd");
        byte[] extraData = HexFormat.of().parseHex("c0ffee");

        // bytes4 is left-aligned in its 32-byte slot.
        byte[] callbackPadded = new byte[32];
        System.arraycopy(callbackSelector, 0, callbackPadded, 0, 4);

        byte[] body = AbiEncoder.encodeRaw(
                AbiEncoder.address(sender),
                AbiEncoder.stringArray(urls),
                AbiEncoder.bytes(callData),
                new AbiValue(false, callbackPadded),
                AbiEncoder.bytes(extraData));

        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(OffchainLookupRevert.SELECTOR, 0, OffchainLookupRevert.SELECTOR.length);
        payload.write(body, 0, body.length);

        Optional<OffchainLookupRevert> parsed = OffchainLookupRevert.tryParse(payload.toByteArray());
        assertTrue(parsed.isPresent());
        OffchainLookupRevert r = parsed.orElseThrow();
        assertEquals(sender, r.sender());
        assertEquals(urls, r.urls());
        assertArrayEquals(callData, r.callData());
        assertArrayEquals(callbackSelector, r.callbackSelector());
        assertArrayEquals(extraData, r.extraData());
    }

    @Test
    void rejectsNonOffchainSelector() {
        byte[] revert = HexFormat.of().parseHex("08c379a0" + "0".repeat(64));
        assertTrue(OffchainLookupRevert.tryParse(revert).isEmpty());
    }

    @Test
    void selectorMatchesErc3668() {
        FunctionSignature s = FunctionSignature.of(
                "OffchainLookup(address,string[],bytes,bytes4,bytes)");
        assertArrayEquals(s.selector(), OffchainLookupRevert.SELECTOR);
    }

    @Test
    void parseDataFieldHandlesPlainAndPrefixedHex() {
        assertArrayEquals(
                HexFormat.of().parseHex("deadbeef"),
                CcipReadHandler.parseDataField("{\"data\":\"0xdeadbeef\"}"));
        assertArrayEquals(
                new byte[0],
                CcipReadHandler.parseDataField("{\"data\":\"0x\"}"));
    }
}
