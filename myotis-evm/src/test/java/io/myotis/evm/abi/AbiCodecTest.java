package io.myotis.evm.abi;

import io.myotis.evm.Address;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AbiCodecTest {

    @Test
    void selectorOfBalanceOfMatchesSpec() {
        // Reference: https://www.4byte.directory/signatures/?bytes4_signature=0x70a08231
        FunctionSignature sig = FunctionSignature.of("balanceOf(address)");
        assertEquals("70a08231", HexFormat.of().formatHex(sig.selector()));
    }

    @Test
    void selectorOfTransferMatchesSpec() {
        // ERC-20 transfer(address,uint256) -> 0xa9059cbb
        FunctionSignature sig = FunctionSignature.of("transfer(address,uint256)");
        assertEquals("a9059cbb", HexFormat.of().formatHex(sig.selector()));
    }

    @Test
    void selectorOfOffchainLookup() {
        // ERC-3668 OffchainLookup -> 0x556f1830
        FunctionSignature sig = FunctionSignature.of(
                "OffchainLookup(address,string[],bytes,bytes4,bytes)");
        assertEquals("556f1830", HexFormat.of().formatHex(sig.selector()));
    }

    @Test
    void encodeBalanceOfCallProducesExpectedCalldata() {
        FunctionSignature sig = FunctionSignature.of("balanceOf(address)");
        Address vitalik = Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        byte[] calldata = AbiEncoder.encodeCall(sig, AbiEncoder.address(vitalik));
        // 4-byte selector + 32-byte zero-padded address.
        String hex = HexFormat.of().formatHex(calldata);
        assertEquals(
                "70a08231"
                        + "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045",
                hex);
    }

    @Test
    void encodeAndDecodeUint256Roundtrip() {
        BigInteger v = new BigInteger("123456789012345678901234567890");
        byte[] enc = AbiEncoder.encodeRaw(AbiEncoder.uint256(v));
        assertEquals(32, enc.length);
        assertEquals(v, AbiDecoder.uint256(enc, 0));
    }

    @Test
    void encodeAndDecodeAddressRoundtrip() {
        Address a = Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        byte[] enc = AbiEncoder.encodeRaw(AbiEncoder.address(a));
        assertEquals(a, AbiDecoder.address(enc, 0));
    }

    @Test
    void encodeAndDecodeDynamicBytesRoundtrip() {
        byte[] payload = HexFormat.of().parseHex("deadbeefcafe");
        // Encode just `bytes` — there is one element in the head/tail, so
        // head is 32 bytes (the offset 0x20) and the tail is the dynamic encoding.
        byte[] enc = AbiEncoder.encodeRaw(AbiEncoder.bytes(payload));
        assertArrayEquals(payload, AbiDecoder.dynamicBytes(enc, 0));
    }

    @Test
    void encodeStringArrayMatchesSolidityLayout() {
        byte[] enc = AbiEncoder.encodeRaw(AbiEncoder.stringArray(List.of("a", "bb")));
        // Validate by round-tripping through a fresh dynamic-bytes parse:
        // top-level offset is 0x20, then array body is at 0x20.
        int offset = AbiDecoder.uint256(enc, 0).intValueExact();
        assertEquals(32, offset);
        int len = AbiDecoder.uint256(enc, offset).intValueExact();
        assertEquals(2, len);
    }

    @Test
    void uint256RejectsNegative() {
        try {
            AbiEncoder.uint256(BigInteger.valueOf(-1));
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("expected uint256(-1) to throw");
    }
}
