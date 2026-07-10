package io.myotis.engines;

import io.myotis.api.EngineException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Golden JSON→record vectors for the RustEnsApi parsers (the Java half of the
 * cross-language pin — the Rust half is {@code eljson::ens_record_json_shapes},
 * which emits these exact literals). No JNI.
 */
class RustEnsRecordJsonTest {

    private static final String ADDR40 = "0x" + "d8".repeat(20);

    private static String ok(String valueFields) {
        return "{\"status\":\"ok\",\"blockNumber\":21000010,\"verified\":true," + valueFields + "}";
    }

    private static final String NO_RECORD =
            "{\"status\":\"noRecord\",\"blockNumber\":21000010,\"verified\":false}";
    private static final String OFFCHAIN =
            "{\"status\":\"offchain\",\"blockNumber\":21000010,\"verified\":false}";

    @Test
    void addressOkNoRecordAndOffchain() {
        var okR = RustEnsApi.addressFromJson("vitalik.eth", ok("\"addressHex\":\"" + ADDR40 + "\""));
        assertEquals(ADDR40, okR.addressHex());
        assertEquals(21000010, okR.blockNumber());
        assertTrue(okR.verified());
        assertNull(okR.error());

        var none = RustEnsApi.addressFromJson("gone.eth", NO_RECORD);
        assertNull(none.addressHex());
        assertNull(none.error()); // successful "no record"
        assertFalse(none.verified());

        var off = RustEnsApi.addressFromJson("cb.id", OFFCHAIN);
        assertNull(off.addressHex());
        assertTrue(off.error().contains("offchain"));
    }

    @Test
    void reverseCarriesForwardVerifiedName() {
        var r = RustEnsApi.reverseFromJson(ADDR40, ok("\"name\":\"vitalik.eth\""));
        assertEquals("vitalik.eth", r.name());
        assertEquals(ADDR40, r.addressHex());
        assertTrue(r.verified());
        // Empty record / failed forward-verify / no reverse resolver are ONE
        // shape: noRecord with a null name and NO error (Java parity).
        var none = RustEnsApi.reverseFromJson(ADDR40, NO_RECORD);
        assertNull(none.name());
        assertEquals(ADDR40, none.addressHex());
        assertNull(none.error());
    }

    @Test
    void textValueAndNoRecord() {
        var r = RustEnsApi.textFromJson("vitalik.eth", "url", ok("\"value\":\"https://vitalik.ca\""));
        assertEquals("https://vitalik.ca", r.value());
        assertEquals("url", r.key());
        var none = RustEnsApi.textFromJson("vitalik.eth", "url", NO_RECORD);
        assertNull(none.value());
        assertNull(none.error());
    }

    @Test
    void bytesShapedRecords() {
        var ch = RustEnsApi.contenthashFromJson("a.eth", ok("\"dataHex\":\"0xc0ffee\""));
        assertEquals("0xc0ffee", ch.contenthashHex());
        var mc = RustEnsApi.multiCoinFromJson("a.eth", 0, ok("\"dataHex\":\"0xc0ffee\""));
        assertEquals("0xc0ffee", mc.addressHex());
        assertEquals(0, mc.coinType());
        var dns = RustEnsApi.dnsRecordFromJson("a.eth", "a.eth.", 1, ok("\"dataHex\":\"0xc0ffee\""));
        assertEquals("0xc0ffee", dns.dataHex());
        assertEquals(1, dns.recordType());
    }

    @Test
    void pubkeyAndAbi() {
        String x = "0x" + "0a".repeat(32);
        String y = "0x" + "0b".repeat(32);
        var pk = RustEnsApi.pubkeyFromJson(
                "a.eth", ok("\"pubkeyXHex\":\"" + x + "\",\"pubkeyYHex\":\"" + y + "\""));
        assertEquals(x, pk.pubkeyXHex());
        assertEquals(y, pk.pubkeyYHex());

        var abi = RustEnsApi.abiFromJson("a.eth", ok("\"contentType\":1,\"dataHex\":\"0x7b7d\""));
        assertEquals(1, abi.contentType());
        assertEquals("0x7b7d", abi.dataHex());
        // contentType folds to 0 on noRecord (JavaEnsApi parity).
        assertEquals(0, RustEnsApi.abiFromJson("a.eth", NO_RECORD).contentType());
    }

    @Test
    void interfaceImplementerAddressShape() {
        var r = RustEnsApi.interfaceFromJson(
                "a.eth", "0x9061b923", ok("\"addressHex\":\"" + ADDR40 + "\""));
        assertEquals(ADDR40, r.implementerHex());
        assertEquals("0x9061b923", r.interfaceIdHex());
    }

    @Test
    void shapeDriftFailsClosed() {
        // status=ok without its value field must throw (→ folded into an error
        // result by the API layer), never read as a successful no-record.
        assertThrows(EngineException.class,
                () -> RustEnsApi.addressFromJson("a.eth", ok("\"unrelated\":1")));
        assertThrows(EngineException.class,
                () -> RustEnsApi.textFromJson("a.eth", "url", ok("\"dataHex\":\"0x00\"")));
        assertThrows(EngineException.class,
                () -> RustEnsApi.pubkeyFromJson("a.eth", ok("\"pubkeyXHex\":\"0x0a\"")));
        assertThrows(EngineException.class, () -> RustEnsApi.abiFromJson(
                "a.eth", ok("\"contentType\":\"NaN\",\"dataHex\":\"0x7b7d\"")));
        // Missing envelope fields are drift too.
        assertThrows(EngineException.class, () -> RustEnsApi.addressFromJson(
                "a.eth", "{\"status\":\"ok\",\"addressHex\":\"" + ADDR40 + "\"}"));
        assertThrows(EngineException.class, () -> RustEnsApi.addressFromJson(
                "a.eth", "{\"status\":\"weird\",\"blockNumber\":1,\"verified\":false}"));
        // An error object throws with the native's message.
        EngineException e = assertThrows(EngineException.class,
                () -> RustEnsApi.addressFromJson("a.eth", "{\"error\":\"no snap peer\"}"));
        assertTrue(e.getMessage().contains("no snap peer"));
    }
}
