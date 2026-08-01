package io.myotis.engines;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Pins the pre-UniFFI string tolerance of the FFI boundary, THROUGH the real
 * library: null and MALFORMED UTF-16 arguments (unpaired surrogates —
 * attacker-reachable via JSON-RPC string params) must degrade to the old hand-JNI
 * semantics ("" / absent) instead of surfacing the generated bindings'
 * {@code MalformedInputException} through the delegators. Self-skips on
 * cargo-less machines like the other live suites.
 */
class RustEngineNativeStringToleranceTest {

    /** A lone high surrogate — valid UTF-16 String object, unencodable as UTF-8. */
    private static final String MALFORMED = "main\uD800net";

    @BeforeAll
    static void setup() {
        assumeTrue(RustEngineNative.isAvailable(),
                "libmyotis_engine not loadable — skipping live FFI tolerance tests");
    }

    @Test
    void malformedNetworkNameDegradesToUnknownInsteadOfThrowing() {
        // Old shim: CESU-8 decode failure → "" on the Rust side → unknown → null.
        assertNull(RustEngineNative.nativeCanonicalNetworkName(MALFORMED));
        // Sanity: well-formed lookups still resolve around the probe.
        assertEquals("mainnet", RustEngineNative.nativeCanonicalNetworkName("mainnet"));
    }

    @Test
    void malformedCreateArgsReturnFailureSentinelInsteadOfThrowing() {
        assertEquals(-1, RustEngineNative.nativeCreate(MALFORMED, MALFORMED));
    }

    @Test
    void malformedAddressOnVerifiedReadStaysInBandError() {
        // Unknown handle + sanitized-to-empty address: the engine answers with its
        // in-band {"error": ...} object; the boundary must not throw.
        String json = RustEngineNative.nativeRequestAccountJson(-12345, MALFORMED);
        assertTrue(json.contains("\"error\""), "expected in-band error JSON, got: " + json);
    }

    @Test
    void malformedHolderIsTreatedAsAbsent() {
        // Old shim: a holder that failed to decode became None. Same in-band error
        // (unknown handle) as the explicit-null call, never an exception.
        String withMalformed =
                RustEngineNative.nativeGetStorageProofJson(-12345, "0x00", 1, MALFORMED);
        String withNull = RustEngineNative.nativeGetStorageProofJson(-12345, "0x00", 1, null);
        assertEquals(withNull, withMalformed);
    }
}
