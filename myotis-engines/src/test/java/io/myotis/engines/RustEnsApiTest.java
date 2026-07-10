package io.myotis.engines;

import io.myotis.api.EnsResolutionResult;
import io.myotis.api.EnsRoot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The RustEnsApi paths that need no native library — the pre-native input
 * guards, which must fold into error results (this impl never throws). The
 * JSON→record mapping is covered by {@link RustEnsRecordJsonTest}.
 */
class RustEnsApiTest {

    private static RustEnsApi api() {
        // A never-started handle: only the pre-native guard paths are exercised.
        return new RustEnsApi(new RustChainHandle(0L, "mainnet", 1L, 0, true));
    }

    @Test
    void ensIsNullOnNetworksWithoutEns() {
        // gnosis (hasEns=false) → ChainHandle.ens() is null; mainnet (true) → non-null.
        assertNull(new RustChainHandle(0L, "gnosis", 100L, 0, false).ens());
        assertNotNull(new RustChainHandle(0L, "mainnet", 1L, 0, true).ens());
    }

    @Test
    void blankNameIsAnErrorResult() {
        EnsResolutionResult r = api().resolveAddress("  ", EnsRoot.AUTO);
        assertNull(r.addressHex());
        assertNotNull(r.error());
        // FINALIZED is a supported root now (EL-C-5-2) — the blank-name guard is
        // root-independent and must not mention finalized.
        EnsResolutionResult fin = api().resolveAddress("  ", EnsRoot.FINALIZED);
        assertNotNull(fin.error());
    }

    @Test
    void blankInputsFoldToErrorResultsForEveryRecordType() {
        // Never throws; error set, no value fields populated as answers. These
        // all stop at the input guard — no native call on a never-started handle.
        var api = api();
        assertNotNull(api.resolveText(" ", "url").error());
        assertNotNull(api.resolveText("a.eth", " ").error());
        assertNotNull(api.resolveContenthash(" ").error());
        assertNotNull(api.resolveMultiCoinAddr(" ", 60).error());
        assertNotNull(api.resolveMultiCoinAddr("a.eth", -1).error());
        assertNotNull(api.resolvePubkey(" ").error());
        assertNotNull(api.resolveAbi(" ", 1).error());
        assertNotNull(api.resolveAbi("a.eth", -1).error());
        assertNotNull(api.resolveDnsRecord(" ", "a.eth.", 1).error());
        assertNotNull(api.resolveDnsRecord("a.eth", " ", 1).error());
        assertNotNull(api.resolveDnsRecord("a.eth", "a.eth.", -1).error());
        assertNotNull(api.resolveDnsRecord("a.eth", "a.eth.", 0x10000).error());
    }

    @Test
    void malformedReverseAddressIsAnErrorResult() {
        // JavaEnsApi THROWS for this; this impl folds it (documented divergence).
        var api = api();
        var bad = api.reverseResolve("0x1234");
        assertNull(bad.name());
        assertTrue(bad.error().contains("40 hex chars"), bad.error());
        assertNotNull(api.reverseResolve(null).error());
        assertNotNull(api.reverseResolve("zz".repeat(20)).error());
    }

    @Test
    void interfaceImplementerEchoesQueriedIdAndValidatesLength() {
        var api = api();
        // The queried id is echoed (JavaEnsApi parity) even on a guard error
        // result (blank name keeps this on the no-native path).
        var ok = api.resolveInterfaceImplementer(" ", new byte[] {(byte) 0x90, 0x61, (byte) 0xb9, 0x23});
        assertEquals("0x9061b923", ok.interfaceIdHex());
        assertNotNull(ok.error());
        // A malformed id is its own error result, never an echo or a throw.
        var bad = api.resolveInterfaceImplementer("a.eth", new byte[] {1, 2, 3});
        assertNull(bad.interfaceIdHex());
        assertTrue(bad.error().contains("4 bytes"));
        assertNull(api.resolveInterfaceImplementer("a.eth", null).interfaceIdHex());
    }
}
