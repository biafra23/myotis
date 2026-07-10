package io.myotis.engines;

import io.myotis.api.EnsResolutionResult;
import io.myotis.api.EnsRoot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The RustEnsApi paths that need no native library (guards + graceful stubs). */
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
    void finalizedRootIsRejectedNotDowngraded() {
        EnsResolutionResult r = api().resolveAddress("vitalik.eth", EnsRoot.FINALIZED);
        assertNull(r.addressHex());
        assertNotNull(r.error());
        assertTrue(r.error().contains("finalized"), r.error());
    }

    @Test
    void blankNameIsAnErrorResult() {
        EnsResolutionResult r = api().resolveAddress("  ", EnsRoot.AUTO);
        assertNull(r.addressHex());
        assertNotNull(r.error());
    }

    @Test
    void unimplementedRecordTypesReturnGracefulErrors() {
        // Never throws; error set, no value fields populated as answers.
        var api = api();
        assertNotNull(api.resolveText("a.eth", "url").error());
        assertNotNull(api.resolveContenthash("a.eth").error());
        assertNotNull(api.resolveMultiCoinAddr("a.eth", 60).error());
        assertNotNull(api.resolvePubkey("a.eth").error());
        assertNotNull(api.resolveAbi("a.eth", 1).error());
        assertNotNull(api.resolveDnsRecord("a.eth", "a.eth.", 1).error());
        assertNotNull(api.resolveInterfaceImplementer("a.eth", new byte[] {1, 2, 3, 4}).error());
        assertNotNull(api.reverseResolve("0x" + "11".repeat(20)).error());
    }

    @Test
    void interfaceImplementerEchoesQueriedIdAndValidatesLength() {
        var api = api();
        // The queried id is echoed (JavaEnsApi parity) even on the stub error result.
        var ok = api.resolveInterfaceImplementer("a.eth", new byte[] {(byte) 0x90, 0x61, (byte) 0xb9, 0x23});
        assertEquals("0x9061b923", ok.interfaceIdHex());
        // A malformed id is its own error result, never an echo or a throw.
        var bad = api.resolveInterfaceImplementer("a.eth", new byte[] {1, 2, 3});
        assertNull(bad.interfaceIdHex());
        assertTrue(bad.error().contains("4 bytes"));
        assertNull(api.resolveInterfaceImplementer("a.eth", null).interfaceIdHex());
    }
}
