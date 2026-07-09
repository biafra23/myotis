package io.myotis.engines;

import io.myotis.api.EnsResolutionResult;
import io.myotis.api.EnsRoot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The RustEnsApi paths that need no native library (guards + graceful stubs). */
class RustEnsApiTest {

    private static RustEnsApi api() {
        // A never-started handle: only the pre-native guard paths are exercised.
        return new RustEnsApi(new RustChainHandle(0L, "mainnet", 1L, 0));
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
}
