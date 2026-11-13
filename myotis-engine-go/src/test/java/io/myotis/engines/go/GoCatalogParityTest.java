package io.myotis.engines.go;

import io.myotis.api.EngineException;
import io.myotis.api.NetworkInfo;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The Go binary's catalog against the shared golden
 * ({@code rust/testdata/networks_catalog.json}) — the native-backed twin of
 * {@code NetworksJsonGoldenTest}: the Go side already proves
 * {@code AvailableNetworksJSON} equals that file field-for-field
 * ({@code TestCatalogMatchesGolden}); this proves the bytes ACTUALLY COMING OUT
 * of the built {@code libmyotis_engine_go} still do (a stale or misbuilt library
 * is caught here, not in a host). Native-backed: self-skips without the library.
 */
class GoCatalogParityTest {

    @Test
    void liveCatalogMatchesTheGoldenAndTheCanonicalTable() throws Exception {
        assumeTrue(GoMyotisEngine.isAvailable(), "libmyotis_engine_go not loaded");
        String golden = Files.readString(
                Path.of("..", "rust", "testdata", "networks_catalog.json"));

        GoMyotisEngine engine = new GoMyotisEngine(); // throws if not available
        // The Go catalog lists ONLY what it can RUN (mainnet — the multichain
        // step adds the rest), and every entry must equal the golden's, exactly
        // as go's own TestCatalogMatchesGolden states. This test adds what that
        // one cannot see: that the bytes the BUILT library actually emits match
        // (a stale go/build library fails here, not in a host).
        List<NetworkInfo> expected = GoMyotisEngine.parseNetworks(golden).stream()
                .filter(n -> n.name().equals("mainnet"))
                .toList();
        assertEquals(expected, engine.availableNetworks(),
                "the built libmyotis_engine_go's catalog no longer matches the golden's "
                        + "runnable subset — rebuild it (goBuildCShared)");

        // The canonical table (catalog.rs, mirrored Go-side): the four names, the
        // two gnosis aliases — and NOTHING else. Case is folded (the Rust table
        // lowercases its input) but whitespace is not trimmed, and there are no
        // "ethereum"/"eth"/"1" aliases — exactly like the Rust table (pinned in
        // TestCanonicalNameMatchesRustTable; this is the same contract seen from
        // the JVM, because the selector's ownership routing depends on all
        // engines canonicalizing identically).
        assertEquals("mainnet", engine.canonicalNetworkName("mainnet"));
        assertEquals("sepolia", engine.canonicalNetworkName("sepolia"));
        assertEquals("gnosis", engine.canonicalNetworkName("gnosis"));
        assertEquals("gnosis", engine.canonicalNetworkName("gbc"));
        assertEquals("gnosis", engine.canonicalNetworkName("xdai"));
        assertEquals("chiado", engine.canonicalNetworkName("chiado"));
        assertEquals("mainnet", engine.canonicalNetworkName("MAINNET")); // case-folded…
        for (String unknown : new String[]{"ethereum", "eth", "1", " mainnet"}) {
            assertThrows(EngineException.class, () -> engine.canonicalNetworkName(unknown),
                    "alias table drifted: '" + unknown + "' resolved on the Go engine");
        }
    }

    @Test
    void meteringCodesRoundTripWithTheRustEnum() {
        assumeTrue(GoMyotisEngine.isAvailable(), "libmyotis_engine_go not loaded");
        // The Go capi's Metering codes are the Rust usage::Metering's (0/1/2);
        // the wrapper maps the API enum to them and back.
        assertEquals(io.myotis.api.NetworkMetering.UNMETERED, GoMyotisEngine.meteringOf(1));
        assertEquals(io.myotis.api.NetworkMetering.METERED, GoMyotisEngine.meteringOf(2));
        assertEquals(io.myotis.api.NetworkMetering.UNKNOWN, GoMyotisEngine.meteringOf(0));
        assertEquals(io.myotis.api.NetworkMetering.UNKNOWN, GoMyotisEngine.meteringOf(77));
    }
}
