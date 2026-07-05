package io.myotis.engines;

import io.myotis.api.NetworkInfo;
import io.myotis.node.api.JavaMyotisEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The cross-language catalog contract, testable WITHOUT the native library: parse the
 * committed golden sample ({@code rust/testdata/networks_catalog.json} — which the Rust
 * side asserts byte-for-byte in {@code catalog::tests}) with the exact parser
 * {@link RustMyotisEngine} uses, and require the result to equal the Java engine's
 * catalog. Any drift — a field rename, a changed port, a reordered or added network on
 * either side — fails here or in the Rust twin.
 */
class NetworksJsonGoldenTest {

    @BeforeAll
    static void registerBouncyCastle() {
        // NetworkConfig's class-load genesis verification needs the KECCAK-256 provider.
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void committedGoldenSampleMatchesJavaEngineCatalog() throws Exception {
        Path golden = Path.of("..", "rust", "testdata", "networks_catalog.json");
        String json = Files.readString(golden);

        List<NetworkInfo> fromGolden = RustMyotisEngine.parseNetworks(json);
        List<NetworkInfo> fromJava = new JavaMyotisEngine().availableNetworks();

        // NetworkInfo is a record — equals() compares every field.
        assertEquals(fromJava, fromGolden,
                "rust/testdata/networks_catalog.json no longer matches the Java engine's "
                        + "catalog. Regenerate it from the Rust side (see catalog.rs) or fix "
                        + "whichever side drifted.");
    }
}
