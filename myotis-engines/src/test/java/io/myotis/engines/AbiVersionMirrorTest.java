package io.myotis.engines;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The ABI handshake constant is copied by hand into every host that gates on it, and a
 * copy that falls behind is worse here than anywhere else: {@link RustEngineNative}
 * turns a mismatch into {@code isAvailable() == false}, which {@code Engines} reads as
 * "no Rust engine" and silently serves the Java one instead — {@code myotis.engine=rust}
 * quietly not being honoured, behind a single {@code log.warn}.
 *
 * <p>UniFFI's per-function checksums do NOT cover this. They catch a library whose SHAPE
 * disagrees with the bindings (a stale {@code .so}); they pass cleanly when the library
 * is current and correct and only the hand-copied integer is behind — which is exactly
 * the drift this pins.
 *
 * <p>Deliberately reads the Rust tree as TEXT, the same trick
 * {@code NetworksJsonGoldenTest} uses for the catalog golden: no native library, no
 * cargo, so this runs in the plain {@code ./gradlew build} CI job. That matters because
 * the Rust-side twin of this check ({@code capi::tests::header_pins_the_current_abi_version})
 * sits behind {@code cargoTest}'s {@code onlyIf { rustAvailable }} and can silently skip.
 * Checking the header here too makes the whole chain — crate constant, C header, JVM
 * mirror — verified unconditionally.
 */
class AbiVersionMirrorTest {

    /** The source of truth. */
    private static final Path CRATE_LIB = Path.of("..", "rust", "myotis-engine", "src", "lib.rs");

    /** The C ABI contract consumed by :app-ios via cinterop. */
    private static final Path C_HEADER = Path.of("..", "rust", "include", "myotis_engine.h");

    private static final Pattern CRATE_CONST =
            Pattern.compile("^pub const ABI_VERSION: i32 = (\\d+);", Pattern.MULTILINE);

    /** Column 0 only, so a `#define` quoted inside a comment isn't mistaken for one. */
    private static final Pattern HEADER_DEFINE =
            Pattern.compile("^#define MYOTIS_ABI_VERSION[ \\t]+(\\d+)", Pattern.MULTILINE);

    @Test
    void javaMirrorMatchesTheCrateConstant() throws IOException {
        assertEquals(soleMatch(CRATE_LIB, CRATE_CONST), RustEngineNative.EXPECTED_ABI_VERSION,
                "RustEngineNative.EXPECTED_ABI_VERSION has drifted from ABI_VERSION in "
                        + "rust/myotis-engine/src/lib.rs. Left stale, the Rust engine reports "
                        + "unavailable and every host silently falls back to the Java engine.");
    }

    @Test
    void cHeaderMatchesTheCrateConstant() throws IOException {
        assertEquals(soleMatch(CRATE_LIB, CRATE_CONST), soleMatch(C_HEADER, HEADER_DEFINE),
                "MYOTIS_ABI_VERSION in rust/include/myotis_engine.h has drifted from "
                        + "ABI_VERSION in rust/myotis-engine/src/lib.rs. The header is the "
                        + "contract for the plain-C ABI consumers, and :app-ios derives "
                        + "RustEngine.EXPECTED_ABI_VERSION from it through cinterop.");
    }

    /**
     * The single capture in {@code file}. Requiring exactly one match is part of the
     * contract on both sides: a second, stale definition left behind (in a dead
     * preprocessor branch, say) must fail loudly rather than shadow the live one.
     */
    private static int soleMatch(Path file, Pattern pattern) throws IOException {
        Matcher m = pattern.matcher(Files.readString(file));
        List<String> found = new ArrayList<>();
        while (m.find()) {
            found.add(m.group(1));
        }
        assertEquals(1, found.size(),
                file + " must match " + pattern + " exactly once, found " + found);
        return Integer.parseInt(found.get(0));
    }
}
