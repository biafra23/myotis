package io.myotis.engines.go;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The JVM mirror of {@code MYOTIS_ABI_VERSION} (PR #832 round-4 review).
 *
 * <p>Every other copy is forced on an ABI bump: the header and the Rust mirror
 * by {@code AbiVersionMirrorTest} ({@code :myotis-engine-rust}), the Go
 * library's own constant by {@code TestABIVersionMatchesHeader}
 * ({@code go/internal/capi}). This mirror was the one nothing pinned — and a
 * stale copy here fails the WRONG way: {@code myotis_init()} answers the new
 * version, {@link GoEngineNative}'s static initializer logs "ABI 58 !=
 * expected 57" and reports the Go engine unavailable, and both native-backed
 * tests leave through {@code assumeTrue} — green CI, and {@code -Pengine=go}
 * dies on a library that is current and correct. (The same hole exists for the
 * "library was built" check on ci.yml: the library IS there; the tests still
 * skip.)
 *
 * <p>Pure text read of the header, like the Rust twin's test: no native
 * library, no go toolchain, so it cannot self-skip — which is the entire
 * point.
 */
class GoAbiVersionMirrorTest {

    /** The C ABI contract BOTH engine libraries implement. */
    private static final Path C_HEADER = Path.of("..", "rust", "include", "myotis_engine.h");

    /** Column 0 only, so a `#define` quoted inside a comment isn't mistaken for one. */
    private static final Pattern HEADER_DEFINE =
            Pattern.compile("^#define MYOTIS_ABI_VERSION[ \\t]+(\\d+)", Pattern.MULTILINE);

    @Test
    void goJvmMirrorMatchesTheHeader() throws IOException {
        assertEquals(soleMatch(C_HEADER, HEADER_DEFINE), GoEngineNative.EXPECTED_ABI_VERSION,
                "GoEngineNative.EXPECTED_ABI_VERSION has drifted from MYOTIS_ABI_VERSION in "
                        + "rust/include/myotis_engine.h. Left stale, the Go engine reports "
                        + "itself unavailable against a current library, with CI green.");
    }

    /** Exactly one match is part of the contract (the Rust twin's rule). */
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
