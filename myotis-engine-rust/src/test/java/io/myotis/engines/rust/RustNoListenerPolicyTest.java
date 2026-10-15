package io.myotis.engines.rust;

import io.myotis.api.WebAccessMode;
import io.myotis.api.WebAccessPolicy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A handle with NO loopback listener (the engine library's in-process consumer)
 * still answers the web-page policy contract: the mode as asked, every entry
 * normalized, the entries that are no origin dropped, duplicate spellings kept
 * as two entries — the same per-entry answer the listener's adapter gives, so a
 * host's "was an entry dropped?" size compare works on both paths. JNI-free:
 * nothing here crosses the FFI (the handle id is a dummy, as in
 * {@link RustStatusJsonTest}).
 */
class RustNoListenerPolicyTest {

    private final RustChainHandle noListener = new RustChainHandle(0L, "mainnet", 1L, 8545, false);

    @Test
    void policyIsNormalizedPerEntryWithoutAListener() {
        WebAccessPolicy applied = noListener.setWebAccessPolicy(new WebAccessPolicy(
                WebAccessMode.ALLOWLIST,
                List.of("HTTPS://App.Example/", "not an origin", "app.example", "https://app.example")));
        assertEquals(WebAccessMode.ALLOWLIST, applied.mode(), "the mode is kept as asked");
        assertEquals(
                List.of("https://app.example", "https://app.example", "https://app.example"),
                applied.origins(),
                "normalized per entry, the non-origin dropped, duplicate spellings kept");
        // The size compare the daemon and the apps make: one entry dropped.
        assertEquals(4 - 1, applied.origins().size());
    }

    @Test
    void offAndAllKeepTheirModeToo() {
        assertEquals(WebAccessMode.OFF,
                noListener.setWebAccessPolicy(new WebAccessPolicy(WebAccessMode.OFF, List.of())).mode());
        assertEquals(WebAccessMode.ALL,
                noListener.setWebAccessPolicy(new WebAccessPolicy(WebAccessMode.ALL, List.of())).mode());
    }

    @Test
    void nothingListensSoNothingWasJudgedAndNothingIsServed() {
        assertTrue(noListener.recentWebOrigins().isEmpty(), "no listener ever judged an origin");
        assertNull(noListener.reads(), "reads() is null before start() on every handle");
    }
}
