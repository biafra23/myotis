package io.myotis.engines;

import io.myotis.jsonrpc.RpcBlockWindow;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The block-selector window ({@link RustVerifiedReads#blockInWindow}) that lets a
 * number-pinned read (MetaMask pins to the just-fetched latest number) resolve to
 * the anchored head, while rejecting genuinely-historical blocks.
 */
class RustBlockWindowTest {

    private static final long HEAD = 25_000_000L;

    private static boolean at(String block) {
        return RustVerifiedReads.blockInWindow(block, () -> HEAD);
    }

    @Test
    void headTagsAndDefaultAreServable() {
        assertTrue(at("latest"));
        assertTrue(at("pending"));
        assertTrue(at("safe"));
        assertTrue(at("finalized"));
        assertTrue(at(null));
        assertTrue(at(""));
    }

    @Test
    void numberPinAtOrNearHeadIsServable() {
        assertTrue(at("0x17d7840"));                          // == HEAD (25_000_000)
        assertTrue(at(Long.toString(HEAD)));                  // decimal form too
        assertTrue(at("0x" + Long.toHexString(HEAD - 64)));   // lag bound
        assertTrue(at("0x" + Long.toHexString(HEAD + 16)));   // ahead bound
    }

    @Test
    void olderOrTooFarAheadNumberIsRejected() {
        assertFalse(at("0x" + Long.toHexString(HEAD - 65)));  // just past the lag bound
        assertFalse(at("0x" + Long.toHexString(HEAD + 17)));  // just past the ahead bound
        assertFalse(at("0x1"));                               // ancient block
        assertFalse(at("earliest"));                          // genesis
    }

    @Test
    void malformedOrNotSyncedIsRejected() {
        assertFalse(at("0xzz"));                              // not a number
        assertFalse(at("garbage"));
        assertFalse(RustVerifiedReads.blockInWindow("0x17d7840", () -> null)); // head unknown
    }

    /**
     * The Rust engine checks eth_call's block itself (#452), for hosts that call
     * it without this adapter in front (the Node binding). Its window must be this
     * one, or the engine would refuse pins this adapter admits, or serve pins it
     * refuses. Read as TEXT, like {@link AbiVersionMirrorTest}, so it runs without
     * cargo; {@code host::call_block_tests} mirrors the cases above.
     */
    @Test
    void rustEngineGateUsesTheSameWindow() throws IOException {
        String host = Files.readString(Path.of("..", "rust", "myotis-engine", "src", "host.rs"));
        assertEquals(RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE,
                soleConst(host, "CALL_BLOCK_LAG_TOLERANCE"),
                "host.rs CALL_BLOCK_LAG_TOLERANCE has drifted from RpcBlockWindow");
        assertEquals(RpcBlockWindow.BLOCK_NUM_TOLERANCE,
                soleConst(host, "CALL_BLOCK_AHEAD_TOLERANCE"),
                "host.rs CALL_BLOCK_AHEAD_TOLERANCE has drifted from RpcBlockWindow");
    }

    /** The value of the one column-0 {@code const NAME: u64 = N;} in {@code source}. */
    private static long soleConst(String source, String name) {
        Matcher m = Pattern.compile("^const " + name + ": u64 = (\\d+);", Pattern.MULTILINE)
                .matcher(source);
        List<Long> found = new ArrayList<>();
        while (m.find()) {
            found.add(Long.parseLong(m.group(1)));
        }
        assertEquals(1, found.size(), name + " must be defined exactly once, found " + found);
        return found.get(0);
    }
}
