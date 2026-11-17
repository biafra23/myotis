package io.myotis.engines.go;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Go ring's lines reach the hosts' pumps through
 * {@code GoMyotisEngine.drainLogs} — and both pumps ({@code app}'s Main, the
 * desktop's DesktopNode) classify by the FIRST token, {@code startsWith
 * ("ERROR")}/{@code "WARN")}, the Rust tracing format's shape. A raw slog line
 * starts with {@code time=… level=WARN msg=…}, so every Go WARN and ERROR
 * landed in the pumps' else-branch at INFO — dropping exactly the refusal and
 * stall lines of the engine under test from a level-filtered view (PR #832
 * review). {@code normalizeForHostPumps} is the fix; this pins it.
 */
class GoLogDrainTest {

    @Test
    void slogLinesBecomeLevelFirstWithAGoMarker() {
        String batch = "time=2026-11-13T10:00:00Z level=INFO msg=started peer=1\n"
                + "time=2026-11-13T10:00:01Z level=WARN msg=\"dns refused\"\n"
                + "time=2026-11-13T10:00:02Z level=ERROR msg=dial-failed\n"
                + "no level token here";
        String[] lines = GoMyotisEngine.normalizeForHostPumps(batch).split("\n");
        assertEquals(4, lines.length);
        // What the pumps switch on:
        assertTrue(lines[0].startsWith("INFO go "), lines[0]);
        assertTrue(lines[1].startsWith("WARN go "), lines[1]);
        assertTrue(lines[2].startsWith("ERROR go "), lines[2]);
        // An unlevelled line lands at INFO (the slog default), never dropped:
        assertTrue(lines[3].startsWith("INFO go "), lines[3]);
        // The original slog content survives (fields stay greppable):
        assertTrue(lines[1].contains("level=WARN msg=\"dns refused\""), lines[1]);
        assertTrue(lines[2].contains("time=2026-11-13T10:00:02Z"), lines[2]);
    }

    @Test
    void emptyBatchStaysEmpty() {
        assertEquals("", GoMyotisEngine.normalizeForHostPumps(""));
        assertEquals("", GoMyotisEngine.normalizeForHostPumps("\n"));
    }
}
