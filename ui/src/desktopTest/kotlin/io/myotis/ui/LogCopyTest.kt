package io.myotis.ui

import kotlinx.datetime.TimeZone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Logs tab's Copy keeps the NEWEST lines that fit its character budget, whole, behind a
 * note when it had to cut — so an oversized paste that a destination truncates still ends
 * with the lines a diagnosis wants, and says what it dropped.
 */
class LogCopyTest {

    private val tz = TimeZone.UTC

    // Zero-padded ids keep every formatted line the same length, so the budget maths is exact.
    private fun line(i: Int) =
        LogLine(i.toLong(), 1_700_000_000_000 + i, 'I', "tag", "line " + i.toString().padStart(3, '0'))

    private fun lines(n: Int) = (0 until n).map { line(it) }

    @Test
    fun underTheBudgetTheCopyIsTheWholeViewVerbatim() {
        val all = lines(10)
        val copy = copyNewest(all, tz, canSave = true, budgetChars = 10_000)
        assertEquals(formatLogs(all, tz), copy.text)
        assertEquals(10, copy.copiedLines)
        assertEquals(0, copy.omittedLines)
        assertFalse(copy.cut)
        assertEquals("Copied all 10 lines.", copy.status())
    }

    @Test
    fun overTheBudgetTheNewestWholeLinesFollowANote() {
        val all = lines(100)
        val one = formatLogLine(line(0), tz).length
        val budget = 10 * one + one / 2  // ten lines fit, an eleventh does not
        val copy = copyNewest(all, tz, canSave = true, budgetChars = budget)
        assertEquals(10, copy.copiedLines)
        assertEquals(90, copy.omittedLines)
        assertTrue(copy.cut)
        val note = cutNote(10, 100, budget, canSave = true)
        assertTrue(copy.text.startsWith("$note\n"))
        // The newest ten, oldest first, each whole — and nothing older.
        assertEquals(formatLogs(all.takeLast(10), tz), copy.text.removePrefix("$note\n"))
        assertTrue(copy.text.length - note.length - 1 <= budget)
        assertTrue(copy.status().contains("newest 10 of 100"))
        assertTrue(copy.status().endsWith("Save… writes the whole log."))
        assertTrue(note.contains("Save… in the Logs tab writes the whole log"))
    }

    @Test
    fun withoutASaveButtonNeitherTheNoteNorTheStatusPointsAtOne() {
        val copy = copyNewest(lines(100), tz, canSave = false, budgetChars = 200)
        assertTrue(copy.cut)
        assertFalse(copy.text.contains("Save…"))
        assertFalse(copy.status().contains("Save…"))
        assertTrue(copy.status().contains("newest 1 of 100") || copy.status().contains("newest"))
    }

    @Test
    fun aNewestLineOverTheBudgetIsStillCopiedAlone() {
        val all = lines(3) + LogLine(3, 1_700_000_000_003, 'E', "tag", "x".repeat(500))
        val copy = copyNewest(all, tz, canSave = true, budgetChars = 100)
        assertEquals(1, copy.copiedLines)
        assertEquals(3, copy.omittedLines)
        assertTrue(copy.text.endsWith("x".repeat(500) + "\n"))
    }

    @Test
    fun anEmptyViewCopiesNothing() {
        val copy = copyNewest(emptyList(), tz, canSave = true)
        assertEquals("", copy.text)
        assertFalse(copy.cut)
        assertEquals("Nothing to copy.", copy.status())
    }

    @Test
    fun theDefaultBudgetFitsAGitHubComment() {
        assertTrue(LOG_COPY_BUDGET_CHARS + cutNote(1, 50_000, LOG_COPY_BUDGET_CHARS, canSave = true).length < 65_536)
    }

    @Test
    fun streamedAndBuiltRenderingsAgree() {
        val all = lines(7)
        val sb = StringBuilder()
        formatLogsTo(sb, all, tz)
        assertEquals(formatLogs(all, tz), sb.toString())
    }

    @Test
    fun theSuggestedFileNameCarriesTheLocalMinute() {
        // 2026-10-10 07:57:11 UTC — the register of this morning's diagnosis.
        assertEquals("myotis-20261010-0757.log", logFileName(1_791_619_031_000, TimeZone.UTC))
        assertEquals("myotis-20261010-0957.log", logFileName(1_791_619_031_000, TimeZone.of("Europe/Berlin")))
    }
}
