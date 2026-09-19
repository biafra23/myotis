package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pins the engines' read-stats serializer contract (schema 1, both engines
 *  emit the identical shape — readstats.rs / ReadStats.java pin the empty
 *  literal) against the Status tab's rows. */
class ReadStatsStatusTest {

    private val empty = "{\"schema\":1,\"windowSeconds\":0," +
        "\"account\":{\"fetches\":0,\"repeats\":0,\"sameStateRoot\":0,\"unchanged\":0," +
        "\"fetchMs\":0,\"sameStateRootFetchMs\":0,\"byAge\":{\"le12s\":{\"reads\":0,\"unchanged\":0}," +
        "\"le60s\":{\"reads\":0,\"unchanged\":0},\"le5m\":{\"reads\":0,\"unchanged\":0}," +
        "\"gt5m\":{\"reads\":0,\"unchanged\":0}}}," +
        "\"storage\":{\"fetches\":0,\"repeats\":0,\"sameStateRoot\":0,\"sameStorageRoot\":0," +
        "\"sameValue\":0,\"fetchMs\":0,\"sameStorageRootFetchMs\":0,\"byAge\":{" +
        "\"le12s\":{\"reads\":0,\"unchanged\":0},\"le60s\":{\"reads\":0,\"unchanged\":0}," +
        "\"le5m\":{\"reads\":0,\"unchanged\":0},\"gt5m\":{\"reads\":0,\"unchanged\":0}}}," +
        "\"code\":{\"fetches\":0,\"repeats\":0,\"fetchMs\":0,\"repeatFetchMs\":0}," +
        "\"tracked\":{\"accounts\":0,\"slots\":0,\"codes\":0}}"

    private val busy = "{\"schema\":1,\"windowSeconds\":1834," +
        "\"account\":{\"fetches\":412,\"repeats\":380,\"sameStateRoot\":9,\"unchanged\":301," +
        "\"fetchMs\":61234,\"sameStateRootFetchMs\":900,\"byAge\":{\"le12s\":{\"reads\":12,\"unchanged\":12}," +
        "\"le60s\":{\"reads\":300,\"unchanged\":250},\"le5m\":{\"reads\":60,\"unchanged\":35}," +
        "\"gt5m\":{\"reads\":8,\"unchanged\":4}}}," +
        "\"storage\":{\"fetches\":2210,\"repeats\":2100,\"sameStateRoot\":40,\"sameStorageRoot\":1800," +
        "\"sameValue\":210,\"fetchMs\":401000,\"sameStorageRootFetchMs\":330000,\"byAge\":{" +
        "\"le12s\":{\"reads\":100,\"unchanged\":100},\"le60s\":{\"reads\":1900,\"unchanged\":1720}," +
        "\"le5m\":{\"reads\":90,\"unchanged\":40},\"gt5m\":{\"reads\":10,\"unchanged\":1}}}," +
        "\"code\":{\"fetches\":31,\"repeats\":24,\"fetchMs\":5100,\"repeatFetchMs\":3900}," +
        "\"tracked\":{\"accounts\":57,\"slots\":410,\"codes\":7}}"

    @Test
    fun empty_shape_parses_to_zeros_and_hides_the_rows() {
        val p = ReadStatsStatus.parse(empty)!!
        assertEquals(0L, p.windowSeconds)
        assertEquals(0L, p.storage.fetches)
        assertFalse(ReadStatsStatus.hasReads(p))
        assertNull(ReadStatsStatus.staleLine(p))
    }

    @Test
    fun error_envelope_and_api_default_parse_to_null() {
        assertNull(ReadStatsStatus.parse("{\"error\":\"handle not started\"}"))
        assertNull(ReadStatsStatus.parse("{\"schema\":1,\"windowSeconds\":0}"))
    }

    @Test
    fun busy_session_renders_the_three_rows() {
        val p = ReadStatsStatus.parse(busy)!!
        assertTrue(ReadStatsStatus.hasReads(p))
        assertEquals(1834L, p.windowSeconds)
        // Per-kind numbers land in the right section (the outer `unchanged` /
        // `fetches` must not be confused with the byAge buckets' keys).
        assertEquals(412L, p.account.fetches)
        assertEquals(301L, p.account.unchanged)
        assertEquals(9L, p.account.avoidable)
        assertEquals(1800L, p.storage.avoidable)
        assertEquals(330000L, p.storage.avoidableMs)
        assertEquals(24L, p.code.repeats)
        assertEquals(2000L, p.storage.recentReads)
        assertEquals(1820L, p.storage.recentUnchanged)
        assertEquals("acct 412 · slot 2,210 · code 31", ReadStatsStatus.fetchesLine(p))
        assertEquals("slot 81% (5m 30s) · acct 2% · code 77%", ReadStatsStatus.cacheableLine(p))
        assertEquals("slot 91% · acct 84%", ReadStatsStatus.staleLine(p))
    }
}
