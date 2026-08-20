package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The watch list is a contract with the wallet: an address the wallet scans but
 * this node does not index is refused outright. These pin the persistence
 * round-trip and the validation that keeps a typo out of the engine config —
 * one malformed entry is not a local failure: parse_log_index_config bails on
 * the first field it cannot parse and returns None for the WHOLE config, so a
 * single mistyped character would turn eth_getLogs off for the entire network.
 */
class LogIndexWatchTest {

    @Test
    fun serialize_parse_round_trips() {
        val entries = listOf(
            LogIndexWatch.Entry("0x45a1502382541cD610CC9068e88727426b696293", 31_305_656),
            LogIndexWatch.Entry("0xB20c66C4DE72433F3cE747b58B86830c459CA911", 14_173_395),
        )
        assertEquals(entries, LogIndexWatch.parse(LogIndexWatch.serialize(entries)))
    }

    @Test
    fun address_validation_rejects_every_malformed_shape() {
        assertTrue(LogIndexWatch.isValidAddress("0x45a1502382541cD610CC9068e88727426b696293"))
        assertFalse("no prefix", LogIndexWatch.isValidAddress("45a1502382541cD610CC9068e88727426b696293"))
        assertFalse("too short", LogIndexWatch.isValidAddress("0x45a1502382541cD610CC9068e88727426b69629"))
        assertFalse("too long", LogIndexWatch.isValidAddress("0x45a1502382541cD610CC9068e88727426b6962931"))
        assertFalse("non-hex", LogIndexWatch.isValidAddress("0x45a1502382541cD610CC9068e88727426b69629g"))
        assertFalse("empty", LogIndexWatch.isValidAddress(""))
        assertFalse("ens name", LogIndexWatch.isValidAddress("vitalik.eth"))
    }

    @Test
    fun parse_dedupes_case_variant_addresses_keeping_the_first() {
        // The engine rejects a config with a duplicate address OUTRIGHT
        // (addresses compare as bytes, so case variants collide) — one
        // hand-edited duplicate must not turn eth_getLogs off for the network.
        val dup = """[{"address":"0x45a1502382541cD610CC9068e88727426b696293","fromBlock":7},""" +
            """{"address":"0x45A1502382541CD610CC9068E88727426B696293","fromBlock":9}]"""
        assertEquals(
            listOf(LogIndexWatch.Entry("0x45a1502382541cD610CC9068e88727426b696293", 7)),
            LogIndexWatch.parse(dup),
        )
    }

    @Test
    fun parse_accepts_fields_in_either_order() {
        // A hand-edited entry must not be silently dropped (and then destroyed
        // by the next save's re-serialization) just for reordering its fields.
        val reordered = """[{"fromBlock":7,"address":"0x45a1502382541cD610CC9068e88727426b696293"}]"""
        assertEquals(
            listOf(LogIndexWatch.Entry("0x45a1502382541cD610CC9068e88727426b696293", 7)),
            LogIndexWatch.parse(reordered),
        )
    }

    @Test
    fun a_configured_network_always_pushes_so_a_disable_can_reach_the_engine() {
        // Import-then-disable: no local entries, enabled false — but the flag
        // IS persisted. Skipping the push would let the engine's boot-time
        // activate-from-disk re-enable the imported index on every restart.
        val disable = LogIndexWatch.configJson("[]", enabled = false, configured = true)!!
        assertTrue(disable.contains("\"enabled\":false"))
        // A virgin network (never configured) still pushes nothing.
        assertNull(LogIndexWatch.configJson("[]", enabled = false, configured = false))
    }

    @Test
    fun the_legacy_kohaku_seed_parses_and_covers_its_networks() {
        // Migration data for pre-generic users: must itself survive the parser
        // (it feeds straight into config pushes) and exist exactly where the
        // preset existed.
        assertEquals(4, LogIndexWatch.parse(LogIndexWatch.legacyKohakuWatchJson("mainnet")!!).size)
        assertEquals(7, LogIndexWatch.parse(LogIndexWatch.legacyKohakuWatchJson("sepolia")!!).size)
        assertNull(LogIndexWatch.legacyKohakuWatchJson("gnosis"))
    }

    @Test
    fun parse_drops_invalid_entries_and_survives_garbage() {
        // A hand-edited settings file must not reach the engine raw: the good
        // entry survives, the bad address is dropped, and non-JSON yields [].
        val mixed = """[{"address":"0xnope","fromBlock":5},""" +
            """{"address":"0x45a1502382541cD610CC9068e88727426b696293","fromBlock":7}]"""
        assertEquals(
            listOf(LogIndexWatch.Entry("0x45a1502382541cD610CC9068e88727426b696293", 7)),
            LogIndexWatch.parse(mixed),
        )
        assertTrue(LogIndexWatch.parse("not json at all").isEmpty())
        assertTrue(LogIndexWatch.parse("[]").isEmpty())
    }

    @Test
    fun config_json_carries_the_entries_and_stays_null_with_nothing_to_say() {
        val watch = LogIndexWatch.serialize(
            listOf(LogIndexWatch.Entry("0x45a1502382541cD610CC9068e88727426b696293", 31_305_656)),
        )
        val json = LogIndexWatch.configJson(watch, enabled = true, maxSpeed = true)!!
        assertTrue(json.contains("\"enabled\":true"))
        assertTrue(json.contains("\"maxSpeed\":true"))
        assertTrue(json.contains("0x45a1502382541cD610CC9068e88727426b696293"))
        assertTrue(json.contains("\"fromBlock\":31305656"))

        // No entries + not enabled = nothing to say: the caller skips the push so
        // the engine keeps eth_getLogs in its honest not-configured state.
        assertNull(LogIndexWatch.configJson("[]", enabled = false))

        // No entries + enabled (an imported snapshot is the subscription): the
        // push still goes out to re-assert enabled/maxSpeed after a restart.
        val importOnly = LogIndexWatch.configJson("[]", enabled = true)!!
        assertTrue(importOnly.contains("\"enabled\":true"))
        assertTrue(importOnly.contains("\"watch\":[]"))

        // Entries + disabled: the push goes out — that is how an active index
        // is turned off.
        val off = LogIndexWatch.configJson(watch, enabled = false)!!
        assertTrue(off.contains("\"enabled\":false"))
    }
}
