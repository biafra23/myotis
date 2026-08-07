package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The watch-list is a contract with the wallet: an address the wallet scans but
 * this node does not index is refused outright, which leaves Privacy Pools and
 * Railgun unable to rebuild their state. These pin the addresses a live Kohaku
 * session was observed querying (2026-08-07 capture), lower-cased for
 * comparison since the engine matches on bytes, not on checksum casing.
 */
class KohakuPresetTest {

    private fun sepoliaAddresses() =
        KohakuPreset.byNetwork.getValue("sepolia").map { it.address.lowercase() }

    @Test
    fun sepolia_indexes_every_contract_kohaku_queries() {
        val observed = listOf(
            "0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea", // railgun proxy
            "0x34a2068192b1297f2a7f85d7d8cde66f8f0921cb", // privacy pools entrypoint
            "0x644d5a2554d36e27509254f32ccfebe8cd58861f", // privacy pools ETH pool
            "0x6709277e170dee3e54101cdb73a450e392adff54", // privacy pools USDT pool
            "0x0b062fe33c4f1592d8ea63f9a0177fca44374c0f", // privacy pools USDC pool
        )
        val indexed = sepoliaAddresses()
        observed.forEach { assertTrue("not on the watch list: $it", it in indexed) }
    }

    @Test
    fun the_pools_start_at_or_below_their_deployment_block() {
        // NOTE what this can and cannot prove. It pins the constant against
        // itself, so it catches an accidental edit — it CANNOT tell you the
        // block is right, and a green run is not evidence of that. What it
        // does check is the direction that matters: a from_block LATER than
        // the real deployment silently drops history (query clamps its
        // coverage requirement to it), while earlier is harmless. So assert
        // the pools never start above Kohaku's documented deployment block.
        val documentedDeployment = 8_587_019L
        val pools = KohakuPreset.byNetwork.getValue("sepolia")
            .filter { it.label.startsWith("Privacy Pools") && it.label.endsWith("pool") }
        assertEquals(3, pools.size)
        pools.forEach {
            assertTrue(
                "${it.label} starts at ${it.fromBlock}, above the documented deployment",
                it.fromBlock <= documentedDeployment,
            )
        }
    }

    @Test
    fun every_preset_entry_is_a_well_formed_unique_address() {
        // One malformed entry is not a local failure: parse_log_index_config
        // bails with `?` on the first field it cannot parse and returns None
        // for the WHOLE config, and LogIndex::new rejects a duplicate address
        // outright. Either way setLogIndexConfig returns false and every host
        // merely logs a warning — so a single mistyped character turns
        // eth_getLogs off for the entire network, with the Index tab showing
        // only "waiting for engine".
        val hex = Regex("^0x[0-9a-fA-F]{40}$")
        KohakuPreset.byNetwork.forEach { (network, watches) ->
            watches.forEach {
                assertTrue("$network ${it.label}: ${it.address}", hex.matches(it.address))
                assertTrue("$network ${it.label}: fromBlock must be positive", it.fromBlock > 0)
            }
            val lower = watches.map { w -> w.address.lowercase() }
            assertEquals("$network has a duplicate address", lower.size, lower.toSet().size)
        }
    }

    @Test
    fun config_json_carries_the_new_entries_and_stays_null_off_preset() {
        val json = KohakuPreset.configJson("sepolia", enabled = true)!!
        assertTrue(json.contains("0x644d5A2554d36e27509254F32ccfeBe8cd58861f"))
        assertTrue(json.contains("\"fromBlock\":8461453"))
        assertNull(KohakuPreset.configJson("gnosis", enabled = true))
    }
}
