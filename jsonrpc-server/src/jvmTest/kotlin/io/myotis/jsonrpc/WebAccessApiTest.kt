package io.myotis.jsonrpc

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The api ↔ gate mapping (#502): what `setWebAccessPolicy` hands back is a per-entry
 * list, so a caller's "did an entry get dropped?" is a plain size compare — two
 * spellings of one origin are two entries (not a drop), a path or a wildcard is.
 */
class WebAccessApiTest {

    @Test fun appliedListIsPerEntryAndKeepsDuplicateSpellings() {
        val gate = WebAccess()
        val asked = io.myotis.api.WebAccessPolicy(
            io.myotis.api.WebAccessMode.ALLOWLIST,
            listOf("app.example", "https://app.example", "App.Example:443/"),
        )
        val applied = WebAccessApi.apply(gate, asked)
        assertEquals(io.myotis.api.WebAccessMode.ALLOWLIST, applied.mode())
        assertEquals(listOf("https://app.example", "https://app.example", "https://app.example"), applied.origins())
        assertEquals(asked.origins().size, applied.origins().size, "nothing was dropped")
        assertEquals(setOf("https://app.example"), gate.policy.origins, "the gate itself holds the set")
        assertTrue(gate.policy.allows("https://app.example"))
    }

    @Test fun aDroppedEntryShrinksTheAppliedList() {
        val gate = WebAccess()
        val asked = io.myotis.api.WebAccessPolicy(
            io.myotis.api.WebAccessMode.ALLOWLIST,
            listOf("https://app.example", "https://app.example/rpc", "*.example.org"),
        )
        val applied = WebAccessApi.apply(gate, asked)
        assertEquals(listOf("https://app.example"), applied.origins())
        assertTrue(applied.origins().size < asked.origins().size, "two entries were not origins")
        assertFalse(gate.policy.allows("https://app.example/rpc".lowercase()))
    }

    @Test fun offAndAllCarryTheirListsThroughUntouchedInMeaning() {
        val gate = WebAccess()
        val off = WebAccessApi.apply(gate, io.myotis.api.WebAccessPolicy(io.myotis.api.WebAccessMode.OFF, listOf("app.example")))
        assertEquals(io.myotis.api.WebAccessMode.OFF, off.mode())
        assertFalse(gate.policy.allows("https://app.example"))
        val all = WebAccessApi.apply(gate, io.myotis.api.WebAccessPolicy(io.myotis.api.WebAccessMode.ALL, listOf()))
        assertEquals(io.myotis.api.WebAccessMode.ALL, all.mode())
        assertTrue(gate.policy.allows("https://anything.example"))
    }
}
