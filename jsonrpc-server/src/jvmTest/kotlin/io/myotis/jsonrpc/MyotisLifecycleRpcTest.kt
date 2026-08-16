package io.myotis.jsonrpc

import io.myotis.api.NodeLifecycle
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The `myotis_pause` / `myotis_wakeup` JSON-RPC methods: the JSON-RPC counterpart
 * of the daemon's `pause` / `resume` IPC commands. Like the status methods they
 * are local control that answers WITHOUT a verified backend, return the
 * `{ok, lifecycle}` shape the IPC command uses, and surface an unwired seam as
 * -32601 (not a crash) and a throwing seam as -32603.
 */
class MyotisLifecycleRpcTest {

    private val json = Json { ignoreUnknownKeys = true }

    /** A stub node whose lifecycle flips on pause()/wakeUp(), like the real stack. */
    private class StubLifecycle(start: String = "RUNNING") : NodeLifecycle {
        private var state = start
        override fun pause(): Boolean { state = "PAUSED"; return true }
        override fun wakeUp(): Boolean { state = "RUNNING"; return true }
        override fun lifecycleName(): String = state
    }

    private fun route(lifecycle: NodeLifecycle?, body: String): String =
        runBlocking {
            RpcRouter(null, MethodLogger(), null, null, lifecycle?.let { NodeLifecycleSource(it) }).handle(body)
        }

    @Test fun myotisPause_returnsPaused_withoutBackend() {
        val resp = route(StubLifecycle(), """{"jsonrpc":"2.0","id":1,"method":"myotis_pause","params":[]}""")
        val obj = json.parseToJsonElement(resp).jsonObject
        assertFalse(obj.containsKey("error"))                                 // local method, no backend needed
        val result = obj["result"]!!.jsonObject
        assertTrue(result["ok"]!!.jsonPrimitive.content.toBoolean())
        assertEquals("PAUSED", result["lifecycle"]!!.jsonPrimitive.content)
    }

    @Test fun myotisWakeup_returnsRunning_withoutBackend() {
        val resp = route(StubLifecycle(start = "PAUSED"),
            """{"jsonrpc":"2.0","id":2,"method":"myotis_wakeup","params":[]}""")
        val result = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertTrue(result["ok"]!!.jsonPrimitive.content.toBoolean())
        assertEquals("RUNNING", result["lifecycle"]!!.jsonPrimitive.content)
    }

    @Test fun lifecycle_ok_isFalse_whenTargetStateNotReached() {
        // A seam that refuses to transition (rebuild failed / STOPPED) must report ok:false
        // with the state it stayed in — never a well-formed lie that the target was reached.
        val stuck = object : NodeLifecycle {
            override fun pause(): Boolean = false
            override fun wakeUp(): Boolean = false
            override fun lifecycleName(): String = "STOPPED"
        }
        val resp = route(stuck, """{"jsonrpc":"2.0","id":1,"method":"myotis_wakeup","params":[]}""")
        val result = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertFalse(result["ok"]!!.jsonPrimitive.content.toBoolean())
        assertEquals("STOPPED", result["lifecycle"]!!.jsonPrimitive.content)
    }

    @Test fun lifecycle_unwired_errorsMethodNotSupported() {
        // No lifecycle seam injected (e.g. a host that didn't wire it) → -32601, not a crash.
        for (m in listOf("myotis_pause", "myotis_wakeup")) {
            val resp = route(null, """{"jsonrpc":"2.0","id":1,"method":"$m","params":[]}""")
            val err = json.parseToJsonElement(resp).jsonObject["error"]!!.jsonObject
            assertEquals(-32601, err["code"]!!.jsonPrimitive.content.toInt())
            assertNull(json.parseToJsonElement(resp).jsonObject["result"])
        }
    }

    @Test fun lifecycle_throws_errorsInternal_notRaw500() {
        // A throwing seam must become a JSON-RPC error envelope (like the status path),
        // not an unhandled exception surfacing as a raw HTTP 500. Throw with a NULL message
        // so the detail must fall back to the exception type, never the literal "null".
        val throwing = object : NodeLifecycle {
            override fun pause(): Boolean = throw IllegalStateException()
            override fun wakeUp(): Boolean = throw IllegalStateException()
            override fun lifecycleName(): String = "RUNNING"
        }
        val resp = route(throwing, """{"jsonrpc":"2.0","id":1,"method":"myotis_pause","params":[]}""")
        val err = json.parseToJsonElement(resp).jsonObject["error"]!!.jsonObject
        assertEquals(-32603, err["code"]!!.jsonPrimitive.content.toInt())
        val msg = err["message"]!!.jsonPrimitive.content
        assertTrue(msg.contains("IllegalStateException"), "expected exception type in: $msg")
        assertFalse(msg.contains("null"), "message must not leak a null: $msg")
    }
}
