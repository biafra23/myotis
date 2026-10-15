package io.myotis.engine

import io.myotis.api.EngineException
import io.myotis.engines.rust.RustMyotisEngine
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The library's entry point over the Rust engine: with the native library on
 * java.library.path (the build puts rust/target/release there) a consumer gets an
 * engine that knows the network catalog; without it, the documented
 * [EngineException] — never a half-built engine.
 */
class MyotisTest {

    @Test
    fun availabilityMirrorsTheRustEngine() {
        assertEquals(RustMyotisEngine.isAvailable(), Myotis.isAvailable())
    }

    @Test
    fun newEngineIsTheRustEngineOrARefusal() {
        if (Myotis.isAvailable()) {
            val engine = Myotis.newEngine()
            val networks = engine.availableNetworks().map { it.name() }
            assertTrue("mainnet" in networks, "the Rust catalog hosts mainnet, got $networks")
            assertTrue(engine.hostedNetworks().isEmpty(), "a fresh engine hosts nothing")
        } else {
            assertThrows(EngineException::class.java) { Myotis.newEngine() }
        }
    }

    @Test
    fun drainLogsNeverThrows() {
        // Empty or a batch — either way a string, with or without the library.
        Myotis.drainLogs(16)
    }
}
