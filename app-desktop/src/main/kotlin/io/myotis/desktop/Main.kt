package io.myotis.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import io.myotis.ui.NodeScreen
import java.nio.file.Path

/**
 * Desktop GUI entry: the SAME shared `:ui` NodeScreen Android renders, driven by the
 * in-process Java backend via [DesktopNodeController]. Starts the enabled networks on
 * launch (runtime start — booting must not rewrite the enabled flags) so the Status
 * view fills in as they sync.
 */
fun main() {
    // PACKAGED apps: Compose ships appResources inside the bundle and exposes
    // the dir via this property — point the engine loader at the bundled Rust
    // lib BEFORE anything touches Engines. Dev runs pass an explicit
    // -Dmyotis.engine.lib (absolute path) and win; a missing lib leaves the
    // property unset, and the selector's Java fallback still works.
    if (System.getProperty("myotis.engine.lib") == null) {
        System.getProperty("compose.application.resources.dir")
            ?.takeIf { it.isNotBlank() } // blank would resolve against the CWD
            ?.let { dir ->
            val os = System.getProperty("os.name").lowercase()
            val lib = when {
                os.contains("mac") -> "libmyotis_engine.dylib"
                os.contains("win") -> "myotis_engine.dll"
                else -> "libmyotis_engine.so"
            }
            val f = Path.of(dir, lib).toFile()
            if (f.isFile) System.setProperty("myotis.engine.lib", f.absolutePath)
        }
    }
    val dataDir = Path.of(System.getProperty("user.home"), ".myotis")
    // settings first: the controller reads it at boot (configured RPC port + snap target).
    val settings = DesktopSettings(file = dataDir.resolve("settings.properties"))
    val controller = DesktopNodeController(dataDir, settings)
    // Apply the persisted engine choice BEFORE the first network start, so a saved
    // Rust-engine preference survives a restart (Android parity: NodeService applies
    // it at service start). Networks keep the engine that created them. An explicit
    // -Dmyotis.engine (the `-Pengine=…` dev knob) wins over the persisted toggle —
    // Engines seeded its choice from it, so don't stomp it here.
    if (System.getProperty(io.myotis.engines.Engines.PROP) == null) {
        controller.applyEngineChoice()
    }
    val history = DesktopQueryHistory(dataDir.resolve("query-history.tsv"))
    settings.enabledNetworks().forEach(controller::startNetwork)

    application {
        Window(
            // Tear down the in-process node stack (Netty event loops, libp2p, sync threads)
            // before exiting so closing the window doesn't leak resources or hang shutdown.
            onCloseRequest = { controller.shutdown(); exitApplication() },
            title = "Myotis",
        ) {
            NodeScreen(controller, settings, DesktopLogSource, history = history)
        }
    }
}
