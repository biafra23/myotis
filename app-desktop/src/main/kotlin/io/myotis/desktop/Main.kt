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
    val dataDir = Path.of(System.getProperty("user.home"), ".myotis")
    // settings first: the controller reads it at boot (configured RPC port + snap target).
    val settings = DesktopSettings()
    val controller = DesktopNodeController(dataDir, settings)
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
