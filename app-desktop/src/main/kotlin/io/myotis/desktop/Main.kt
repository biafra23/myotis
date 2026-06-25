package io.myotis.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import io.myotis.ui.NodeScreen
import java.nio.file.Path

/**
 * Desktop GUI entry: the SAME shared `:ui` NodeScreen Android renders, driven by the
 * in-process Java backend via [DesktopNodeController]. Starts the primary network on
 * launch so the Status view fills in as it syncs.
 */
fun main() {
    val dataDir = Path.of(System.getProperty("user.home"), ".myotis")
    val controller = DesktopNodeController(dataDir)
    val settings = DesktopSettings()
    controller.enableNetwork(settings.primaryNetwork())

    application {
        Window(
            // Tear down the in-process node stack (Netty event loops, libp2p, sync threads)
            // before exiting so closing the window doesn't leak resources or hang shutdown.
            onCloseRequest = { controller.shutdown(); exitApplication() },
            title = "Myotis",
        ) {
            NodeScreen(controller, settings, DesktopLogSource)
        }
    }
}
