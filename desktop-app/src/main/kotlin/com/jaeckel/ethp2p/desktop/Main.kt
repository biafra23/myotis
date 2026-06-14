package com.jaeckel.ethp2p.desktop

import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlin.system.exitProcess

/**
 * Desktop entry point. Owns an application-scoped coroutine scope and the embedded-node
 * controller, renders the single main window, and guarantees a clean process exit: the
 * window close fires {@code exitApplication()}, after which we synchronously tear down the
 * node (Netty/Ktor non-daemon threads) and {@code exitProcess(0)} so the JVM always
 * terminates. A JVM shutdown hook covers SIGINT/SIGTERM as well.
 */
fun main() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val controller = DesktopNodeController(scope)
    Runtime.getRuntime().addShutdownHook(Thread({ controller.shutdownBlocking() }, "myotis-shutdown"))

    application {
        val windowState = rememberWindowState(size = DpSize(560.dp, 760.dp))
        Window(
            onCloseRequest = ::exitApplication,
            title = "Myotis",
            state = windowState,
        ) {
            App(controller)
        }
    }

    controller.shutdownBlocking()
    exitProcess(0)
}
