package io.myotis.ios

import androidx.compose.ui.window.ComposeUIViewController
import io.myotis.ui.NodeScreen
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSUserDomainMask
import platform.UIKit.UIViewController

/**
 * The iOS composition root — the Xcode app's single entry point (called from
 * MyotisApp.swift). Builds the seam actuals once, auto-starts the enabled
 * networks (desktop Main.kt parity), and hands the shared [NodeScreen] to a
 * ComposeUIViewController.
 */
private object AppRuntime {
    val settings = IosSettings()
    val logs = IosLogSource()
    val controller = IosNodeController(dataDir(), settings, logs)
    val history = IosQueryHistory()

    init {
        settings.enabledNetworks().forEach(controller::startNetwork)
    }

    /** ~/Library/Application Support/myotis — backed up, not user-visible. */
    private fun dataDir(): String {
        val base = NSSearchPathForDirectoriesInDomains(
            NSApplicationSupportDirectory, NSUserDomainMask, true,
        ).firstOrNull() as? String ?: error("no Application Support directory")
        return "$base/myotis"
    }
}

@Suppress("FunctionName", "unused") // called from Swift
fun MainViewController(): UIViewController = ComposeUIViewController {
    NodeScreen(
        controller = AppRuntime.controller,
        settings = AppRuntime.settings,
        logs = AppRuntime.logs,
        history = AppRuntime.history,
    )
}
