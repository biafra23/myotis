package io.myotis.desktop

import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.window.Notification
import androidx.compose.ui.window.Tray
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.isTraySupported
import androidx.compose.ui.window.rememberTrayState
import androidx.compose.ui.window.rememberWindowState
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
    val resourcesDir: Path? = System.getProperty("compose.application.resources.dir")
        ?.takeIf { it.isNotBlank() } // blank would resolve against the CWD
        ?.let(Path::of)
    if (System.getProperty("myotis.engine.lib") == null && resourcesDir != null) {
        val os = System.getProperty("os.name").lowercase()
        val lib = when {
            os.contains("mac") -> "libmyotis_engine.dylib"
            os.contains("win") -> "myotis_engine.dll"
            else -> "libmyotis_engine.so"
        }
        val f = resourcesDir.resolve(lib).toFile()
        if (f.isFile) System.setProperty("myotis.engine.lib", f.absolutePath)
    }
    // A PoC flavour (-PbeePoc / -PrailgunPoc → -Dmyotis.<flavour>=true) lives in its own
    // data dir and seeds its networks' log indexes from the bundle before anything reads
    // that dir. Null for a regular build, which is every build that sets neither property.
    val poc = Poc.active()
    val dataDir = poc?.dataDir() ?: Path.of(System.getProperty("user.home"), ".myotis")
    // Keep the PoC's logs in its own data dir too. logback-desktop.xml reads
    // myotis.logdir when the first logger is created, so this must precede
    // every log call (PocFlavour's logger is lazy for exactly this reason).
    if (poc != null && System.getProperty("myotis.logdir") == null) {
        System.setProperty("myotis.logdir", dataDir.resolve("logs").toString())
    }
    val settingsFile = dataDir.resolve("settings.properties")
    val firstStart = !java.nio.file.Files.exists(settingsFile)
    poc?.installSeedsIfAbsent(resourcesDir, dataDir)
    // settings first: the controller reads it at boot (configured RPC port + snap target).
    val settings = DesktopSettings(file = settingsFile)
    poc?.applyFirstStartSettings(settings, firstStart)
    val controller = DesktopNodeController(dataDir, settings)
    // macOS naps a GUI app whose window is hidden — and this one serves JSON-RPC to other
    // processes, so unless Settings → Power → "Sleep when not in focus" allows it, hold a
    // user-initiated activity for the process lifetime (AppNap.kt). After the logdir
    // property and the settings read, before anything starts: the outcome is one of the
    // first lines of a start's log.
    if (AppNap.isMac) {
        controller.applyAppNap()
        org.slf4j.LoggerFactory.getLogger("io.myotis.desktop.Main").info(
            when {
                AppNap.active -> "App Nap disabled for this process (NSProcessInfo activity held)"
                settings.allowAppNap() -> "App Nap allowed (Settings → Power → Sleep when not in focus)"
                else -> "App Nap NOT disabled — RPC may stall while the window is hidden"
            },
        )
    }
    // Apply the persisted engine choice BEFORE the first network start, so a saved
    // Rust-engine preference survives a restart (Android parity: NodeService applies
    // it at service start). Networks keep the engine that created them. An explicit
    // -Dmyotis.engine (the `-Pengine=…` dev knob) wins over the persisted toggle —
    // Engines seeded its choice from it, so don't stomp it here.
    if (System.getProperty(io.myotis.engines.Engines.PROP) == null) {
        controller.applyEngineChoice()
    }
    // Apply the Tor preference (docs/privacy-and-tor.md) after the engine choice so it lands
    // on the Rust engine it requires. Unlike the engine choice (which SelectorEngine reads
    // directly), the Rust Tor flag must be PUSHED to the native library — so always call it,
    // with an explicit -Dmyotis.tor winning over the persisted toggle.
    System.getProperty(io.myotis.engines.Tor.PROP)?.let {
        io.myotis.engines.Tor.select(it.toBoolean())
    } ?: controller.applyTorMode()
    val history = DesktopQueryHistory(dataDir.resolve("query-history.tsv"))
    settings.enabledNetworks().forEach(controller::startNetwork)

    // The window title names the flavour, so two PoC builds running side by side are
    // distinguishable at a glance (they already own separate data dirs). The tray uses it too.
    val appTitle = poc?.let { "Myotis ${it.label}" } ?: "Myotis"

    application {
        val windowState = rememberWindowState()
        val trayState = rememberTrayState()
        // Bumped by a click on the tray icon or its menu (and, on Windows, its notification):
        // bring the window forward on the Status tab, where a refused page has its Allow.
        var showRequests by remember { mutableStateOf(0) }
        // A click on a notification does not reach onAction everywhere (macOS activates the
        // app instead), so an announcement also arms this: the next time the window gains
        // focus, however the user got there, it opens on the Status tab.
        var statusOnFocus by remember { mutableStateOf(false) }
        var focusReturns by remember { mutableStateOf(0) }
        // The tray icon: a Show / Quit menu, and the notification route wherever macOS's
        // Notification Center is not (below).
        if (isTraySupported) {
            Tray(
                icon = MyotisTrayIcon,
                state = trayState,
                tooltip = appTitle,
                onAction = { showRequests++ },
                menu = {
                    Item("Show $appTitle", onClick = { showRequests++ })
                    Item("Quit $appTitle", onClick = { controller.shutdown(); exitApplication() })
                },
            )
        }
        Window(
            state = windowState,
            // Tear down the in-process node stack (Netty event loops, libp2p, sync threads)
            // before exiting so closing the window doesn't leak resources or hang shutdown.
            onCloseRequest = { controller.shutdown(); exitApplication() },
            title = appTitle,
        ) {
            LaunchedEffect(showRequests) {
                if (showRequests > 0) {
                    windowState.isMinimized = false
                    window.toFront()
                    window.requestFocus()
                }
            }
            DisposableEffect(window) {
                val listener = object : java.awt.event.WindowAdapter() {
                    override fun windowGainedFocus(e: java.awt.event.WindowEvent) {
                        if (statusOnFocus) {
                            statusOnFocus = false
                            focusReturns++
                        }
                    }
                }
                window.addWindowFocusListener(listener)
                onDispose { window.removeWindowFocusListener(listener) }
            }
            LaunchedEffect(Unit) {
                // Where a refused web page is announced (DesktopAlerts.kt): Notification Center
                // in a packaged macOS app, the tray icon's notification on other desktops with a
                // tray; a desktop with neither (GNOME, by default) keeps it in the window. Chosen
                // here, once the window exists: MacNotifications must not be set up before
                // NSApplication has finished launching. Its start() also asks for permission,
                // which is what lists Myotis in System Settings → Notifications.
                val notifier = when {
                    MacNotifications.start() -> DesktopNotifier(MacNotifications::post)
                    isTraySupported -> DesktopNotifier { title, message ->
                        trayState.sendNotification(Notification(title, message, Notification.Type.Info))
                        true
                    }
                    else -> null
                }
                watchWebRefusals(controller, settings, notifier, window) {
                    // Already in front: the user sees the banner if Status is open; arm
                    // only for a window the user has to come back to.
                    if (!window.isFocused) statusOnFocus = true
                }
            }
            NodeScreen(
                controller, settings, DesktopLogSource, history = history,
                statusRequests = showRequests + focusReturns,
            )
        }
    }
}
