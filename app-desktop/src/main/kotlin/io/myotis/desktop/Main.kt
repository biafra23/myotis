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
import kotlinx.coroutines.launch
import java.nio.file.Path

/**
 * Desktop GUI entry: the SAME shared `:ui` NodeScreen Android renders, driven by the
 * in-process Java backend via [DesktopNodeController]. Starts the enabled networks on
 * launch (runtime start — booting must not rewrite the enabled flags) so the Status
 * view fills in as they sync.
 */
/**
 * Which profile directory this desktop process runs in (PR #832 review).
 * PoC flavours already live apart; a `-Pengine=go` launch (the desktop-only
 * Go engine) gets the same isolation — `~/.myotis-go` — because the Go
 * engine's catalog lists only what it can RUN, while DesktopSettings treats
 * the running engine's catalog as the list of every network there is: its
 * load prunes saved enabled-networks the catalog lacks, and every settings
 * write rewrites the whole file from the pruned state. Without this, one
 * `-Pengine=go` launch plus any setting change would silently drop
 * `gnosis`/`sepolia` and their `rpcPort.<net>` overrides from the shared
 * `~/.myotis` profile, with nothing logged. The Go engine's `nodekey` and
 * `nodedb/` stay off the regular profile the same way. A PoC flavour wins
 * over the engine flag (its directory also carries its seeds) — though main()
 * REFUSES that combination outright (see [flavourOnGoRefusal]), so the
 * precedence is only the function's total-function fallback.
 */
internal fun desktopDataDir(pocDir: Path?, engineProp: String?, home: String): Path =
    pocDir ?: Path.of(home, if (engineChoiceIsGo(engineProp)) ".myotis-go" else ".myotis")

/**
 * Whether the `-Dmyotis.engine` launch flag (the `-Pengine=…` dev knob) selects
 * the Go engine. Trimmed + lowercased like the selector's own parsing. The
 * persisted Settings toggle cannot select `go` — it is a java/rust switch —
 * so this property is the ONLY way a desktop process ends up on the Go engine.
 */
internal fun engineChoiceIsGo(engineProp: String?): Boolean =
    engineProp?.trim()?.lowercase() == "go"

/**
 * Why a PoC flavour and `-Pengine=go` cannot run together (PR #832 round-3
 * review): each PoC's sole network is the one the Go engine's shrunken
 * catalog prunes — Bee runs gnosis only, the RAILGUN PoC sepolia only — and
 * [DesktopSettings] load prunes saved enabled-networks the running engine's
 * catalog lacks, rewriting the whole settings file from the pruned state. The
 * combo would boot a PoC profile with its network silently gone: an empty
 * app, not an error. Non-null return is the refusal message; null = the pair
 * is fine.
 */
internal fun flavourOnGoRefusal(pocFlavour: String?, engineProp: String?): String? =
    if (pocFlavour != null && engineChoiceIsGo(engineProp)) {
        "myotis: the $pocFlavour flavour cannot run on the Go engine (-Dmyotis.engine=go):" +
            " the Go engine's catalog is mainnet-only, so this flavour's network would be" +
            " pruned from its own settings on first start. Launch the flavour without" +
            " -Pengine=go (or run the Go engine on a regular build)."
    } else {
        null
    }

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
    // NOTE (PR #832 round-3 review): Engines.PROP is a `static final String`
    // compile-time constant, and Kotlin INLINES such constants at the use site —
    // this expression does NOT class-load Engines. That is deliberate (this file
    // must not initialize the selector before the engine-library probe above
    // has settled `myotis.engine.lib`); if the constant ever stops being
    // compile-time, this line silently gains an early class-load.
    val engineProp = System.getProperty(io.myotis.engines.Engines.PROP)
    flavourOnGoRefusal(poc?.label, engineProp)?.let {
        System.err.println(it)
        kotlin.system.exitProcess(2)
    }
    val dataDir = desktopDataDir(
        pocDir = poc?.dataDir(),
        engineProp = engineProp,
        home = System.getProperty("user.home"),
    )
    // Keep ISOLATED profiles' logs with their profile: PoC flavours and the
    // `-Pengine=go` profile alike (PR #832 round-3 review — the first version
    // redirected PoC launches only, so a Go run drained its engine logs into
    // the shared profile's logs next to regular runs). logback-desktop.xml
    // reads myotis.logdir when the first logger is created, so this must
    // precede every log call (PocFlavour's logger is lazy for exactly this
    // reason). An explicit -Dmyotis.logdir still wins.
    if (dataDir != Path.of(System.getProperty("user.home"), ".myotis") &&
        System.getProperty("myotis.logdir") == null
    ) {
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
    // Apply the Tor preference (docs/how-it-works/privacy-and-tor.md) after the engine choice so it lands
    // on the Rust engine it requires. Unlike the engine choice (which SelectorEngine reads
    // directly), the Rust Tor flag must be PUSHED to the native library — so always call it,
    // with an explicit -Dmyotis.tor winning over the persisted toggle.
    // An explicit -Dmyotis.tor must pass the SAME Go gate DesktopNode.applyTorMode
    // applies to the persisted toggle (PR #832 round-3 review): Tor is
    // Rust-engine-only, and Tor.select under a Go-engine run would report
    // success while the Go engine's account reads leave from the real IP —
    // the accepted-and-ignored privacy switch.
    val torProp = System.getProperty(io.myotis.engines.rust.Tor.PROP)
    when {
        io.myotis.engines.Engines.choice() == "go" ->
            if (torProp?.toBoolean() == true) {
                org.slf4j.LoggerFactory.getLogger("io.myotis.desktop.Main").warn(
                    "[desktop] -Dmyotis.tor requested but this run is the Go engine,"
                            + " which has no Tor: account reads leave from this host's real IP."
                            + " The switch applies again on a launch without -Dmyotis.engine=go",
                )
            }
        torProp != null -> io.myotis.engines.rust.Tor.select(torProp.toBoolean())
        else -> controller.applyTorMode()
    }
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
                // Watched balances (the Watch tab) announce through the same route, and are
                // checked on their schedule for as long as the window lives.
                controller.setWatchNotifier(notifier?.let { n -> { title, message -> n.post(title, message) } })
                launch { watchBalances(controller) }
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
