package io.myotis.desktop

import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.window.Notification
import androidx.compose.ui.window.TrayState
import io.myotis.ui.Settings
import io.myotis.ui.WebAccessMode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private val log = org.slf4j.LoggerFactory.getLogger("io.myotis.desktop.DesktopAlerts")

/** How often the listeners' recent lists are checked for a new refusal: in-memory reads. */
private const val REFUSAL_POLL_MS = 5_000L

/**
 * Tell the user, outside the window, that a web page was refused (#502). Inside the
 * window the Status banner already does; but the refused page is in the browser, in
 * front, and the Myotis window is behind it. Two signals, each where the platform has it:
 *
 * - a native notification through the tray icon ([tray]; Notification Center on macOS,
 *   a toast on Windows, the tray's own balloon elsewhere) — null where the desktop has
 *   no system tray (GNOME without an extension), and then logged once;
 * - an attention request when the window is not focused ([requestUserAttention]: the
 *   dock icon bounces on macOS, the taskbar entry flashes on Windows).
 *
 * Neither carries an Allow button — desktop notifications have none — so both point at
 * the app, and [onAnnounced] tells the window, which opens on the Status tab the next
 * time it comes forward (Main.kt). Runs for the window's lifetime; one failed pass is
 * logged and the next one tries again.
 */
internal suspend fun watchWebRefusals(
    controller: DesktopNodeController,
    settings: Settings,
    tray: TrayState?,
    window: java.awt.Window,
    onAnnounced: () -> Unit,
) {
    if (tray == null) {
        log.info("no system tray on this desktop: refused web pages show in the Myotis window only")
    }
    val alerts = WebRefusalAlerts()
    var capLogged = false
    while (true) {
        delay(REFUSAL_POLL_MS)
        try {
            val fresh = withContext(Dispatchers.IO) {
                // Only Specific sites has refusals to announce: Off refuses by the user's
                // own choice, All sites refuses nothing. Skip the engine walk there.
                val mode = settings.webAccessMode()
                if (mode != WebAccessMode.ALLOWLIST) emptyList()
                else alerts.next(controller.recentWebOrigins(), mode, settings.webAccessOrigins())
            }
            if (alerts.capped && !capLogged) {
                capLogged = true
                log.warn("web page refusals: {} announced this run, no more notifications until restart " +
                    "(the Status screen still lists them)", WebRefusalAlerts.MAX_PER_RUN)
            }
            if (fresh.isEmpty()) continue
            val (title, message) = refusalNotificationText(fresh)
            tray?.sendNotification(Notification(title, message, Notification.Type.Info))
            val attention = !window.isFocused && requestUserAttention(window)
            onAnnounced()
            log.info("web page refused, announced: {} (notification: {}, attention: {})",
                fresh.joinToString { it.origin }, tray != null, attention)
        } catch (e: CancellationException) {
            throw e
        } catch (t: Throwable) {
            // A pass racing a network stop or an engine switch must not end the watcher
            // for the rest of the run, nor escape into the window's composition.
            log.warn("web page refusal check failed: {}", t.toString())
        }
    }
}

/**
 * Ask the desktop to draw the user's eye to [window]: flash its taskbar entry where the
 * platform does that per window (Windows), else bounce the dock icon once (macOS; not
 * the critical, keep-bouncing kind). False where neither exists (most Linux desktops).
 * Call on the AWT event thread.
 */
internal fun requestUserAttention(window: java.awt.Window): Boolean = runCatching {
    if (!java.awt.Taskbar.isTaskbarSupported()) return@runCatching false
    val taskbar = java.awt.Taskbar.getTaskbar()
    when {
        taskbar.isSupported(java.awt.Taskbar.Feature.USER_ATTENTION_WINDOW) -> {
            taskbar.requestWindowUserAttention(window)
            true
        }
        taskbar.isSupported(java.awt.Taskbar.Feature.USER_ATTENTION) -> {
            taskbar.requestUserAttention(true, false)
            true
        }
        else -> false
    }
}.getOrElse {
    log.debug("attention request failed: {}", it.toString())
    false
}

/**
 * The tray icon: a filled disc with a light centre. Drawn rather than loaded — the repo's
 * logo is a wide, black-on-transparent mark that would vanish on a dark menu bar and
 * letterbox in a square slot; a mid-tone disc reads on light and dark bars alike.
 */
internal object MyotisTrayIcon : Painter() {
    override val intrinsicSize: Size = Size(64f, 64f)

    override fun DrawScope.onDraw() {
        drawCircle(color = Color(0xFF6750A4))
        drawCircle(color = Color.White, radius = size.minDimension * 0.2f)
    }
}
