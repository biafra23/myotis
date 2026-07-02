package com.jaeckel.ethp2p.android

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import com.jaeckel.ethp2p.android.cmp.AndroidLogSource
import com.jaeckel.ethp2p.android.cmp.AndroidNetworkStatus
import com.jaeckel.ethp2p.android.cmp.AndroidNodeController
import com.jaeckel.ethp2p.android.cmp.AndroidSettings
import io.myotis.ui.NodeScreen

/**
 * Thin Android host for the shared Compose UI. Binds [NodeService], adapts it to the `:ui` seam
 * ([AndroidNodeController]/[AndroidSettings]/[AndroidLogSource]/[AndroidNetworkStatus]), and
 * renders the SAME `io.myotis.ui.NodeScreen` the desktop app uses. Every screen composable lives
 * in `:ui` — none here — so there is zero UI duplication between Android and Desktop.
 */
class MainActivity : ComponentActivity() {

    // Exposed to Compose via a state holder so recomposition sees bind/unbind.
    private val boundServiceState = mutableStateOf<NodeService?>(null)

    // Registered eagerly so the permission dialog can fire once we hit the Start button. The
    // result fires whether the user grants or denies; either way we start the service — denial
    // just means the foreground notification is invisible on Android 13+, not that it fails.
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> startNodeService() }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            boundServiceState.value = (service as NodeService.LocalBinder).service()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            boundServiceState.value = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            // Seam adapters built once and remembered so a SINGLE controller survives the
            // bind/unbind cycle (onStart binds, onStop unbinds): the shared NodeScreen's state
            // (selected tab, in-flight query) isn't reset on foreground/background. The controller
            // reads the CURRENT service through the { boundServiceState.value } provider, so it
            // still tracks rebinds.
            val controller = remember {
                AndroidNodeController(
                    serviceProvider = { boundServiceState.value },
                    appContext = applicationContext,
                    onStartService = ::ensureNodeStarted,
                )
            }
            val settings = remember { AndroidSettings(applicationContext) }
            val logs = remember { AndroidLogSource() }
            val netStatus = remember { AndroidNetworkStatus(applicationContext) }
            MaterialTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    NodeScreen(controller, settings, logs, netStatus, ::openWifiSettings)
                }
            }
        }
        // Auto-start the node when the app launches so the user doesn't have to tap "Start node".
        // Start *silently* via startForegroundService — a foreground service runs fine on Android
        // 13+ even without POST_NOTIFICATIONS (the notification is just hidden), so we do NOT
        // prompt for it here: requesting on a cold launch has no user context, drives high denial
        // rates, and would re-prompt on every fresh launch once denied. The permission is
        // requested only from the explicit Start-node button (ensureNodeStarted), where the user
        // has context.
        //
        // Gated on savedInstanceState == null so it fires only on a genuinely fresh launch — NOT a
        // config-change recreation (rotation) or process-death restore, which would override an
        // explicit Stop — and on !isRunning so relaunching while the service is already up is a
        // no-op.
        if (savedInstanceState == null && !NodeService.isRunning()) {
            startNodeService()
        }
    }

    override fun onStart() {
        super.onStart()
        // BIND_AUTO_CREATE creates the service shell for the binding lifetime only. onStartCommand
        // (which actually boots the node) is NOT called by binding alone, so this does not
        // auto-start peer discovery.
        bindService(Intent(this, NodeService::class.java), connection, Context.BIND_AUTO_CREATE)
    }

    override fun onStop() {
        super.onStop()
        try {
            unbindService(connection)
        } catch (_: IllegalArgumentException) {
        }
    }

    /**
     * Start the node if it isn't already running, first requesting the POST_NOTIFICATIONS
     * permission on Android 13+ so the foreground-service notification is visible. Used by the
     * shared UI's Start action (via the controller's onStartService), where prompting has clear
     * user context. (Auto-start on launch deliberately skips this and starts silently — see
     * onCreate.) A no-op when the service is already running.
     */
    private fun ensureNodeStarted() {
        if (NodeService.isRunning()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            // Defer startForegroundService until the permission dialog resolves — otherwise we'd
            // post the notification before the user has decided and the callback would have to
            // start the service a second time.
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startNodeService()
        }
    }

    private fun startNodeService() {
        startForegroundService(Intent(this, NodeService::class.java))
    }

    private fun openWifiSettings() {
        startActivity(Intent(android.provider.Settings.ACTION_WIFI_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
