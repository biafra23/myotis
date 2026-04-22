package com.jaeckel.ethp2p.android

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

class MainActivity : ComponentActivity() {

    // Exposed to Compose via a state holder so recomposition sees bind/unbind.
    private val boundServiceState = mutableStateOf<NodeService?>(null)

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
            MaterialTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    NodeScreen(
                        serviceProvider = { boundServiceState.value },
                        onToggle = ::toggleService,
                        onOpenNetworkSettings = ::openWifiSettings,
                        onClearCaches = ::clearPeerCaches,
                    )
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        // BIND_AUTO_CREATE creates the service shell for the binding lifetime only.
        // onStartCommand (which actually boots the node) is NOT called by binding
        // alone, so this does not auto-start peer discovery.
        bindService(Intent(this, NodeService::class.java), connection, Context.BIND_AUTO_CREATE)
    }

    override fun onStop() {
        super.onStop()
        try {
            unbindService(connection)
        } catch (_: IllegalArgumentException) {
        }
    }

    private fun toggleService() {
        val svc = Intent(this, NodeService::class.java)
        if (NodeService.isRunning()) {
            // We're bound with BIND_AUTO_CREATE from onStart, which keeps the
            // service alive even after stopService. Ask the service to tear
            // down networking explicitly; it will also call stopSelf so the
            // foreground notification clears immediately.
            boundServiceState.value?.shutdown() ?: stopService(svc)
        } else {
            ensureNotificationPermission()
            startForegroundService(svc)
        }
    }

    private fun openWifiSettings() {
        startActivity(Intent(android.provider.Settings.ACTION_WIFI_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    private fun clearPeerCaches() {
        boundServiceState.value?.clearCaches()
    }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }
}

@Composable
private fun NodeScreen(
    serviceProvider: () -> NodeService?,
    onToggle: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
    onClearCaches: () -> Unit,
) {
    var snapshot by remember { mutableStateOf<NodeService.Snapshot?>(null) }
    var running by remember { mutableStateOf(NodeService.isRunning()) }
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    val online = rememberIsOnline()

    LaunchedEffect(Unit) {
        while (isActive) {
            running = NodeService.isRunning()
            snapshot = serviceProvider()?.snapshot()
            delay(2000)
        }
    }
    // Tick once a second so the uptime readout doesn't jump in 2-second steps.
    LaunchedEffect(Unit) {
        while (isActive) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (!online) {
            OfflineBanner(onOpenNetworkSettings)
        }

        Button(
            onClick = onToggle,
            enabled = running || online,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (running) "Stop node" else "Start node")
        }

        OutlinedButton(
            onClick = onClearCaches,
            enabled = serviceProvider() != null,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Clear peer caches")
        }

        val s = snapshot
        if (s == null || !s.running) {
            Text(
                if (online) "Tap Start to launch the node."
                else "Connect to the internet before starting the node."
            )
        } else {
            StatusRow("uptime", formatUptime(now - s.startTimeMs))
            StatusSummary(s)
            HorizontalDivider()
            Text("READY peers (${s.readyPeerList.size})", style = MaterialTheme.typography.titleSmall)
            PeerList(s.readyPeerList)
        }
    }
}

private fun formatUptime(ms: Long): String {
    val seconds = (ms / 1000).coerceAtLeast(0)
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return when {
        h > 0 -> "%dh %02dm %02ds".format(h, m, s)
        m > 0 -> "%dm %02ds".format(m, s)
        else -> "%ds".format(s)
    }
}

@Composable
private fun OfflineBanner(onOpenNetworkSettings: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        )
    ) {
        Column(
            Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("No internet connection", style = MaterialTheme.typography.titleSmall)
            Text(
                "The node needs internet access to discover and connect to peers. " +
                    "Enable Wi-Fi or mobile data to continue.",
                fontSize = 13.sp
            )
            Button(onClick = onOpenNetworkSettings, modifier = Modifier.fillMaxWidth()) {
                Text("Open network settings")
            }
        }
    }
}

@Composable
private fun rememberIsOnline(): Boolean {
    val context = LocalContext.current
    var online by remember { mutableStateOf(currentlyOnline(context)) }
    DisposableEffect(context) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                online = currentlyOnline(context)
            }

            override fun onLost(network: Network) {
                online = currentlyOnline(context)
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                online = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            }
        }
        cm.registerDefaultNetworkCallback(callback)
        onDispose { cm.unregisterNetworkCallback(callback) }
    }
    return online
}

private fun currentlyOnline(context: Context): Boolean {
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val network = cm.activeNetwork ?: return false
    val caps = cm.getNetworkCapabilities(network) ?: return false
    return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
}

@Composable
private fun StatusSummary(s: NodeService.Snapshot) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        StatusRow("discovered (kademlia)", s.discoveredPeers.toString())
        StatusRow("connected (RLPx)", s.connectedPeers.toString())
        StatusRow("ready (eth handshake)", s.readyPeers.toString())
        StatusRow("snap supported", s.snapPeers.toString())
        StatusRow("cached at boot", s.cachedPeers.toString())
        StatusRow("dialing", s.attemptedPeers.toString())
        StatusRow("in backoff", s.backedOffPeers.toString())
        StatusRow("blacklisted", s.blacklistedPeers.toString())
    }
}

@Composable
private fun StatusRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
        Text(value, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
    }
}

@Composable
private fun PeerList(peers: List<com.jaeckel.ethp2p.networking.rlpx.RLPxConnector.PeerInfo>) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        items(peers) { p ->
            Column {
                Text(
                    "${p.remoteAddress()}  snap=${p.snapSupported()}",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp
                )
                Text(
                    p.clientId() ?: "(no clientId)",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
