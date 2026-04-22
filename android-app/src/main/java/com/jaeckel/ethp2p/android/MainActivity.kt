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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
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
            stopService(svc)
        } else {
            ensureNotificationPermission()
            startForegroundService(svc)
        }
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
) {
    var snapshot by remember { mutableStateOf<NodeService.Snapshot?>(null) }
    var running by remember { mutableStateOf(NodeService.isRunning()) }

    LaunchedEffect(Unit) {
        while (isActive) {
            running = NodeService.isRunning()
            snapshot = serviceProvider()?.snapshot()
            delay(2000)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Button(onClick = onToggle, modifier = Modifier.fillMaxWidth()) {
            Text(if (running) "Stop node" else "Start node")
        }

        val s = snapshot
        if (s == null || !s.running) {
            Text("Tap Start to launch the node.")
        } else {
            StatusSummary(s)
            HorizontalDivider()
            Text("READY peers (${s.readyPeerList.size})", style = MaterialTheme.typography.titleSmall)
            PeerList(s.readyPeerList)
        }
    }
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
