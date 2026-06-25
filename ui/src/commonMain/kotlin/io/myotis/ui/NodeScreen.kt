package io.myotis.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * The shared Myotis screen — identical on Android and Desktop. This Step-1 slice renders the
 * Status view for the primary network from [NodeController]'s snapshot flow; the Query
 * / Logs / Settings tabs are ported next (this composable becomes the tab host).
 */
@Composable
fun NodeScreen(controller: NodeController, settings: Settings) {
    // remember(controller): snapshots() returns a fresh Flow each call, so collecting it
    // directly would re-subscribe on every recomposition. Retain it across recompositions.
    val snapshotsFlow = remember(controller) { controller.snapshots() }
    val snapshots by snapshotsFlow.collectAsState(initial = emptyMap())
    MaterialTheme {
        Column(Modifier.fillMaxSize().padding(16.dp)) {
            Text("Myotis", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(12.dp))

            val primary = settings.primaryNetwork()
            val snap = snapshots[primary]
            if (snap == null) {
                Text("Node stopped — no data for $primary")
            } else {
                StatusView(snap)
            }

            Spacer(Modifier.height(16.dp))
            // A snapshot for `primary` exists only while its stack is registered (running or
            // mid-boot), so drive button state off it: Start is disabled once the network is
            // up, Stop only while it is. Stop the primary network specifically (not a global
            // shutdown) so the pairing reads correctly once more networks are added.
            val primaryActive = snap != null
            Row {
                Button(
                    onClick = { controller.enableNetwork(primary) },
                    enabled = !primaryActive,
                ) { Text("Start $primary") }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = { controller.disableNetwork(primary) },
                    enabled = primaryActive,
                ) { Text("Stop") }
            }
        }
    }
}

@Composable
private fun StatusView(s: NodeSnapshot) {
    Column {
        StatusRow("Network", s.network)
        StatusRow("Beacon", s.beaconState)
        StatusRow("EL block", s.executionBlockNumber.toString())
        StatusRow("Peers", "${s.connectedPeers} (ready ${s.readyPeers}, snap ${s.snapPeers})")
        StatusRow("Discovered", s.discoveredPeers.toString())
        StatusRow("Sync period", "${s.syncCurrentPeriod} / ${s.syncTargetPeriod}")
        // verifiedHeadAgeMs == Long.MAX_VALUE is the "no verified head yet" sentinel — show a
        // dash instead of the raw ~9.2e18 ms, which would read as a nonsensical age.
        StatusRow("Verified head age", if (s.verifiedHeadAgeMs == Long.MAX_VALUE) "—" else "${s.verifiedHeadAgeMs} ms")
        StatusRow("Uptime", "${s.uptimeSeconds}s")
    }
}

@Composable
private fun StatusRow(key: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(key, Modifier.width(160.dp))
        Text(value)
    }
}
