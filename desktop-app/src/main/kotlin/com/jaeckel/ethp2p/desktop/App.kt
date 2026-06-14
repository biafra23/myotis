package com.jaeckel.ethp2p.desktop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

private val NETWORKS = listOf("mainnet", "sepolia", "holesky")

@Composable
fun App(controller: DesktopNodeController) {
    val state by controller.state.collectAsState()
    val scope = rememberCoroutineScope()

    var selectedNetwork by remember { mutableStateOf(state.network) }
    var addressInput by remember { mutableStateOf("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045") }
    var output by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }

    val running = state.status == NodeStatus.RUNNING
    val starting = state.status == NodeStatus.STARTING
    val stopping = state.status == NodeStatus.STOPPING

    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Myotis", style = MaterialTheme.typography.headlineMedium)
                Text(
                    "Trustless Ethereum light-client wallet",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                // ── Network + run controls ──────────────────────────────────
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Network", style = MaterialTheme.typography.titleMedium)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            NETWORKS.forEach { net ->
                                FilterChip(
                                    selected = selectedNetwork == net,
                                    onClick = { if (!running && !starting) selectedNetwork = net },
                                    enabled = !running && !starting && !stopping,
                                    label = { Text(net) },
                                )
                            }
                        }
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            if (running) {
                                Button(onClick = { controller.stop() }, enabled = !stopping) { Text("Stop node") }
                            } else {
                                Button(
                                    onClick = { controller.start(selectedNetwork) },
                                    enabled = !starting && !stopping,
                                ) { Text("Start node") }
                            }
                            if (starting || stopping) {
                                CircularProgressIndicator(modifier = Modifier.width(20.dp))
                            }
                            Text(statusLabel(state.status), style = MaterialTheme.typography.bodyMedium)
                        }
                        state.error?.let { err ->
                            Text("Error: $err", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }

                // ── Live status ─────────────────────────────────────────────
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Status", style = MaterialTheme.typography.titleMedium)
                        StatRow("Network", state.network)
                        StatRow("Beacon sync", state.beaconState)
                        StatRow("Peers", state.peerCount.toString())
                        StatRow("Snap peers", state.snapPeerCount.toString())
                        StatRow("Finalized slot", if (state.finalizedSlot > 0) state.finalizedSlot.toString() else "—")
                        StatRow("Execution block", if (state.executionBlock > 0) state.executionBlock.toString() else "—")
                    }
                }

                // ── Account lookup ──────────────────────────────────────────
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Verified account lookup", style = MaterialTheme.typography.titleMedium)
                        OutlinedTextField(
                            value = addressInput,
                            onValueChange = { addressInput = it },
                            label = { Text("Address (0x…)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Button(
                                enabled = running && !busy,
                                onClick = {
                                    busy = true
                                    output = ""
                                    scope.launch {
                                        val addr = DesktopNodeController.jsonEscape(addressInput.trim())
                                        output = controller.command("""{"cmd":"get-account","address":"$addr"}""")
                                        busy = false
                                    }
                                },
                            ) { Text("Get account") }
                            OutlinedButton(
                                enabled = running && !busy,
                                onClick = {
                                    busy = true
                                    output = ""
                                    scope.launch {
                                        output = controller.command("""{"cmd":"status"}""")
                                        busy = false
                                    }
                                },
                            ) { Text("Status JSON") }
                            if (busy) CircularProgressIndicator(modifier = Modifier.width(20.dp))
                        }
                        if (!running) {
                            Text(
                                "Start the node to run verified lookups.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        if (output.isNotBlank()) {
                            Text(
                                output,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontFamily = FontFamily.Monospace)
    }
}

private fun statusLabel(status: NodeStatus): String = when (status) {
    NodeStatus.STOPPED -> "Stopped"
    NodeStatus.STARTING -> "Starting…"
    NodeStatus.RUNNING -> "Running"
    NodeStatus.STOPPING -> "Stopping…"
    NodeStatus.ERROR -> "Error"
}
