package io.myotis.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/**
 * The shared Myotis screen — identical on Android and Desktop. A tab host over the per-network
 * [NodeController]/[Settings]/[LogSource] seam. Status + Query + Logs are ported; Settings follows.
 */
@Composable
fun NodeScreen(controller: NodeController, settings: Settings, logs: LogSource) {
    // remember(controller): snapshots() returns a fresh Flow each call, so collecting it
    // directly would re-subscribe on every recomposition. Retain it across recompositions.
    val snapshotsFlow = remember(controller) { controller.snapshots() }
    val snapshots by snapshotsFlow.collectAsState(initial = emptyMap())
    val primary = settings.primaryNetwork()
    var tab by remember { mutableStateOf(0) }

    MaterialTheme {
        Column(Modifier.fillMaxSize().padding(16.dp)) {
            Text("Myotis", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(12.dp))

            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Status") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Query") })
                Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("Logs") })
            }
            Spacer(Modifier.height(16.dp))

            when (tab) {
                0 -> StatusTab(controller, snapshots[primary], primary)
                1 -> QueryTab(controller, primary)
                2 -> LogsTab(logs)
            }
        }
    }
}

@Composable
private fun StatusTab(controller: NodeController, snap: NodeSnapshot?, primary: String) {
    Column {
        if (snap == null) {
            Text("Node stopped — no data for $primary")
        } else {
            StatusView(snap)
        }

        Spacer(Modifier.height(16.dp))
        // A snapshot for `primary` exists only while its stack is registered (running or
        // mid-boot): Start disabled once up, Stop only while it is. Stop the primary network
        // specifically so the pairing reads correctly once more networks are added.
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

/**
 * Verified account / ENS query over the shared seam. An input that contains a dot is treated
 * as an ENS name (→ [NodeController.resolveEns]); otherwise a hex address (→
 * [NodeController.requestAccount]). Verification status is surfaced prominently — the whole
 * point is that the result is cryptographically anchored, not peer-claimed.
 */
@Composable
private fun QueryTab(controller: NodeController, network: String) {
    val scope = rememberCoroutineScope()
    // Key on `network`: when the active network changes, reset the query input + results so we
    // never show one network's account/ENS result under another.
    var input by remember(network) { mutableStateOf("") }
    var loading by remember(network) { mutableStateOf(false) }
    var account by remember(network) { mutableStateOf<AccountResult?>(null) }
    var ens by remember(network) { mutableStateOf<EnsResult?>(null) }
    var error by remember(network) { mutableStateOf<String?>(null) }

    fun submit() {
        val q = input.trim()
        if (q.isEmpty() || loading) return
        loading = true; error = null; account = null; ens = null
        scope.launch {
            try {
                if (q.contains('.')) ens = controller.resolveEns(network, q)
                else account = controller.requestAccount(network, q)
            } catch (c: CancellationException) {
                throw c  // let structured cancellation propagate (e.g. composable disposed)
            } catch (t: Throwable) {
                error = t.message ?: t.toString()
            } finally {
                loading = false
            }
        }
    }

    Column(Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            label = { Text("Address (0x…) or ENS name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = { submit() }, enabled = !loading) { Text("Query on $network") }
        Spacer(Modifier.height(16.dp))

        when {
            loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("Querying…")
            }
            error != null -> Text("Error: $error", color = MaterialTheme.colorScheme.error)
            account != null -> AccountResultView(account!!)
            ens != null -> EnsResultView(ens!!)
        }
    }
}

@Composable
private fun AccountResultView(a: AccountResult) {
    Column {
        StatusRow("Address", a.address)
        StatusRow("Exists", a.exists.toString())
        if (a.exists) {
            StatusRow("Balance (wei)", a.balanceWei ?: "—")
            StatusRow("Nonce", a.nonce.toString())
            StatusRow("Storage root", a.storageRootHex ?: "—")
            StatusRow("Code hash", a.codeHashHex ?: "—")
        }
        StatusRow("Block", a.blockNumber.toString())
        StatusRow("Proof valid", a.peerProofValid.toString())
        val badge = if (a.beaconChainVerified) {
            buildString {
                append("✓ ")
                append(a.verifyMethod ?: "verified")
                if (a.blsVerified) append(" (BLS)")
            }
        } else {
            "✗ ${a.failReason ?: "unverified"}"
        }
        StatusRow(
            "Verification",
            badge,
            color = if (a.beaconChainVerified) MaterialTheme.colorScheme.primary
            else MaterialTheme.colorScheme.error,
        )
    }
}

@Composable
private fun EnsResultView(e: EnsResult) {
    Column {
        StatusRow("Name", e.name)
        StatusRow("Address", e.addressHex ?: "—")
        StatusRow("Block", if (e.blockNumber >= 0) e.blockNumber.toString() else "—")
        StatusRow(
            "Verified",
            if (e.verified) "✓ finalized" else "unverified (peer head)",
            color = if (e.verified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
        )
        if (e.error != null) {
            StatusRow("Error", e.error, color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun StatusRow(key: String, value: String, color: Color? = null) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(key, Modifier.width(160.dp))
        Text(
            value,
            color = color ?: Color.Unspecified,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/**
 * Live log viewer over [LogSource]: poll the cheap version counter and re-snapshot only on
 * change; filter by substring on tag/message; auto-follow the tail unless the user scrolls up;
 * copy the visible lines or clear the ring. Mirrors the Android Logs tab.
 */
@Composable
private fun LogsTab(logs: LogSource) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    var lines by remember { mutableStateOf<List<LogLine>>(emptyList()) }
    var lastVersion by remember { mutableStateOf(-1L) }
    var filter by remember { mutableStateOf("") }

    LaunchedEffect(logs) {
        while (true) {
            val v = logs.version()
            if (v != lastVersion) {
                lines = logs.snapshot()
                lastVersion = v
            }
            delay(250)
        }
    }

    val shown = remember(lines, filter) {
        val f = filter.trim().lowercase()
        if (f.isEmpty()) lines
        else lines.filter { it.tag.lowercase().contains(f) || it.message.lowercase().contains(f) }
    }

    val listState = rememberLazyListState()
    // Auto-follow: true while the last line is visible (i.e. the user hasn't scrolled up).
    val atBottom by remember {
        derivedStateOf {
            val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            last >= shown.size - 1
        }
    }
    LaunchedEffect(shown.size) {
        if (atBottom && shown.isNotEmpty()) listState.scrollToItem(shown.size - 1)
    }

    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = filter,
                onValueChange = { filter = it },
                label = { Text("Filter — tag or message") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = { clipboard.setText(AnnotatedString(formatLogs(shown))) }) { Text("Copy") }
            Spacer(Modifier.width(4.dp))
            OutlinedButton(onClick = { logs.clear() }) { Text("Clear") }
        }
        Spacer(Modifier.height(8.dp))
        Box(Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
                items(shown, key = { it.sequence }) { LogLineRow(it) }
            }
            if (!atBottom && shown.isNotEmpty()) {
                Button(
                    onClick = { scope.launch { listState.scrollToItem(shown.size - 1) } },
                    modifier = Modifier.align(Alignment.BottomEnd).padding(8.dp),
                ) { Text("↓ Latest") }
            }
        }
        Text("${shown.size} / ${lines.size} lines", style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun LogLineRow(line: LogLine) {
    val color = when (line.level) {
        'E' -> MaterialTheme.colorScheme.error
        'W' -> Color(0xFFB58900)            // dim amber
        'D', 'V' -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> MaterialTheme.colorScheme.onSurface
    }
    val shortTag = line.tag.substringAfterLast('.')
    Text(
        "${formatLogTime(line.timestampMillis)} ${line.level} $shortTag: ${line.message}",
        fontSize = 11.sp,
        fontFamily = FontFamily.Monospace,
        color = color,
    )
}

private fun formatLogs(lines: List<LogLine>): String = buildString {
    for (l in lines) {
        append(formatLogTime(l.timestampMillis)).append(' ').append(l.level)
        append(' ').append(l.tag).append(": ").append(l.message).append('\n')
    }
}

/** HH:mm:ss.SSS in the local time zone (matches the logback console/file pattern). */
private fun formatLogTime(ms: Long): String {
    val dt = Instant.fromEpochMilliseconds(ms).toLocalDateTime(TimeZone.currentSystemDefault())
    fun p2(n: Int) = n.toString().padStart(2, '0')
    fun p3(n: Int) = n.toString().padStart(3, '0')
    return "${p2(dt.hour)}:${p2(dt.minute)}:${p2(dt.second)}.${p3(dt.nanosecond / 1_000_000)}"
}
