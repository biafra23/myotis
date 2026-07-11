package io.myotis.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

// Verified head older than this reads as "warming up" (amber) — wallet calls would -32000 until a
// fresh servable head exists. Matches the old Android ReadinessStrip threshold.
private const val READY_HEAD_WARM_MS = 45_000L

/** Default [NetworkStatus] for hosts with no connectivity concept (Desktop): always online. */
private object AlwaysOnline : NetworkStatus {
    override fun online(): kotlinx.coroutines.flow.Flow<Boolean> = kotlinx.coroutines.flow.flowOf(true)
}

/** Fallback when a host doesn't supply persistence — history simply isn't retained. */
private object NoQueryHistory : QueryHistory {
    override fun entries(): List<QueryHistoryEntry> = emptyList()
    override fun add(input: String, label: String) {}
    override fun clear() {}
}

/**
 * The shared Myotis screen — identical on Android and Desktop. A tab host over the per-network
 * [NodeController]/[Settings]/[LogSource] seam (Status / Query / Logs / Settings). [netStatus]
 * drives the offline banner and [onOpenNetworkSettings] opens the platform's network settings;
 * both default to the always-online / no-op behavior desktop wants.
 */
@Composable
fun NodeScreen(
    controller: NodeController,
    settings: Settings,
    logs: LogSource,
    netStatus: NetworkStatus = AlwaysOnline,
    onOpenNetworkSettings: () -> Unit = {},
    history: QueryHistory = NoQueryHistory,
) {
    // remember(controller): snapshots() returns a fresh Flow each call, so collecting it
    // directly would re-subscribe on every recomposition. Retain it across recompositions.
    val snapshotsFlow = remember(controller) { controller.snapshots() }
    val snapshots by snapshotsFlow.collectAsState(initial = emptyMap())
    val onlineFlow = remember(netStatus) { netStatus.online() }
    val online by onlineFlow.collectAsState(initial = true)
    var tab by remember { mutableStateOf(0) }
    // Logs-tab text filter, hoisted HERE deliberately: the `when (tab)` below disposes a
    // tab's composition on switch, so any `remember` inside LogsTab dies with it. Living
    // beside `tab` gives the filter the same lifetime as the tab selection itself (the
    // level filter needs no hoisting — it write-throughs to logs.setLevel and is re-read).
    var logFilter by remember { mutableStateOf("") }

    // Network selector: chips over the ENABLED set (the Settings switches), plus any
    // still-live stack. Sourcing from settings rather than the live map keeps a
    // runtime-stopped chain's chip visible — Stop on the Status page is decoupled from
    // the Settings enable switch, so an enabled-but-stopped chain stays selectable and
    // can be started again from Status. enabledNetworks() is a plain read (no snapshot
    // state), so SettingsTab bumps enabledRev on every toggle to re-derive the chips
    // immediately — without it they'd lag until the boot/stop lands in `snapshots`.
    var enabledRev by remember { mutableStateOf(0) }
    val chains = remember(enabledRev, snapshots) {
        (settings.enabledNetworks() + snapshots.keys).distinct()
    }
    var selected by remember { mutableStateOf<String?>(null) }
    val network = selected?.takeIf { it in chains } ?: chains.firstOrNull() ?: settings.primaryNetwork()
    val current = snapshots[network]

    MaterialTheme {
        Column(Modifier.fillMaxSize().padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Myotis", style = MaterialTheme.typography.headlineSmall)
                if (chains.isNotEmpty()) {
                    Spacer(Modifier.width(12.dp))
                    NetworkChips(chains, network, onSelect = { selected = it })
                }
            }
            Spacer(Modifier.height(8.dp))
            // Readiness traffic-light strip: the wallet's "safe to transact" signal for the
            // selected chain. Uses the configurable deep-pool threshold from Settings.
            ReadinessStrip(current, settings.deepPoolThreshold())
            Spacer(Modifier.height(12.dp))

            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Status") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Query") })
                Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("Logs") })
                Tab(selected = tab == 3, onClick = { tab = 3 }, text = { Text("Settings") })
            }
            Spacer(Modifier.height(16.dp))

            when (tab) {
                0 -> StatusTab(controller, settings, current, network, online, onOpenNetworkSettings)
                1 -> QueryTab(controller, settings, current, network, history)
                2 -> LogsTab(logs, logFilter, onFilterChange = { logFilter = it })
                3 -> SettingsTab(controller, settings, snapshots, onEnabledChanged = { enabledRev++ })
            }
        }
    }
}

/** Horizontally-scrolling chips over the enabled chains — picks the chain Status + Query act on. */
@Composable
private fun NetworkChips(chains: List<String>, selected: String, onSelect: (String) -> Unit) {
    Row(
        Modifier.horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        chains.forEach { c ->
            FilterChip(
                selected = c == selected,
                onClick = { onSelect(c) },
                label = { Text(c.replaceFirstChar { it.uppercase() }) },
            )
        }
    }
}

/**
 * Readiness traffic-light — the wallet's "safe to transact" signal for the selected chain.
 * red = not running / not synced; amber = synced but the verified head is still warming (wallet
 * calls would error -32000); green = ready for simple reads; bright thick green = deep peer pool,
 * heavy confirm screens will load. The state is exposed via a11y semantics so it isn't conveyed
 * by color/thickness alone.
 */
@Composable
private fun ReadinessStrip(s: NodeSnapshot?, deepPoolThreshold: Int) {
    val (color, height, label) = when {
        s != null && s.lifecycle == "PAUSED" ->
            Triple(Color(0xFF78909C), 3.dp, "Node readiness: sleeping — a request wakes it")
        s == null || !s.running ->
            Triple(Color(0xFFD32F2F), 3.dp, "Node readiness: not running")
        s.beaconState != "SYNCED" ->
            Triple(Color(0xFFD32F2F), 3.dp, "Node readiness: not synced")
        s.verifiedHeadAgeMs > READY_HEAD_WARM_MS ->
            Triple(Color(0xFFF9A825), 3.dp, "Node readiness: warming up, not ready to transact")
        s.snapServingPeers >= deepPoolThreshold ->
            Triple(Color(0xFF00E676), 6.dp,
                "Node readiness: fully ready — deep peer pool, heavy confirm screens will load")
        else ->
            Triple(Color(0xFF2E7D32), 3.dp,
                "Node readiness: ready for simple reads; peer pool still filling for heavy confirm screens")
    }
    Box(
        Modifier
            .fillMaxWidth()
            .height(height)
            .background(color)
            .semantics { contentDescription = label },
    )
}

/** Query-tab banner: the beacon light client isn't SYNCED, so results are peer-claimed, not verified. */
@Composable
private fun ConsensusUnsyncedBanner(beaconState: String) {
    Column(
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.errorContainer).padding(12.dp),
    ) {
        Text(
            "Consensus not synced (beacon: $beaconState) — balances & nonces are peer-claimed, " +
                "not cryptographically verified against a beacon-attested state root yet.",
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
    }
}

/**
 * Settings: enable/disable each network (each runs concurrently as its own node with its own
 * JSON-RPC port) and tune the shared snap/readiness/BLS/freshness knobs. Toggles that affect
 * a running stack apply live; RPC-port edits are deferred to Save and reboot only the changed
 * chain. Mirrors the Android SettingsScreen over the [Settings]/[NodeController] seam.
 */
@Composable
private fun SettingsTab(
    controller: NodeController,
    settings: Settings,
    snapshots: Map<String, NodeSnapshot>,
    // Notifies the screen that the persisted enabled set changed, so the network
    // chips (derived from settings, not snapshot state) re-derive immediately.
    onEnabledChanged: () -> Unit = {},
) {
    val networks = remember { settings.allNetworks() }
    // Per-network enabled toggle + RPC-port text, seeded from persisted settings. Toggling a
    // switch acts immediately (persists + boots/stops that chain); the RPC port is deferred to Save.
    val enabled = remember {
        mutableStateMapOf<String, Boolean>().apply {
            networks.forEach { put(it, settings.isNetworkEnabled(it)) }
        }
    }
    val rpcPorts = remember {
        mutableStateMapOf<String, String>().apply {
            networks.forEach { put(it, settings.rpcPortFor(it).toString()) }
        }
    }
    var snapTarget by remember { mutableStateOf(settings.snapTarget().toString()) }
    var deepPool by remember { mutableStateOf(settings.deepPoolThreshold().toString()) }
    var idlePause by remember { mutableStateOf(settings.idlePauseMinutes().toString()) }
    var stayAwakeCharging by remember { mutableStateOf(settings.stayAwakeWhileCharging()) }
    var strictFreshness by remember { mutableStateOf(settings.strictStateFreshness()) }
    var nativeBls by remember { mutableStateOf(settings.nativeBlsEnabled()) }
    var rustEngine by remember { mutableStateOf(settings.rustEngineEnabled()) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Networks", style = MaterialTheme.typography.titleMedium)
        Text(
            "Toggle a chain to run it. Each enabled chain runs concurrently as its own node " +
                "with its own JSON-RPC port — add each port to MetaMask as a separate RPC URL.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        networks.forEach { id ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(
                    Modifier.fillMaxWidth().padding(top = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(settings.displayName(id))
                    Switch(
                        checked = enabled[id] == true,
                        onCheckedChange = { on ->
                            enabled[id] = on
                            settings.setNetworkEnabled(id, on)
                            if (on) controller.enableNetwork(id) else controller.disableNetwork(id)
                            onEnabledChanged()
                        },
                    )
                }
                OutlinedTextField(
                    value = rpcPorts[id] ?: "",
                    onValueChange = { rpcPorts[id] = it.filter(Char::isDigit).take(5) },
                    label = { Text("JSON-RPC port (default ${settings.defaultRpcPort(id)})") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        HorizontalDivider()

        Text("Node tuning", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = snapTarget,
            onValueChange = { snapTarget = it.filter(Char::isDigit).take(3) },
            label = { Text("Snap-peer target (default 32)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = deepPool,
            onValueChange = { deepPool = it.filter(Char::isDigit).take(3) },
            label = { Text("Readiness \"deep pool\" threshold (default 16)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        // Idle-sleep is only meaningful on a host that actually runs the idle controller
        // (Android). On desktop (no controller) the setting is a no-op, so don't surface a
        // battery-saving toggle that can't take effect.
        if (settings.supportsIdleSleep()) {
            OutlinedTextField(
                value = idlePause,
                onValueChange = { idlePause = it.filter(Char::isDigit).take(3) },
                label = { Text("Idle sleep after (minutes, 0 = never)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "After this many minutes without a wallet request or query, the node goes to " +
                    "sleep: all P2P networking stops (saving battery) while the JSON-RPC port keeps " +
                    "listening. The first request wakes it — expect that call to take a little longer. " +
                    "On a fresh start it runs through to SYNCED before the first sleep, as long as it " +
                    "has a network to sync over.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            // Applies live — the idle tick reads it each pass.
            SwitchRow(
                label = "Stay awake while charging",
                checked = stayAwakeCharging,
                onChange = { on -> stayAwakeCharging = on; settings.setStayAwakeWhileCharging(on) },
            )
            Text(
                "On (default): while the phone is plugged in, skip idle sleep and keep the node " +
                    "awake and synced (battery isn't a concern). Off: sleep on the same idle timer " +
                    "whether charging or not. Emergency low-memory pauses happen either way.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // Strict freshness is the default; the switch exposes the RELAXED (opt-in) state, so the
        // checked value is the negation. Persisted immediately; applies on the next node restart.
        SwitchRow(
            label = "Relaxed state freshness",
            checked = !strictFreshness,
            onChange = { relaxed -> strictFreshness = !relaxed; settings.setStrictStateFreshness(!relaxed) },
        )
        Text(
            "Off (default, recommended): strict 2-minute freshness — fee calc / eth_call " +
                "fast-fail when no fresh servable root exists, and the wallet retries. " +
                "On (opt-in, experimental): serve a slightly older verified root — but if " +
                "it isn't fully servable this can HANG the confirm screen for up to 2 min " +
                "instead of failing fast. Applies on the next node (re)start.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // Native BLS applies immediately — flips the process-global backend live.
        SwitchRow(
            label = "Native BLS acceleration",
            checked = nativeBls,
            onChange = { on -> nativeBls = on; settings.setNativeBlsEnabled(on); controller.applyBlsBackend() },
        )
        Text(
            "On (default): use the bundled native blst library for sync-committee BLS " +
                "verification (much faster than pure-Java). Off: force the pure-Java Milagro path — " +
                "slower, but useful if the native library fails to load. Applies immediately.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // Engine choice applies per network (re)start — running networks keep their engine.
        SwitchRow(
            label = "Rust engine (experimental)",
            checked = rustEngine,
            onChange = { on -> rustEngine = on; settings.setRustEngineEnabled(on); controller.applyEngineChoice() },
        )
        Text(
            "Off (default): the proven Java engine runs every network. On: prefer the " +
                "experimental Rust engine where it can serve — it is being built out and " +
                "currently falls back to the Java engine for hosting. Applies when a " +
                "network is (re)started, not to already-running networks.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            "An RPC-port change reboots that chain; snap-peer target applies live to every " +
                "running chain, and the readiness threshold persists for the next check.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            onClick = {
                val snap = snapTarget.toIntOrNull() ?: 32
                val deep = deepPool.toIntOrNull() ?: 16
                settings.setSnapTarget(snap)          // persist
                settings.setDeepPool(deep)            // persist (read at readiness-check time)
                // Idle sleep: persisted only on hosts that run the controller; the tick reads it
                // live. Blank/invalid input keeps the CURRENT value rather than silently enabling
                // sleep (the label says "0 = never"), so a stray edit can't turn it on by accident.
                if (settings.supportsIdleSleep()) {
                    settings.setIdlePauseMinutes(idlePause.toIntOrNull() ?: settings.idlePauseMinutes())
                }
                controller.setTargetSnapPeers(snap)   // live-apply to running stacks
                networks.forEach { id ->
                    // Compare the EFFECTIVE (post-clamp) persisted port before vs after, not the
                    // raw typed value: setRpcPort clamps out-of-range input to the network default,
                    // so an invalid entry on an already-default chain must NOT count as "changed"
                    // and needlessly reboot a live RPC server. Mirrors the original applyTunables,
                    // which compared rpcPortFor() before/after the set.
                    val oldPort = settings.rpcPortFor(id)
                    settings.setRpcPort(id, rpcPorts[id]?.toIntOrNull() ?: settings.defaultRpcPort(id))
                    // Reboot only a RUNNING chain whose port actually changed — rebind that one
                    // RPC server without disturbing the others or reviving a stopped chain.
                    if (settings.rpcPortFor(id) != oldPort && snapshots[id] != null) controller.rebootNetwork(id)
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Save") }
    }
}

/** A label + right-aligned [Switch] row — the repeated toggle layout in [SettingsTab]. */
@Composable
private fun SwitchRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(top = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label)
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun StatusTab(
    controller: NodeController,
    settings: Settings,
    snap: NodeSnapshot?,
    primary: String,
    online: Boolean,
    onOpenNetworkSettings: () -> Unit,
) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        if (!online) {
            OfflineBanner(onOpenNetworkSettings)
            Spacer(Modifier.height(16.dp))
        }

        if (snap == null) {
            Text("Node stopped — no data for $primary")
        } else {
            SyncProgressBar(snap)
            StatusView(snap)
        }

        Spacer(Modifier.height(16.dp))
        // A snapshot for `primary` exists only while its stack is registered (running or
        // mid-boot): Start disabled once up, Stop only while it is. Start/Stop here are
        // RUNTIME-only (startNetwork/stopNetwork) — deliberately decoupled from the
        // Settings enable switches, so stopping a chain from Status does not flip its
        // switch off. The one exception: Start on a chain that isn't enabled at all
        // (e.g. fresh install, nothing on) goes through enableNetwork so a cold host
        // has an enabled set to boot.
        val primaryActive = snap != null
        Row {
            Button(
                onClick = {
                    if (settings.isNetworkEnabled(primary)) controller.startNetwork(primary)
                    else controller.enableNetwork(primary)
                },
                // Don't offer Start while offline — discovery can't reach any peer.
                enabled = !primaryActive && online,
            ) { Text("Start $primary") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(
                onClick = { controller.stopNetwork(primary) },
                enabled = primaryActive,
            ) { Text("Stop") }
        }

        Spacer(Modifier.height(16.dp))
        // Maintenance actions (mirrors the old Android Status screen): wipe peer caches to give
        // discovery a fresh slate, or drop the persisted sync snapshot to re-bootstrap next start.
        OutlinedButton(
            onClick = { controller.clearCaches(primary) },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Clear peer caches") }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = { controller.resetSyncState(primary) },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Reset sync state") }

        // Per-peer detail for the READY peers (address, snap support, client id).
        if (snap != null && snap.readyPeerList.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Text("READY peers (${snap.readyPeerList.size})", style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            snap.readyPeerList.forEach { PeerRowView(it) }
        }
    }
}

/** App-wide beacon sync banner: indeterminate while bootstrapping, determinate as the light
 *  client catches up sync-committee periods, gone once SYNCED. */
@Composable
private fun SyncProgressBar(s: NodeSnapshot) {
    if (!s.running || s.beaconState == "SYNCED" || s.beaconState == "STOPPED") return
    val start = s.syncStartPeriod
    val current = s.syncCurrentPeriod
    val target = s.syncTargetPeriod
    val determinate = s.beaconState == "CATCHING_UP" && start >= 0 && target > start
    Column(Modifier.fillMaxWidth().padding(bottom = 10.dp)) {
        Text(
            // Label follows the beacon STATE, not the bar's determinacy — a CATCHING_UP node with
            // an unknown start period still reads "catching up", never "bootstrapping".
            when {
                s.beaconState != "CATCHING_UP" -> "Bootstrapping light client…"
                determinate && current >= target -> "Finishing sync…"
                determinate -> "Catching up sync committees — period $current / $target"
                else -> "Catching up sync committees…"
            },
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(4.dp))
        if (determinate) {
            val progress = ((current - start).toFloat() / (target - start).toFloat()).coerceIn(0f, 1f)
            LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
        } else {
            LinearProgressIndicator(Modifier.fillMaxWidth())
        }
    }
}

/** One tappable-free READY-peer row: address + snap flag, with the client id beneath. */
@Composable
private fun PeerRowView(p: PeerRow) {
    Column(Modifier.padding(vertical = 2.dp)) {
        Text(
            "${p.remoteAddress}  snap=${p.snapSupported}",
            fontFamily = FontFamily.Monospace, fontSize = 12.sp,
            maxLines = 1, overflow = TextOverflow.Ellipsis,
        )
        Text(
            p.clientId ?: "(no clientId)",
            fontFamily = FontFamily.Monospace, fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1, overflow = TextOverflow.Ellipsis,
        )
    }
}

/** Shown at the top of Status when the device has no connectivity. */
@Composable
private fun OfflineBanner(onOpenNetworkSettings: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.errorContainer)
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            "No internet connection",
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
        Text(
            "The node needs internet access to discover and connect to peers. " +
                "Enable Wi-Fi or mobile data to continue.",
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
        Button(onClick = onOpenNetworkSettings, modifier = Modifier.fillMaxWidth()) {
            Text("Open network settings")
        }
    }
}

@Composable
private fun StatusView(s: NodeSnapshot) {
    val tz = remember { TimeZone.currentSystemDefault() }
    Column {
        StatusRow("Network", s.network)
        StatusRow("State", when (s.lifecycle) {
            "PAUSED" -> "Sleeping (wakes on request)"
            "RUNNING" -> "Running"
            else -> "Stopped"
        })
        StatusRow("Beacon", s.beaconState)
        StatusRow("EL block", s.executionBlockNumber.toString())
        StatusRow("CL peers", "served ${s.clServedPeersLastMin}/min, con ${s.clConnectedPeers}")
        StatusRow("EL peers", "ready ${s.readyPeers}, snap ${s.snapPeers}, serving ${s.snapServingPeers}")
        // Cache rows: "proven" (CL) / "snap-ok" (EL) predict how fast the NEXT
        // cold start finds servers — the cache learning is visible live.
        StatusRow(
            "CL cache",
            "${s.clCachedPeers} (proven ${s.clCachedProven}, nolc ${s.clCachedNolc}, " +
                "untried ${(s.clCachedPeers - s.clCachedProven - s.clCachedNolc).coerceAtLeast(0)})",
        )
        StatusRow("EL cache", "${s.elCachedPeers} (snap-ok ${s.elCachedSnapOk}, snap-bad ${s.elCachedSnapBad})")
        StatusRow("Discovered", s.discoveredPeers.toString())
        StatusRow("Discv5 peers", s.discv5Peers.toString())
        StatusRow("In backoff", s.backedOffPeers.toString())
        StatusRow("Blacklisted", s.blacklistedPeers.toString())
        StatusRow("Sync period", "${s.syncCurrentPeriod} / ${s.syncTargetPeriod}")
        // verifiedHeadAgeMs == Long.MAX_VALUE is the "no verified head yet" sentinel — show a
        // dash instead of the raw ~9.2e18 ms, which would read as a nonsensical age.
        StatusRow("Verified head age", if (s.verifiedHeadAgeMs == Long.MAX_VALUE) "—" else "${s.verifiedHeadAgeMs} ms")
        StatusRow("Uptime", "${s.uptimeSeconds}s")
        // Pseudo-sleep observability: how much the node has idle-slept, and when/why it
        // last woke. Foreground (opening the app) is excluded from the "last woke" reason,
        // so this keeps showing the last real request/catch-up wake even as you view it.
        StatusRow(
            "Sleep",
            if (s.pauseCount == 0) "never slept"
            else "${formatDuration(s.totalPausedMs)} over ${s.pauseCount} " +
                if (s.pauseCount == 1) "pause" else "pauses",
        )
        if (s.lastResumeEpochMs > 0) {
            val slept = if (s.lastPauseEpochMs > 0) " · slept ${formatLogTime(s.lastPauseEpochMs, tz)}" else ""
            StatusRow("Last woke", "${formatLogTime(s.lastResumeEpochMs, tz)} (${s.lastWakeReason ?: "?"})$slept")
        }
    }
}

/**
 * Verified account / ENS query over the shared seam. ENS-looking input (anything that isn't a
 * bare 0x + 40-hex address) resolves the name first, then — the crucial two-phase step — fetches
 * AND beacon-verifies the account at the resolved address, so an ENS query still shows a balance.
 * A plain address goes straight to [NodeController.requestAccount]. Verification status is shown
 * prominently, and a banner warns when the beacon light client isn't SYNCED (results peer-claimed).
 */
@Composable
private fun QueryTab(
    controller: NodeController,
    settings: Settings,
    snap: NodeSnapshot?,
    network: String,
    history: QueryHistory,
) {
    val scope = rememberCoroutineScope()
    val running = snap?.running == true
    val ensCapable = remember(network) { settings.hasEns(network) }
    // Key on `network`: reset input + results when the active chain changes so one chain's result
    // never shows under another.
    var input by remember(network) { mutableStateOf("") }
    var loading by remember(network) { mutableStateOf(false) }
    var loadingMsg by remember(network) { mutableStateOf("Querying…") }
    var account by remember(network) { mutableStateOf<AccountResult?>(null) }
    var ens by remember(network) { mutableStateOf<EnsResult?>(null) }
    var error by remember(network) { mutableStateOf<String?>(null) }
    // History is global (all chains); re-read the local snapshot after each add/clear. Start empty
    // and load off the main thread (entries() reads a file) so composition never blocks on disk.
    var historyList by remember(network) { mutableStateOf<List<QueryHistoryEntry>>(emptyList()) }
    LaunchedEffect(Unit) { historyList = withContext(Dispatchers.Default) { history.entries() } }

    // Takes the query string (not the input state) so a tapped history row runs immediately
    // without waiting for the input state write to settle.
    fun run(raw: String) {
        val q = raw.trim()
        if (q.isEmpty() || loading) return
        input = q
        loading = true; error = null; account = null; ens = null
        scope.launch {
            try {
                if (looksLikeEnsName(q)) {
                    if (!ensCapable) {
                        error = "ENS isn't available on ${network.replaceFirstChar { it.uppercase() }} — enter a 0x address."
                        return@launch
                    }
                    loadingMsg = "Resolving…"
                    val r = controller.resolveEns(network, q)
                    ens = r
                    // Phase 2: on a clean resolution, fetch + verify the account at the address.
                    val addr = r.addressHex
                    if (r.error == null && addr != null) {
                        loadingMsg = "Verifying account…"
                        account = controller.requestAccount(network, addr)
                    }
                } else {
                    loadingMsg = "Verifying account…"
                    account = controller.requestAccount(network, q)
                }
            } catch (c: CancellationException) {
                throw c  // let structured cancellation propagate (e.g. composable disposed)
            } catch (t: Throwable) {
                error = t.message ?: t.toString()
            } finally {
                loading = false
                // Record for one-tap re-run (off the main thread — file write); label = the
                // resolved address for ENS, else empty.
                val label = ens?.addressHex ?: ""
                historyList = withContext(Dispatchers.Default) { history.add(q, label); history.entries() }
            }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        if (!running) {
            Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.errorContainer).padding(12.dp)) {
                Text(
                    "Node is not running on ${network.replaceFirstChar { it.uppercase() }}. " +
                        "Start it from the Status tab before querying.",
                    fontSize = 13.sp, color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            Spacer(Modifier.height(12.dp))
        } else if (snap?.beaconState != "SYNCED") {
            ConsensusUnsyncedBanner(snap?.beaconState ?: "STOPPED")
            Spacer(Modifier.height(12.dp))
        }

        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            label = { Text(if (ensCapable) "Address (0x…) or ENS name" else "Address (0x…)") },
            singleLine = true,
            enabled = !loading,
            modifier = Modifier.fillMaxWidth(),
        )
        if (!ensCapable) {
            Spacer(Modifier.height(4.dp))
            Text(
                "ENS isn't available on ${network.replaceFirstChar { it.uppercase() }} — enter a 0x " +
                    "address. Balance & nonce are still beacon-verified.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { run(input) },
            enabled = running && input.isNotBlank() && !loading,
        ) { Text("Look up") }
        Spacer(Modifier.height(16.dp))

        // The resolved-ENS panel stays visible while the account verifies (and even if it fails).
        ens?.let {
            EnsResultView(it)
            Spacer(Modifier.height(12.dp))
        }
        when {
            loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text(loadingMsg)
            }
            error != null -> Text("Error: $error", color = MaterialTheme.colorScheme.error)
            account != null -> AccountResultView(account!!)
        }

        // Recent-query history: tap a row to re-run it (uses the stored input, not the label).
        if (historyList.isNotEmpty()) {
            Spacer(Modifier.height(20.dp))
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Recent", style = MaterialTheme.typography.titleSmall)
                TextButton(onClick = {
                    // clear() deletes a file — off the main thread.
                    scope.launch {
                        withContext(Dispatchers.Default) { history.clear() }
                        historyList = emptyList()
                    }
                }) { Text("Clear") }
            }
            historyList.forEach { e -> QueryHistoryRow(e, enabled = !loading, onClick = { run(e.input) }) }
        }
    }
}

/** One tappable past-query row: the stored input, with the resolved label beneath when present. */
@Composable
private fun QueryHistoryRow(e: QueryHistoryEntry, enabled: Boolean, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .padding(vertical = 6.dp),
    ) {
        Text(
            e.input,
            fontFamily = FontFamily.Monospace, fontSize = 13.sp,
            maxLines = 1, overflow = TextOverflow.Ellipsis,
        )
        if (e.label.isNotEmpty()) {
            Text(
                e.label,
                fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/**
 * ENS heuristic matching the old NodeService.looksLikeEnsName: a bare 0x + 40-hex string is an
 * address; anything else (has a dot, wrong length, non-hex chars) is treated as an ENS name.
 */
private fun looksLikeEnsName(input: String): Boolean {
    var s = input.trim()
    if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2)
    if (s.length != 40) return true
    return !s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
}

@Composable
private fun AccountResultView(a: AccountResult) {
    val clipboard = LocalClipboardManager.current
    Column {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Result", style = MaterialTheme.typography.titleSmall)
            // One-tap copy of the FULL result (untruncated hex), for pasting into a block explorer.
            OutlinedButton(onClick = { clipboard.setText(AnnotatedString(formatAccountResult(a))) }) {
                Text("Copy")
            }
        }
        StatusRow("Address", a.address)
        StatusRow("Exists", a.exists.toString())
        if (a.exists) {
            StatusRow("Balance (ETH)", formatEth(a.balanceWei))
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

/** Wei (decimal string) → ETH with 6 dp, truncated toward zero. Pure-Kotlin (commonMain has no
 *  java.math.BigDecimal): pad to ≥19 digits, split at the 18th from the right. Non-numeric input
 *  passes through unchanged. */
private fun formatEth(weiDecimal: String?): String {
    if (weiDecimal == null) return "—"
    val neg = weiDecimal.startsWith("-")
    val digits = weiDecimal.trimStart('-')
    if (digits.isEmpty() || !digits.all { it in '0'..'9' }) return weiDecimal
    val padded = digits.padStart(19, '0')
    val intPart = padded.dropLast(18).trimStart('0').ifEmpty { "0" }
    val frac = padded.takeLast(18).take(6)
    return (if (neg) "-" else "") + "$intPart.$frac"
}

/** Full plaintext dump of an account result for the clipboard (untruncated hex). */
private fun formatAccountResult(a: AccountResult): String = buildString {
    appendLine("address: ${a.address}")
    appendLine("exists: ${a.exists}")
    if (a.exists) {
        appendLine("balance (ETH): ${formatEth(a.balanceWei)}")
        appendLine("balance (wei): ${a.balanceWei ?: "—"}")
        appendLine("nonce: ${a.nonce}")
        a.storageRootHex?.let { appendLine("storageRoot: $it") }
        a.codeHashHex?.let { appendLine("codeHash: $it") }
    }
    appendLine("block: ${a.blockNumber}")
    a.peerStateRootHex?.let { appendLine("peerStateRoot: $it") }
    appendLine("peerProofValid: ${a.peerProofValid}")
    appendLine("beaconVerified: ${a.beaconChainVerified}")
    if (a.beaconChainVerified) {
        a.verifyMethod?.let { appendLine("method: $it") }
        appendLine("matchedSlot: ${a.matchedBeaconSlot}")
        appendLine("blsVerified: ${a.blsVerified}")
    } else {
        a.failReason?.let { appendLine("failReason: $it") }
    }
}

@Composable
private fun EnsResultView(e: EnsResult) {
    val clipboard = LocalClipboardManager.current
    Column {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("ENS", style = MaterialTheme.typography.titleSmall)
            e.addressHex?.let { addr ->
                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(addr)) }) { Text("Copy address") }
            }
        }
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
private fun LogsTab(logs: LogSource, filter: String, onFilterChange: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val tz = remember { TimeZone.currentSystemDefault() }  // resolve once, not per row
    var lines by remember { mutableStateOf<List<LogLine>>(emptyList()) }
    var shown by remember { mutableStateOf<List<LogLine>>(emptyList()) }
    var lastVersion by remember { mutableStateOf(-1L) }
    var level by remember(logs) { mutableStateOf(logs.level()) }

    // Poll the cheap version counter; the O(n) snapshot of up to 50k lines runs off the main
    // thread so it can't jank the UI.
    LaunchedEffect(logs) {
        while (true) {
            val v = logs.version()
            if (v != lastVersion) {
                lines = withContext(Dispatchers.Default) { logs.snapshot() }
                lastVersion = v
            }
            delay(250)
        }
    }

    // Filter off the main thread too, and cooperatively cancel superseded passes (rapid typing).
    // Filters by the selected minimum level AND the text query; `level` also drives capture (via
    // logs.setLevel), so this display filter mainly hides already-captured lines below `level`.
    LaunchedEffect(lines, filter, level) {
        val f = filter.trim()
        val minRank = level.ordinal
        shown = if (f.isEmpty() && level == LogLevel.DEBUG) lines
        else withContext(Dispatchers.Default) {
            lines.filter {
                ensureActive()  // withContext receiver is the CoroutineScope
                logLevelRank(it.level) >= minRank &&
                    // contains(ignoreCase = true) avoids allocating a lowercased copy of every
                    // tag/message per keystroke (up to 50k lines).
                    (f.isEmpty() || it.tag.contains(f, ignoreCase = true) || it.message.contains(f, ignoreCase = true))
            }
        }
    }

    val listState = rememberLazyListState()
    // Auto-follow: key on `shown` so the derived state re-reads the current list (not a stale
    // capture); size-2 tolerates the one-frame lag before a freshly-appended item is laid out.
    val atBottom by remember(shown) {
        derivedStateOf {
            val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            last >= shown.size - 2
        }
    }
    LaunchedEffect(shown.size) {
        if (atBottom && shown.isNotEmpty()) listState.scrollToItem(shown.size - 1)
    }

    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = filter,
                onValueChange = onFilterChange,
                label = { Text("Filter — tag or message") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = {
                scope.launch {
                    // Formatting up to 50k lines also goes off the main thread.
                    val text = withContext(Dispatchers.Default) { formatLogs(shown, tz) }
                    clipboard.setText(AnnotatedString(text))
                }
            }) { Text("Copy") }
            Spacer(Modifier.width(4.dp))
            OutlinedButton(onClick = { logs.clear() }) { Text("Clear") }
        }
        Spacer(Modifier.height(4.dp))
        // Capture level: lower it (e.g. DEBUG) to surface the chatty wire / peer-churn lines,
        // raise it to quiet the log. Applies to capture (logs.setLevel) AND hides already-captured
        // lines below the selection.
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text("Level", style = MaterialTheme.typography.labelMedium)
            LogLevel.entries.forEach { lvl ->
                FilterChip(
                    selected = level == lvl,
                    onClick = { level = lvl; logs.setLevel(lvl) },
                    label = { Text(lvl.name) },
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Box(Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
                items(shown, key = { it.sequence }) { LogLineRow(it, tz) }
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
private fun LogLineRow(line: LogLine, tz: TimeZone) {
    val color = when (line.level) {
        'E' -> MaterialTheme.colorScheme.error
        'W' -> Color(0xFFB58900)            // dim amber
        'D', 'V' -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> MaterialTheme.colorScheme.onSurface
    }
    val shortTag = line.tag.substringAfterLast('.')
    Text(
        "${formatLogTime(line.timestampMillis, tz)} ${line.level} $shortTag: ${line.message}",
        fontSize = 11.sp,
        fontFamily = FontFamily.Monospace,
        color = color,
    )
}

/** Rank a captured line's level char against [LogLevel.ordinal] (DEBUG=0 … ERROR=3). 'V' (TRACE)
 *  ranks with DEBUG so it shows at the DEBUG selection: TRACE isn't a selectable capture level, but
 *  a 'V' line can still reach the ring if some logger is independently at TRACE (Desktop's appender
 *  maps TRACE→'V'). */
private fun logLevelRank(c: Char): Int = when (c) {
    'E' -> 3
    'W' -> 2
    'I' -> 1
    else -> 0   // 'D' and 'V'
}

private fun formatLogs(lines: List<LogLine>, tz: TimeZone): String = buildString {
    for (l in lines) {
        append(formatLogTime(l.timestampMillis, tz)).append(' ').append(l.level)
        append(' ').append(l.tag).append(": ").append(l.message).append('\n')
    }
}

/** Compact elapsed duration: "45s" / "3m 12s" / "1h 3m". */
private fun formatDuration(ms: Long): String {
    val totalSec = ms / 1000
    val h = totalSec / 3600
    val m = (totalSec % 3600) / 60
    val sec = totalSec % 60
    return when {
        h > 0 -> "${h}h ${m}m"
        m > 0 -> "${m}m ${sec}s"
        else -> "${sec}s"
    }
}

/** HH:mm:ss.SSS in [tz] (matches the logback console/file pattern). */
private fun formatLogTime(ms: Long, tz: TimeZone): String {
    val dt = Instant.fromEpochMilliseconds(ms).toLocalDateTime(tz)
    fun p2(n: Int) = n.toString().padStart(2, '0')
    fun p3(n: Int) = n.toString().padStart(3, '0')
    return "${p2(dt.hour)}:${p2(dt.minute)}:${p2(dt.second)}.${p3(dt.nanosecond / 1_000_000)}"
}
