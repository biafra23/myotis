package io.myotis.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
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
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.time.Clock
import kotlin.time.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

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
 * The shared Myotis screen — identical on Android, Desktop and iOS. A tab host over the
 * per-network [NodeController]/[Settings]/[LogSource] seam: Status / Query / Settings, plus
 * Logs and Index under [Settings.expertMode]. A phone-width window gets a bottom navigation
 * bar, a wider one the tab row under the header. [netStatus] feeds the readiness ladder
 * (the strip's and the status card's offline rung, and the Start gate) and
 * [onOpenNetworkSettings] opens the platform's network settings; both default to the
 * always-online / no-op behavior desktop wants.
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
    // The Index tab is the log-index feature's home — where contracts are added,
    // snapshots imported, and progress read — so, within Expert mode, it shows
    // whenever the engine choice can serve the feature (anything but a forced Java
    // engine; the log index is Rust-engine-only), OR while any live engine reports an
    // enabled index: an imported/dropped-in snapshot activates engine-side without any
    // Settings flag ever having been touched, and hiding a running index from an
    // expert would leave its controls unreachable. Normal mode hides the tab in
    // every case (the Expert switch's note names it); there the index shows as the
    // readiness strip's catch-up line and the Status tab's Log index tile, and the
    // PoC flavours that ship a seeded index first-start in Expert mode. Settings are
    // plain reads, so the toggles that change them bump logIndexRev; the engine side
    // re-derives from `snapshots`.
    var logIndexRev by remember { mutableStateOf(0) }
    val showIndexTab = remember(logIndexRev, snapshots) {
        !settings.preferJavaEngine() ||
            snapshots.values.any { it.logIndexJson?.contains("\"enabled\":true") == true }
    }
    // Expert mode is a plain settings read like the engine preference above: the
    // Settings switch bumps expertRev so the tab set re-derives immediately.
    var expertRev by remember { mutableStateOf(0) }
    val expert = remember(expertRev) { settings.expertMode() }
    // Normal mode is the three screens a wallet user needs; Expert mode adds the Logs
    // tab and — under the rule above — the Index tab.
    val tabs = remember(expert, showIndexTab) {
        buildList {
            add("Status")
            add("Query")
            if (expert) {
                add("Logs")
                if (showIndexTab) add("Index")
            }
            add("Settings")
        }
    }
    // Selection is the tab's LABEL, not its position — positions shift when Index
    // appears/disappears. A selection whose tab just vanished falls back to Status.
    var tabLabel by remember { mutableStateOf("Status") }
    val tab = tabs.indexOf(tabLabel).coerceAtLeast(0)
    // The fallback also RESETS the stale label: without this, a selection stuck on a
    // vanished tab would silently jump back to it if a future change ever flipped the
    // visibility inputs without a tab click in between (today every re-show path goes
    // through a click on another tab, but nothing should rest on that).
    LaunchedEffect(tabs) { if (tabLabel !in tabs) tabLabel = "Status" }
    // Logs-tab text filter, hoisted HERE deliberately: the `when` below disposes a
    // tab's composition on switch, so any `remember` inside LogsTab dies with it. Living
    // beside `tabLabel` gives the filter the same lifetime as the tab selection itself (the
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
    // Per-network log-index head catch-up for the top bar. Every network is observed on
    // every snapshot, not just the selected one, so a catch-up's start stays current.
    val logIndexCatchUp = remember { LogIndexCatchUp() }
    val logIndexCatchUps = logIndexCatchUp.observeAll(snapshots.mapValues { it.value.logIndexJson })

    // Follow the platform's light/dark appearance, and paint the scheme's own
    // background behind everything. The Surface is load-bearing twice over:
    // without it Compose draws over the host window's background (black in iOS
    // dark mode) while the default MaterialTheme stays light — near-black text
    // on black — and it is also what sets LocalContentColor to onBackground, so
    // unspecified Text colors adapt. Every color in the screens below is a
    // scheme token (the few literals are saturated status colors that read on
    // both), so the two stock schemes are all it takes.
    val colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()
    MaterialTheme(colorScheme = colorScheme) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            // Stale-anchor consent. The engines park fail-closed (beaconState
            // STALE_ANCHOR) when a network's sync anchor is older than the
            // weak-subjectivity bound; this dialog is the "ask the user" half of
            // that contract. Dismissals are remembered only WHILE the network
            // stays parked, so a later, separate park asks again.
            var staleDismissed by remember { mutableStateOf(setOf<String>()) }
            staleDismissed = staleDismissed.filterTo(mutableSetOf()) {
                snapshots[it]?.beaconState == "STALE_ANCHOR"
            }
            val staleNet = snapshots.entries.firstOrNull {
                it.value.beaconState == "STALE_ANCHOR" && it.key !in staleDismissed
            }?.key
            val staleSnap = staleNet?.let { snapshots[it] }
            if (staleNet != null && staleSnap != null) {
                StaleAnchorDialog(
                    network = staleNet,
                    s = staleSnap,
                    onAccept = {
                        controller.acceptStaleAnchor(staleNet)
                        staleDismissed = staleDismissed + staleNet
                    },
                    onDismiss = { staleDismissed = staleDismissed + staleNet },
                )
            }

            // The one ladder the strip and the Status tab's card both paint.
            val readiness = readinessOf(current, settings.deepPoolThreshold(), logIndexCatchUps[network], online)

            // The header and the tab content are the same in both layouts below; only
            // where the tab switcher sits differs.
            val header: @Composable () -> Unit = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Title + version stacked: the version is the first thing to ask for in
                    // a bug report, so it's on screen everywhere rather than buried in an
                    // about box. Release builds read "v0.1.4"; anything else carries the
                    // commit it was built from ("v0.1.4-fbf551"), which is what makes a
                    // screenshot actionable. Generated — see ui/build.gradle.kts.
                    // Merged into one semantics node so a screen reader announces
                    // "Myotis v0.1.4" rather than two unrelated labels.
                    Column(Modifier.semantics(mergeDescendants = true) {}) {
                        Text("Myotis", style = MaterialTheme.typography.headlineSmall)
                        Text(
                            "v$APP_VERSION",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (chains.isNotEmpty()) {
                        Spacer(Modifier.width(12.dp))
                        NetworkChips(chains, network, engineOf = { snapshots[it]?.engine },
                            onSelect = { selected = it })
                    }
                }
                Spacer(Modifier.height(8.dp))
                // Readiness traffic-light strip: the wallet's "safe to transact" signal for the
                // selected chain.
                ReadinessStrip(readiness, logIndexCatchUps[network])
                Spacer(Modifier.height(12.dp))
            }
            val content: @Composable () -> Unit = {
                when (tabs[tab]) {
                    "Status" -> StatusTab(
                        controller, settings, current, network, online, onOpenNetworkSettings,
                        expert = expert, readiness = readiness, catchUp = logIndexCatchUps[network],
                        // The card's "Review" re-asks a dismissed stale-anchor question.
                        onReviewStaleAnchor = { staleDismissed = staleDismissed - network },
                    )
                    "Query" -> QueryTab(controller, settings, current, network, history, expert)
                    "Logs" -> LogsTab(logs, logFilter, onFilterChange = { logFilter = it })
                    "Index" -> IndexTab(controller, settings, current, network,
                        onLogIndexChanged = { logIndexRev++ })
                    "Settings" -> SettingsTab(controller, settings, snapshots, expert = expert,
                        onEnabledChanged = { enabledRev++ }, onLogIndexChanged = { logIndexRev++ },
                        onExpertChanged = { expertRev++ })
                }
            }

            // A phone-width window gets a bottom navigation bar — within the thumb's reach,
            // icons and labels; a wider one keeps the tab row under the header. Both are
            // selectable nodes carrying the tab's label, so tests and screen readers see the
            // same tabs either way.
            BoxWithConstraints(Modifier.fillMaxSize()) {
                if (maxWidth < COMPACT_WIDTH) {
                    Scaffold(
                        containerColor = MaterialTheme.colorScheme.background,
                        bottomBar = {
                            NavigationBar {
                                tabs.forEachIndexed { i, label ->
                                    NavigationBarItem(
                                        selected = tab == i,
                                        onClick = { tabLabel = label },
                                        icon = { Icon(NavIcons.of(label), contentDescription = null) },
                                        label = { Text(label) },
                                    )
                                }
                            }
                        },
                    ) { inner ->
                        Column(Modifier.fillMaxSize().padding(inner).padding(16.dp)) {
                            header()
                            content()
                        }
                    }
                } else {
                    Column(Modifier.fillMaxSize().padding(16.dp)) {
                        header()
                        TabRow(selectedTabIndex = tab) {
                            tabs.forEachIndexed { i, label ->
                                Tab(selected = tab == i, onClick = { tabLabel = label }, text = { Text(label) })
                            }
                        }
                        Spacer(Modifier.height(16.dp))
                        content()
                    }
                }
            }
        }
    }
}

/** Below this width the tab switcher is a bottom navigation bar (a phone); at or above it, a tab row. */
internal val COMPACT_WIDTH = 600.dp

/** Horizontally-scrolling chips over the enabled chains — picks the chain Status + Query act on. */
@Composable
private fun NetworkChips(
    chains: List<String>,
    selected: String,
    engineOf: (String) -> String?,
    onSelect: (String) -> Unit,
) {
    Row(
        Modifier.horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        chains.forEach { c ->
            FilterChip(
                selected = c == selected,
                onClick = { onSelect(c) },
                label = {
                    // One-letter engine suffix — "Mainnet (r)" = rust, "(j)" = java —
                    // so multi-network users see per-network engine at a glance.
                    val eng = engineOf(c)?.firstOrNull()?.let { " ($it)" } ?: ""
                    Text(c.replaceFirstChar { it.uppercase() } + eng)
                },
            )
        }
    }
}

/**
 * Readiness traffic-light — the wallet's "safe to transact" signal for the selected chain.
 * red = not running / not synced; amber = synced but the verified head is still warming (wallet
 * calls would error -32000); amber progress bar = the log index is catching up to the head
 * ([catchUp]; head-reaching `eth_getLogs` is refused until it has, so a log-scanning wallet is
 * not ready either); green = ready for simple reads; bright thick green = deep peer pool,
 * heavy confirm screens will load. The state is exposed via a11y semantics so it isn't conveyed
 * by color/thickness alone.
 */
@Composable
internal fun ReadinessStrip(
    s: NodeSnapshot?,
    deepPoolThreshold: Int,
    catchUp: CatchUpProgress? = null,
    online: Boolean = true,
) = ReadinessStrip(readinessOf(s, deepPoolThreshold, catchUp, online), catchUp)

/** The strip over a ladder rung already computed — [NodeScreen] shares one with the status card. */
@Composable
internal fun ReadinessStrip(r: Readiness, catchUp: CatchUpProgress?) {
    // One ladder for every readiness surface (Readiness.kt); the strip only paints it.
    val color = StatusColors.of(r.level)
    // The two rungs past "ready" are drawn thicker: the deep pool, and the index
    // catch-up whose strip doubles as its progress bar.
    val height = when (r.level) {
        ReadinessLevel.INDEX_CATCHING_UP, ReadinessLevel.FULLY_READY -> 6.dp
        else -> 3.dp
    }
    val label = r.a11yLabel
    if (r.level == ReadinessLevel.INDEX_CATCHING_UP && catchUp != null) {
        // The strip itself becomes the progress bar, with the gap spelled out beneath it.
        // One semantics node carrying both the label and, while it moves, the bar's value.
        Column(
            Modifier.fillMaxWidth().testTag(READINESS_STRIP_TAG)
                .clearAndSetSemantics {
                    contentDescription = label
                    if (!catchUp.stalled) {
                        progressBarRangeInfo = ProgressBarRangeInfo(catchUp.fraction, 0f..1f)
                    }
                },
        ) {
            if (catchUp.stalled) {
                // Nothing is closing the gap: a bar would promise motion.
                Box(Modifier.fillMaxWidth().height(height).background(color))
            } else {
                LinearProgressIndicator(
                    progress = { catchUp.fraction },
                    modifier = Modifier.fillMaxWidth().height(height),
                    color = color,
                    trackColor = color.copy(alpha = 0.25f),
                )
            }
            Text(
                LogIndexStatus.catchUpLine(catchUp),
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        return
    }
    Box(
        Modifier
            .fillMaxWidth()
            .height(height)
            .background(color)
            .testTag(READINESS_STRIP_TAG)
            .semantics { contentDescription = label },
    )
}

internal const val READINESS_STRIP_TAG = "readiness-strip"

/**
 * The stale-anchor consent dialog — the interactive half of the weak-subjectivity
 * gate. Shown while a network is parked in STALE_ANCHOR: the engine refuses to
 * sync from an anchor older than the bound until the user updates the app,
 * raises the bound (Settings), or accepts the risk here. "Sync anyway" applies
 * to THIS RUN only; the engine never persists the consent.
 */
@Composable
private fun StaleAnchorDialog(
    network: String,
    s: NodeSnapshot,
    onAccept: () -> Unit,
    onDismiss: () -> Unit,
) {
    val agePeriods = (s.syncTargetPeriod - s.syncCurrentPeriod).coerceAtLeast(0)
    // Rough period length per chain, for a human-scale age (exact math stays in
    // periods — this is display only): mainnet preset ~27.3 h, Gnosis ~11.4 h.
    val hoursPerPeriod = if (network == "gnosis") 11.4 else 27.3
    val ageDays = ((agePeriods * hoursPerPeriod) / 24.0).toInt()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Sync anchor too old — ${network.replaceFirstChar { it.uppercase() }}") },
        text = {
            Text(
                "The newest trust anchor this node has (its built-in checkpoint or last " +
                    "verified sync state) is $agePeriods sync-committee periods old" +
                    (if (ageDays > 0) " (~$ageDays days)" else "") +
                    ", past the weak-subjectivity bound of ${s.wsBoundPeriods} periods.\n\n" +
                    "Beyond this window, validators who have since exited could sign a fake " +
                    "chain continuation (a long-range attack), and signature verification " +
                    "alone cannot tell it from the real chain. Syncing is paused, and " +
                    "verified reads stay unavailable, until you decide.\n\n" +
                    "Safest: update the app (a fresh build carries a fresh checkpoint). " +
                    "Alternatively raise the bound in Settings, or sync anyway if you " +
                    "trust your network and peers — for this run only.",
            )
        },
        confirmButton = { TextButton(onClick = onAccept) { Text("Sync anyway (accept risk)") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Stay paused") } },
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
    // Whether Expert mode is on (re-read by NodeScreen on every flip): shows the
    // node-tuning section below the Power and Expert-mode rows.
    expert: Boolean = false,
    // Notifies the screen that the Kohaku log-index effective state changed (the
    // per-network flags or the Rust engine it depends on), so the Index tab's
    // visibility re-derives immediately.
    onLogIndexChanged: () -> Unit = {},
    // Notifies the screen that Expert mode flipped, so the tab set and this tab's
    // sections re-derive immediately.
    onExpertChanged: () -> Unit = {},
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
    // The Expert-mode tuning fields live here, not in NodeTuning: Save persists the text
    // fields, and the section comes and goes with the Expert switch while the tab stays.
    val tuning = remember { TuningFields(settings) }
    var idlePause by remember { mutableStateOf(settings.idlePauseMinutes().toString()) }
    var stayAwakeCharging by remember { mutableStateOf(settings.stayAwakeWhileCharging()) }
    var allowNap by remember { mutableStateOf(settings.allowAppNap()) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SettingsSection("Networks")
        SettingsNote(
            "Turn a chain on to run it. Each chain runs as its own node with its own JSON-RPC " +
                "port — add each port to your wallet as a separate RPC URL. Save applies a " +
                "port change by restarting that chain.",
        )
        networks.forEach { id ->
            NetworkCard(
                name = settings.displayName(id),
                enabled = enabled[id] == true,
                port = rpcPorts[id] ?: "",
                portLabel = "JSON-RPC port (default ${settings.defaultRpcPort(id)})",
                onEnabled = { on ->
                    enabled[id] = on
                    settings.setNetworkEnabled(id, on)
                    if (on) controller.enableNetwork(id) else controller.disableNetwork(id)
                    onEnabledChanged()
                },
                onPort = { rpcPorts[id] = it.filter(Char::isDigit).take(5) },
            )
        }

        // Power: the rows that trade responsiveness for battery or CPU, one per host that
        // has such a knob — macOS App Nap, Android's idle controller. Linux has neither
        // (no per-app throttling of unfocused windows, no idle controller), so the section
        // is simply absent there.
        if (settings.supportsAppNap() || settings.supportsIdleSleep()) {
            HorizontalDivider()
            SettingsSection("Power")
        }
        if (settings.supportsAppNap()) {
            // Applies live — the controller begins or ends the no-nap activity at once.
            SwitchRow(
                label = "Sleep when not in focus",
                checked = allowNap,
                onChange = { on -> allowNap = on; settings.setAllowAppNap(on); controller.applyAppNap() },
            )
            SettingsNote(
                "Off (default): Myotis stays fully awake while its window is hidden or covered, " +
                    "so wallets on this Mac keep getting prompt answers. On: macOS may slow Myotis " +
                    "down when it is not in focus (App Nap) — saves power, but a wallet's first " +
                    "request after a while can stall for seconds. Applies immediately.",
            )
        }
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
            SettingsNote(
                "After this many minutes without a wallet request or query, the node goes to " +
                    "sleep: all P2P networking stops (saving battery) while the JSON-RPC port keeps " +
                    "listening. The first request wakes it — expect that call to take a little longer. " +
                    "On a fresh start it runs through to SYNCED before the first sleep, as long as it " +
                    "has a network to sync over.",
            )
            // Applies live — the idle tick reads it each pass.
            SwitchRow(
                label = "Stay awake while charging",
                checked = stayAwakeCharging,
                onChange = { on -> stayAwakeCharging = on; settings.setStayAwakeWhileCharging(on) },
            )
            SettingsNote(
                "On (default): while the phone is plugged in, skip idle sleep and keep the node " +
                    "awake and synced (battery isn't a concern). Off: sleep on the same idle timer " +
                    "whether charging or not. Emergency low-memory pauses happen either way.",
            )
        }

        HorizontalDivider()
        // Persisted at once; NodeScreen re-reads it and re-derives the tab set.
        SwitchRow(
            label = "Expert mode",
            checked = expert,
            onChange = { on -> settings.setExpertMode(on); onExpertChanged() },
        )
        SettingsNote(
            "On: the Logs and Index tabs, every status row with its maintenance actions, and " +
                "the node-tuning settings below. Off (default): the three screens a wallet needs.",
        )

        if (expert) {
            HorizontalDivider()
            NodeTuning(controller, settings, tuning, onLogIndexChanged)
        }
        Button(
            onClick = {
                // Save writes only what the current mode shows. `tuning` outlives an Expert
                // flip-off (the tab stays composed), so an edit typed in Expert mode and never
                // saved would otherwise be persisted — and live-applied — by a normal-mode
                // Save with no field on screen showing it; for the weak-subjectivity bound
                // that is a security knob widened invisibly.
                if (expert) {
                    val snap = tuning.snapTarget.toIntOrNull() ?: 32
                    val window = tuning.servedWindow.toIntOrNull() ?: 32
                    val deep = tuning.deepPool.toIntOrNull() ?: 16
                    // Blank/invalid keeps the CURRENT value (0 would silently restore the
                    // default bound — a security knob must not change on a stray edit).
                    val ws = tuning.wsBound.toIntOrNull() ?: settings.wsBoundPeriods()
                    settings.setSnapTarget(snap)          // persist
                    settings.setServedBlockWindow(window) // persist
                    settings.setDeepPool(deep)            // persist (read at readiness-check time)
                    settings.setWsBoundPeriods(ws)        // persist
                    controller.setTargetSnapPeers(snap)   // live-apply to running stacks
                    controller.setServedBlockWindow(window) // live-apply to running stacks
                    controller.setWsBoundPeriods(ws)      // live-apply (a STALE_ANCHOR park re-evaluates)
                }
                // Idle sleep: persisted only on hosts that run the controller; the tick reads it
                // live. Blank/invalid input keeps the CURRENT value rather than silently enabling
                // sleep (the label says "0 = never"), so a stray edit can't turn it on by accident.
                if (settings.supportsIdleSleep()) {
                    settings.setIdlePauseMinutes(idlePause.toIntOrNull() ?: settings.idlePauseMinutes())
                }
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

/**
 * The Expert-mode tuning fields of [SettingsTab], seeded from [Settings] once per tab
 * composition. The text fields are persisted by the Save button; the switches write
 * through as they flip and are mirrored here for the UI.
 */
private class TuningFields(settings: Settings) {
    var snapTarget by mutableStateOf(settings.snapTarget().toString())
    var servedWindow by mutableStateOf(settings.servedBlockWindow().toString())
    var deepPool by mutableStateOf(settings.deepPoolThreshold().toString())
    var wsBound by mutableStateOf(settings.wsBoundPeriods().toString())
    var strictFreshness by mutableStateOf(settings.strictStateFreshness())
    var nativeBls by mutableStateOf(settings.nativeBlsEnabled())
    var preferJava by mutableStateOf(settings.preferJavaEngine())
    var torRouting by mutableStateOf(settings.torEnabled())
}

/**
 * The Expert-mode "Node tuning" section of [SettingsTab]: the knobs that shape how the
 * node syncs and serves, over the tab's [TuningFields].
 */
@Composable
private fun NodeTuning(
    controller: NodeController,
    settings: Settings,
    f: TuningFields,
    onLogIndexChanged: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        SettingsSection("Node tuning")
        OutlinedTextField(
            value = f.snapTarget,
            onValueChange = { f.snapTarget = it.filter(Char::isDigit).take(3) },
            label = { Text("Snap-peer target (default 32)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = f.servedWindow,
            onValueChange = { f.servedWindow = it.filter(Char::isDigit).take(4) },
            label = { Text("Served-block window (eth/69, default 32)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = f.deepPool,
            onValueChange = { f.deepPool = it.filter(Char::isDigit).take(3) },
            label = { Text("Readiness \"deep pool\" threshold (default 16)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = f.wsBound,
            onValueChange = { f.wsBound = it.filter(Char::isDigit).take(4) },
            label = { Text("Weak-subjectivity bound in periods (0 = network default)") },
            supportingText = {
                Text(
                    "How old the sync anchor may be before the node refuses to sync and " +
                        "asks for consent (mainnet default 13 periods ≈ two weeks). Raising " +
                        "it weakens the long-range-attack protection — leave 0 unless you " +
                        "know why.",
                )
            },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        // Strict freshness is the default; the switch exposes the RELAXED (opt-in) state, so the
        // checked value is the negation. Persisted immediately; applies on the next node restart.
        SwitchRow(
            label = "Relaxed state freshness",
            checked = !f.strictFreshness,
            onChange = { relaxed -> f.strictFreshness = !relaxed; settings.setStrictStateFreshness(!relaxed) },
        )
        SettingsNote(
            "Off (default, recommended): strict 2-minute freshness — fee calc / eth_call " +
                "fast-fail when no fresh servable root exists, and the wallet retries. " +
                "On (opt-in, experimental): serve a slightly older verified root — but if " +
                "it isn't fully servable this can HANG the confirm screen for up to 2 min " +
                "instead of failing fast. Applies on the next node (re)start.",
        )

        // Native BLS applies immediately — flips the process-global backend live.
        SwitchRow(
            label = "Native BLS acceleration",
            checked = f.nativeBls,
            onChange = { on -> f.nativeBls = on; settings.setNativeBlsEnabled(on); controller.applyBlsBackend() },
        )
        SettingsNote(
            "On (default): use the bundled native blst library for sync-committee BLS " +
                "verification (much faster than pure-Java). Off: force the pure-Java Milagro path — " +
                "slower, but useful if the native library fails to load. Applies immediately.",
        )

        // Engine choice applies per network (re)start — running networks keep their engine.
        // A host that cannot run the Java engine at all (Android below API 33) shows why
        // instead of a toggle it would refuse to honour.
        val javaUnavailable = remember { settings.javaEngineUnavailableReason() }
        if (javaUnavailable != null) {
            Text("Engine: Rust only")
            SettingsNote(
                javaUnavailable,
            )
        } else {
            SwitchRow(
                label = "Prefer Java engine",
                checked = f.preferJava,
                onChange = { on ->
                    f.preferJava = on; settings.setPreferJavaEngine(on); controller.applyEngineChoice()
                    onLogIndexChanged()
                },
            )
            SettingsNote(
                "Off (default): the Rust engine runs each network where it can serve, " +
                    "falling back to the Java engine otherwise. The Rust engine is the " +
                    "primary engine — the log index (Index tab) and Tor routing run on it " +
                    "only. On: force the original Java engine everywhere, giving up those " +
                    "features — currently the only way to use the Query tab's " +
                    "transaction-history scan (mainnet, Java engine only). Applies when a " +
                    "network is (re)started, not to already-running networks. On hosts with " +
                    "an idle controller (Android) both engines idle-sleep; the Status screen's " +
                    "Sleep row shows it per network.",
            )
        }

        // Tor routing — shown only on hosts that can actually route over Tor
        // (controller.supportsTor; a privacy switch that flips ON while reads keep
        // leaving from the real IP would be accepted-and-ignored). Where shown, the
        // row is disabled while the Java engine is forced above.
        if (controller.supportsTor) {
            SwitchRow(
                label = "Route reads over Tor (experimental)",
                checked = f.torRouting && !f.preferJava,
                enabled = !f.preferJava,
                onChange = { on -> f.torRouting = on; settings.setTorEnabled(on); controller.applyTorMode() },
            )
            SettingsNote(
                if (f.preferJava) {
                    "Turn off “Prefer Java engine” first — Tor routing is built into the Rust engine only."
                } else {
                    "Off (default): reads use the peer pool directly from your IP. On: route " +
                        "account/balance reads over the Tor network (embedded Arti) so snap peers see " +
                        "a Tor exit, not your IP — each address gets its own isolated circuit and a " +
                        "fresh node identity. SCOPE: only account (balance/nonce) reads route over Tor " +
                        "today; token-balance (storage), contract code, and eth_call/gas-estimation " +
                        "still use your real IP — full coverage is a follow-up. HEADS-UP: earlier tests " +
                        "were not very successful — many peers reject Tor exit IPs and :30303 exit " +
                        "coverage is patchy, so reads can be slow (seconds to tens of seconds) or " +
                        "fail-closed while this is on. Takes effect immediately — the next read on a " +
                        "running Rust-engine network routes over Tor (no restart needed)."
                },
            )
        }
        SettingsNote(
            "Save applies the snap-peer target and served-block window live to every running " +
                "chain; the readiness threshold persists for the next check.",
        )
    }
}

/**
 * A label + right-aligned [Switch] row — the repeated toggle layout in [SettingsTab].
 * The ROW is the toggleable (the switch itself has no handler), so a screen reader
 * announces one named switch — "Expert mode, on" — instead of a label and an unnamed
 * toggle side by side, and the whole row is the tap target.
 */
@Composable
internal fun SwitchRow(
    label: String,
    checked: Boolean,
    enabled: Boolean = true,
    onChange: (Boolean) -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .toggleable(value = checked, enabled = enabled, role = Role.Switch, onValueChange = onChange)
            .padding(top = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            color = if (enabled) Color.Unspecified else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Switch(checked = checked, enabled = enabled, onCheckedChange = null)
    }
}

/**
 * The Status tab. Both modes open with the readiness card ([StatusHero]) and its
 * actions. Normal mode follows with the vitals tiles and nothing else; Expert mode
 * with today's banners, the full rows, the maintenance actions and the READY peers.
 */
@Composable
private fun StatusTab(
    controller: NodeController,
    settings: Settings,
    snap: NodeSnapshot?,
    primary: String,
    online: Boolean,
    onOpenNetworkSettings: () -> Unit,
    expert: Boolean,
    readiness: Readiness,
    // The log index's head catch-up as the ladder saw it, so the tile agrees with the card.
    catchUp: CatchUpProgress?,
    onReviewStaleAnchor: () -> Unit,
) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        // A snapshot for `primary` exists only while its stack is registered (running or
        // mid-boot): Start shows while it is down, Stop while it is up. Start/Stop are
        // RUNTIME-only (startNetwork/stopNetwork) — deliberately decoupled from the
        // Settings enable switches, so stopping a chain here does not flip its switch
        // off. The one exception: Start on a chain that isn't enabled at all (e.g. fresh
        // install, nothing on) goes through enableNetwork so a cold host has an enabled
        // set to boot.
        val primaryActive = snap != null
        StatusHero(readiness, help = { HelpButton("Readiness", StatusHelp.READINESS) }) {
            // Offline: the fix is outside the app, so offer the door to it — whatever rung
            // leads (a sleeping stack outranks offline on the card, and still needs the door
            // before a wake can succeed).
            if (!online) Button(onClick = onOpenNetworkSettings) { Text("Open network settings") }
            // Parked on the user's consent: bring the dismissed dialog back.
            if (readiness.level == ReadinessLevel.NEEDS_DECISION) {
                Button(onClick = onReviewStaleAnchor) { Text("Review") }
            }
            if (primaryActive) {
                OutlinedButton(onClick = { controller.stopNetwork(primary) }) { Text("Stop") }
            } else {
                Button(
                    onClick = {
                        if (settings.isNetworkEnabled(primary)) controller.startNetwork(primary)
                        else controller.enableNetwork(primary)
                    },
                    // Don't offer Start while offline — discovery can't reach any peer.
                    enabled = online,
                ) { Text("Start $primary") }
            }
            if (expert) HelpButton("Start / Stop", StatusHelp.START_STOP)
        }
        Spacer(Modifier.height(16.dp))

        snap?.upgrade?.let {
            UpgradeBanner(it, cutOff = upgradeCutOff(snap))
            Spacer(Modifier.height(16.dp))
        }

        if (!expert) {
            VitalsGrid(vitalsOf(snap, settings.deepPoolThreshold(), catchUp))
            return@Column
        }

        if (snap != null) {
            HuntBanner(snap)
            SyncProgressBar(snap)
            StatusView(snap, hostSleeps = settings.supportsIdleSleep())
        }

        Spacer(Modifier.height(16.dp))
        // Maintenance actions (mirrors the old Android Status screen): wipe peer caches to give
        // discovery a fresh slate, or drop the persisted sync snapshot to re-bootstrap next start.
        //
        // BOTH are offered only while the network is down (owner's call, 2026-09-16): each is one
        // mis-click away from throwing out hours of learned peers or the sync anchor, and neither
        // is worth that risk mid-run. The reasons they are unsafe differ, though, and the
        // difference is worth keeping written down.
        //
        // `clearCaches` actually WORKS while running — on the Java engine: it goes THROUGH the
        // engine (clearPeerState plus the live cache instances), so a live stack cannot write the
        // old peers back. Gating it therefore costs something real — handing discovery a fresh
        // slate without a restart is a genuine debugging move — and that cost is accepted
        // deliberately to make the accidental click impossible. On the Rust engine the gate is
        // load-bearing as well: clearPeerState is a no-op there (the engine exports no clear over
        // the FFI), the host only deletes the cache files, and a running native pool rewrites
        // them from memory on its next flush — stopped is the one window where the delete sticks
        // (RustChainHandle.clearPeerState).
        //
        // `resetSyncState` only deletes `sync-state*.snapshot*` from disk, and whether that
        // STICKS while the chain runs depends on the engine and on what it is doing — which is
        // the reason to gate it rather than the reason not to. Rust, synced: persistence is
        // throttled to a sync-committee PERIOD advance (~11 h gnosis, ~27 h mainnet) and there
        // is no stop-time persist, so the delete usually holds. Rust, catching up: a persist
        // lands per applied period, i.e. seconds, and the delete is gone. Java: the `.roots`
        // sidecar — matched by the same glob — is rewritten unthrottled every ~12 s, and
        // `close()` persists again at shutdown. So pressed on a running chain the action is
        // unpredictable rather than merely slow, and it only ever takes effect at the NEXT
        // start anyway. Stop, reset, start is the sequence to use — on desktop the delete now
        // takes the same per-network boot lock as the cache clear, so it cannot race the next
        // boot's snapshot read. Android's reset is still an unlocked detached delete (and drops
        // only the main file, no sibling glob), so there the sequence stays best-effort.
        //
        // One honest limit: `primaryActive` follows the host's 2 s snapshot poll, and the engine
        // drops a stopping chain from its registry BEFORE the loop finishes tearing down (it
        // tracks that window itself and refuses a fresh create into the same directory). So the
        // button can go live a moment before the last writer is gone. A write there needs a
        // period advance, so the odds are slim — but the gate is a guard rail, not a lock.
        // Android has a third window that is not poll-related: its bridge emits an EMPTY
        // snapshot map whenever the Activity is unbound from the foreground service — while the
        // engine under it keeps running — so just after a rebind these can render enabled
        // against a live node until the next tick, and a tap then executes for real (the
        // service handle is resolved at click time, by which point the bind has completed).
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(
                onClick = { controller.clearCaches(primary) },
                enabled = !primaryActive,
                modifier = Modifier.weight(1f),
            ) { Text("Clear peer caches") }
            HelpButton("Clear peer caches", StatusHelp.CLEAR_CACHES)
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(
                onClick = { controller.resetSyncState(primary) },
                enabled = !primaryActive,
                modifier = Modifier.weight(1f),
            ) { Text("Reset sync state") }
            HelpButton("Reset sync state", StatusHelp.RESET_SYNC_STATE)
        }
        if (primaryActive) {
            Spacer(Modifier.height(4.dp))
            Text(
                "Stop $primary first: these discard learned peers and the sync anchor, and a "
                    + "reset only applies at the next start anyway.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        // Per-peer detail for the READY peers (address, snap support, client id).
        if (snap != null && snap.readyPeerList.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Text("READY peers (${snap.readyPeerList.size})", style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            snap.readyPeerList.forEach { PeerRowView(it) }
        }
    }
}

/** LC hunt banner: shown while the light client is starved of servers and hunting
 *  aggressively (boosted discovery + probing). Sits ABOVE the sync progress bar
 *  when both are visible, and shows on its own when the bar is gone (e.g. a
 *  snap-peer hunt on a SYNCED node). */
@Composable
private fun HuntBanner(s: NodeSnapshot) {
    if (!s.running) return
    val targets = buildList {
        if (s.lcHunting) add("light-client servers")
        if (s.elHunting) add("snap peers")
    }
    if (targets.isEmpty()) return
    Text(
        "Hunting for ${targets.joinToString(" and ")}…",
        style = MaterialTheme.typography.bodySmall,
        color = StatusColors.Amber, // same signal family as "warming up"
        modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp)
            .semantics { contentDescription = "LC hunt active: searching for light-client servers" },
    )
}

/** App-wide beacon sync banner: indeterminate while bootstrapping, determinate as the light
 *  client catches up sync-committee periods, gone once SYNCED. */
@Composable
private fun SyncProgressBar(s: NodeSnapshot) {
    if (!s.running || s.beaconState == "SYNCED" || s.beaconState == "STOPPED") return
    if (s.beaconState == "STALE_ANCHOR") {
        // Parked, not progressing: a progress bar would promise motion. The strip,
        // the Beacon status row, and the consent dialog carry this state.
        Column(Modifier.fillMaxWidth().padding(bottom = 10.dp)) {
            Text(
                "Sync paused — trust anchor older than the weak-subjectivity bound " +
                    "(${(s.syncTargetPeriod - s.syncCurrentPeriod).coerceAtLeast(0)} periods; " +
                    "bound ${s.wsBoundPeriods}). Waiting for your decision.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        return
    }
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

/**
 * Upgrade banner (Status + Query): peers announce — or report already activated — a network
 * upgrade this build doesn't support. SCHEDULED is a heads-up with the date. ACTIVE is an
 * alarm only when [cutOff] (the node's own verified state agrees it stopped verifying);
 * otherwise it is a softer "update the app" while the node still verifies. Nothing it shows
 * feeds verification (advisory only), so a false report can't make a wrong answer look right.
 */
@Composable
private fun UpgradeBanner(u: UpgradeNotice, cutOff: Boolean) {
    val tz = remember { TimeZone.currentSystemDefault() }
    // 0 = unknown: peers are seen on the fork but nobody announced its time (a
    // consensus fork digest does not encode it).
    val at = if (u.activationEpochSec == 0L) "an unknown date"
        else formatDateTime(u.activationEpochSec * 1000, tz)
    val alarm = u.active && cutOff
    val container = if (alarm) MaterialTheme.colorScheme.errorContainer
        else MaterialTheme.colorScheme.tertiaryContainer
    val onContainer = if (alarm) MaterialTheme.colorScheme.onErrorContainer
        else MaterialTheme.colorScheme.onTertiaryContainer
    Column(
        Modifier
            .fillMaxWidth()
            .background(container)
            .padding(12.dp)
            .semantics(mergeDescendants = true) {},
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(
            when {
                alarm -> "Update required"
                u.active -> "Network upgrade reported — update the app"
                else -> "Network upgrade ahead — update required"
            },
            style = MaterialTheme.typography.titleSmall,
            color = onContainer,
        )
        Text(
            when {
                alarm -> "Peers report the network upgraded on $at, and this node is no longer " +
                    "verifying new blocks. This version can't follow the upgrade — update the app."
                u.active -> "Peers report the network upgraded on $at to rules this version " +
                    "doesn't support. This node is still verifying for now — update the app " +
                    "before it stops."
                else -> "Peers announce a network upgrade on $at that this version doesn't " +
                    "support. Update the app before then — otherwise it stops verifying at the upgrade."
            },
            fontSize = 13.sp,
            color = onContainer,
        )
        Text(
            // "0x00000000" = unknown: a blob-parameter-only fork rotates to a digest
            // this version cannot compute (see UpgradeNotice.forkId).
            "Reported by peers in ${u.observedPeers} distinct networks · fork id " +
                (if (u.forkId == "0x00000000") "unknown" else u.forkId),
            fontSize = 11.sp,
            color = onContainer,
        )
    }
}

@Composable
private fun StatusView(s: NodeSnapshot, hostSleeps: Boolean) {
    val tz = remember { TimeZone.currentSystemDefault() }
    Column {
        StatusRow("Network", s.network, help = StatusHelp.NETWORK)
        StatusRow(
            "State",
            when (s.lifecycle) {
                "PAUSED" -> "Sleeping (wakes on request)"
                "RUNNING" -> "Running"
                else -> "Stopped"
            },
            help = StatusHelp.STATE,
        )
        StatusRow("Beacon", s.beaconState, help = StatusHelp.BEACON)
        StatusRow("EL block", s.executionBlockNumber.toString(), help = StatusHelp.EL_BLOCK)
        // Tor verified-read routing (docs/privacy-and-tor.md) — shown only when it
        // applies (Rust engine + a Tor-capable build); see NodeSnapshot.tor.
        s.logIndex?.let { StatusRow("Log index", it, help = StatusHelp.LOG_INDEX) }
        s.tor?.let { mode ->
            StatusRow(
                "Tor",
                when (mode) {
                    "active" -> "routing reads (circuit ready)"
                    "on" -> "on — circuit bootstrapping…"
                    "off" -> "off"
                    else -> mode
                },
                help = StatusHelp.TOR,
                color = if (mode == "active") MaterialTheme.colorScheme.primary else null,
            )
        }
        // Peer rows, grouped by layer so a reader never has to know which of
        // "Discovered" (discv4) and "Discv5 peers" is which side. Each group's
        // header carries the two numbers people scan for — live peers and the
        // on-disk cache total — and the rows underneath keep their full values
        // and help texts. The rows that occur in both groups ("Peers", "Cache")
        // pass the qualified name as the help dialog's title, since the dialog
        // stands alone without the header above it.
        //
        // EL — the devp2p side: the snap pool, its peer cache, what EL peers
        // ask US for, and the discv4 table / dial backoff / wrong-chain lists
        // (all EL by their help texts).
        PeerGroupHeader(peerGroupTitle("EL", elPeersPhrase(s.readyPeers), s.elCachedPeers))
        // Same total-first shape as the cache row (the pool holds only ready
        // peers, so the total IS the ready count).
        StatusRow(
            "Peers",
            elPeersValue(s.readyPeers, s.snapPeers, s.snapServingPeers, s.snap2ServingPeers),
            help = StatusHelp.EL_PEERS,
            title = "EL peers",
        )
        // Cache rows: confirmed-server counts predict how fast the NEXT cold
        // start finds servers — the cache learning is visible live. One icon
        // vocabulary for both groups, sized for phone-width screens:
        // ✓ confirmed server (EL: snap-ok · CL: proven LC), ✕ confirmed not
        // (snap-bad / nolc), ? untried.
        // The derived untried bucket can't go negative from ONE CacheFileStats
        // parse (buckets are mutually exclusive per line), but coerce anyway so
        // a future host feeding these fields from another source can't render
        // "?-3".
        StatusRow(
            "Cache",
            "${s.elCachedPeers} · ✓${s.elCachedSnapOk} ✕${s.elCachedSnapBad} " +
                "?${(s.elCachedPeers - s.elCachedSnapOk - s.elCachedSnapBad).coerceAtLeast(0)}",
            help = StatusHelp.EL_CACHE,
            title = "EL cache",
        )
        // What peers ask US for: demand for our served headers/blocks, and how often we
        // could answer. Bodies-served stays 0 (light client; prompt empty replies).
        StatusRow(
            "Hdr asks",
            "${s.peerHeaderRequests} · served ${s.peerHeaderRequestsServed}",
            help = StatusHelp.HDR_ASKS,
        )
        StatusRow(
            "Blk asks",
            "${s.peerBodyRequests} · served ${s.peerBodyRequestsServed}",
            help = StatusHelp.BLK_ASKS,
        )
        StatusRow("Discovered", s.discoveredPeers.toString(), help = StatusHelp.DISCOVERED)
        StatusRow("In backoff", s.backedOffPeers.toString(), help = StatusHelp.IN_BACKOFF)
        StatusRow("Blacklisted", s.blacklistedPeers.toString(), help = StatusHelp.BLACKLISTED)

        // CL — the libp2p side: light-client servers, their cache, the discv5
        // table. The header shows "served N/min" rather than a connection
        // count: CL connections are short-lived, so "con" is usually 0 and
        // says nothing about whether the node is being served.
        PeerGroupHeader(peerGroupTitle("CL", "served ${s.clServedPeersLastMin}/min", s.clCachedPeers))
        StatusRow(
            "Peers",
            "served ${s.clServedPeersLastMin}/min, con ${s.clConnectedPeers}",
            help = StatusHelp.CL_PEERS,
            title = "CL peers",
        )
        StatusRow(
            "Cache",
            "${s.clCachedPeers} · ✓${s.clCachedProven} ✕${s.clCachedNolc} " +
                "?${(s.clCachedPeers - s.clCachedProven - s.clCachedNolc).coerceAtLeast(0)}",
            help = StatusHelp.CL_CACHE,
            title = "CL cache",
        )
        StatusRow("Discv5 peers", s.discv5Peers.toString(), help = StatusHelp.DISCV5_PEERS)
        // Close the CL group the way the headers open theirs, whether or not
        // the Reads rows follow.
        Spacer(Modifier.height(8.dp))

        // The read-fetch shadow cache (docs/read-stats.md): verified state
        // fetches this run, the share a sound cache keying would have served
        // (storage-root keyed slots, per-block accounts, content-addressed
        // code) with the storage time it would have saved, and how often a
        // value up to a minute old would still have been right. Rows appear
        // once the engine has observed a fetch; hidden on hosts that don't
        // feed the JSON. Not a peer group: these are about OUR reads.
        s.readStatsJson?.let(ReadStatsStatus::parse)?.takeIf(ReadStatsStatus::hasReads)?.let { rs ->
            StatusRow("Reads", ReadStatsStatus.fetchesLine(rs), help = StatusHelp.READS)
            StatusRow("Cacheable", ReadStatsStatus.cacheableLine(rs), help = StatusHelp.CACHEABLE)
            ReadStatsStatus.staleLine(rs)?.let {
                StatusRow("Stale ≤60s ok", it, help = StatusHelp.STALE_OK)
            }
            Spacer(Modifier.height(8.dp))
        }
        // JSON-RPC listener: where a same-device client reaches this network's
        // verified endpoint — or why it can't (port squatted / bind failed).
        if (s.rpcPort > 0) {
            if (s.rpcServing) {
                StatusRow("RPC", "127.0.0.1:${s.rpcPort}", help = StatusHelp.RPC)
            } else {
                StatusRow(
                    "RPC",
                    "port ${s.rpcPort} unavailable",
                    help = StatusHelp.RPC,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
        StatusRow(
            "Sync period",
            "${s.syncCurrentPeriod} / ${s.syncTargetPeriod}",
            help = StatusHelp.SYNC_PERIOD,
        )
        // verifiedHeadAgeMs == Long.MAX_VALUE is the "no verified head yet" sentinel — show a
        // dash instead of the raw ~9.2e18 ms, which would read as a nonsensical age.
        StatusRow(
            "Head age",
            if (s.verifiedHeadAgeMs == Long.MAX_VALUE) "—" else "${s.verifiedHeadAgeMs} ms",
            help = StatusHelp.HEAD_AGE,
        )
        StatusRow("Uptime", "${s.uptimeSeconds}s", help = StatusHelp.UPTIME)
        // Pseudo-sleep observability: how much the node has idle-slept, and when/why it
        // last woke. Foreground (opening the app) is excluded from the "last woke" reason,
        // so this keeps showing the last real request/catch-up wake even as you view it.
        // Both engines idle-sleep now (the Rust engine pauses/warm-resumes natively);
        // only a host WITHOUT an idle controller can't sleep at all — say so instead
        // of a misleading "never slept" (desktop: supportsIdleSleep=false, nothing
        // ever triggers a pause).
        StatusRow(
            "Sleep",
            when {
                !hostSleeps -> "always on"
                s.pauseCount == 0 -> "never slept"
                else -> "${formatDuration(s.totalPausedMs)} over ${s.pauseCount} " +
                    "${if (s.pauseCount == 1) "pause" else "pauses"}"
            },
            help = StatusHelp.SLEEP,
        )
        if (s.lastResumeEpochMs > 0) {
            val slept = if (s.lastPauseEpochMs > 0) " · slept ${formatLogTime(s.lastPauseEpochMs, tz)}" else ""
            StatusRow(
                "Last woke",
                "${formatLogTime(s.lastResumeEpochMs, tz)} (${s.lastWakeReason ?: "?"})$slept",
                help = StatusHelp.LAST_WOKE,
            )
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
    // Expert mode opens the result card's raw rows by default.
    expert: Boolean = false,
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
    var ensProfile by remember(network) { mutableStateOf<EnsProfile?>(null) }
    var ensProfileError by remember(network) { mutableStateOf<String?>(null) }
    var ensProfileLoading by remember(network) { mutableStateOf(false) }
    var ensOwnership by remember(network) { mutableStateOf<EnsOwnership?>(null) }
    // Both record reads came back (a host without an actual answers null, which counts).
    var ensRecordsRead by remember(network) { mutableStateOf(false) }
    // The on-demand records read in flight, so a new lookup cancels it and a superseded
    // job never writes into the card of a later name (the scanJob pattern below).
    var ensRecordsJob by remember(network) { mutableStateOf<Job?>(null) }
    var error by remember(network) { mutableStateOf<String?>(null) }
    // History is global (all chains); re-read the local snapshot after each add/clear. Start empty
    // and load off the main thread (entries() reads a file) so composition never blocks on disk.
    // Keyed on `network` like the state it fills: a chain switch resets the list, so reload it.
    var historyList by remember(network) { mutableStateOf<List<QueryHistoryEntry>>(emptyList()) }
    LaunchedEffect(network) { historyList = withContext(Dispatchers.Default) { history.entries() } }

    // --- Transaction-history scan state (TrueBlocks index; desktop-mainnet-only hosts). ---
    // Keys arrive in stream order (newest chunk first); a null row = placeholder still
    // resolving. SnapshotStateMap writes recompose only the affected row — that's the
    // "block number first, parsed tx replaces it in place" mechanic.
    var scanJob by remember(network) { mutableStateOf<Job?>(null) }
    var scanRunning by remember(network) { mutableStateOf(false) }
    var scanInfo by remember(network) { mutableStateOf<TxScanEvent.Started?>(null) }
    var scanProgress by remember(network) { mutableStateOf<TxScanEvent.Progress?>(null) }
    var scanDone by remember(network) { mutableStateOf<Int?>(null) }
    var scanError by remember(network) { mutableStateOf<String?>(null) }
    val txKeys = remember(network) { mutableStateListOf<Pair<Long, Int>>() }
    val txRows = remember(network) { mutableStateMapOf<Pair<Long, Int>, TxRowUi?>() }
    val txErrors = remember(network) { mutableStateMapOf<Pair<Long, Int>, String>() }

    fun startTxScan(address: String) {
        scanJob?.cancel()
        txKeys.clear(); txRows.clear(); txErrors.clear()
        scanInfo = null; scanProgress = null; scanDone = null; scanError = null
        scanRunning = true
        scanJob = scope.launch {
            try {
                controller.transactionHistory(network, address).collect { ev ->
                    when (ev) {
                        is TxScanEvent.Started -> scanInfo = ev
                        is TxScanEvent.Progress -> scanProgress = ev
                        is TxScanEvent.Hit -> {
                            val key = ev.blockNumber to ev.txIndex
                            if (key !in txRows) {
                                txKeys.add(key)
                                txRows[key] = null
                            }
                        }
                        is TxScanEvent.Tx -> txRows[ev.row.blockNumber to ev.row.txIndex] = ev.row
                        is TxScanEvent.Failed -> txErrors[ev.blockNumber to ev.txIndex] = ev.error
                        is TxScanEvent.Done -> scanDone = ev.total
                    }
                }
            } catch (c: CancellationException) {
                throw c  // structured cancellation (Stop button / tab left)
            } catch (t: Throwable) {
                scanError = t.message ?: t.toString()
            } finally {
                // Only the CURRENT scan may flip the flag off: a cancelled scan's finally
                // can run after its replacement already set scanRunning = true.
                if (scanJob === coroutineContext[Job]) scanRunning = false
            }
        }
    }

    // NetworkChips sit above the tab content, so the user can switch chains while a scan
    // runs. All scan state is remember(network) (so it visually resets), but the coroutine
    // lives in the tab-scoped `scope` — cancel it when `network` changes, or it keeps
    // fetching for the old address with no Stop button to reach it. onDispose reads the
    // now-departing composition's scanJob holder, i.e. the job that was actually running.
    DisposableEffect(network) {
        onDispose { scanJob?.cancel() }
    }

    // Takes the query string (not the input state) so a tapped history row runs immediately
    // without waiting for the input state write to settle.
    fun run(raw: String) {
        val q = raw.trim()
        if (q.isEmpty() || loading) return
        input = q
        loading = true; error = null; account = null; ens = null
        ensRecordsJob?.cancel(); ensRecordsJob = null
        ensProfile = null; ensProfileError = null; ensProfileLoading = false; ensOwnership = null; ensRecordsRead = false
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
        snap?.let { s ->
            s.upgrade?.let {
                UpgradeBanner(it, cutOff = upgradeCutOff(s))
                Spacer(Modifier.height(12.dp))
            }
        }
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
            // The keyboard's search key runs the lookup, like the button below.
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            keyboardActions = KeyboardActions(onSearch = { if (running) run(input) }),
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
        ens?.let { e ->
            EnsResultView(
                e, ensProfile, ensProfileError, ensProfileLoading, ensOwnership, ensRecordsRead,
                // The records beyond the address and who holds the name, on demand and
                // side by side — a name without an address can still carry both. Their
                // failures show on the card, never as the query's error.
                onReadRecords = {
                    ensRecordsJob?.cancel()
                    ensProfileLoading = true; ensProfileError = null; ensOwnership = null; ensRecordsRead = false
                    // Started lazily so the ownership check below sees THIS job even when the
                    // host answers without suspending (a dispatcher that runs it inline).
                    val job = scope.launch(start = CoroutineStart.LAZY) {
                        // A later lookup or click cancelled and replaced this job; only the
                        // job the card still owns may fill it.
                        val mine = { ensRecordsJob === coroutineContext[Job] }
                        try {
                            coroutineScope {
                                val records = async { runCatching { controller.resolveEnsProfile(network, e.name) } }
                                val holder = async { runCatching { controller.resolveEnsOwnership(network, e.name) } }
                                records.await()
                                    .onSuccess { if (mine()) ensProfile = it }
                                    .onFailure {
                                        if (it is CancellationException) throw it
                                        if (mine()) ensProfileError = it.message ?: it.toString()
                                    }
                                holder.await()
                                    .onSuccess { if (mine()) ensOwnership = it }
                                    .onFailure {
                                        if (it is CancellationException) throw it
                                        if (mine()) {
                                            ensOwnership = EnsOwnership(e.name, null, null, false, null, -1, -1, -1, false, it.message ?: it.toString())
                                        }
                                    }
                            }
                            if (mine()) ensRecordsRead = true
                        } finally {
                            if (mine()) ensProfileLoading = false
                        }
                    }
                    ensRecordsJob = job
                    job.start()
                },
            )
            Spacer(Modifier.height(12.dp))
        }
        when {
            loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text(loadingMsg)
            }
            error != null -> Text("Error: $error", color = MaterialTheme.colorScheme.error)
            account != null -> AccountResultView(account!!, nativeCurrencySymbol(network), expert)
        }

        // Transaction-history add-on (TrueBlocks Unchained Index): shown once an account
        // resolved, on hosts/networks that support the scan (desktop mainnet, Java engine).
        // supportsTransactionHistory is a cheap registry check — evaluate per composition so
        // the section appears once the node is up, without a network switch.
        val currentAccount = account
        if (!loading && currentAccount != null && running &&
            controller.supportsTransactionHistory(network)
        ) {
            Spacer(Modifier.height(20.dp))
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Transactions", style = MaterialTheme.typography.titleSmall)
                if (scanRunning) {
                    TextButton(onClick = { scanJob?.cancel() }) { Text("Stop") }
                } else {
                    Button(onClick = { startTxScan(currentAccount.address) }) {
                        Text(if (txKeys.isEmpty()) "Find transactions" else "Rescan")
                    }
                }
            }
            scanInfo?.let { TxScanInfoCaption(it) }
            if (scanRunning) {
                Spacer(Modifier.height(6.dp))
                val p = scanProgress
                if (p != null && p.totalChunks > 0) {
                    LinearProgressIndicator(
                        progress = { (p.chunksScanned.toFloat() / p.totalChunks).coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Scanning chunk ${p.chunksScanned + 1}/${p.totalChunks}" +
                            " (block ~${groupDigits(p.currentRange.substringAfter('-').trimStart('0'))})" +
                            " — ${p.hits} hit${if (p.hits == 1) "" else "s"}" +
                            " · ${formatBytes(p.bytesDownloaded)} fetched",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
            }
            scanError?.let {
                Spacer(Modifier.height(6.dp))
                Text("Scan error: $it", color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
            }
            scanDone?.let {
                Spacer(Modifier.height(6.dp))
                Text(
                    "Scan complete — $it transaction${if (it == 1) "" else "s"}.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (txKeys.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                // Plain capped Column, not LazyColumn: QueryTab's root already scrolls
                // vertically, and a nested unbounded LazyColumn would throw.
                txKeys.take(TX_ROWS_RENDER_CAP).forEach { key ->
                    val row = txRows[key]
                    val err = txErrors[key]
                    when {
                        row != null -> TxRowView(row)
                        err != null -> TxFailedRowView(key.first, key.second, err)
                        else -> TxHitRow(key.first, key.second, active = scanRunning)
                    }
                }
                if (txKeys.size > TX_ROWS_RENDER_CAP) {
                    Text(
                        "Showing the first $TX_ROWS_RENDER_CAP of ${txKeys.size} hits" +
                            " (newest first) — the counters above keep scanning.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // Recent-query history: tap a card to re-run it (uses the stored input, not the label).
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
            // One card per past query, spaced apart. The ages tick: re-read the clock every
            // 30 s, so a tab left open does not keep saying "just now".
            var now by remember { mutableStateOf(nowEpochMillis()) }
            LaunchedEffect(historyList) {
                while (true) {
                    now = nowEpochMillis()
                    delay(30_000)
                }
            }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                historyList.forEach { e ->
                    // Same gate as Look up: a stopped node cannot answer a re-run either.
                    QueryHistoryCard(e, nowMillis = now, enabled = running && !loading, onClick = { run(e.input) })
                }
            }
        }
    }
}

/**
 * One past query as a tappable card: the stored input, the resolved address beneath it
 * when there is one (an ENS lookup), and how long ago it ran. Tapping re-runs the
 * stored input, not the label.
 */
@Composable
private fun QueryHistoryCard(e: QueryHistoryEntry, nowMillis: Long, enabled: Boolean, onClick: () -> Unit) {
    OutlinedCard(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().semantics { role = Role.Button },
    ) {
        // A disabled card dims its content colour; the secondary lines follow it then rather than
        // keep their own, so the whole card reads as disabled.
        val secondary = if (enabled) MaterialTheme.colorScheme.onSurfaceVariant else LocalContentColor.current
        Row(
            Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    e.input,
                    fontFamily = FontFamily.Monospace, fontSize = 13.sp,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                if (e.label.isNotEmpty()) {
                    Text(
                        e.label,
                        fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                        color = secondary,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Spacer(Modifier.width(12.dp))
            Text(
                historyAge(e.timestampMillis, nowMillis),
                style = MaterialTheme.typography.labelSmall,
                color = secondary,
            )
        }
    }
}

/** The wall clock in epoch milliseconds; kotlin.time's Clock is @ExperimentalTime in the 2.2 stdlib. */
@OptIn(kotlin.time.ExperimentalTime::class)
private fun nowEpochMillis(): Long = Clock.System.now().toEpochMilliseconds()

/** How long ago a past query ran, for its card: "just now", "5 min ago", "3 h ago", "2 d ago". */
internal fun historyAge(thenMillis: Long, nowMillis: Long): String {
    val sec = ((nowMillis - thenMillis) / 1000).coerceAtLeast(0)
    return when {
        sec < 60 -> "just now"
        sec < 3_600 -> "${sec / 60} min ago"
        sec < 86_400 -> "${sec / 3_600} h ago"
        else -> "${sec / 86_400} d ago"
    }
}

// Rendering cap for the streamed transaction list. The scan itself keeps running past
// this (the progress line keeps counting); a debug list longer than this isn't readable.
private const val TX_ROWS_RENDER_CAP = 300

// Index tip trailing the verified head by more than this gets the loud staleness
// banner. ~100k mainnet blocks ≈ 14 days — beyond that, "recent history" is missing.
private const val TX_INDEX_STALE_BLOCKS = 100_000L

// Mainnet block time, for turning a block gap into a human age.
private const val SECONDS_PER_BLOCK = 12L

/**
 * Freshness + trust caption for the scan: which manifest, how it was found, index tip
 * vs head. When the index trails the verified head badly (upstream TrueBlocks publishing
 * has stalled for ~a year as of mid-2026), a prominent warning banner spells out the
 * approximate age and the cutoff block — a small amber caption undersold a gap that
 * makes ALL recent history silently absent.
 */
@Composable
private fun TxScanInfoCaption(info: TxScanEvent.Started) {
    val lagBlocks = info.headBlock?.let { it - info.latestIndexedBlock } ?: -1L
    val veryStale = lagBlocks > TX_INDEX_STALE_BLOCKS
    val degradedSource = info.cidSource != "contract"
    val cidShort = if (info.manifestCid.length > 12) {
        "${info.manifestCid.take(8)}…${info.manifestCid.takeLast(4)}"
    } else info.manifestCid

    if (veryStale) {
        val ageDays = lagBlocks * SECONDS_PER_BLOCK / 86_400
        Spacer(Modifier.height(6.dp))
        Column(
            Modifier.fillMaxWidth()
                .background(MaterialTheme.colorScheme.errorContainer)
                .padding(10.dp),
        ) {
            Text(
                "⚠ Index is ~$ageDays days behind the chain head",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                "Indexed to block ${groupDigits(info.latestIndexedBlock.toString())}, head is " +
                    "${groupDigits(info.headBlock.toString())} — anything after the indexed block " +
                    "will NOT appear below. This is the newest index the TrueBlocks publisher " +
                    "has released, not a sync problem on this node.",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
        }
        Spacer(Modifier.height(4.dp))
    }
    Text(
        buildString {
            append("Index $cidShort (").append(info.cidSource).append(")")
            append(" · indexed to block ").append(groupDigits(info.latestIndexedBlock.toString()))
            info.headBlock?.let { append(" · head ").append(groupDigits(it.toString())) }
            append(" · results unverified — debug aid")
        },
        style = MaterialTheme.typography.bodySmall,
        // Amber when the CID didn't come from the live contract read (cached/hardcoded),
        // or when staleness can't be judged (no verified head to compare against).
        color = if (degradedSource || info.headBlock == null) StatusColors.Amber
        else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** Placeholder row: the index hit's block number. Shows a spinner + "fetching…" while the
 *  scan is live; once the scan is stopped, an unresolved hit reads "not fetched (stopped)"
 *  instead of a forever-spinning row. */
@Composable
private fun TxHitRow(blockNumber: Long, txIndex: Int, active: Boolean) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (active) {
            CircularProgressIndicator(Modifier.size(12.dp), strokeWidth = 1.5.dp)
            Spacer(Modifier.width(8.dp))
        }
        Text(
            "#${groupDigits(blockNumber.toString())} · tx $txIndex · " +
                if (active) "fetching…" else "not fetched (scan stopped)",
            fontFamily = FontFamily.Monospace, fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** Resolved row: succinct headline, block/from/hash beneath; tap to copy the tx hash. */
@Composable
private fun TxRowView(row: TxRowUi) {
    val clipboard = LocalClipboardManager.current
    Column(
        Modifier
            .fillMaxWidth()
            .clickable { clipboard.setText(AnnotatedString(row.hash)) }
            .padding(vertical = 4.dp),
    ) {
        Text(row.headline, style = MaterialTheme.typography.bodyMedium)
        Text(
            buildString {
                append("#").append(groupDigits(row.blockNumber.toString()))
                row.from?.let { append(" · from ").append(it.take(8)).append('…').append(it.takeLast(4)) }
                append(" · ").append(row.hash.take(10)).append('…')
                append(" · tap to copy hash")
            },
            fontFamily = FontFamily.Monospace, fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1, overflow = TextOverflow.Ellipsis,
        )
    }
}

/** A hit whose tx couldn't be fetched/decoded — kept in place so the list stays honest. */
@Composable
private fun TxFailedRowView(blockNumber: Long, txIndex: Int, error: String) {
    Text(
        "#${groupDigits(blockNumber.toString())} · tx $txIndex — $error",
        fontFamily = FontFamily.Monospace, fontSize = 12.sp,
        color = MaterialTheme.colorScheme.error,
        modifier = Modifier.padding(vertical = 4.dp),
        maxLines = 1, overflow = TextOverflow.Ellipsis,
    )
}

/** "22841000" → "22,841,000" (pure Kotlin; commonMain has no NumberFormat). */
private fun groupDigits(s: String): String {
    val digits = s.ifEmpty { "0" }
    if (digits.length <= 3 || !digits.all { it in '0'..'9' }) return digits
    return digits.reversed().chunked(3).joinToString(",").reversed()
}

private fun formatBytes(b: Long): String = when {
    b >= 1_073_741_824 -> "${(b * 10 / 1_073_741_824).toDouble() / 10} GB"
    b >= 1_048_576 -> "${b / 1_048_576} MB"
    b >= 1024 -> "${b / 1024} KB"
    else -> "$b B"
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

/**
 * A verified account, balance first: the address, the balance in the chain's native
 * [currency] (or that there is no account yet), a verification badge, the two numbers
 * a wallet user looks for, and the raw rows behind "Show raw details" — open from the
 * start under [expert].
 */
@Composable
private fun AccountResultView(a: AccountResult, currency: String?, expert: Boolean) {
    val clipboard = LocalClipboardManager.current
    var showRaw by remember(expert) { mutableStateOf(expert) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    a.address,
                    Modifier.weight(1f),
                    fontFamily = FontFamily.Monospace, fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.width(8.dp))
                // One-tap copy of the FULL result (untruncated hex), for pasting into a block explorer.
                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(formatAccountResult(a, currency))) }) {
                    Text("Copy")
                }
            }
            // The numbers below are a peer's claim until the beacon chain vouches for them:
            // an unverified result leads with the red pill and shows the balance muted, so
            // the headline figure never looks more authoritative than it is.
            val verified = a.beaconChainVerified
            if (!verified) VerificationBadge(a)
            if (a.exists) {
                Column {
                    // On mainnet the verified caption reads "Balance (ETH)" verbatim: the iOS
                    // UI test (QueryFlowTests) waits for it.
                    Text(
                        if (verified) balanceCaption(currency) else "${balanceCaption(currency)} — unverified peer claim",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        formatNative(a.balanceWei),
                        style = MaterialTheme.typography.headlineMedium,
                        color = if (verified) Color.Unspecified else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                // Non-existence is a claim too — a peer hiding a balance would make exactly this one.
                Text(
                    if (verified) "No account at this address yet"
                    else "No account at this address yet — unverified peer claim",
                    style = MaterialTheme.typography.titleMedium,
                    color = if (verified) Color.Unspecified else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    if (verified) "Nothing has been sent to it on this chain, so there is no balance to show."
                    else "A peer reports nothing has been sent to it; the node could not verify that yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (verified) VerificationBadge(a)
            Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                // The nonce, in a wallet user's words — a contract's counts its creations.
                // Muted with the balance while the result is a claim.
                if (a.exists) ResultStat("Transactions sent (nonce)", a.nonce.toString(), muted = !verified)
                // The block's age beneath its number, when the engine proved the
                // block's timestamp (it does for a verified read of the attested block).
                ResultStat(
                    "Block", a.blockNumber.toString(), muted = !verified,
                    detail = rememberBlockAge(a.blockTimestamp),
                )
            }
            TextButton(onClick = { showRaw = !showRaw }) {
                Text(if (showRaw) "Hide raw details" else "Show raw details")
            }
            if (showRaw) {
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
                // The verification verdict is the pill above; the raw rows don't repeat it.
            }
        }
    }
}

/** A small labelled number on the result card; [muted] while the result is only a peer's claim. */
@Composable
private fun ResultStat(label: String, value: String, muted: Boolean, detail: String? = null) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = MaterialTheme.typography.titleMedium,
            color = if (muted) MaterialTheme.colorScheme.onSurfaceVariant else Color.Unspecified,
        )
        // A small line beneath the value, e.g. a block's age.
        detail?.let {
            Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * The result's verification as a pill: green "Verified" with the method (and BLS when
 * the match was signed), red "Unverified" with the ladder's fail reason. Nothing here
 * is served unverified — a red pill leads the card and says a peer's claim could not be
 * tied to the beacon chain, and the muted numbers below it are that claim.
 */
@Composable
private fun VerificationBadge(a: AccountResult) {
    val ok = a.beaconChainVerified
    val color = if (ok) StatusColors.Green else StatusColors.Red
    val text = if (ok) {
        "✓ Verified" + (a.verifyMethod?.let { " · $it" } ?: "") + (if (a.blsVerified) " · BLS" else "")
    } else {
        "✗ Unverified · ${a.failReason ?: "unknown"}"
    }
    Surface(shape = RoundedCornerShape(50), color = color.copy(alpha = 0.15f)) {
        Text(
            text,
            Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelLarge,
            color = color,
        )
    }
}

/**
 * The native currency a chain's balances are counted in, as a wallet shows it: xDAI on
 * Gnosis Chain, ETH on mainnet and Sepolia (Sepolia's is test ether). Null for a network
 * this table does not know, and the card then names no unit: a network added later reads
 * "Balance" until it is listed here, never a wrong symbol. Every listed chain has 18
 * decimals, which is what [formatNative] assumes; check that before listing a new one.
 */
internal fun nativeCurrencySymbol(network: String): String? = when (network) {
    "mainnet", "sepolia" -> "ETH"
    "gnosis" -> "xDAI"
    else -> null
}

/** The balance caption: "Balance (ETH)", or just "Balance" when the unit is unknown. */
internal fun balanceCaption(currency: String?): String =
    if (currency != null) "Balance ($currency)" else "Balance"


/** Wei (decimal string) → the native currency with 6 dp, truncated toward zero; 18 decimals
 *  on every supported chain ([nativeCurrencySymbol]). Pure-Kotlin (commonMain has no
 *  java.math.BigDecimal): pad to ≥19 digits, split at the 18th from the right. Non-numeric input
 *  passes through unchanged. */
private fun formatNative(weiDecimal: String?): String {
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
private fun formatAccountResult(a: AccountResult, currency: String?): String = buildString {
    appendLine("address: ${a.address}")
    appendLine("exists: ${a.exists}")
    if (a.exists) {
        appendLine((if (currency != null) "balance ($currency)" else "balance") + ": ${formatNative(a.balanceWei)}")
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
private fun EnsResultView(
    e: EnsResult,
    profile: EnsProfile?,
    profileError: String?,
    profileLoading: Boolean,
    ownership: EnsOwnership?,
    recordsRead: Boolean,
    onReadRecords: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val uriHandler = LocalUriHandler.current
    val tz = remember { TimeZone.currentSystemDefault() }
    var gatewayNote by remember(e.name) { mutableStateOf<String?>(null) }
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
        // The block's age next to its number, from the verified header the resolution ran against.
        val age = rememberBlockAge(e.blockTimestamp)
        StatusRow(
            "Block",
            when {
                e.blockNumber < 0 -> "—"
                age != null -> "${e.blockNumber} · $age"
                else -> e.blockNumber.toString()
            },
        )
        StatusRow(
            "Verified",
            if (e.verified) "✓ finalized" else "unverified (peer head)",
            color = if (e.verified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
        )
        if (e.error != null) {
            StatusRow("Error", e.error, color = MaterialTheme.colorScheme.error)
        }
        // The records beyond the address, on demand: the contenthash decoded (ipfs://, ipns://,
        // bzz://) with a gateway link labelled for what it is — a third party, off the verified
        // path — and the text records as key: value, selectable and never cut short; a record
        // read from the peer head says so. One failure shared by every record is one line.
        // Offered until both reads came back clean — a failed read keeps it, as the retry;
        // a host without one of the actuals answers null, which is a read that came back.
        val readable = !recordsRead || profileError != null || ownership?.error != null
        if (e.error == null && readable) {
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(enabled = !profileLoading, onClick = onReadRecords) { Text("Read records") }
                Spacer(Modifier.width(8.dp))
                if (profileLoading) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                    Text("Reading records…", style = MaterialTheme.typography.bodySmall)
                } else {
                    HelpButton(
                        "ENS records",
                        "Reads who holds the name (registrant, manager, resolver, expiry and grace " +
                            "period — the registry and the .eth registrar, seen through the NameWrapper), " +
                            "the name's contenthash (ENSIP-7 — an IPFS, IPNS or Swarm pointer) and its " +
                            "common text records (avatar, description, url, email, com.twitter, " +
                            "com.github, org.telegram, com.discord), each verified against finalized " +
                            "state where possible — a record served from the peer head is marked as " +
                            "such. Every record is its own resolution, so this costs more than the " +
                            "address lookup.",
                    )
                }
            }
        }
        // Who holds the name: the registrant (the .eth token owner), the manager (the
        // registry owner, who sets records and subnames), the resolver, and the term —
        // with the grace period spelled out, since an expired name in it is still the
        // registrant's to renew and nobody else's to register.
        ownership?.let { o ->
            when {
                o.error != null -> StatusRow("Ownership", o.error, color = MaterialTheme.colorScheme.error)
                !o.known -> Text("Nothing on chain for this name.", style = MaterialTheme.typography.labelSmall)
                else -> SelectionContainer {
                    Column {
                        val style = MaterialTheme.typography.bodySmall
                        o.registrantHex?.let { Text("Registrant: $it", style = style) }
                        o.managerHex?.let { Text("Manager: $it" + if (o.wrapped) " (wrapped)" else "", style = style) }
                        o.resolverHex?.let { Text("Resolver: $it", style = style) }
                        if (o.expiresAt >= 0) {
                            Text(ensExpiryLine(o.expiresAt, o.gracePeriodSeconds, nowSeconds(), tz), style = style)
                        }
                        if (!o.verified) Text("Ownership read from the peer head.", style = style)
                    }
                }
            }
        }
        profile?.let { p ->
            val peerHead = " (peer head)"
            val common = p.records.map { it.error }.distinct().singleOrNull()
            if (common != null && p.records.all { it.value == null }) {
                StatusRow("Records", common, color = MaterialTheme.colorScheme.error)
                return@let
            }
            val content = p.records.firstOrNull { it.key == ENS_CONTENTHASH_KEY }
            val contentHex = content?.value
            if (contentHex != null) {
                val link = decodeContenthash(contentHex)
                SelectionContainer {
                    Text(
                        "Content: " + (link?.uri ?: "undecoded $contentHex") + if (content.verified) "" else peerHead,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedButton(onClick = { clipboard.setText(AnnotatedString(link?.uri ?: contentHex)) }) {
                        Text(if (link != null) "Copy link" else "Copy hex")
                    }
                    val gateway = ensGatewayUrl(e.name)
                    if (link != null && gateway != null) {
                        OutlinedButton(onClick = {
                            // A browser launch can throw (no handler for https on this host);
                            // the link on the clipboard is the fallback, said in one line.
                            runCatching { uriHandler.openUri(gateway) }.onFailure {
                                clipboard.setText(AnnotatedString(gateway))
                                gatewayNote = "Could not open a browser — $gateway is on the clipboard."
                            }
                        }) { Text("Open via eth.limo") }
                        HelpButton(
                            "eth.limo",
                            "Opens $gateway — eth.limo is a THIRD-PARTY gateway that resolves the name " +
                                "itself and serves the content over HTTPS. What the browser shows is " +
                                "not verified by this node: compare it with the content link above, " +
                                "which is.",
                        )
                    }
                }
                gatewayNote?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            } else if (content?.error != null) {
                StatusRow("Content", content.error, color = MaterialTheme.colorScheme.error)
            }
            val texts = p.records.filter { it.key != ENS_CONTENTHASH_KEY && (it.value != null || it.error != null) }
            if (texts.isNotEmpty()) {
                SelectionContainer {
                    Column {
                        texts.forEach { r ->
                            val v = r.value
                            if (v != null) {
                                Text("${r.key}: $v" + if (r.verified) "" else peerHead, style = MaterialTheme.typography.bodySmall)
                            } else {
                                Text("${r.key}: ${r.error}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                }
            }
            if (contentHex == null && content?.error == null && texts.isEmpty()) {
                Text("No records beyond the address.", style = MaterialTheme.typography.labelSmall)
            }
        }
        profileError?.let { StatusRow("Records", it, color = MaterialTheme.colorScheme.error) }
    }
}

/** A Status-tab row: label, value, and — when [help] is given — a "ⓘ" hint. Nothing else
 *  in a row is interactive, so the whole row is the tap target for the explanation. The
 *  help dialog is titled [title], which defaults to the row's own label; a row whose
 *  label is only meaningful under its group header ("Peers" under "EL · …") passes the
 *  qualified name so the dialog can stand on its own. */
@Composable
private fun StatusRow(
    key: String,
    value: String,
    help: String? = null,
    color: Color? = null,
    title: String = key,
) {
    var showHelp by remember { mutableStateOf(false) }
    // The row's own text names it for screen readers; the click label names the action.
    val tappable = if (help == null) Modifier else Modifier.clickable(
        onClickLabel = "show explanation",
        role = Role.Button,
    ) { showHelp = true }
    Row(Modifier.fillMaxWidth().then(tappable).padding(vertical = 2.dp)) {
        Row(Modifier.width(160.dp)) {
            // weight(1f) reserves the badge's own width first, so a long label truncates
            // instead of the two overflowing the 160dp column into the value's Text.
            // A row whose label repeats across groups ("Peers") is announced by its
            // qualified title, so a screen reader hears the layer the eye gets
            // from the header above.
            val named = if (title == key) Modifier else Modifier.semantics { contentDescription = title }
            Text(
                key,
                Modifier.weight(1f, fill = false).then(named),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (help != null) HelpGlyph(Modifier.padding(start = 4.dp))
        }
        Text(
            value,
            color = color ?: Color.Unspecified,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
    if (showHelp && help != null) HelpDialog(title, help) { showHelp = false }
}

/** A standalone "ⓘ" for items whose own tap is already an action (the buttons). */
@Composable
private fun HelpButton(title: String, help: String) {
    var showHelp by remember { mutableStateOf(false) }
    IconButton(
        onClick = { showHelp = true },
        modifier = Modifier.semantics { contentDescription = "Help: $title" },
    ) { HelpGlyph(fontSize = 16.sp) }
    if (showHelp) HelpDialog(title, help) { showHelp = false }
}

@Composable
private fun HelpGlyph(modifier: Modifier = Modifier, fontSize: TextUnit = 11.sp) {
    Text(
        "ⓘ",
        fontSize = fontSize,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        // Decorative: the tap target carries the label for screen readers.
        modifier = modifier.clearAndSetSemantics {},
    )
}

/** The explanation stays up until dismissed (Close, tap outside, or back). */
@Composable
private fun HelpDialog(title: String, help: String, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        // AlertDialog's text slot doesn't scroll; long entries at large font scales would clip.
        text = { Text(help, Modifier.verticalScroll(rememberScrollState())) },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

/**
 * A peer group's header on the Status tab: `EL · 12 peers · 96 cache` /
 * `CL · served 2/min · 3 cache`. [peers] is the group's live-peer phrase as
 * the caller words it (the EL side counts ready pool peers — [elPeersPhrase] —
 * the CL side counts servers that answered in the last minute), [cache] the
 * on-disk peer-cache total — the same number the group's Cache row starts with.
 */
internal fun peerGroupTitle(layer: String, peers: String, cache: Int): String =
    "$layer · $peers · $cache cache"

/** The EL header's peer phrase: `12 peers`, `0 peers` — and `1 peer`, a common
 *  state on phones (snap target 3, pools often at 1–2). */
internal fun elPeersPhrase(ready: Int): String = "$ready ${if (ready == 1) "peer" else "peers"}"

/** The header above a Status-tab peer group (see [peerGroupTitle]). A semantics
 *  heading, so a screen-reader user exploring the rows underneath — which say
 *  just "Peers" / "Cache" — can navigate by headings to learn the layer. */
@Composable
private fun PeerGroupHeader(title: String) {
    Spacer(Modifier.height(8.dp))
    Text(title, Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(2.dp))
}

/**
 * The EL group's "Peers" row value: `ready · snap M · serving K`, with the number of
 * serving peers connected over snap/2 (EIP-8189) in parentheses after K —
 * "serving 8 (3)". No parentheses while none of them is on snap/2, so a pool that
 * is all snap/1 reads exactly as it did before snap/2 existed.
 */
internal fun elPeersValue(ready: Int, snap: Int, serving: Int, snap2Serving: Int): String {
    val snap2 = if (snap2Serving > 0) " ($snap2Serving)" else ""
    return "$ready · snap $snap · serving $serving$snap2"
}

/**
 * Status-tab help text, one entry per on-screen item — the in-app twin of
 * docs/status-screen.md. **Keep both in sync**: a behavior change to
 * [StatusView]/[ReadinessStrip]/[StatusTab] that changes what a row means
 * must update its string here AND the matching row in that doc.
 */
private object StatusHelp {
    const val NETWORK = "The chain name (mainnet / sepolia / gnosis / …)."
    const val STATE = "Stack lifecycle: sleeping (idle-paused — networking off, RPC still " +
        "listening), running, or stopped."
    const val BEACON = "Beacon light client sync state (STARTING/SYNCING/CATCHING_UP/SYNCED/" +
        "STALE_ANCHOR). On Android, STARTING shows as STOPPED and the sync bar is then hidden. " +
        "SYNCED alone doesn't guarantee reads succeed — see Head age."
    const val EL_BLOCK = "Block number of the latest beacon-finalized execution payload — not " +
        "the optimistic head eth_blockNumber uses. Trails the chain head by about two epochs " +
        "(~64–96 blocks on mainnet) on a healthy node."
    const val LOG_INDEX = "Log index backfill progress, e.g. \"12,041 logs · " +
        "5,594,611–8,461,900\", or \"backfilling\". Shown only when the log index feature applies."
    const val TOR = "Desktop only, and only with the Rust engine on a -PtorEngine build. " +
        "Scope: only account (balance/nonce) reads route over Tor today — storage/token reads, " +
        "eth_call/gas estimation, tx broadcast, the CL fetch, and discovery still leave from " +
        "your real IP."
    const val CL_PEERS = "\"served N/min\" = distinct peers that answered a light-client " +
        "request in the last 60s. \"con N\" = currently-connected CL peers — usually near 0, " +
        "since connections are short-lived."
    const val EL_PEERS = "\"N\" ready peers total, \"snap M\" negotiated snap (snap/1 or " +
        "snap/2), \"serving K\" can answer a read right now. A number in parentheses after it " +
        "— \"serving 8 (3)\" — is how many of those serving peers are connected over snap/2, " +
        "the newer protocol version; no parentheses means all of them are on snap/1. Reads work " +
        "the same on both. Reads gate on serving, not snap — a cold pool can show snap peers " +
        "for hours before any of them can actually serve."
    const val CL_CACHE = "Peers in the on-disk CL peer cache: total · ✓ proven light-client " +
        "servers · ✕ confirmed non-servers · ? untried. Predicts how fast the next cold start " +
        "finds servers."
    const val EL_CACHE = "Peers in the on-disk EL (snap) peer cache: total · ✓ confirmed " +
        "snap-serving · ✕ confirmed snap-denied · ? untried."
    const val HDR_ASKS = "GetBlockHeaders requests other peers sent us: total received · " +
        "served with a non-empty reply."
    const val BLK_ASKS = "GetBlockBodies requests other peers sent us. Served is always 0 by " +
        "design — this light client holds no bodies."
    const val READS = "Verified account/storage/code fetches that crossed the network since " +
        "start (the read-fetch shadow cache — docs/read-stats.md)."
    const val CACHEABLE = "Share of each kind's fetches a SOUND cache keying would have served " +
        "for free (storage-root for slots, per-block for accounts, content-addressing for " +
        "code), with the time it would have saved."
    const val STALE_OK = "Of repeats within a minute of the last fetch, how often the value " +
        "was still correct — the ceiling for an UNSOUND \"serve a value up to a minute old\" " +
        "strategy. Not a proposal to actually do this; nothing here is served unverified."
    const val DISCOVERED = "EL peers currently in the discv4 (Kademlia) routing table — a live " +
        "table size, not a running total. Shrinks as buckets evict, and is 0 while the stack " +
        "sleeps."
    const val DISCV5_PEERS = "Live nodes currently in the discv5 (CL-side) routing table."
    const val IN_BACKOFF = "Peers currently in dial backoff after a recent failed connection " +
        "attempt — won't be redialed until it expires."
    const val BLACKLISTED = "Peers blacklisted as wrong-chain (network-id/genesis mismatch, or " +
        "an undecodable Status from a foreign chain) — not re-dialed until the stack restarts " +
        "(on the Rust engine, also cleared by a sleep/wake)."
    const val RPC = "Local JSON-RPC listener for this network. Hidden if the host doesn't " +
        "report a port. Shows the bind address, or \"unavailable\" if the port was already taken."
    const val SYNC_PERIOD = "Sync-committee period progress: current / target. While parked in " +
        "STALE_ANCHOR, current is the refused anchor's period and target is the wall clock's " +
        "period."
    const val HEAD_AGE = "Freshness, in ms, of the head context verified reads are served " +
        "against. \"—\" = no verified head yet, so no read can be served. The UI turns amber " +
        "past 45s."
    const val UPTIME = "Seconds since this network's stack started running."
    const val SLEEP = "Idle-sleep summary: \"always on\" if this host can't idle-sleep, " +
        "\"never slept\", or the total time paused over N pauses."
    const val LAST_WOKE = "When the node last woke on a real request, and why (foreground/" +
        "app-open wakes don't count). \"slept\" is the most recent time it went to sleep — " +
        "which can be AFTER this wake, if it's asleep again now."

    const val READINESS = "The card's headline is the readiness ladder, worst first: Sleeping → " +
        "No internet connection → Not running → Update required → Needs your decision → Syncing → " +
        "Almost ready → Ready. \"Ready\" means verified reads are being served; the strip above " +
        "turns bright green once the peer pool is deep enough for heavy wallet screens too. " +
        "\"Ready — log index catching up\" means reads work but log queries near the head are " +
        "refused until the index has caught up. The tiles: Execution peers = peers that can " +
        "answer a read right now, of all connected; Consensus = the beacon light client's state " +
        "and how many servers answered in the last minute; Verified head = how old the head your " +
        "answers come from is (fresh under 45 s); Log index (if enabled) = whether it serves at " +
        "the head — an incomplete history is noted, but does not affect readiness."
    const val START_STOP = "Runtime-only start/stop — independent of the network's enabled " +
        "switch in Settings. Exception: starting a disabled network also enables it, so a " +
        "cold host has something to boot next time."
    const val CLEAR_CACHES = "Wipes the on-disk peer caches through the engine for a fresh " +
        "discovery slate. Only enabled while stopped — a guard rail against clicking it on a " +
        "live node, not a hard lock."
    const val RESET_SYNC_STATE = "Deletes the persisted sync snapshot; the next start " +
        "re-bootstraps from the embedded checkpoint alone. If this build is older than the " +
        "network's weak-subjectivity bound, that parks the next start in STALE_ANCHOR — " +
        "updating the app first avoids that."
}

/**
 * Live log viewer over [LogSource]: poll the cheap version counter and re-snapshot only on
 * change; filter by substring on tag/message; auto-follow the tail unless the user scrolls up;
 * copy the newest visible lines that fit [LOG_COPY_BUDGET_CHARS] ([copyNewest]), save the whole
 * log through the host ([LogSource.saveLog]), or clear the ring. Mirrors the Android Logs tab.
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
    // One line under the buttons about the last Copy / Save: what the copy holds (and that it
    // was cut), or where the host put the file.
    var exportNote by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }

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
    // Tail-follow is explicit intent state, NOT re-derived from layout on every append: the old
    // "last visible >= shown.size - 2" check compared a stale layout against the fresh list, so
    // any poll batch of more than 2 lines silently broke follow (how often depended on each
    // platform's log volume and frame timing). Entering the tab starts following — this
    // composition is disposed on tab switch, so `remember` resets the flag to true per visit.
    var follow by remember { mutableStateOf(true) }
    // Guards the auto-snap below so its own scrollToItem can't read as a user scroll.
    var autoSnapping by remember { mutableStateOf(false) }
    // "At the tail" with ~1 item of tolerance (trackpad jitter, a stop a hair above the last
    // line). Index and count come from the SAME layout pass, so a freshly-appended batch that
    // hasn't been laid out yet can't skew the comparison the way the old shown.size check did.
    fun nearTail(): Boolean {
        val info = listState.layoutInfo
        val last = info.visibleItemsInfo.lastOrNull() ?: return true
        return last.index >= info.totalItemsCount - 2
    }
    // Break: any scroll this composable didn't initiate that leaves the tail stops following.
    // isScrollInProgress covers every input path uniformly — touch drag/fling, desktop mouse
    // wheel and trackpad, and accessibility scroll actions (which bypass nested scroll and
    // pointer input entirely, so a NestedScrollConnection would miss them).
    LaunchedEffect(listState) {
        snapshotFlow { listState.isScrollInProgress && !autoSnapping && !nearTail() }
            .collect { if (it) follow = false }
    }
    // Resume: coming to rest at the tail re-arms following (drag, fling, or the button below).
    // canScrollBackward keeps a list that merely FITS the viewport from re-arming — without it,
    // scrolling up to read and then typing a filter that shrinks `shown` onto one screen would
    // silently flip follow back on, and clearing the filter would yank away the reading
    // position. Reading `follow` in the expression re-evaluates it when only the flag changed,
    // so a break-then-return while the layout stays put can't leave follow stuck off.
    LaunchedEffect(listState) {
        snapshotFlow { !follow && listState.canScrollBackward && nearTail() }
            .collect { if (it) follow = true }
    }
    // Snap while following, keyed on the tail line's identity — sequence, not size, because at
    // ring capacity the size stays constant while lines shift. One long-lived collector instead
    // of an effect restart per 250ms poll (snapshotFlow conflates, and emits nothing at all
    // while follow is off or the tail is unchanged).
    LaunchedEffect(listState) {
        snapshotFlow { if (follow) shown.lastOrNull()?.sequence else null }
            .collect {
                if (it != null) {
                    autoSnapping = true
                    try {
                        // Re-check: `shown` can go empty (Clear, filter) between the emission
                        // and this collect step, and scrollToItem(-1) throws.
                        if (shown.isNotEmpty()) listState.scrollToItem(shown.size - 1)
                    } finally {
                        autoSnapping = false
                    }
                }
            }
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
                    // Formatting goes off the main thread. The copy is the NEWEST shown lines
                    // that fit the budget, behind a note when it had to cut — a paste of the
                    // whole ring loses its tail wherever it lands (see LOG_COPY_BUDGET_CHARS).
                    val copy = withContext(Dispatchers.Default) { copyNewest(shown, tz, logs.canSaveLog) }
                    clipboard.setText(AnnotatedString(copy.text))
                    exportNote = copy.status()
                }
            }) { Text("Copy") }
            if (logs.canSaveLog) {
                Spacer(Modifier.width(4.dp))
                // The whole log, through the host: its on-disk file where it keeps one, else
                // the unfiltered ring, streamed. The ring is snapshotted when the host writes,
                // not at the click: nothing big is held while the host's picker is open, and
                // the file holds what was logged up to the write. The host answers with one
                // line, maybe from a worker thread; a host that throws instead is reported the
                // same way, so the button never stays disabled. The label stays put while
                // disabled — a wider "Saving…" would reflow the row at phone width.
                OutlinedButton(
                    enabled = !saving,
                    onClick = {
                        saving = true
                        exportNote = null
                        val started = runCatching {
                            logs.saveLog(
                                suggestedLogFileName(tz),
                                { sink -> formatLogsTo(sink, logs.snapshot(), tz) },
                            ) { line ->
                                exportNote = line
                                saving = false
                            }
                        }.getOrElse {
                            exportNote = "Save failed: ${it.message ?: it::class.simpleName}"
                            false
                        }
                        if (!started) saving = false
                    },
                ) { Text("Save…") }
            }
            Spacer(Modifier.width(4.dp))
            // Clearing empties the ring — tail-follow the fresh lines that come after.
            OutlinedButton(onClick = { logs.clear(); follow = true }) { Text("Clear") }
        }
        exportNote?.let { Text(it, style = MaterialTheme.typography.labelSmall) }
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
            LazyColumn(state = listState, modifier = Modifier.fillMaxSize().testTag("logList")) {
                items(shown, key = { it.sequence }) { LogLineRow(it, tz) }
            }
            if (!follow && shown.isNotEmpty()) {
                Button(
                    // Setting follow makes the snap collector emit, which scrolls to the tail.
                    onClick = { follow = true },
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

/** yyyy-MM-dd HH:mm in [tz] (a date the user plans around, not a log stamp) — cut from
 *  the ISO-8601 form, which is stable across kotlinx-datetime's field renames. */
@OptIn(kotlin.time.ExperimentalTime::class)
private fun formatDateTime(ms: Long, tz: TimeZone): String =
    Instant.fromEpochMilliseconds(ms).toLocalDateTime(tz).toString().take(16).replace('T', ' ')

/** Wall-clock seconds, for a term's "in N days" on the ENS card. */
@OptIn(kotlin.time.ExperimentalTime::class)
private fun nowSeconds(): Long = kotlin.time.Clock.System.now().epochSeconds

/** The confirm button of the Index tab's remove dialog — every row's own button reads "Remove" too. */
internal const val INDEX_REMOVE_CONFIRM_TAG = "index-remove-confirm"

/**
 * The log-index tab: the feature's home. Enter the contracts to watch (address +
 * the block to index back to), toggle collection per network, import portable
 * snapshots, and read per-contract backfill progress. Data rides the snapshot's
 * raw status JSON (2 s cadence, same as everything else).
 */
@Composable
private fun IndexTab(
    controller: NodeController,
    settings: Settings,
    snapshot: NodeSnapshot?,
    network: String,
    // Turning collection off for the last enabled network can hide this tab (the
    // screen falls back to Status), so the screen needs to hear about flag changes.
    onLogIndexChanged: () -> Unit = {},
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        var collecting by remember(network) { mutableStateOf(settings.logIndexEnabled(network)) }
        // The persisted watch store. The tab is not its only writer — a host
        // changes it from its own thread (an import's contracts are added, a
        // delivered removal's marker dropped; see LogIndexWatch) — so it is
        // re-read with every status snapshot as well as after every edit here,
        // and an edit starts from the store's CURRENT value, never from this copy.
        var storeRev by remember(network) { mutableStateOf(0) }
        val store = remember(network, storeRev, snapshot) { settings.logIndexWatchJson(network) }
        val watch = remember(store) { LogIndexWatch.parse(store) }
        val unwatched = remember(store) {
            LogIndexWatch.unwatched(store).mapTo(HashSet()) { it.lowercase() }
        }
        val edit: ((String) -> String) -> Unit = { change ->
            settings.setLogIndexWatchJson(network, change(settings.logIndexWatchJson(network)))
            storeRev++
        }
        // Null while the engine gives no status — the network is stopped, or its
        // handle is paused or still starting and answers the probe with an error
        // object. That is "unknown", never "the index holds nothing".
        val parsed = LogIndexStatus.parseOrNull(snapshot?.logIndexJson)
        // The addresses the engine's index holds; null while that is unknown.
        val indexed = parsed?.entries?.mapTo(HashSet()) { it.address }
        // Whether this host has a config push to send at all (LogIndexWatch.configJson
        // sends none for an index it never configured). A removal travels in that
        // push, so without one it is not on its way anywhere.
        val pushes = collecting || settings.logIndexConfigured(network)
        // Removing has to REACH the engine: its config push is additive, so a
        // contract that merely left this list would stay indexed. The store keeps
        // the address marked removed and the push names it under `unwatch` — at
        // once while the network runs, on its next start otherwise.
        val remove: (List<String>) -> Unit = { addresses ->
            val held = parsed != null && addresses.any { it.lowercase() in indexed.orEmpty() }
            if (!pushes && !held) {
                // This host never pushed a config, so it cannot have subscribed
                // them, and the engine holds none of them: there is nothing to
                // deliver. No marker — it would wait for a push it has no business
                // in, and unwatch a contract that arrived by other means meanwhile.
                edit { json -> addresses.fold(json) { acc, a -> LogIndexWatch.forget(acc, a) } }
            } else {
                edit { json -> addresses.fold(json) { acc, a -> LogIndexWatch.unwatch(acc, a) } }
                // An index this host never configured (a snapshot dropped into the
                // data dir, activated engine-side) gets no push — one would switch it
                // off or start a backfill the user never asked for. Removing one of
                // ITS contracts is the user taking it over, so record what the engine
                // is doing as this host's settings first: the push then re-asserts
                // the engine's own runtime bits instead of changing them.
                // It is still a FULL push. With collection now recorded as on,
                // whatever else the list holds — contracts typed in while this
                // host had nothing configured — is subscribed with it, as the
                // next start's push would do anyway. Holding them back would
                // leave a list that reads as collected and is not.
                if (!pushes && parsed != null) {
                    settings.setLogIndexMaxSpeed(network, parsed.maxSpeed)
                    settings.setLogIndexBackfillPaused(network, parsed.backfillPaused)
                    settings.setLogIndexEnabled(network, parsed.enabled)
                    collecting = parsed.enabled
                    onLogIndexChanged()
                }
                controller.applyLogIndex(network)
            }
        }
        // Removing deletes collected logs, which only a fresh backfill (or import)
        // brings back — so it is confirmed first, unless there is nothing to lose:
        // the engine holds none of the addresses (typed in, never collected).
        var confirmRemoval by remember(network) { mutableStateOf<List<String>?>(null) }
        val askToRemove: (List<String>) -> Unit = { addresses ->
            val mayHoldLogs =
                if (indexed != null) addresses.any { it.lowercase() in indexed } else pushes
            if (mayHoldLogs) confirmRemoval = addresses else remove(addresses)
        }
        confirmRemoval?.let { addresses ->
            val one = addresses.size == 1
            AlertDialog(
                onDismissRequest = { confirmRemoval = null },
                title = {
                    Text(if (one) "Remove this contract?" else "Remove ${addresses.size} contracts?")
                },
                text = {
                    Text(
                        (if (one) "${addresses.first()}\n\nThe logs collected for it"
                        else "The logs collected for them") +
                            " on $network are deleted and indexing stops. Adding " +
                            (if (one) "it" else "one") + " again starts its backfill over. " +
                            "The other contracts keep their logs.",
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            confirmRemoval = null
                            remove(addresses)
                        },
                        modifier = Modifier.testTag(INDEX_REMOVE_CONFIRM_TAG),
                    ) { Text("Remove") }
                },
                dismissButton = { TextButton(onClick = { confirmRemoval = null }) { Text("Cancel") } },
            )
        }
        Text(
            "Index and serve eth_getLogs for contracts you choose — every log verified " +
                "against receipt roots, backfilled to the block you set. Runs on the Rust " +
                "engine only.",
        )

        // ---- The watch list: the user's entries, persisted host-side. ----
        watch.forEach { entry ->
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(entry.address)
                    Text(
                        "from block ${entry.fromBlock}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                TextButton(onClick = { askToRemove(listOf(entry.address)) }) { Text("Remove") }
            }
        }
        // ---- Contracts the engine indexes that the list above does not hold. ----
        // An imported snapshot's contracts from before imports were adopted into
        // the list, or ones removed here back when Remove only edited the list and
        // never reached the engine. Shown so nothing is indexed out of sight, and
        // so those earlier removals can be finished. An address already marked
        // removed is left out while a push is carrying its removal to the engine.
        val listed = remember(watch) { watch.mapTo(HashSet()) { it.address.lowercase() } }
        val unlisted = parsed?.entries.orEmpty()
            .filter { it.address !in listed && !(pushes && it.address in unwatched) }
        if (unlisted.isNotEmpty()) {
            Text("Indexed, but not in your list", style = MaterialTheme.typography.titleSmall)
            Text(
                "The engine indexes these on $network although they are not listed above: " +
                    "they came with an imported snapshot, or were removed here before " +
                    "removing reached the engine. Keep adds one to your list. Remove " +
                    "deletes its collected logs and stops indexing it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            unlisted.forEach { e ->
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(e.name ?: e.address)
                        Text(
                            (if (e.name != null) "${e.address} · " else "") + "from block ${e.fromBlock}" +
                                (if (e.restricted) " · selected events only — cannot be listed" else ""),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    // Not for an entry indexed under a topic restriction: the list
                    // carries no topics, so the next push would name it
                    // unrestricted — a conflict the engine answers by replacing the
                    // whole index.
                    if (!e.restricted) {
                        TextButton(onClick = {
                            // The engine already indexes it: listing it changes
                            // nothing there, so no push.
                            edit { LogIndexWatch.watch(it, LogIndexWatch.Entry(e.address, e.fromBlock)) }
                        }) { Text("Keep") }
                    }
                    TextButton(onClick = { askToRemove(listOf(e.address)) }) { Text("Remove") }
                }
            }
            if (unlisted.size > 1) {
                OutlinedButton(onClick = { askToRemove(unlisted.map { it.address }) }) {
                    Text("Remove all ${unlisted.size}")
                }
            }
        }
        var addAddress by remember(network) { mutableStateOf("") }
        var addFrom by remember(network) { mutableStateOf("") }
        OutlinedTextField(
            value = addAddress,
            onValueChange = { addAddress = it.trim() },
            label = { Text("Contract address (0x…)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = addFrom,
            onValueChange = { addFrom = it.filter(Char::isDigit) },
            label = { Text("Index back to block (the contract's deployment block)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        // An address the engine indexes under a topic restriction cannot be added:
        // the list carries no topics, so the push would name it unrestricted — a
        // conflict the engine answers by replacing the whole index.
        val addRestricted = parsed?.entries
            ?.any { it.restricted && it.address == addAddress.lowercase() } == true
        val addValid = LogIndexWatch.isValidAddress(addAddress) &&
            addFrom.toLongOrNull() != null &&
            addAddress.lowercase() !in listed &&
            !addRestricted
        if (addRestricted) {
            Text(
                "This contract is already indexed for selected events only. Adding it here " +
                    "would replace the whole index — remove it above first.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Button(
            enabled = addValid,
            onClick = {
                val entry = LogIndexWatch.Entry(addAddress, addFrom.toLong())
                edit { LogIndexWatch.watch(it, entry) }
                addAddress = ""
                addFrom = ""
                if (collecting) controller.applyLogIndex(network)
                onLogIndexChanged()
            },
        ) { Text("Add contract") }
        Text(
            "Earlier is safer for the from-block: the index only answers queries for " +
                "ranges it has covered, so a from-block AFTER the real deployment silently " +
                "hides the earlier events, while an earlier one merely walks further. " +
                "Removing a contract deletes the logs collected for it and stops indexing " +
                "it; the other contracts keep theirs. If $network is not running, the " +
                "removal takes effect when it next starts.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // `collecting` keeps the row visible even with an empty watch list: an
        // imported snapshot enables collection without any local entries, and
        // hiding the switch then would leave the index with no off switch.
        if (watch.isNotEmpty() || collecting) {
            SwitchRow(
                label = "Collect logs on $network",
                checked = collecting,
                enabled = true,
                onChange = { on ->
                    collecting = on
                    settings.setLogIndexEnabled(network, on)
                    controller.applyLogIndex(network)
                    onLogIndexChanged()
                },
            )
        }
        if (collecting) {
            var maxSpeed by remember(network) { mutableStateOf(settings.logIndexMaxSpeed(network)) }
            SwitchRow(
                label = "Max download speed on $network",
                checked = maxSpeed,
                enabled = true,
                onChange = { on ->
                    maxSpeed = on
                    settings.setLogIndexMaxSpeed(network, on)
                    // Re-push the config; pacing is fingerprint-neutral, so
                    // accumulated coverage survives the flip.
                    controller.applyLogIndex(network)
                },
            )
            Text(
                if (maxSpeed) "Backfills as fast as peers serve — heavier on network and battery."
                else "Nice background pace — one small batch every few seconds.",
            )
            var backfillPaused by remember(network) {
                mutableStateOf(settings.logIndexBackfillPaused(network))
            }
            SwitchRow(
                label = "Pause backfill on $network",
                checked = backfillPaused,
                enabled = true,
                onChange = { on ->
                    backfillPaused = on
                    settings.setLogIndexBackfillPaused(network, on)
                    // Fingerprint-neutral like the pacing bit: coverage already
                    // walked survives, and resuming continues from the same cursor.
                    controller.applyLogIndex(network)
                },
            )
            Text(
                if (backfillPaused)
                    "Walking down to each contract's start is OFF — coverage stays where it is " +
                        "and only the head is followed. Queries below the covered range are " +
                        "REFUSED, never answered empty. Use this when the consumer already has " +
                        "the older history."
                else "Walks down to each contract's start block in the background.",
            )
        }
        // Import: merge portable snapshot files (built by the daemon's
        // build-logindex tool, or exported by another node) into this
        // network's index — the alternative to backfilling from peers.
        if (controller.canImportLogIndex) {
            var importResult by remember(network) { mutableStateOf<String?>(null) }
            var importing by remember(network) { mutableStateOf(false) }
            Button(
                enabled = !importing,
                onClick = {
                    importing = true
                    importResult = null
                    val started = controller.importLogIndexSnapshots(network) { line ->
                        importResult = line
                        importing = false
                        // Importing is the opt-in — reflect the flag the host persisted,
                        // and the contracts it adopted into the watch list.
                        collecting = settings.logIndexEnabled(network)
                        storeRev++
                        onLogIndexChanged()
                    }
                    if (!started) importing = false
                },
            ) { Text(if (importing) "Importing…" else "Import log-index snapshot…") }
            importResult?.let { Text(it) }
        }
        // A seed the host installed from its own bundle (Bee PoC flavour) is
        // served indistinguishably from walked coverage — say so where the
        // coverage is shown, and only while the engine's index is actually on
        // (an install that did not reach the engine must not look seeded).
        val seededNotice = remember(network) { controller.seededIndexNotice(network) }
        when {
            parsed?.enabled == true -> {
                seededNotice?.let { Text(it) }
                Text("${parsed.logCount} logs collected")
                LogIndexStatus.progressLine(parsed)?.let { Text("Backfill: $it") }
                // The ENGINE's entry list is authoritative — it includes imported
                // subscriptions the watch list here knows nothing about. Labels
                // prefer the engine name (imports carry baked-in names, and the
                // engine's naming pass ENS-reverse-resolves unnamed entries),
                // then the raw address.
                parsed.entries.forEach { e ->
                    val label = e.name ?: e.address
                    val low = e.coveredLow
                    val high = e.coveredHigh
                    Column {
                        Text(label)
                        if (pushes && e.address in unwatched) {
                            // Removed above; gone from here once the engine has
                            // taken the push that names it. A push the engine did
                            // not take (asleep past the wake gate's patience) is
                            // not repeated on its own before the next start, so
                            // it can be sent again from here.
                            Row(
                                Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text("removing…")
                                TextButton(onClick = { controller.applyLogIndex(network) }) {
                                    Text("Retry")
                                }
                            }
                        } else if (low == null || high == null) {
                            Text("waiting — target block ${e.fromBlock}")
                            LinearProgressIndicator(progress = { 0f }, modifier = Modifier.fillMaxWidth())
                        } else {
                            val total = (high - e.fromBlock + 1).coerceAtLeast(1)
                            val done = (high - low + 1).coerceIn(0, total)
                            val pct = done.toFloat() / total.toFloat()
                            val complete = low <= e.fromBlock
                            Text(
                                if (complete) "complete — blocks ${e.fromBlock}–$high"
                                else "blocks $low–$high · target ${e.fromBlock} · ${(pct * 100).toInt()}%"
                            )
                            LinearProgressIndicator(
                                progress = { if (complete) 1f else pct },
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }
                }
                // Watch entries the engine hasn't picked up yet (config not
                // pushed / engine restarting): keep their waiting rows visible.
                watch.filter { w -> parsed.entries.none { it.address == w.address.lowercase() } }
                    .forEach { w ->
                        Column {
                            Text(w.address)
                            Text("waiting — target block ${w.fromBlock}")
                            LinearProgressIndicator(progress = { 0f }, modifier = Modifier.fillMaxWidth())
                        }
                    }
            }
            collecting ->
                Text("Waiting for the engine (the network must be running on the Rust engine).")
            watch.isEmpty() ->
                Text(
                    "No contracts watched on $network yet. Add one above, or import a " +
                        "log-index snapshot built elsewhere."
                )
            else -> Text("Collection is off.")
        }
    }
}
