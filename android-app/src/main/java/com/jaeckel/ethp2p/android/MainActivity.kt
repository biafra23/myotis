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
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Switch
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.jaeckel.ethp2p.android.log.LogBuffer
import com.jaeckel.ethp2p.networking.NetworkConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.sample
import kotlinx.coroutines.future.await
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal
import java.math.BigInteger
import java.math.RoundingMode
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {

    // Exposed to Compose via a state holder so recomposition sees bind/unbind.
    private val boundServiceState = mutableStateOf<NodeService?>(null)

    // Registered eagerly so the permission dialog can fire once we hit the
    // Start button. The result fires whether the user grants or denies;
    // either way we start the service — denial just means the foreground
    // notification is invisible on Android 13+, not that the service fails.
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
            MaterialTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    NodeScreen(
                        serviceProvider = { boundServiceState.value },
                        onToggle = ::toggleService,
                        onOpenNetworkSettings = ::openWifiSettings,
                        onClearCaches = ::clearPeerCaches,
                        onResetSync = ::resetSyncState,
                        onEnableNetwork = ::setNetworkEnabled,
                        onApplyTunables = ::applyTunables,
                    )
                }
            }
        }
        // Auto-start the node when the app launches so the user doesn't have to
        // tap "Start node". Start *silently* via startForegroundService — a
        // foreground service runs fine on Android 13+ even without
        // POST_NOTIFICATIONS (the notification is just hidden), so we do NOT
        // prompt for it here: requesting on a cold launch has no user context,
        // drives high denial rates, and would re-prompt on every fresh launch
        // once denied. The permission is requested only from the explicit
        // Start-node button (ensureNodeStarted), where the user has context.
        //
        // Gated on savedInstanceState == null so it fires only on a genuinely
        // fresh launch — NOT a config-change recreation (rotation) or
        // process-death restore, which would override an explicit Stop — and on
        // !isRunning so relaunching while the service is already up is a no-op.
        if (savedInstanceState == null && !NodeService.isRunning()) {
            startNodeService()
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
        if (NodeService.isRunning()) {
            // We're bound with BIND_AUTO_CREATE from onStart, which keeps the
            // service alive even after stopService. Ask the service to tear
            // down networking explicitly; it will also call stopSelf so the
            // foreground notification clears immediately.
            boundServiceState.value?.shutdown()
                ?: stopService(Intent(this, NodeService::class.java))
        } else {
            ensureNodeStarted()
        }
    }

    /**
     * Start the node if it isn't already running, first requesting the
     * POST_NOTIFICATIONS permission on Android 13+ so the foreground-service
     * notification is visible. Used by the explicit Start-node button, where
     * prompting has clear user context. (Auto-start on launch deliberately
     * skips this and starts silently — see onCreate.) A no-op when the service
     * is already running.
     */
    private fun ensureNodeStarted() {
        if (NodeService.isRunning()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            // Defer startForegroundService until the permission dialog
            // resolves — otherwise we'd post the notification before the
            // user has decided and the callback would have to start the
            // service a second time.
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

    private fun clearPeerCaches(network: String) {
        boundServiceState.value?.clearCaches(network)
    }

    private fun resetSyncState(network: String) {
        boundServiceState.value?.resetSyncState(network)
    }

    /**
     * Enable or disable a network (Step 9). Each network runs as its own concurrent stack.
     * When the service isn't bound yet, persist the flag and start the service (which boots
     * the whole enabled-set); otherwise toggle just that stack.
     */
    private fun setNetworkEnabled(name: String, on: Boolean) {
        val svc = boundServiceState.value
        if (on) {
            if (svc != null) svc.enableNetwork(name)
            else { NodeService.setNetworkEnabled(this, name, true); startNodeService() }
        } else {
            if (svc != null) svc.disableNetwork(name)
            else NodeService.setNetworkEnabled(this, name, false)
        }
    }

    /** Persist a network's RPC port + the shared snap-peer knobs. An RPC-port change reboots
     *  only that network's stack; snap target applies live to all stacks. */
    private fun applyTunables(network: String, rpcPort: Int, snapTarget: Int, deepPool: Int) {
        val oldPort = NodeService.rpcPortFor(this, network)
        NodeService.setRpcPort(this, network, rpcPort)
        val newPort = NodeService.rpcPortFor(this, network)
        NodeService.setDeepPoolThreshold(this, deepPool)
        val svc = boundServiceState.value
        if (svc != null) {
            svc.setTargetSnapPeers(snapTarget)               // live update + persists
            if (newPort != oldPort) svc.rebootNetwork(network)  // rebind only this RPC server
        } else {
            NodeService.setSnapTargetPref(this, snapTarget)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NodeScreen(
    serviceProvider: () -> NodeService?,
    onToggle: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
    onClearCaches: (String) -> Unit,
    onResetSync: (String) -> Unit,
    onEnableNetwork: (String, Boolean) -> Unit,
    onApplyTunables: (String, Int, Int, Int) -> Unit,
) {
    // Per-network snapshots (Step 9): one stack per chain runs concurrently; the UI views one
    // at a time via the chip selector. `selectedChain` is the chip in focus and drives Status +
    // Query; null until the first poll lands. The uptime tick is owned here so both tabs read it.
    var snapshots by remember { mutableStateOf<Map<String, NodeService.Snapshot>>(emptyMap()) }
    var selectedChain by rememberSaveable { mutableStateOf<String?>(null) }
    var running by remember { mutableStateOf(NodeService.isRunning()) }
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    var selectedTab by remember { mutableStateOf(0) }
    val online = rememberIsOnline()
    val context = LocalContext.current
    var showSettings by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }
    // Readiness deep-pool threshold is configurable in Settings; seed from prefs and
    // update live when saved so ReadinessStrip reflects it without a restart.
    var deepPool by remember { mutableStateOf(NodeService.deepPoolThreshold(context)) }

    // Query-tab state is hoisted here, NOT inside QueryTab, so it survives
    // switching tabs. QueryTab leaves the composition whenever another tab is
    // selected, which would otherwise discard the result and cancel the
    // in-flight query (its rememberCoroutineScope dies with it). NodeScreen
    // stays composed across tab switches, so both the state and the coroutine
    // launched from queryScope outlive navigating away and back.
    var queryInput by rememberSaveable { mutableStateOf("") }
    var queryState by remember { mutableStateOf<QueryState>(QueryState.Idle) }
    var queryHistory by remember { mutableStateOf<List<AndroidQueryHistory.Entry>>(emptyList()) }
    val queryScope = rememberCoroutineScope()

    // Logs-tab filter is hoisted here too, for the same reason as the Query
    // state above: LogsTab leaves the composition when another tab is selected,
    // so a filter kept in its own `remember` would reset to empty on every
    // visit. Holding it in NodeScreen (and persisting it via rememberSaveable)
    // keeps the filter sticky across tab switches and process recreation.
    var logsFilter by rememberSaveable { mutableStateOf("") }

    // Load persisted query history once the service is bound / running flips.
    LaunchedEffect(running) {
        val svc = serviceProvider() ?: return@LaunchedEffect
        queryHistory = withContext(Dispatchers.IO) { svc.queryHistory().list() }
    }

    // Shared by the button and by tapping a history entry. One text input
    // handles both addresses and ENS names: if it doesn't look like a 40-hex
    // address we resolve it via ENS first, then look up the resolved address.
    // Runs on queryScope (NodeScreen-scoped) so leaving the Query tab mid-query
    // doesn't cancel it.
    fun runQuery(raw: String) {
        val svc = serviceProvider()
        if (svc == null) {
            queryState = QueryState.Failure("Service not bound")
            return
        }
        val chain = selectedChain ?: NodeService.primaryNetwork(context)
        // ENS only exists on mainnet/Sepolia — on a chain without it (Gnosis) we never run
        // ENS resolution; a typed name is rejected with a hint (the UI also labels the field
        // "Address" there). Plain address balance/account queries work on every chain.
        val ensCapable = NetworkConfig.byName(chain).hasEns()
        val q = raw.trim()
        if (q.isEmpty()) return
        queryInput = q
        queryState = QueryState.Loading
        queryScope.launch {
            // Bounce blocking work off to IO (snap-peer + EVM futures, sub-second
            // happy path, up to ~60s on retry); keep the main dispatcher free.
            // For ENS we update state between the two phases so the resolved
            // address shows immediately, then the verified account fills in.
            val outcome: QueryState = try {
                if (NodeService.looksLikeEnsName(q)) {
                    if (!ensCapable) {
                        QueryState.Failure(
                            "ENS isn't available on ${chain.replaceFirstChar { it.uppercase() }} — enter a 0x address.")
                    } else {
                    val res = withContext(Dispatchers.IO) { svc.resolveEns(chain, q).await() }
                    if (res.error != null || res.addressHex == null) {
                        QueryState.Failure("ENS: ${res.error ?: "name does not resolve"}")
                    } else {
                        // Show the address now; verify the account next. If the
                        // account phase fails, keep the resolved address visible.
                        queryState = QueryState.ResolvedPendingAccount(res)
                        try {
                            QueryState.Success(
                                withContext(Dispatchers.IO) { svc.requestAccount(chain, res.addressHex).await() }, res)
                        } catch (t: Throwable) {
                            QueryState.ResolvedAccountFailed(
                                res, t.cause?.message ?: t.message ?: t::class.java.simpleName)
                        }
                    }
                    }
                } else {
                    QueryState.Success(
                        withContext(Dispatchers.IO) { svc.requestAccount(chain, q).await() }, null)
                }
            } catch (t: Throwable) {
                QueryState.Failure(t.cause?.message ?: t.message ?: t::class.java.simpleName)
            }
            queryState = outcome
            // Record history when the query produced a usable result — a verified
            // account, or at least a resolved address (even if the account lookup
            // then failed). The resolution is the expensive part worth remembering.
            val histLabel: String? = when (outcome) {
                is QueryState.Success -> outcome.resolution?.addressHex ?: ""
                is QueryState.ResolvedAccountFailed -> outcome.resolution.addressHex ?: ""
                else -> null
            }
            if (histLabel != null) {
                queryHistory = withContext(Dispatchers.IO) {
                    svc.queryHistory().add(q, histLabel)
                    svc.queryHistory().list()
                }
            }
        }
    }

    LaunchedEffect(Unit) {
        while (isActive) {
            // snapshots() walks each stack's active handler list, sorts ready peers, and reads
            // the backoff map. Cheap on a phone but not free — keep it off the main thread so a
            // pause inside the sort or brief lock contention with Netty's READY transitions
            // can't blow the frame budget.
            val s = withContext(Dispatchers.Default) {
                serviceProvider()?.snapshots() ?: emptyMap()
            }
            running = NodeService.isRunning()
            snapshots = s
            // Keep the selected chip valid. When stopped, snapshots is empty, so fall back to the
            // enabled-set — otherwise selectedChain would be wiped to null on every poll. Only reset
            // when the current selection isn't among the available chains (e.g. disabled in Settings).
            val activeChains = s.keys.ifEmpty { NodeService.enabledNetworks(context) }
            if (selectedChain == null || selectedChain !in activeChains) {
                selectedChain = activeChains.firstOrNull()
            }
            delay(2000)
        }
    }
    val currentSnapshot = selectedChain?.let { snapshots[it] }
    LaunchedEffect(Unit) {
        while (isActive) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    if (showSettings) {
        SettingsScreen(
            onEnableNetwork = { name, on ->
                onEnableNetwork(name, on)
                // Gnosis runs the JSON-RPC server on a distinct port (default 8546) because
                // MetaMask won't save two RPC endpoints with the same URL. Surface it on enable.
                if (on && name == "gnosis") {
                    val port = NodeService.rpcPortFor(context, "gnosis")
                    queryScope.launch {
                        snackbarHostState.showSnackbar(
                            "Gnosis JSON-RPC is on port $port — add it to MetaMask as a " +
                                "separate RPC URL (it can't reuse mainnet's).",
                        )
                    }
                }
            },
            onApplyTunables = { network, port, snap, deep ->
                deepPool = deep
                onApplyTunables(network, port, snap, deep)
                showSettings = false
            },
            onBack = { showSettings = false },
        )
        return
    }
    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    // App name + network selector on one line. The highlighted chip is the selected
                    // chain (drives Status + Query), so there's no separate "· <network>" text or
                    // chip row beneath. When the node is stopped (snapshots empty) the chips fall back
                    // to the enabled-set so the user still sees/selects networks, and the chips scroll
                    // horizontally so a third network can't push the Settings action off-screen.
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("Myotis")
                        val chipChains = snapshots.keys.toList()
                            .ifEmpty { NodeService.enabledNetworks(context) }
                        Row(
                            modifier = Modifier
                                .weight(1f)
                                .horizontalScroll(rememberScrollState()),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            chipChains.forEach { c ->
                                FilterChip(
                                    selected = c == selectedChain
                                        || (selectedChain == null && c == chipChains.firstOrNull()),
                                    onClick = { selectedChain = c },
                                    label = { Text(c.replaceFirstChar { it.uppercase() }) },
                                )
                            }
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { showSettings = true }) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
    ) { padding ->
      Column(Modifier.fillMaxSize().padding(padding)) {
        // App-wide sync banner above the tabs: indeterminate while bootstrapping,
        // determinate as the light client catches up sync-committee periods, gone
        // once SYNCED.
        SyncProgressBar(currentSnapshot)
        // Readiness traffic-light: a thin strip atop the tabs. red = consensus not
        // synced; amber = synced but no warm verified head yet (wallet calls will
        // error -32000); green = warmed up, safe to transact. The deep-pool gate
        // (bright/thick green) uses the configurable threshold from Settings.
        ReadinessStrip(currentSnapshot, deepPool)
        TabRow(selectedTabIndex = selectedTab) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = { Text("Status") }
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = { Text("Query") }
            )
            Tab(
                selected = selectedTab == 2,
                onClick = { selectedTab = 2 },
                text = { Text("Logs") }
            )
        }
        val chainForActions = selectedChain ?: NodeService.primaryNetwork(context)
        when (selectedTab) {
            0 -> StatusTab(
                snapshot = currentSnapshot,
                running = running,
                now = now,
                online = online,
                serviceProvider = serviceProvider,
                onToggle = onToggle,
                onOpenNetworkSettings = onOpenNetworkSettings,
                onClearCaches = { onClearCaches(chainForActions) },
                onResetSync = { onResetSync(chainForActions) },
            )
            1 -> QueryTab(
                snapshot = currentSnapshot,
                chain = chainForActions,
                running = running,
                input = queryInput,
                onInputChange = { queryInput = it },
                state = queryState,
                history = queryHistory,
                onRunQuery = { runQuery(it) },
                onClearHistory = {
                    val svc = serviceProvider()
                    if (svc != null) queryScope.launch {
                        queryHistory = withContext(Dispatchers.IO) {
                            svc.queryHistory().clear()
                            svc.queryHistory().list()
                        }
                    }
                },
            )
            else -> LogsTab(
                chains = snapshots.keys.toList(),
                filter = logsFilter,
                onFilterChange = { logsFilter = it },
            )
        }
      }
    }
}

/**
 * Settings page: enable/disable each network (Step 9 — chains run concurrently) and tune the
 * per-network RPC port + the shared snap-peer knobs. Reached from the top-bar gear.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsScreen(
    onEnableNetwork: (String, Boolean) -> Unit,
    onApplyTunables: (String, Int, Int, Int) -> Unit,   // network, rpcPort, snapTarget, deepPool
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val networks = remember { NetworkConfig.allNetworks() }
    // Per-network enabled toggle + RPC-port text, seeded from prefs. Toggling a switch acts
    // immediately (boots/stops that chain's stack); the RPC port is deferred to Save.
    val enabled = remember {
        mutableStateMapOf<String, Boolean>().apply {
            networks.forEach { put(it.name(), NodeService.isNetworkEnabled(context, it.name())) }
        }
    }
    val rpcPorts = remember {
        mutableStateMapOf<String, String>().apply {
            networks.forEach { put(it.name(), NodeService.rpcPortFor(context, it.name()).toString()) }
        }
    }
    var snapTarget by remember { mutableStateOf(NodeService.snapTarget(context).toString()) }
    var deepPool by remember { mutableStateOf(NodeService.deepPoolThreshold(context).toString()) }
    var strictFreshness by remember { mutableStateOf(NodeService.strictStateFreshness(context)) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                // Scrollable: on the cover display the Networks + Node tuning content
                // (and the Save button) overflows the screen — without this the toggle
                // and Save fall below the fold and are unreachable.
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Networks", style = MaterialTheme.typography.titleMedium)
            Text(
                "Toggle a chain to run it. Each enabled chain runs concurrently as its own node " +
                    "with its own JSON-RPC port — add each port to MetaMask as a separate RPC URL.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            networks.forEach { nc ->
                val id = nc.name()
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(
                        Modifier.fillMaxWidth().padding(top = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(nc.displayName())
                        Switch(
                            checked = enabled[id] == true,
                            onCheckedChange = { on -> enabled[id] = on; onEnableNetwork(id, on) },
                        )
                    }
                    OutlinedTextField(
                        value = rpcPorts[id] ?: "",
                        onValueChange = { rpcPorts[id] = it.filter(Char::isDigit).take(5) },
                        label = { Text("JSON-RPC port (default ${nc.defaultRpcPort()})") },
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
                label = { Text("Readiness “deep pool” threshold (default 16)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            Row(
                Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Relaxed state freshness")
                Switch(
                    checked = !strictFreshness,
                    onCheckedChange = { relaxed ->
                        strictFreshness = !relaxed
                        NodeService.setStrictStateFreshness(context, !relaxed)
                    },
                )
            }
            Text(
                "Off (default, recommended): strict 2-minute freshness — fee calc / eth_call " +
                    "fast-fail when no fresh servable root exists, and the wallet retries. " +
                    "On (opt-in, experimental): serve a slightly older verified root — but if " +
                    "it isn’t fully servable this can HANG the confirm screen for up to 2 min " +
                    "instead of failing fast. Applies on the next node (re)start.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "An RPC-port change reboots that chain; snap-peer target and the readiness " +
                    "threshold apply live to every chain.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = {
                    val snap = snapTarget.toIntOrNull() ?: NodeService.DEFAULT_SNAP_TARGET
                    val deep = deepPool.toIntOrNull() ?: NodeService.DEFAULT_DEEP_POOL
                    // Apply per network: each call persists this chain's RPC port (rebooting it
                    // only if the port changed) and re-applies the shared snap/deep knobs.
                    networks.forEach { nc ->
                        val id = nc.name()
                        val port = rpcPorts[id]?.toIntOrNull() ?: nc.defaultRpcPort()
                        onApplyTunables(id, port, snap, deep)
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Save") }
        }
    }
}

/**
 * App-wide beacon sync banner, drawn above the tab bar. Hidden when the node is
 * stopped or SYNCED. While catching up sync-committee periods it's a determinate
 * bar `(current - start) / (target - start)`; while bootstrapping (no anchor yet)
 * or during the brief post-catch-up state-root fill it's indeterminate.
 */
@Composable
private fun SyncProgressBar(snapshot: NodeService.Snapshot?) {
    val s = snapshot ?: return
    if (!s.running || s.beaconState == "SYNCED" || s.beaconState == "STOPPED") return

    val start = s.syncStartPeriod
    val current = s.syncCurrentPeriod
    val target = s.syncTargetPeriod
    val determinate = s.beaconState == "CATCHING_UP" && start >= 0 && target > start

    Column(Modifier.fillMaxWidth()) {
        val label = when {
            !determinate -> "Bootstrapping light client…"
            current >= target -> "Finishing sync…"
            else -> "Catching up sync committees — period $current / $target"
        }
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
        )
        if (determinate) {
            val fraction = ((current - start).coerceAtLeast(0).toFloat() /
                (target - start).toFloat()).coerceIn(0f, 1f)
            LinearProgressIndicator(
                progress = { fraction },
                modifier = Modifier.fillMaxWidth(),
            )
        } else {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }
    }
}

/**
 * Readiness traffic-light — a thin full-width strip atop the tab bar encoding the
 * three gates a wallet transaction needs, the way nothing else in the UI does. The
 * three gates (running+SYNCED, warm verified head, deep snap pool) surface as FOUR
 * tiers, since "no gate passed" is its own state:
 *
 *  - **red**   — not running, or consensus light client not SYNCED yet. The node
 *                can't serve anything verified; don't transact.
 *  - **amber** — beacon SYNCED but no warm verified RPC head (snap peers absent /
 *                head-build failing). Wallet calls error `-32000 no verified head`,
 *                so MetaMask's confirm screen stalls. "Almost — wait."
 *  - **green** — a verified head was built within [READY_HEAD_WARM_MS]. eth_call /
 *                balances / a SIMPLE confirm-screen will serve. Safe to send, but a
 *                heavy confirm screen (MetaMask's ~1000-token sweep) may still stall
 *                while the snap pool is shallow.
 *  - **bright + thick green** — head warm AND a DEEP snap pool ([DEEP_POOL_SNAP_PEERS]+
 *                peers). The EVM prefetch fans ~48 concurrent fetches across enough
 *                peers that even a heavy confirm screen converges. Fully ready.
 *
 * The green gates read [NodeService.Snapshot.verifiedHeadAgeMs] (shared backend's
 * warmer) and [NodeService.Snapshot.snapServingPeers] (the *serving* pool, not the
 * negotiated count — heavy confirm screens converge on peers that actually serve).
 * The head threshold is generous vs.
 * the head TTL+build time on mobile (~12s TTL + 20-26s build) so a healthy node
 * stays green between rebuilds instead of flickering amber.
 */
private const val READY_HEAD_WARM_MS = 45_000L
/** Snap peers needed before a HEAVY confirm screen converges. MetaMask's ~1000-token
 *  BalanceChecker sweep + Multicall3 simulation drive the EVM prefetch to fan out
 *  ~48 concurrent snap fetches; those only finish in time when spread across a deep
 *  pool. Below this the node serves simple reads (plain green) but heavy screens
 *  stall; at/above it they converge (bright, thick green). On-device: a cold phone
 *  needs minutes of dialing to reach this — the bright bar is the honest "go" signal. */
private const val DEEP_POOL_SNAP_PEERS = 16

@Composable
private fun ReadinessStrip(snapshot: NodeService.Snapshot?, deepPoolThreshold: Int = DEEP_POOL_SNAP_PEERS) {
    val s = snapshot
    // Color, thickness AND a spoken label, derived together so they can never
    // disagree. The label is exposed via semantics so readiness is discoverable by
    // TalkBack and not conveyed by color/thickness alone (invisible to color-vision
    // deficiencies). The strip stays a thin non-interactive line; the description is
    // its only a11y surface.
    val (target, height, label) = when {
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
    // Ease between states so a transient blip reads as a gentle pulse, not a flash —
    // and the thickness grows smoothly when the pool crosses the deep-pool gate.
    val color by animateColorAsState(targetValue = target, label = "readiness")
    val barHeight by androidx.compose.animation.core.animateDpAsState(
        targetValue = height, label = "readiness-height")
    Box(
        Modifier
            .fillMaxWidth()
            .height(barHeight)
            .background(color)
            .semantics { contentDescription = label },
    )
}

@Composable
private fun StatusTab(
    snapshot: NodeService.Snapshot?,
    running: Boolean,
    now: Long,
    online: Boolean,
    serviceProvider: () -> NodeService?,
    onToggle: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
    onClearCaches: () -> Unit,
    onResetSync: () -> Unit,
) {
    // SelectionContainer wraps the whole tab so long-pressing any text
    // (peer rows, stats, hashes) lets the user copy from the standard
    // Android selection toolbar. Buttons stay tappable — selection only
    // engages on Text composables.
    //
    // Single LazyColumn so EL stats + beacon stats + peer list scroll
    // together — a nested LazyColumn inside a non-scrolling Column
    // would only scroll the peers.
    SelectionContainer {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (!online) {
                item { OfflineBanner(onOpenNetworkSettings) }
            }

            item {
                Button(
                    onClick = onToggle,
                    enabled = running || online,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (running) "Stop node" else "Start node")
                }
            }

            item {
                OutlinedButton(
                    onClick = onClearCaches,
                    enabled = serviceProvider() != null,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Clear peer caches")
                }
            }

            item {
                OutlinedButton(
                    onClick = onResetSync,
                    enabled = serviceProvider() != null,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    // Deletes the persisted sync-committee snapshot so the next
                    // start re-bootstraps from the embedded checkpoint (debugging).
                    Text("Reset sync state")
                }
            }

            val s = snapshot
            if (s == null || !s.running) {
                item {
                    Text(
                        if (online) "Tap Start to launch the node."
                        else "Connect to the internet before starting the node."
                    )
                }
            } else {
                item { StatusRow("uptime", formatUptime(now - s.startTimeMs)) }
                item { Text("Execution layer (devp2p)", style = MaterialTheme.typography.titleSmall) }
                item { StatusSummary(s) }
                item { HorizontalDivider() }
                item { Text("Beacon (consensus)", style = MaterialTheme.typography.titleSmall) }
                item { BeaconSummary(s) }
                item { HorizontalDivider() }
                item {
                    Text("READY peers (${s.readyPeerList.size})",
                        style = MaterialTheme.typography.titleSmall)
                }
                items(s.readyPeerList) { p -> PeerRow(p) }
            }
        }
    }
}

private sealed interface QueryState {
    data object Idle : QueryState
    data object Loading : QueryState
    // ENS resolved → show the address right away while the (separate, fast)
    // account lookup + beacon verification runs. Resolution is the slow part of
    // an ENS query; the account verify is a cheap state-root match, so surfacing
    // the address first makes the query feel responsive.
    data class ResolvedPendingAccount(
        val resolution: NodeService.EnsResolution,
    ) : QueryState
    data class Success(
        val result: NodeService.AccountQueryResult,
        // Non-null when the input was an ENS name we resolved first.
        val resolution: NodeService.EnsResolution?,
    ) : QueryState
    // Resolution succeeded but the account lookup/verification failed — keep the
    // resolved address on screen (it's still useful) rather than discarding it.
    data class ResolvedAccountFailed(
        val resolution: NodeService.EnsResolution,
        val message: String,
    ) : QueryState
    data class Failure(val message: String) : QueryState
}

@Composable
private fun QueryTab(
    snapshot: NodeService.Snapshot?,
    chain: String,
    running: Boolean,
    input: String,
    onInputChange: (String) -> Unit,
    state: QueryState,
    history: List<AndroidQueryHistory.Entry>,
    onRunQuery: (String) -> Unit,
    onClearHistory: () -> Unit,
) {
    // ENS only resolves on chains that have it (mainnet/Sepolia). On others the field accepts
    // addresses only, so we relabel it and drop the ENS hint.
    val ensCapable = remember(chain) { NetworkConfig.byName(chain).hasEns() }
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (!running) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    )
                ) {
                    Text(
                        "Node is not running. Start it from the Status tab " +
                            "before issuing a query.",
                        modifier = Modifier.padding(12.dp),
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            val beaconState = snapshot?.beaconState
            // Anything but SYNCED means we cannot match the peer's state root
            // against a beacon-attested anchor — flag that so the user knows
            // balances/nonces are peer-claimed, not cryptographically verified.
            if (beaconState != "SYNCED") {
                item { ConsensusUnsyncedBanner(beaconState ?: "STOPPED") }
            }
        }

        item {
            OutlinedTextField(
                value = input,
                onValueChange = onInputChange,
                label = { Text(if (ensCapable) "Address or ENS name" else "Address") },
                placeholder = { Text(if (ensCapable) "0x… or vitalik.eth" else "0x…") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = state !is QueryState.Loading,
            )
        }
        if (!ensCapable) {
            item {
                Text(
                    "ENS isn't available on ${chain.replaceFirstChar { it.uppercase() }} — " +
                        "enter a 0x address. Balance & nonce are still beacon-verified.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        item {
            Button(
                onClick = { onRunQuery(input) },
                enabled = running && input.isNotBlank() && state !is QueryState.Loading,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Look up")
            }
        }

        when (val st = state) {
            is QueryState.Idle -> { /* nothing */ }
            is QueryState.Loading -> item { LoadingRow("Resolving…") }
            is QueryState.ResolvedPendingAccount -> {
                item { EnsResolutionPanel(st.resolution) }
                item { LoadingRow("Verifying account…") }
            }
            is QueryState.Success -> {
                st.resolution?.let { item { EnsResolutionPanel(it) } }
                item { AccountResultPanel(st.result) }
            }
            is QueryState.ResolvedAccountFailed -> {
                item { EnsResolutionPanel(st.resolution) }
                item { ErrorPanel("Account lookup failed: ${st.message}") }
            }
            is QueryState.Failure -> item { ErrorPanel(st.message) }
        }

        if (history.isNotEmpty()) {
            item {
                Row(
                    Modifier.fillMaxWidth().padding(top = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Recent", style = MaterialTheme.typography.titleSmall)
                    OutlinedButton(onClick = onClearHistory) { Text("Clear") }
                }
            }
            items(history) { entry ->
                HistoryRow(
                    entry = entry,
                    enabled = running && state !is QueryState.Loading,
                    onClick = { onRunQuery(entry.input) },
                )
            }
        }
    }
}

/** One tappable past-query row: tap to re-run with that input. */
@Composable
private fun HistoryRow(
    entry: AndroidQueryHistory.Entry,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(entry.input, style = MaterialTheme.typography.bodyMedium)
            if (entry.label.isNotEmpty()) {
                Text(
                    "→ ${shortenHash(entry.label)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** Shows what an ENS name resolved to, above the account result. */
@Composable
private fun EnsResolutionPanel(res: NodeService.EnsResolution) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("ENS", style = MaterialTheme.typography.titleSmall)
        StatusRow("name", res.name)
        StatusRow("resolved", res.addressHex ?: "—")
        if (res.blockNumber >= 0) StatusRow("at block #", res.blockNumber.toString())
        // The trust level of the mapping depends on which state it resolved
        // against (NodeService.ensResolutionRoot). AUTO (default) tries the
        // beacon-verified finalized state first and only falls back to a peer's
        // head when finalized yields no answer; resolving over finalized anchors
        // the name→address mapping cryptographically (beaconVerified=true), while
        // the head fallback is proof-checked against the peer's *claimed* root but
        // not beacon-attested (peer-claimed). res.beaconVerified reports which
        // path produced this result; show the matching line so it's never
        // confused with the account state's own verification below.
        if (res.beaconVerified) {
            StatusRow("mapping", "beacon-verified")
        } else {
            Text(
                "The name→address mapping is peer-claimed (not beacon-verified). "
                    + "The account state below is independently beacon-verified.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        HorizontalDivider()
    }
}

/**
 * Live log viewer fed by [LogBuffer]. Auto-follows the tail when the user
 * is parked at the bottom and pauses follow as soon as they scroll up;
 * a "Jump to latest" button reappears so they can resume.
 *
 * <p>Selection is enabled (long-press → standard Android selection toolbar
 * with Copy / Share). The toolbar above also exposes "Copy all" — useful
 * when the buffer has thousands of lines and dragging selection handles
 * across them is impractical.
 */
@Composable
private fun LogsTab(
    chains: List<String>,
    filter: String,
    onFilterChange: (String) -> Unit,
) {
    // Poll the LogBuffer's monotonic version counter rather than the buffer
    // itself — re-snapshotting only on change keeps the recomposition cost
    // bounded even when the consensus stack is logging dozens of lines/sec.
    var entries by remember { mutableStateOf<List<LogBuffer.Entry>>(emptyList()) }
    var lastVersion by remember { mutableLongStateOf(-1L) }
    LaunchedEffect(Unit) {
        while (isActive) {
            val v = LogBuffer.version()
            if (v != lastVersion) {
                entries = LogBuffer.snapshot()
                lastVersion = v
            }
            // 250ms ≈ 4 Hz refresh — fast enough to feel live, slow enough
            // not to thrash the LazyColumn during log bursts.
            delay(250)
        }
    }

    // Filter on tag + message (case-insensitive substring), computed OFF the main
    // thread — substring-scanning up to MAX_LINES (50k) entries on every keystroke
    // / 4 Hz buffer poll would jank the UI and laggy the typing. The unfiltered
    // view shows the whole buffer (no line cap); the LazyColumn renders lazily.
    var shown by remember { mutableStateOf<List<LogBuffer.Entry>>(emptyList()) }
    // Filtered view — keyed on `filter` ONLY, deliberately NOT on `entries`. The live
    // buffer refreshes `entries` ~4x/s; the previous version keyed this effect on
    // `entries` too, so every refresh cancelled and restarted the up-to-50k-entry
    // case-insensitive scan. Under heavy log churn (most visibly with two networks
    // running at once) the scan never finished before the next refresh killed it, so the
    // filtered list stayed permanently empty — it looked like the filter was broken or
    // that no requests were happening. Fix: run one immediate pass for responsiveness,
    // then keep it fresh from a sample()-throttled view of the buffer so each scan has
    // room to complete (collectLatest only supersedes the prior *sampled* pass, not every
    // 250ms tick). The unfiltered view stays fully live — a cheap direct assignment.
    //
    // We observe the `lastVersion` Long (updated atomically with `entries`) rather than
    // `entries` itself: snapshotFlow dedupes by structural equality, and an equals() over
    // a 50k-entry list on every tick would be an O(N) main-thread cost. lastVersion gives
    // the same change signal as an O(1) primitive compare; we then read `entries` inside.
    LaunchedEffect(filter) {
        if (filter.isBlank()) {
            snapshotFlow { lastVersion }.collect { shown = entries }
        } else {
            val matches = { e: LogBuffer.Entry ->
                e.tag.contains(filter, ignoreCase = true) ||
                    e.message.contains(filter, ignoreCase = true)
            }
            // ensureActive() bails a superseded scan promptly rather than running it out.
            shown = withContext(Dispatchers.Default) { entries.filter { ensureActive(); matches(it) } }
            snapshotFlow { lastVersion }
                .sample(500L)
                .collectLatest {
                    val snap = entries
                    shown = withContext(Dispatchers.Default) { snap.filter { ensureActive(); matches(it) } }
                }
        }
    }

    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    // Auto-follow: ON when the bottom is visible, OFF the moment the user
    // scrolls away. derivedStateOf keeps recomposition off the hot path —
    // we only re-evaluate when the LazyColumn's layout info actually
    // changes.
    val atBottom by remember {
        derivedStateOf {
            val info = listState.layoutInfo
            val last = info.visibleItemsInfo.lastOrNull()
            last == null || last.index >= info.totalItemsCount - 1
        }
    }
    var autoFollow by remember { mutableStateOf(true) }
    LaunchedEffect(listState) {
        snapshotFlow { atBottom }
            .distinctUntilChanged()
            .collect { autoFollow = it }
    }

    // Pin to the latest item whenever a new line arrives AND we're following.
    // Using scrollToItem (instant) rather than animateScrollToItem keeps
    // pace with rapid log streams without queuing animations.
    LaunchedEffect(shown.size, autoFollow) {
        if (autoFollow && shown.isNotEmpty()) {
            listState.scrollToItem(shown.size - 1)
        }
    }

    Box(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "${shown.size}${if (filter.isNotBlank()) " / ${entries.size}" else ""} " +
                        "line${if (shown.size == 1) "" else "s"}" +
                        if (autoFollow) " · live" else " · paused",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                OutlinedButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(formatLogs(shown)))
                    },
                    enabled = shown.isNotEmpty(),
                ) { Text("Copy") }
                OutlinedButton(
                    onClick = { LogBuffer.clear() },
                    enabled = entries.isNotEmpty(),
                ) { Text("Clear") }
            }
            // Network filter chips (Step 9): the buffer is one combined stream for all chains,
            // so tapping a chain chip just sets the text filter to its name (ChainStack lines
            // are tagged "[<network>]"; deep subsystem lines may not be — best-effort). "All"
            // clears the filter. Only shown when more than one chain is live.
            if (chains.size > 1) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FilterChip(
                        selected = filter.isBlank(),
                        onClick = { onFilterChange("") },
                        label = { Text("All") },
                    )
                    chains.forEach { c ->
                        FilterChip(
                            selected = filter.equals(c, ignoreCase = true),
                            onClick = { onFilterChange(c) },
                            label = { Text(c.replaceFirstChar { it.uppercase() }) },
                        )
                    }
                }
            }
            OutlinedTextField(
                value = filter,
                onValueChange = onFilterChange,
                label = { Text("Filter — tag or message") },
                singleLine = true,
                trailingIcon = if (filter.isNotEmpty()) {
                    { TextButton(onClick = { onFilterChange("") }) { Text("✕") } }
                } else null,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
            )
            HorizontalDivider()
            // SelectionContainer here gives a long-press → Copy gesture on
            // any visible line. It's compatible with LazyColumn — selection
            // tracks across items as you drag the handle.
            SelectionContainer(Modifier.fillMaxSize()) {
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 8.dp),
                ) {
                    // Keying by sequence keeps the user's scroll position
                    // anchored to a specific log line as older entries fall
                    // off the front of the ring buffer.
                    items(shown, key = { it.sequence }) { entry ->
                        LogLineRow(entry)
                    }
                }
            }
        }
        // "Jump to latest" floats over the list when the user has scrolled
        // up to read older lines. Clicking it scrolls to the end and (via
        // the auto-follow LaunchedEffect above, since atBottom flips back
        // to true) resumes live tailing.
        if (!autoFollow) {
            Button(
                onClick = {
                    scope.launch {
                        if (shown.isNotEmpty()) listState.scrollToItem(shown.size - 1)
                    }
                },
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(16.dp),
            ) { Text("Jump to latest ↓") }
        }
    }
}

private val LOG_TIME_FORMAT = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

@Composable
private fun LogLineRow(entry: LogBuffer.Entry) {
    // Color by level so warnings / errors visually pop against a wall of INFO.
    val levelColor = when (entry.level) {
        'E' -> MaterialTheme.colorScheme.error
        'W' -> Color(0xFFB58900) // dim amber — readable on both light/dark
        'D' -> MaterialTheme.colorScheme.onSurfaceVariant
        'V' -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> MaterialTheme.colorScheme.onSurface  // 'I' and unknown
    }
    val ts = LOG_TIME_FORMAT.format(Date(entry.timestampMillis))
    // Logger names like "com.jaeckel.ethp2p.consensus.BeaconLightClient" are
    // long; strip the package for display while keeping the full name in the
    // copy-all output so debugging context isn't lost.
    val shortTag = entry.tag.substringAfterLast('.')
    Text(
        text = "$ts ${entry.level} $shortTag: ${entry.message}",
        fontSize = 11.sp,
        fontFamily = FontFamily.Monospace,
        color = levelColor,
    )
}

/** Render the buffer in `adb logcat -v threadtime`-ish format for clipboard. */
private fun formatLogs(entries: List<LogBuffer.Entry>): String = buildString {
    for (e in entries) {
        append(LOG_TIME_FORMAT.format(Date(e.timestampMillis)))
        append(' ').append(e.level)
        append(' ').append(e.tag).append(": ").append(e.message)
        append('\n')
    }
}

@Composable
private fun LoadingRow(message: String = "Querying snap peer…") {
    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        CircularProgressIndicator(modifier = Modifier.height(20.dp))
        Spacer(Modifier.height(4.dp))
        Text(message, fontSize = 13.sp)
    }
}

@Composable
private fun ConsensusUnsyncedBanner(state: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        )
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Consensus layer not synced",
                style = MaterialTheme.typography.titleSmall)
            Text(
                "Beacon state is $state. Until the light client catches up, " +
                    "responses are peer-claimed and cannot be cryptographically " +
                    "verified against a beacon-attested state root.",
                fontSize = 12.sp
            )
        }
    }
}

@Composable
private fun ErrorPanel(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        )
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("Query failed", style = MaterialTheme.typography.titleSmall)
            Text(message, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        }
    }
}

@Composable
private fun AccountResultPanel(r: NodeService.AccountQueryResult) {
    val clipboard = LocalClipboardManager.current
    SelectionContainer {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Result", style = MaterialTheme.typography.titleSmall)
                // DisableSelection is implicit on Buttons; the explicit
                // copy is a one-tap convenience that pastes the *full*
                // hex (not the shortened form) for every field.
                OutlinedButton(
                    onClick = { clipboard.setText(AnnotatedString(formatAccountResult(r))) },
                ) { Text("Copy") }
            }
            // Show full hex — selection range copy needs the full string,
            // and shortenHash() makes that impossible. Long lines wrap.
            StatusRow("address", r.address)
            StatusRow("exists", r.exists.toString())
            if (r.exists) {
                StatusRow("balance (ETH)", formatEth(r.balanceWei))
                StatusRow("balance (wei)", r.balanceWei ?: "—")
                StatusRow("nonce", r.nonce.toString())
                r.storageRootHex?.let { StatusRow("storageRoot", it) }
                r.codeHashHex?.let { StatusRow("codeHash", it) }
            }
            StatusRow("block #", r.blockNumber.toString())
            r.peerStateRootHex?.let { StatusRow("peer stateRoot", it) }
            HorizontalDivider()
            Text("Verification", style = MaterialTheme.typography.titleSmall)
            StatusRow("peer proof valid", r.peerProofValid.toString())
            StatusRow("beacon-verified", r.beaconChainVerified.toString())
            if (r.beaconChainVerified) {
                r.verifyMethod?.let { StatusRow("method", it) }
                StatusRow("matched slot", r.matchedBeaconSlot.toString())
                StatusRow("BLS verified", r.blsVerified.toString())
            } else {
                r.failReason?.let { StatusRow("fail reason", it) }
            }
        }
    }
}

/** Format an AccountQueryResult as a plain-text JSON-ish blob for clipboard. */
private fun formatAccountResult(r: NodeService.AccountQueryResult): String = buildString {
    appendLine("address=${r.address}")
    appendLine("exists=${r.exists}")
    if (r.exists) {
        appendLine("balanceWei=${r.balanceWei}")
        appendLine("balanceETH=${formatEth(r.balanceWei)}")
        appendLine("nonce=${r.nonce}")
        r.storageRootHex?.let { appendLine("storageRoot=$it") }
        r.codeHashHex?.let { appendLine("codeHash=$it") }
    }
    appendLine("blockNumber=${r.blockNumber}")
    r.peerStateRootHex?.let { appendLine("peerStateRoot=$it") }
    appendLine("peerProofValid=${r.peerProofValid}")
    appendLine("beaconChainVerified=${r.beaconChainVerified}")
    if (r.beaconChainVerified) {
        r.verifyMethod?.let { appendLine("verifyMethod=$it") }
        appendLine("matchedBeaconSlot=${r.matchedBeaconSlot}")
        appendLine("blsVerified=${r.blsVerified}")
    } else {
        r.failReason?.let { appendLine("failReason=$it") }
    }
}

/** Format a wei amount (decimal string) as ETH with 6-decimal precision. */
private fun formatEth(weiDecimal: String?): String {
    if (weiDecimal == null) return "—"
    return try {
        val wei = BigInteger(weiDecimal)
        val eth = BigDecimal(wei).divide(BigDecimal.TEN.pow(18), 6, RoundingMode.DOWN)
        eth.toPlainString()
    } catch (_: NumberFormatException) {
        weiDecimal
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
        // The pool head builds / heavy confirm screens actually draw from — when this drops
        // well below "snap supported", reads stall even though the headline count looks fine.
        StatusRow("snap serving", s.snapServingPeers.toString())
        StatusRow("cached at boot", s.cachedPeers.toString())
        StatusRow("dialing", s.attemptedPeers.toString())
        StatusRow("in backoff", s.backedOffPeers.toString())
        StatusRow("blacklisted", s.blacklistedPeers.toString())
    }
}

@Composable
private fun BeaconSummary(s: NodeService.Snapshot) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        StatusRow("state", s.beaconState)
        StatusRow("bootstrapped", s.beaconBootstrapped.toString())
        // discv5 is the CL (eth2) discovery layer — belongs with the beacon stats.
        StatusRow("discv5 peers", s.discv5Peers.toString())
        StatusRow("CL peers (eth2)", s.clPeersDiscovered.toString())
        StatusRow("CL peers connected", s.clPeersConnected.toString())
        StatusRow("CL peers (light_client)", s.clPeersLightClient.toString())
        StatusRow("CL peers cached", s.clPeersCached.toString())
        StatusRow("finalized slot", if (s.finalizedSlot == 0L) "—" else s.finalizedSlot.toString())
        StatusRow("execution block", if (s.executionBlockNumber == 0L) "—" else s.executionBlockNumber.toString())
        s.executionBlockHashHex?.let { StatusRow("execution hash", shortenHash(it)) }
    }
}

private fun shortenHash(hex: String): String =
    if (hex.length <= 18) hex else hex.substring(0, 10) + "…" + hex.substring(hex.length - 8)

@Composable
private fun StatusRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
        Text(value, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
    }
}

@Composable
private fun PeerRow(p: com.jaeckel.ethp2p.networking.rlpx.RLPxConnector.PeerInfo) {
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
