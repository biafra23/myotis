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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.future.await
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal
import java.math.BigInteger
import java.math.RoundingMode

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
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
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

    private fun clearPeerCaches() {
        boundServiceState.value?.clearCaches()
    }
}

@Composable
private fun NodeScreen(
    serviceProvider: () -> NodeService?,
    onToggle: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
    onClearCaches: () -> Unit,
) {
    // Snapshot + uptime tick are owned by the parent so both tabs can read
    // them — the Query tab needs `beaconState` to decide whether to warn the
    // user that responses can't be cryptographically verified yet.
    var snapshot by remember { mutableStateOf<NodeService.Snapshot?>(null) }
    var running by remember { mutableStateOf(NodeService.isRunning()) }
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    var selectedTab by remember { mutableStateOf(0) }
    val online = rememberIsOnline()

    LaunchedEffect(Unit) {
        while (isActive) {
            running = NodeService.isRunning()
            snapshot = serviceProvider()?.snapshot()
            delay(2000)
        }
    }
    LaunchedEffect(Unit) {
        while (isActive) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    Column(Modifier.fillMaxSize()) {
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
        }
        when (selectedTab) {
            0 -> StatusTab(
                snapshot = snapshot,
                running = running,
                now = now,
                online = online,
                serviceProvider = serviceProvider,
                onToggle = onToggle,
                onOpenNetworkSettings = onOpenNetworkSettings,
                onClearCaches = onClearCaches,
            )
            else -> QueryTab(
                snapshot = snapshot,
                running = running,
                serviceProvider = serviceProvider,
            )
        }
    }
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
) {
    // Single LazyColumn for the whole tab so EL stats + beacon stats + peer
    // list scroll together — a nested LazyColumn inside a non-scrolling
    // Column would only scroll the peers.
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

private sealed interface QueryState {
    data object Idle : QueryState
    data object Loading : QueryState
    data class Success(val result: NodeService.AccountQueryResult) : QueryState
    data class Failure(val message: String) : QueryState
}

@Composable
private fun QueryTab(
    snapshot: NodeService.Snapshot?,
    running: Boolean,
    serviceProvider: () -> NodeService?,
) {
    var address by remember { mutableStateOf("") }
    var state by remember { mutableStateOf<QueryState>(QueryState.Idle) }
    val scope = rememberCoroutineScope()

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
                value = address,
                onValueChange = { address = it.trim() },
                label = { Text("Account address") },
                placeholder = { Text("0x…") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = state !is QueryState.Loading,
            )
        }

        item {
            Button(
                onClick = {
                    val svc = serviceProvider()
                    if (svc == null) {
                        state = QueryState.Failure("Service not bound")
                        return@Button
                    }
                    state = QueryState.Loading
                    scope.launch {
                        state = try {
                            // Bounce off the IO dispatcher because requestAccount
                            // will block the calling thread on the snap peer
                            // future internally; we don't want to occupy the
                            // main dispatcher while peers respond (~hundreds of
                            // ms in the happy path, 30s timeout on retry).
                            val result = withContext(Dispatchers.IO) {
                                svc.requestAccount(address).await()
                            }
                            QueryState.Success(result)
                        } catch (t: Throwable) {
                            QueryState.Failure(
                                t.cause?.message ?: t.message
                                    ?: t::class.java.simpleName
                            )
                        }
                    }
                },
                enabled = running && address.isNotEmpty() && state !is QueryState.Loading,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Get account")
            }
        }

        when (val st = state) {
            is QueryState.Idle -> { /* nothing */ }
            is QueryState.Loading -> item { LoadingRow() }
            is QueryState.Success -> item { AccountResultPanel(st.result) }
            is QueryState.Failure -> item { ErrorPanel(st.message) }
        }
    }
}

@Composable
private fun LoadingRow() {
    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        CircularProgressIndicator(modifier = Modifier.height(20.dp))
        Spacer(Modifier.height(4.dp))
        Text("Querying snap peer…", fontSize = 13.sp)
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
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Result", style = MaterialTheme.typography.titleSmall)
        StatusRow("address", shortenHash(r.address))
        StatusRow("exists", r.exists.toString())
        if (r.exists) {
            StatusRow("balance (ETH)", formatEth(r.balanceWei))
            StatusRow("balance (wei)", r.balanceWei ?: "—")
            StatusRow("nonce", r.nonce.toString())
            r.storageRootHex?.let { StatusRow("storageRoot", shortenHash(it)) }
            r.codeHashHex?.let { StatusRow("codeHash", shortenHash(it)) }
        }
        StatusRow("block #", r.blockNumber.toString())
        r.peerStateRootHex?.let { StatusRow("peer stateRoot", shortenHash(it)) }
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
        StatusRow("cached at boot", s.cachedPeers.toString())
        StatusRow("dialing", s.attemptedPeers.toString())
        StatusRow("in backoff", s.backedOffPeers.toString())
        StatusRow("blacklisted", s.blacklistedPeers.toString())
        StatusRow("discv5 peers", s.discv5Peers.toString())
        StatusRow("CL peers (eth2)", s.clPeersDiscovered.toString())
    }
}

@Composable
private fun BeaconSummary(s: NodeService.Snapshot) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        StatusRow("state", s.beaconState)
        StatusRow("bootstrapped", s.beaconBootstrapped.toString())
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
