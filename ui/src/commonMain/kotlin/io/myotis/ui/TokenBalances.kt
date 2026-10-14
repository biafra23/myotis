package io.myotis.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

// Token reads in flight at once. Each is an EVM run over proof-fetched state, i.e. snap
// round trips to peers; a lookup must not fire every row at the pool at the same time.
// The semaphore holding the bound lives in QueryTab, not in the result: a new lookup
// replaces the result while the old one's reads still run (the hosts wait their engine runs
// out), and a fresh semaphore per result would let both sets run at once.
internal const val TOKEN_READS_IN_FLIGHT = 4

/**
 * One lookup's token balances, as the query result shows them: the tokens read for the
 * holder ([PopularTokens] plus the user's own [CustomTokens]) and what each read returned.
 * Built afresh on every composition by [rememberTokenBalances] over its remembered state.
 */
internal class TokenBalancesState(
    val tokens: List<Token>,
    private val results: Map<String, TokenBalance>,
    private val onRetry: () -> Unit,
    private val onUseChainDecimals: (Token, Int) -> Unit,
    private val onRefresh: () -> Unit = {},
    /** Whether the user can add tokens in Settings on this host ([Settings.supportsCustomTokens]). */
    val canAddTokens: Boolean = true,
) {
    /** [t]'s result; null while it is being read (or was read for since-edited decimals). */
    fun resultFor(t: Token): TokenBalance? = results[t.key]?.takeIf { it.token == t }

    val pending: Int get() = tokens.count { resultFor(it) == null }
    val anyFailed: Boolean get() = tokens.any { t -> resultFor(t)?.let { it.raw == null } == true }

    /**
     * Every row failing the same way (the node stopped, its read surface is down) is one
     * problem: said once instead of on every row.
     */
    val sharedError: String?
        get() = tokens.map { resultFor(it) }
            .takeIf { it.size > 1 && it.all { r -> r != null && r.raw == null } }
            ?.map { it!!.error }?.distinct()?.singleOrNull()

    /** Read the failed rows again. */
    fun retry() = onRetry()

    /** Read every row again — a balance read a while ago may have moved since. */
    fun refresh() = onRefresh()

    /** Store the contract's own decimals for the custom token [t]. */
    fun useChainDecimals(t: Token, decimals: Int) = onUseChainDecimals(t, decimals)
}

/**
 * Read [holder]'s balance of every token [network] lists — built in and the user's own —
 * with a verified `eth_call` to `balanceOf` ([readTokenBalance]), as soon as this enters
 * composition. A row that failed is read again by itself once the node is back up and
 * synced ([ready]). [contractDecimals] remembers what each custom token's contract
 * answered to `decimals()` across lookups (the caller scopes it to the network), so that
 * check costs one call per token, not one per read; [permits] bounds the reads in flight
 * ([TOKEN_READS_IN_FLIGHT]) across lookups.
 */
@Composable
internal fun rememberTokenBalances(
    controller: NodeController,
    settings: Settings,
    network: String,
    holder: String,
    ready: Boolean,
    contractDecimals: MutableMap<String, Int>,
    permits: Semaphore,
): TokenBalancesState {
    // Read when the result appears: the Settings tab edits the list, and leaving the Query
    // tab drops this, so the next lookup sees the edit.
    var customJson by remember(network) { mutableStateOf(settings.customTokensJson(network)) }
    val tokens = remember(network, customJson) { listedTokens(network, customJson) }

    // Bumping [refresh] drops every result and re-reads every row; bumping one row's
    // attempt re-reads that row alone.
    var refresh by remember(network, holder) { mutableStateOf(0) }
    val results = remember(network, holder, refresh) { mutableStateMapOf<String, TokenBalance>() }
    val attempts = remember(network, holder, refresh) { mutableStateMapOf<String, Int>() }
    tokens.forEach { t ->
        // One effect per token, keyed on the token itself: a custom token's edited
        // decimals re-read it, and a row's bumped attempt re-reads it.
        key(t.key) {
            LaunchedEffect(network, holder, refresh, t, attempts[t.key] ?: 0) {
                permits.withPermit {
                    val r = readTokenBalance(controller, network, holder, t, contractDecimals[t.key])
                    r.chainDecimals?.let { contractDecimals[t.key] = it }
                    results[t.key] = r
                }
            }
        }
    }
    fun retryFailed() {
        results.filterValues { it.raw == null }.keys.forEach { k ->
            results.remove(k)
            attempts[k] = (attempts[k] ?: 0) + 1
        }
    }
    // Rows that failed while the node was down or catching up are read again once it is
    // ready: a stopped node's "not running" must not outlive the node coming back.
    LaunchedEffect(ready) { if (ready) retryFailed() }

    return TokenBalancesState(
        tokens, results,
        onRetry = ::retryFailed,
        onUseChainDecimals = { t, d ->
            customJson = CustomTokens.serialize(
                CustomTokens.parse(customJson).map { if (it.key == t.key) it.copy(decimals = d) else it },
            )
            settings.setCustomTokensJson(network, customJson)
        },
        onRefresh = { refresh++ },
        canAddTokens = settings.supportsCustomTokens(),
    )
}

/**
 * The token balances inside the query result: the tokens the holder has a balance of (and
 * any that could not be read), with the zero balances one tap away. Rows fill in as their
 * reads land; the header counts the reads still out.
 */
@Composable
internal fun TokenBalancesSection(state: TokenBalancesState, running: Boolean) {
    var showAll by remember { mutableStateOf(false) }
    val sharedError = state.sharedError
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                "Tokens",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            if (state.pending > 0) {
                CircularProgressIndicator(Modifier.size(12.dp), strokeWidth = 1.5.dp)
                Spacer(Modifier.width(6.dp))
                Text(
                    "${state.tokens.size - state.pending} of ${state.tokens.size} read",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // A failed row need not wait for a slow read elsewhere to be tried again.
                if (state.anyFailed && running) TextButton(onClick = state::retry) { Text("Retry failed") }
            } else if (running && state.tokens.isNotEmpty()) {
                TextButton(onClick = state::refresh) { Text("Refresh") }
            }
        }
        sharedError?.let {
            Text(
                "Could not read any token balance: $it",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        var held = 0
        state.tokens.forEach { t ->
            val r = state.resultFor(t)
            val zero = r?.raw != null && r.raw.trimStart('0').isEmpty()
            val hasBalance = r?.raw != null && !zero
            if (hasBalance) held++
            // Collapsed: what the holder has, what could not be read (unless one shared
            // error already said it), and a custom token whose decimals disagree with its
            // contract even at a zero balance. Expanded: every token, zero and in-flight.
            val failedAlone = r != null && r.raw == null && sharedError == null
            if (showAll || hasBalance || failedAlone || r?.decimalsMismatch == true) {
                TokenRow(t, r, showError = sharedError == null, onUseChainDecimals = { state.useChainDecimals(t, it) })
            }
        }
        if (!showAll && state.pending == 0 && held == 0 && sharedError == null && !state.anyFailed) {
            Text(
                when {
                    state.tokens.isNotEmpty() -> "No balance in any of the ${state.tokens.size} tokens checked."
                    state.canAddTokens -> "No tokens are listed for this chain — add some in Settings."
                    else -> "No tokens are listed for this chain."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (state.tokens.isNotEmpty()) {
            TextButton(onClick = { showAll = !showAll }) {
                Text(if (showAll) "Hide zero balances" else "Show all ${state.tokens.size} tokens")
            }
        }
    }
}

@Composable
private fun TokenRow(
    t: Token,
    r: TokenBalance?,
    showError: Boolean,
    onUseChainDecimals: (Int) -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    if (t.custom) "${t.symbol} · custom" else t.symbol,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                Text(
                    shortAddress(t.address),
                    fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(8.dp))
            when {
                r == null -> CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                r.raw != null -> {
                    val zero = r.raw.trimStart('0').isEmpty()
                    Text(
                        formatTokenAmount(r.raw, t.decimals),
                        style = MaterialTheme.typography.titleMedium,
                        color = if (zero) MaterialTheme.colorScheme.onSurfaceVariant else Color.Unspecified,
                    )
                }
                else -> Text("—", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        r?.error?.takeIf { showError }?.let {
            Text(
                "Could not read: $it",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        if (r != null && r.decimalsMismatch) {
            val d = r.chainDecimals!!
            Text(
                "The contract reports $d decimals, this entry says ${t.decimals} — the amount " +
                    "above is scaled by ${t.decimals}.",
                style = MaterialTheme.typography.bodySmall,
                color = StatusColors.Amber,
            )
            TextButton(onClick = { onUseChainDecimals(d) }) { Text("Use $d decimals") }
        }
    }
}

/**
 * The Settings tab's Tokens section: which tokens every Query lookup reads, per chain —
 * the built-in list, the user's own with Remove, and the add form where the host can
 * store them ([Settings.supportsCustomTokens]). Opens on [network], the chain picked at
 * the top; the chips switch to any other. Changes are stored at once (no Save).
 */
@Composable
internal fun TokenSettings(
    controller: NodeController,
    settings: Settings,
    network: String,
    snapshots: Map<String, NodeSnapshot>,
) {
    val networks = remember { settings.allNetworks() }
    var net by remember(network) { mutableStateOf(network) }
    val popular = remember(net) { PopularTokens.forNetwork(net) }
    var custom by remember(net) { mutableStateOf(CustomTokens.parse(settings.customTokensJson(net))) }
    fun save(next: List<Token>) {
        val removed = custom.any { c -> next.none { it.key == c.key } }
        custom = next
        settings.setCustomTokensJson(net, CustomTokens.serialize(next))
        // The balance watch reads this list too: a removed token's stored balance is dropped
        // now, so re-adding it later starts from a fresh baseline, not the forgotten one.
        if (removed) controller.onWatchListChanged(net, added = false)
    }
    var adding by remember(net) { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SettingsSection("Tokens")
        SettingsNote(
            "Every Query lookup shows the address's balance of these tokens, each a verified " +
                "eth_call to the token's balanceOf. Built-in tokens are pinned by contract " +
                "address; add any other ERC-20 token by its contract address.",
        )
        if (networks.size > 1) {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                networks.forEach { id ->
                    FilterChip(selected = id == net, onClick = { net = id }, label = { Text(settings.displayName(id)) })
                }
            }
        }
        Text("Built in", style = MaterialTheme.typography.labelMedium)
        if (popular.isEmpty()) {
            SettingsNote("None for this chain.")
        } else {
            Text(popular.joinToString(" · ") { it.symbol }, style = MaterialTheme.typography.bodyMedium)
        }
        Text("Added by you", style = MaterialTheme.typography.labelMedium)
        if (custom.isEmpty()) SettingsNote("None yet.")
        custom.forEach { t ->
            // A contract this release pins as built-in: the lookup reads the built-in entry,
            // so this one does nothing any more (the user may remove it).
            val shadowed = popular.any { it.key == t.key }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "${t.symbol} · ${t.decimals} decimals" + if (shadowed) " · now built in, not used" else "",
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (shadowed) MaterialTheme.colorScheme.onSurfaceVariant else Color.Unspecified,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        t.address,
                        fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
                if (settings.supportsCustomTokens()) {
                    TextButton(onClick = { save(custom.filterNot { it.key == t.key }) }) { Text("Remove") }
                }
            }
        }
        if (settings.supportsCustomTokens()) {
            if (adding) {
                AddTokenForm(
                    controller, net, running = snapshots[net]?.running == true, listed = popular + custom,
                    onAdd = { save(custom + it); adding = false },
                    onCancel = { adding = false },
                )
            } else {
                OutlinedButton(onClick = { adding = true }) { Text("Add token") }
            }
        }
    }
}

/**
 * The add-token form: contract address, a name, decimals. "Read from contract" fills the
 * name and decimals from the token's own `symbol()`/`decimals()` — a convenience, the user
 * can still edit them; what is stored is checked by [CustomTokens.validate].
 */
@Composable
private fun AddTokenForm(
    controller: NodeController,
    network: String,
    running: Boolean,
    listed: List<Token>,
    onAdd: (Token) -> Unit,
    onCancel: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var address by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var decimals by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    var note by remember { mutableStateOf<String?>(null) }
    var reading by remember { mutableStateOf<Job?>(null) }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
        Text("Add a token", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = address,
            onValueChange = { address = it; problem = null; note = null },
            label = { Text("Contract address (0x…)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it; problem = null },
            label = { Text("Name (e.g. the token's symbol)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = decimals,
            onValueChange = { decimals = it.filter { c -> c in '0'..'9' }.take(3); problem = null },
            label = { Text("Decimals") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        SettingsNote(
            "Decimals scale the raw amount: most tokens use 18, USDC and USDT use 6. A wrong " +
                "value shows a balance off by powers of ten; it is checked against the " +
                "contract's own decimals() when the balance is read.",
        )
        note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = {
                when (val c = CustomTokens.validate(address, name, decimals, listed)) {
                    is CustomTokens.Check.Ok -> {
                        reading?.cancel()
                        onAdd(c.token)
                    }
                    is CustomTokens.Check.Invalid -> problem = c.reason
                }
            }) { Text("Add") }
            OutlinedButton(
                onClick = {
                    val a = address.trim()
                    problem = null
                    note = null
                    reading?.cancel()
                    // Started lazily so `mine` sees THIS job even when the host answers
                    // without suspending (the ENS records read's pattern in NodeScreen).
                    val job = scope.launch(start = CoroutineStart.LAZY) {
                        val mine = { reading === coroutineContext[Job] }
                        try {
                            val m = readTokenMetadata(controller, network, a)
                            if (!mine()) return@launch
                            m.symbol?.let { name = CustomTokens.cleanName(it).take(CustomTokens.MAX_NAME_LENGTH) }
                            m.decimals?.let { decimals = it.toString() }
                            note = when {
                                m.error != null -> "Could not read the contract: ${m.error}"
                                else -> "The contract calls itself ${m.symbol ?: "(no symbol)"} and reports " +
                                    (m.decimals?.let { "$it decimals" } ?: "no decimals — enter them yourself") + "."
                            }
                        } finally {
                            if (mine()) reading = null
                        }
                    }
                    reading = job
                    job.start()
                },
                enabled = running && reading == null && isHexAddress(address.trim()),
            ) { Text("Read from contract") }
            if (reading != null) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
        }
        if (!running) {
            SettingsNote(
                "Reading the contract needs this chain running; you can still enter the name " +
                    "and decimals yourself.",
            )
        }
        TextButton(onClick = { reading?.cancel(); onCancel() }) { Text("Cancel") }
        Spacer(Modifier.height(4.dp))
    }
}

/** "0xA0b8…eB48". */
private fun shortAddress(a: String): String = if (a.length > 12) "${a.take(6)}…${a.takeLast(4)}" else a

/**
 * The token balances as plaintext, for the query result's Copy: one line per token with
 * its amount, raw base units, decimals and full contract address.
 */
internal fun formatTokenBalances(state: TokenBalancesState): String = buildString {
    appendLine("tokens:")
    state.tokens.forEach { t ->
        val r = state.resultFor(t)
        append("  ").append(t.symbol).append(if (t.custom) " (custom)" else "").append(": ")
        when {
            r == null -> append("not read yet")
            r.raw != null -> append(formatTokenAmount(r.raw, t.decimals))
                .append(" (raw ").append(r.raw).append(", ").append(t.decimals).append(" decimals)")
            else -> append("error: ").append(r.error)
        }
        if (r?.decimalsMismatch == true) append(" [contract reports ${r.chainDecimals} decimals]")
        append(" — ").appendLine(t.address)
    }
}
