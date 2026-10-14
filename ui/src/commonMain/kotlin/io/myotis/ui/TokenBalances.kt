package io.myotis.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
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
private const val TOKEN_READS_IN_FLIGHT = 4

/**
 * The Query tab's token balances for [holder] on [network]: the built-in [PopularTokens]
 * plus the user's own ([CustomTokens], added and removed here when the host persists them),
 * each read with a verified `eth_call` to `balanceOf` ([readTokenBalance]) as soon as the
 * card shows. Rows fill in as their reads land; a row that could not be read says why, and
 * is read again by itself once the node is back up and synced ([ready]).
 * [contractDecimals] remembers what each custom token's contract answered to `decimals()`
 * across lookups (the caller scopes it to the network), so that check costs one call per
 * token, not one per read.
 */
@Composable
internal fun TokenBalancesCard(
    controller: NodeController,
    settings: Settings,
    network: String,
    holder: String,
    running: Boolean,
    ready: Boolean,
    contractDecimals: MutableMap<String, Int>,
) {
    val clipboard = LocalClipboardManager.current
    val popular = remember(network) { PopularTokens.forNetwork(network) }
    var custom by remember(network) { mutableStateOf(CustomTokens.parse(settings.customTokensJson(network))) }
    fun saveCustom(next: List<Token>) {
        custom = next
        settings.setCustomTokensJson(network, CustomTokens.serialize(next))
    }
    // A custom entry for a contract a later release pinned as built-in shows once, as built-in.
    val tokens = popular + custom.filterNot { c -> popular.any { it.key == c.key } }

    // Bumping [refresh] drops every result and re-reads every row; bumping one row's attempt
    // re-reads that row alone.
    var refresh by remember(network, holder) { mutableStateOf(0) }
    val results = remember(network, holder, refresh) { mutableStateMapOf<String, TokenBalance>() }
    val attempts = remember(network, holder, refresh) { mutableStateMapOf<String, Int>() }
    val permits = remember { Semaphore(TOKEN_READS_IN_FLIGHT) }
    tokens.forEach { t ->
        // One effect per token, keyed on the token itself: adding a token reads only it,
        // removing one cancels its read, and a custom token's edited decimals re-read it.
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
    // Rows that failed while the node was down or catching up are read again once it is
    // ready: a stopped node's "not running" must not outlive the node coming back.
    LaunchedEffect(ready) {
        if (!ready) return@LaunchedEffect
        results.filterValues { it.raw == null }.keys.forEach { k ->
            results.remove(k)
            attempts[k] = (attempts[k] ?: 0) + 1
        }
    }
    // Every row failing the same way (the node stopped, its read surface is down) is one
    // problem: say it once instead of on every row.
    val read = tokens.mapNotNull { t -> results[t.key]?.takeIf { it.token == t } }
    val sharedError = read
        .takeIf { it.size == tokens.size && it.size > 1 && it.all { r -> r.raw == null } }
        ?.map { it.error }?.distinct()?.singleOrNull()
    var hideZero by remember { mutableStateOf(false) }
    var adding by remember(network) { mutableStateOf(false) }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Tokens", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                TextButton(onClick = { refresh++ }, enabled = running) { Text("Refresh") }
                OutlinedButton(onClick = {
                    clipboard.setText(AnnotatedString(formatTokenBalances(holder, tokens, results)))
                }) { Text("Copy") }
            }
            Text(
                "Each balance is a verified eth_call to the token's balanceOf, run against the " +
                    "beacon-verified head state. Built-in tokens are pinned by contract address.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (tokens.isEmpty()) {
                Text(
                    "No built-in tokens for this network — add one by its contract address.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            sharedError?.let {
                Text(
                    "Could not read any balance: $it",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            tokens.forEach { t ->
                // A result read for a since-edited token (other decimals) is stale: wait.
                val r = results[t.key]?.takeIf { it.token == t }
                val zero = r?.raw != null && r.raw.trimStart('0').isEmpty()
                if (!(hideZero && zero)) {
                    HorizontalDivider()
                    TokenRow(
                        t, r,
                        showError = sharedError == null,
                        onRemove = if (t.custom) ({ saveCustom(custom.filterNot { it.key == t.key }) }) else null,
                        onUseChainDecimals = { d ->
                            saveCustom(custom.map { if (it.key == t.key) it.copy(decimals = d) else it })
                        },
                    )
                }
            }
            if (tokens.isNotEmpty()) {
                TextButton(onClick = { hideZero = !hideZero }) {
                    Text(if (hideZero) "Show zero balances" else "Hide zero balances")
                }
            }
            if (settings.supportsCustomTokens()) {
                if (adding) {
                    AddTokenForm(
                        controller, network, running, listed = tokens,
                        onAdd = { saveCustom(custom + it); adding = false },
                        onCancel = { adding = false },
                    )
                } else {
                    TextButton(onClick = { adding = true }) { Text("+ Add token") }
                }
            }
        }
    }
}

@Composable
private fun TokenRow(
    t: Token,
    r: TokenBalance?,
    showError: Boolean,
    onRemove: (() -> Unit)?,
    onUseChainDecimals: (Int) -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    if (t.custom) "${t.symbol} · custom" else t.symbol,
                    style = MaterialTheme.typography.titleSmall,
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
            if (onRemove != null) {
                TextButton(onClick = onRemove) { Text("Remove") }
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
        Text(
            "Decimals scale the raw amount: most tokens use 18, USDC and USDT use 6. A wrong " +
                "value shows a balance off by powers of ten; it is checked against the " +
                "contract's own decimals() when the balance is read.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
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
        TextButton(onClick = { reading?.cancel(); onCancel() }) { Text("Cancel") }
        Spacer(Modifier.height(4.dp))
    }
}

/** "0xA0b8…eB48". */
private fun shortAddress(a: String): String = if (a.length > 12) "${a.take(6)}…${a.takeLast(4)}" else a

/** Plaintext of the card for the clipboard: one line per token, full addresses. */
internal fun formatTokenBalances(holder: String, tokens: List<Token>, results: Map<String, TokenBalance>): String =
    buildString {
        appendLine("holder: $holder")
        tokens.forEach { t ->
            val r = results[t.key]?.takeIf { it.token == t }
            append(t.symbol).append(if (t.custom) " (custom)" else "").append(": ")
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
