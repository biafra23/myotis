package io.myotis.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.datetime.TimeZone

/** The Watch tab's address field and its Watch button (tests reach them by tag). */
internal const val WATCH_ADDRESS_TAG = "watch-address"
internal const val WATCH_LABEL_TAG = "watch-label"
internal const val WATCH_ADD_TAG = "watch-add"
internal const val WATCH_CHECK_TAG = "watch-check"

/**
 * The Watch tab: the selected network's watched addresses with their last verified
 * balance, the form that adds one, "Check now", and the recent changes — each with what
 * the block scan attributed it to. The host does the checking ([BalanceWatcher], on its
 * own schedule and from [NodeController.checkWatched]); this tab edits the list and
 * reads the state the checks store, re-read with every status snapshot so a background
 * check shows up without a tap.
 */
@Composable
internal fun WatchTab(
    controller: NodeController,
    settings: Settings,
    snapshot: NodeSnapshot?,
    network: String,
) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val currency = nativeCurrencySymbol(network)
    val unit = currency?.let { " $it" } ?: ""
    val tz = remember { TimeZone.currentSystemDefault() }
    // Bumped after every edit and check here; `snapshot` brings in what the host's own
    // checks stored meanwhile (it changes every couple of seconds).
    var rev by remember(network) { mutableStateOf(0) }
    val entries = remember(network, rev) { BalanceWatch.parseList(settings.watchListJson(network)) }
    val state = remember(network, rev, snapshot) { BalanceWatch.parseState(settings.watchStateJson(network)) }
    // The ages below re-read the clock with every snapshot, like the state itself.
    val now = remember(snapshot, rev) { wallClockMillis() }
    var checking by remember(network) { mutableStateOf(false) }
    var checkResult by remember(network) { mutableStateOf<String?>(null) }
    val running = snapshot?.running == true

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            "Watch addresses on ${settings.displayName(network)}: Myotis reads their balance " +
                "from the network, checks the proof, and tells you when it changes — with the " +
                "transaction behind it when a scan of the blocks in between finds one.",
        )
        Text(
            controller.watchSchedule ?: "This app checks only when you tap Check now.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // Check now's body; adding an address runs it too, so the new address gets its
        // baseline at once instead of at the host's next scheduled check.
        fun runCheck() {
            if (checking) return
            checking = true
            checkResult = null
            scope.launch {
                checkResult = try {
                    val found = controller.checkWatched(network)
                    when {
                        found == null -> "A check is already running."
                        found.isEmpty() -> "No change."
                        found.size == 1 -> "1 change."
                        else -> "${found.size} changes."
                    }
                } catch (c: CancellationException) {
                    throw c
                } catch (t: Throwable) {
                    "Check failed: ${t.message ?: t::class.simpleName}"
                } finally {
                    checking = false
                    rev++
                }
            }
        }

        // ---- Add ----
        var address by remember(network) { mutableStateOf("") }
        var label by remember(network) { mutableStateOf("") }
        var addError by remember(network) { mutableStateOf<String?>(null) }
        fun add() {
            val current = BalanceWatch.parseList(settings.watchListJson(network))
            addError = BalanceWatch.addError(current, address)
            if (addError != null) return
            val entry = WatchEntry(BalanceWatch.normalizeAddress(address)!!, BalanceWatch.cleanLabel(label))
            settings.setWatchListJson(network, BalanceWatch.serializeList(current + entry))
            address = ""
            label = ""
            rev++
            controller.onWatchListChanged(network)
            if (running) runCheck()
        }
        OutlinedTextField(
            value = address,
            onValueChange = { address = it.trim(); addError = null },
            label = { Text("Address (0x…)") },
            singleLine = true,
            isError = addError != null,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, imeAction = ImeAction.Next),
            modifier = Modifier.fillMaxWidth().testTag(WATCH_ADDRESS_TAG),
        )
        OutlinedTextField(
            value = label,
            onValueChange = { label = it.take(BalanceWatch.MAX_LABEL) },
            label = { Text("Name (optional)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(WATCH_LABEL_TAG),
        )
        addError?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        Button(
            onClick = ::add,
            enabled = address.isNotBlank(),
            modifier = Modifier.testTag(WATCH_ADD_TAG),
        ) { Text("Watch") }
        Text(
            "The first check of an address records its balance; a later one that finds it " +
                "different is a change. Only balances whose proof verifies count — a peer " +
                "cannot invent a change, or hide one, by answering with an unverified claim.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // ---- The list ----
        if (entries.isNotEmpty()) {
            HorizontalDivider()
            controller.watchNotificationsNote?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(
                    enabled = running && !checking,
                    onClick = ::runCheck,
                    modifier = Modifier.testTag(WATCH_CHECK_TAG),
                ) { Text("Check now") }
                Spacer(Modifier.width(12.dp))
                when {
                    checking -> {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Checking…", style = MaterialTheme.typography.bodySmall)
                    }
                    !running -> Text(
                        "Start ${settings.displayName(network)} on the Status tab to check.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    checkResult != null -> Text(checkResult!!, style = MaterialTheme.typography.bodySmall)
                    state.lastCheckMs > 0 -> Text(
                        "Last checked ${formatBlockAge((now - state.lastCheckMs) / 1000)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            entries.forEach { e ->
                WatchedAddressCard(
                    entry = e,
                    state = state.addresses[BalanceWatch.key(e.address)],
                    unit = unit,
                    nowMs = now,
                    onCopy = { clipboard.setText(AnnotatedString(e.address)) },
                    onRemove = {
                        val current = BalanceWatch.parseList(settings.watchListJson(network))
                        settings.setWatchListJson(network, BalanceWatch.serializeList(current.filter { it.address != e.address }))
                        rev++
                    },
                )
            }
        }

        // ---- Recent changes ----
        if (state.changes.isNotEmpty()) {
            HorizontalDivider()
            Text("Recent changes", style = MaterialTheme.typography.titleMedium)
            state.changes.forEach { c ->
                WatchChangeCard(
                    change = c,
                    currency = currency,
                    tz = tz,
                    onCopy = { text -> clipboard.setText(AnnotatedString(text)) },
                )
            }
        }
    }
}

/** One watched address: its name, the full address, and the last verified balance. */
@Composable
private fun WatchedAddressCard(
    entry: WatchEntry,
    state: WatchAddressState?,
    unit: String,
    nowMs: Long,
    onCopy: () -> Unit,
    onRemove: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        BalanceWatch.displayName(entry.address, entry.label),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        entry.address,
                        fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
                TextButton(onClick = onCopy) { Text("Copy") }
                TextButton(onClick = onRemove) { Text("Remove") }
            }
            val seen = state?.seen
            if (seen != null) {
                Text(BalanceWatch.formatUnits(seen.balanceWei) + unit, style = MaterialTheme.typography.headlineSmall)
                val age = if (seen.blockTimestamp > 0) " · ${formatBlockAge(nowMs / 1000 - seen.blockTimestamp)}" else ""
                Text(
                    "✓ Verified at block ${BalanceWatch.grouped(seen.blockNumber)}$age",
                    style = MaterialTheme.typography.bodySmall,
                    color = StatusColors.Green,
                )
            } else if (state?.error == null) {
                Text(
                    "Not checked yet",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            state?.error?.let { err ->
                Text(
                    "Last check had no verified answer: $err (${formatBlockAge((nowMs - state.errorAtMs) / 1000)})" +
                        if (seen != null) " — showing the last verified balance." else "",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

/** One change: the move, when, what the scan attributed it to, and the hashes to copy. */
@Composable
private fun WatchChangeCard(change: WatchChange, currency: String?, tz: TimeZone, onCopy: (String) -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(BalanceWatch.notificationTitle(change, currency), style = MaterialTheme.typography.titleSmall)
            Text(
                "${formatDateTime(change.detectedAtMs, tz)} · block ${BalanceWatch.grouped(change.toBlock)} · " +
                    "${BalanceWatch.formatUnits(change.oldWei)} → ${BalanceWatch.formatUnits(change.newWei)}" +
                    (currency?.let { " $it" } ?: ""),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(BalanceWatch.causeSummary(change, currency), style = MaterialTheme.typography.bodySmall)
            change.causes.mapNotNull { it.txHash }.distinct().forEach { hash ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SelectionContainer(Modifier.weight(1f)) {
                        Text(
                            hash,
                            fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                            maxLines = 1, overflow = TextOverflow.Ellipsis,
                        )
                    }
                    OutlinedButton(onClick = { onCopy(hash) }) { Text("Copy tx") }
                }
            }
        }
    }
}
