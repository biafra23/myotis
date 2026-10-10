@file:OptIn(kotlin.time.ExperimentalTime::class)

package io.myotis.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.time.Clock

/**
 * The web-page policy (#502) as Compose state, written through to [Settings] and
 * live-applied through [NodeController.applyWebAccess]. ONE holder, hoisted in
 * `NodeScreen`, so the Status tab's refusal banner and the Settings section agree
 * the moment either changes it: an Allow on the banner is in the list at once.
 */
internal class WebAccessFields(private val settings: Settings, private val controller: NodeController) {
    var mode by mutableStateOf(settings.webAccessMode())
        private set

    /** The allowed sites, normalized ([WebAccessUi.normalize]), in the order added. */
    val origins = mutableStateListOf<String>().apply { addAll(settings.webAccessOrigins()) }

    /** Refusals the user waved away on the Status tab — for this screen's lifetime only. */
    val dismissed = mutableStateListOf<String>()

    fun changeMode(m: WebAccessMode) {
        mode = m
        settings.setWebAccessMode(m)
        controller.applyWebAccess()
    }

    /** Allow a site — typed, or an origin from the recent list. False when [input] is not an origin. */
    fun allow(input: String): Boolean {
        val origin = WebAccessUi.normalize(input) ?: return false
        if (origin !in origins) {
            origins.add(origin)
            persist()
        }
        return true
    }

    fun remove(origin: String) {
        if (origins.remove(origin)) persist()
    }

    fun dismiss(origin: String) {
        if (origin !in dismissed) dismissed.add(origin)
    }

    fun isAllowed(origin: String): Boolean = WebAccessUi.isAllowed(mode, origins, origin)

    /**
     * Re-read the persisted policy: a host can change it behind the screen's back
     * (Android's refusal notification has its own Allow), and a later edit here must
     * build on that list, not on a stale copy that would overwrite it. Called on every
     * snapshot tick; a no-op when nothing moved.
     */
    fun refresh() {
        val m = settings.webAccessMode()
        if (m != mode) mode = m
        val o = settings.webAccessOrigins()
        if (o != origins.toList()) {
            origins.clear()
            origins.addAll(o)
        }
    }

    fun pendingRefusals(rows: List<WebOriginRow>): List<WebOriginRow> =
        WebAccessUi.pendingRefusals(rows, mode, origins, dismissed.toSet())

    private fun persist() {
        settings.setWebAccessOrigins(origins.toList())
        controller.applyWebAccess()
    }
}

/**
 * The Settings tab's "Web page access" section: the three modes, the allowed-sites
 * list with its add field, and the recent web pages of every network folded into one
 * list with Allow / Remove per row. Everything applies at once — no Save, no restart.
 */
@Composable
internal fun WebAccessSection(f: WebAccessFields, snapshots: Map<String, NodeSnapshot>) {
    SettingsSection("Web page access")
    SettingsNote(
        "A web page open in a browser on this device can talk to the node's JSON-RPC port — " +
            "read balances, run calls — for any address it knows, with no wallet prompt. " +
            "This decides which pages may. Wallet apps such as MetaMask Mobile are not web " +
            "pages and always work; a browser-extension wallet (MetaMask in Chrome or Firefox) " +
            "counts as a site and needs allowing once. Applies immediately.",
    )
    ModeRow("Off", f.mode == WebAccessMode.OFF) { f.changeMode(WebAccessMode.OFF) }
    ModeRow("Specific sites", f.mode == WebAccessMode.ALLOWLIST) { f.changeMode(WebAccessMode.ALLOWLIST) }
    ModeRow("All sites", f.mode == WebAccessMode.ALL) { f.changeMode(WebAccessMode.ALL) }
    when (f.mode) {
        WebAccessMode.OFF -> SettingsNote("No web page may use the node. Pages that try are listed below.")
        WebAccessMode.ALL -> Text(
            "Any web page — including one you did not mean to open — can tell that Myotis is " +
                "running and read from it, with no prompt. Prefer Specific sites.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
        WebAccessMode.ALLOWLIST -> AllowedSites(f)
    }
    RecentWebPages(f, snapshots)
}

/** One of the three mode rows: the row is the selectable, so it is one named radio button. */
@Composable
private fun ModeRow(label: String, selected: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect)
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Spacer(Modifier.width(8.dp))
        Text(label)
    }
}

@Composable
private fun AllowedSites(f: WebAccessFields) {
    Text("Allowed sites", style = MaterialTheme.typography.titleSmall)
    if (f.origins.isEmpty()) {
        SettingsNote(
            "None yet. A page that tries to use the node appears under Recent web pages — " +
                "allow it there, or add it here.",
        )
    }
    f.origins.forEach { origin ->
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(origin, style = MaterialTheme.typography.bodyMedium)
                WebAccessUi.knownClient(origin)?.let { SettingsNote(it) }
            }
            TextButton(onClick = { f.remove(origin) }) { Text("Remove") }
        }
    }
    var input by remember { mutableStateOf("") }
    var invalid by remember { mutableStateOf(false) }
    val add = {
        if (f.allow(input)) input = "" else invalid = true
    }
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            value = input,
            onValueChange = { input = it; invalid = false },
            label = { Text("Add a site") },
            supportingText = {
                Text(
                    if (invalid) "Not a site. Use app.example, https://app.example or http://localhost:3000."
                    else "A bare domain means https://; type http:// for a local dev server.",
                )
            },
            isError = invalid,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { add() }),
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(8.dp))
        Button(onClick = add, enabled = input.isNotBlank()) { Text("Add") }
    }
}

@Composable
private fun RecentWebPages(f: WebAccessFields, snapshots: Map<String, NodeSnapshot>) {
    Text("Recent web pages", style = MaterialTheme.typography.titleSmall)
    val rows = remember(snapshots) { WebAccessUi.merge(snapshots.values.map { it.webOrigins }) }
    if (rows.isEmpty()) {
        SettingsNote("No web page has tried to use the node since it started.")
        return
    }
    val now = Clock.System.now().toEpochMilliseconds()
    rows.forEach { r ->
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(r.origin, style = MaterialTheme.typography.bodyMedium)
                SettingsNote(
                    listOfNotNull(
                        WebAccessUi.knownClient(r.origin),
                        r.network,
                        if (r.lastAllowed) "allowed" else "refused",
                        "${r.attempts} request" + if (r.attempts == 1L) "" else "s",
                        formatAge((now - r.lastSeenEpochMs).coerceAtLeast(0)) + " ago",
                    ).joinToString(" · "),
                )
            }
            if (f.mode == WebAccessMode.ALLOWLIST) {
                if (f.isAllowed(r.origin)) {
                    TextButton(onClick = { f.remove(r.origin) }) { Text("Remove") }
                } else if (WebAccessUi.allowable(r.origin)) {
                    TextButton(onClick = { f.allow(r.origin) }) { Text("Allow") }
                }
            }
        }
    }
    SettingsNote(
        "Requests since the node started, the browser's preflight checks included. Kept in " +
            "memory only and never shared — it is browsing history.",
    )
}

/**
 * The Status tab's refusal banner: the browser tells a page nothing about WHY its
 * request failed (a blocked cross-origin fetch is just a network error to the page;
 * the reason is in the developer console), so this is where the user learns that a
 * site wants in — and allows it, if they trust it, for every request from then on.
 */
@Composable
internal fun WebAccessBanner(pending: List<WebOriginRow>, onAllow: (String) -> Unit, onDismiss: (String) -> Unit) {
    if (pending.isEmpty()) return
    val onContainer = MaterialTheme.colorScheme.onTertiaryContainer
    Column(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.tertiaryContainer)
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(
            if (pending.size == 1) "A web page was refused" else "${pending.size} web pages were refused",
            style = MaterialTheme.typography.titleSmall,
            color = onContainer,
        )
        pending.take(3).forEach { r ->
            val who = WebAccessUi.knownClient(r.origin)?.let { " ($it)" } ?: ""
            Text(
                "${r.origin}$who tried to use the node and was refused. Allow it only if you " +
                    "trust that site: it can then read balances and run calls through your node.",
                fontSize = 13.sp,
                color = onContainer,
            )
            Row {
                TextButton(onClick = { onAllow(r.origin) }) { Text("Allow") }
                TextButton(onClick = { onDismiss(r.origin) }) { Text("Dismiss") }
            }
        }
        if (pending.size > 3) {
            Text(
                "…and ${pending.size - 3} more under Settings → Web page access.",
                fontSize = 13.sp,
                color = onContainer,
            )
        }
    }
}
