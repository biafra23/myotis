package io.myotis.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.myotis.logindex.LogIndexDownloads
import io.myotis.logindex.LogIndexPresets
import io.myotis.logindex.LogIndexPresets.Preset

/** Test tags: a preset's checkbox row, the add button, the metered switch. */
internal fun indexPresetTag(id: String) = "index-preset-$id"
internal const val INDEX_PRESET_ADD_TAG = "index-preset-add"
internal const val INDEX_ALLOW_METERED_TAG = "index-allow-metered"

/**
 * The Index tab's "Predefined contracts": the protocols [LogIndexPresets] knows
 * for [network], each with what it costs to download and keep, the selection's
 * total, whether adding them together saves a re-walk, and the "download on
 * metered connections too" switch (off by default — the engine holds the walk on
 * a metered network). Adding one is adding its contracts to the watch list
 * ([onAdd]); the walk that follows is the same verified backfill as for a
 * contract typed in by hand.
 */
@Composable
internal fun LogIndexPresetSection(
    settings: Settings,
    network: String,
    /** The watch list's addresses (lowercased) → their fromBlock: a preset whose
     *  contracts are all in it is added. */
    listed: Map<String, Long>,
    /** Whether the index already watches anything — then adding starts a re-walk for the new ones. */
    indexHoldsContracts: Boolean,
    /** The verified head, for the estimates; null while unknown (the census head is used). */
    headBlock: Long?,
    /** The host's metering report (NodeSnapshot.networkMetering). */
    networkMetering: String?,
    /** Whether the walk is paused by the user's switch below — then adding does not start it. */
    backfillPaused: Boolean,
    onAllowMeteredChanged: (Boolean) -> Unit,
    onAdd: (List<Preset>) -> Unit,
) {
    val available = remember(network) { LogIndexPresets.forNetwork(network) }
    var allowMetered by remember(network) { mutableStateOf(settings.logIndexAllowMetered(network)) }
    if (available.isEmpty()) {
        // No predefined contracts on this network; the metered switch still applies
        // to anything typed in by hand.
        MeteredSwitch(network, allowMetered, networkMetering) {
            allowMetered = it
            onAllowMeteredChanged(it)
        }
        return
    }
    val addable = remember(network, listed) { LogIndexPresetText.addable(network, listed.keys) }
    var selected by remember(network) { mutableStateOf(emptySet<String>()) }
    // A preset that got added (here, or by hand) leaves the selection.
    val selection = addable.filter { it.id in selected }

    Text("Predefined contracts", style = MaterialTheme.typography.titleSmall)
    Text(
        "Download and verify the history a protocol's wallet needs. Every log is checked against " +
            "the block's receipts root before it is kept; nothing is taken on trust. Sizes are " +
            "estimates from a census of the chain.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    available.forEach { p ->
        val done = p !in addable
        val single = remember(p.id, headBlock) { LogIndexDownloads.estimate(listOf(p), headBlock) }
        Row(
            Modifier
                .fillMaxWidth()
                .testTag(indexPresetTag(p.id))
                .toggleable(
                    value = done || p.id in selected,
                    enabled = !done,
                    role = Role.Checkbox,
                    onValueChange = { on -> selected = if (on) selected + p.id else selected - p.id },
                ),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Checkbox(checked = done || p.id in selected, onCheckedChange = null, enabled = !done)
            Column(Modifier.weight(1f)) {
                Text(p.title + if (done) LogIndexPresetText.addedSuffix(p, listed) else "")
                Text(p.summary, style = MaterialTheme.typography.bodySmall)
                Text(
                    LogIndexPresetText.presetLine(p, single),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
    if (selection.isNotEmpty()) {
        val total = remember(selection, headBlock) { LogIndexDownloads.estimate(selection, headBlock) }
        OutlinedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                LogIndexPresetText.totalLines(total)?.forEach { Text(it) }
                LogIndexPresetText.togetherLine(total)?.let {
                    Text(it, color = MaterialTheme.colorScheme.primary)
                }
                LogIndexPresetText.adviceLine(selection, addable, headBlock)?.let {
                    Text(it, color = MaterialTheme.colorScheme.primary)
                }
                if (indexHoldsContracts) {
                    Text(LogIndexPresetText.EXISTING_INDEX_NOTE, style = MaterialTheme.typography.bodySmall)
                }
                if (backfillPaused) {
                    Text(
                        "The backfill is paused below: the contracts are added, and the download " +
                            "starts when you resume it.",
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
    MeteredSwitch(network, allowMetered, networkMetering) {
        allowMetered = it
        onAllowMeteredChanged(it)
    }
    Button(
        enabled = selection.isNotEmpty(),
        modifier = Modifier.testTag(INDEX_PRESET_ADD_TAG),
        onClick = {
            onAdd(selection)
            selected = emptySet()
        },
    ) {
        Text(
            when (selection.size) {
                0 -> "Select contracts to download"
                1 -> "Add ${selection.first().title} and download"
                else -> "Add ${selection.size} and download"
            },
        )
    }
}

@Composable
private fun MeteredSwitch(network: String, on: Boolean, networkMetering: String?, onChange: (Boolean) -> Unit) {
    Column(Modifier.testTag(INDEX_ALLOW_METERED_TAG)) {
        SwitchRow(
            label = "Download on metered connections on $network",
            checked = on,
            enabled = true,
            onChange = onChange,
        )
        Text(
            LogIndexPresetText.meteredLine(on, networkMetering),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
