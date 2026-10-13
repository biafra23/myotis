package io.myotis.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp

/**
 * The normal-mode Settings pieces: one card per chain, and the section furniture the
 * tab is built from. The tuning knobs stay in `SettingsTab` under Expert mode.
 */

/**
 * A chain's card: its name with the run switch, and its JSON-RPC port underneath. The
 * name row is the toggleable (the switch has no handler of its own), so a screen reader
 * announces "Mainnet, on" as one switch and the whole row is the tap target.
 */
@Composable
internal fun NetworkCard(
    name: String,
    enabled: Boolean,
    port: String,
    portLabel: String,
    onEnabled: (Boolean) -> Unit,
    onPort: (String) -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .toggleable(value = enabled, role = Role.Switch, onValueChange = onEnabled),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(name, style = MaterialTheme.typography.titleMedium)
                Switch(checked = enabled, onCheckedChange = null)
            }
            OutlinedTextField(
                value = port,
                onValueChange = onPort,
                label = { Text(portLabel) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/** A section heading on the Settings tab. */
@Composable
internal fun SettingsSection(title: String) {
    Text(title, style = MaterialTheme.typography.titleMedium)
}

/** The muted explanation under a control. */
@Composable
internal fun SettingsNote(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
