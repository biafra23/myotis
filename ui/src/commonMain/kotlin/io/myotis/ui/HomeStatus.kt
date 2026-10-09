package io.myotis.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * The normal-mode Status screen's two pieces: the readiness card and the vitals
 * tiles. Both draw the pure-Kotlin model in Readiness.kt and nothing else, so the
 * strip above the tabs, the card and the tiles can never disagree.
 */

internal const val STATUS_HERO_TAG = "status-hero"

/**
 * The readiness card: a colored dot and the headline, the one-line detail, a bar
 * while something measurable is in progress, and the [action] row (Start / Stop and
 * whatever the rung needs — network settings, the stale-anchor review). [help] is
 * the card's own "ⓘ" slot.
 */
@Composable
internal fun StatusHero(
    r: Readiness,
    help: @Composable () -> Unit = {},
    action: @Composable RowScope.() -> Unit,
) {
    val color = StatusColors.of(r.level)
    Card(
        Modifier.fillMaxWidth().testTag(STATUS_HERO_TAG),
        // A light wash of the rung's color behind the card, so the state reads at a
        // glance on either scheme; the text keeps the surface's own content color.
        colors = CardDefaults.cardColors(
            containerColor = color.copy(alpha = 0.12f),
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.Top) {
                // The headline and detail form one announcement; the buttons stay their own.
                Column(
                    Modifier.weight(1f).semantics(mergeDescendants = true) {},
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        ToneDot(color, 14.dp)
                        Spacer(Modifier.width(10.dp))
                        Text(r.headline, style = MaterialTheme.typography.headlineSmall)
                    }
                    r.detail?.let {
                        Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                help()
            }
            when {
                r.progress != null -> LinearProgressIndicator(
                    progress = { r.progress },
                    modifier = Modifier.fillMaxWidth(),
                    color = color,
                    trackColor = color.copy(alpha = 0.25f),
                )
                r.indeterminate -> LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    color = color,
                    trackColor = color.copy(alpha = 0.25f),
                )
            }
            // Two buttons can share the row (offline + stopped); on a narrow phone they wrap.
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                action()
            }
        }
    }
}

/** The vitals, two per row: execution peers / consensus, verified head / log index (when enabled). */
@Composable
internal fun VitalsGrid(v: Vitals) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            VitalTile(v.el, Modifier.weight(1f))
            VitalTile(v.cl, Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            VitalTile(v.head, Modifier.weight(1f))
            if (v.index != null) VitalTile(v.index, Modifier.weight(1f)) else Spacer(Modifier.weight(1f))
        }
    }
}

/** One tile: label, a tone dot with the value, the detail beneath. One semantics node. */
@Composable
private fun VitalTile(v: Vital, modifier: Modifier) {
    val announced = "${v.label}: ${v.value}" + (v.detail?.let { ", $it" } ?: "")
    Card(modifier.semantics(mergeDescendants = true) { contentDescription = announced }) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(v.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (v.tone != Tone.NONE) {
                    ToneDot(StatusColors.of(v.tone), 8.dp)
                    Spacer(Modifier.width(6.dp))
                }
                Text(v.value, style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            v.detail?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

/** The status dot the card and the tiles share. Decorative: the text beside it carries the meaning. */
@Composable
private fun ToneDot(color: Color, size: Dp) {
    Box(Modifier.size(size).background(color, CircleShape))
}
