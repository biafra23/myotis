package io.myotis.ui

import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

/**
 * What an amount reads while [Settings.hideAmounts] is on: one fixed width, so neither
 * the number nor its length shows through. The unit next to it stays (`•••• ETH`) —
 * what is held is visible, how much is not.
 */
const val AMOUNT_MASK = "••••"

/** [text] itself, or [AMOUNT_MASK] when [hidden]. */
fun maskAmount(text: String, hidden: Boolean): String = if (hidden) AMOUNT_MASK else text

/**
 * Whether the screens below the header hide amounts. Provided once by [NodeScreen] from
 * [Settings.hideAmounts], so every tab reads the same live value without threading it
 * through each composable.
 */
internal val LocalHideAmounts = compositionLocalOf { false }

/** The header's toggle (tests reach it by tag). */
internal const val HIDE_AMOUNTS_TAG = "hide-amounts"

/**
 * The header's hide-amounts toggle, top left on every tab: an open eye while amounts
 * show, a closed eye (tinted, so the mode is noticed) while they are hidden. Outlined
 * on purpose — the Watch tab's navigation icon is the filled eye.
 */
@Composable
internal fun HideAmountsButton(hidden: Boolean, onToggle: () -> Unit) {
    IconButton(
        onClick = onToggle,
        modifier = Modifier.testTag(HIDE_AMOUNTS_TAG),
        colors = if (hidden) {
            IconButtonDefaults.iconButtonColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
        } else {
            IconButtonDefaults.iconButtonColors()
        },
    ) {
        Icon(
            if (hidden) EyeIcons.Closed else EyeIcons.Open,
            contentDescription = if (hidden) "Show amounts" else "Hide amounts",
            modifier = Modifier.size(24.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** The toggle's two glyphs: 24 dp line icons, 2 dp round strokes (`Icon` tints them). */
internal object EyeIcons {
    /** An open eye, outlined. */
    val Open: ImageVector by lazy {
        stroked(
            "EyeOpen",
            "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z",
            "M15 12a3 3 0 1 1-6 0a3 3 0 1 1 6 0z",
        )
    }

    /** A closed eye: the lower lid's curve with four lashes. */
    val Closed: ImageVector by lazy {
        stroked(
            "EyeClosed",
            "M2 10s3.5 5 10 5 10-5 10-5",
            "M4.6 13.1L3 15.2",
            "M9.2 14.8l-0.6 2.5",
            "M14.8 14.8l0.6 2.5",
            "M19.4 13.1L21 15.2",
        )
    }

    private fun stroked(name: String, vararg paths: String): ImageVector {
        val b = ImageVector.Builder(name = name, defaultWidth = 24.dp, defaultHeight = 24.dp, viewportWidth = 24f, viewportHeight = 24f)
        paths.forEach {
            b.addPath(
                addPathNodes(it),
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 2f,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round,
            )
        }
        return b.build()
    }
}
