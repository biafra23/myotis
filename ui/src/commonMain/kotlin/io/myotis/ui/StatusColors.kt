package io.myotis.ui

import androidx.compose.ui.graphics.Color

/**
 * The saturated status colors every readiness surface shares — the strip above
 * the tabs, the status card and the vitals tiles. Literals on purpose: they are
 * the one place the screens step outside the Material scheme, because a traffic
 * light has to read the same on the light and the dark scheme.
 */
internal object StatusColors {
    /** Sleeping — nothing wrong, nothing happening. */
    val Grey = Color(0xFF78909C)
    /** Not running, not synced, blocked on an update or a decision. */
    val Red = Color(0xFFD32F2F)
    /** Synced but not ready: warming up, hunting, or the log index trails the head. */
    val Amber = Color(0xFFF9A825)
    /** Ready for simple reads. */
    val Green = Color(0xFF2E7D32)
    /** Fully ready — deep peer pool. */
    val BrightGreen = Color(0xFF00E676)

    fun of(level: ReadinessLevel): Color = when (level) {
        ReadinessLevel.SLEEPING -> Grey
        ReadinessLevel.OFFLINE,
        ReadinessLevel.STOPPED,
        ReadinessLevel.UPDATE_REQUIRED,
        ReadinessLevel.NEEDS_DECISION,
        ReadinessLevel.SYNCING -> Red
        ReadinessLevel.WARMING,
        ReadinessLevel.INDEX_CATCHING_UP -> Amber
        ReadinessLevel.READY -> Green
        ReadinessLevel.FULLY_READY -> BrightGreen
    }

    fun of(tone: Tone): Color = when (tone) {
        Tone.NONE -> Grey
        Tone.BAD -> Red
        Tone.WAIT -> Amber
        Tone.OK -> Green
        Tone.GREAT -> BrightGreen
    }
}
