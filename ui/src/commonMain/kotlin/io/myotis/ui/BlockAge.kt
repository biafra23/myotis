package io.myotis.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.delay
import kotlin.time.Clock

/**
 * How old a block is, for a wallet user: "14 s ago", "3 min ago", "2 h ago", "1 d ago".
 * [ageSeconds] is the wall clock minus the block's own timestamp; a block that reads as
 * from the future (a clock a little behind the chain's) is "just now", never negative.
 */
internal fun formatBlockAge(ageSeconds: Long): String = when {
    ageSeconds <= 0 -> "just now"
    ageSeconds < 60 -> "$ageSeconds s ago"
    ageSeconds < 3_600 -> "${ageSeconds / 60} min ago"
    ageSeconds < 86_400 -> "${ageSeconds / 3_600} h ago"
    else -> "${ageSeconds / 86_400} d ago"
}

/** How often a block age shown as [formatBlockAge] needs re-reading: every second while it
 *  counts seconds, every 30 s once it counts minutes or more. */
internal fun blockAgeRefreshMillis(ageSeconds: Long): Long = if (ageSeconds < 60) 1_000L else 30_000L

/**
 * The age of the block with timestamp [blockTimestampSeconds] (unix seconds, as the engine
 * reports it), kept current: re-read every second while it is under a minute old and every
 * 30 s after. Null when the engine reported no timestamp (≤ 0), so the caller shows the
 * block number alone.
 */
@Composable
internal fun rememberBlockAge(blockTimestampSeconds: Long): String? {
    if (blockTimestampSeconds <= 0) return null
    // Keyed on the block: a new result starts from a fresh reading, not the last one.
    var nowSeconds by remember(blockTimestampSeconds) { mutableStateOf(wallClockSeconds()) }
    LaunchedEffect(blockTimestampSeconds) {
        while (true) {
            nowSeconds = wallClockSeconds()
            delay(blockAgeRefreshMillis(nowSeconds - blockTimestampSeconds))
        }
    }
    return formatBlockAge(nowSeconds - blockTimestampSeconds)
}

/** The wall clock in unix seconds; kotlin.time's Clock is @ExperimentalTime in the 2.2 stdlib. */
@OptIn(kotlin.time.ExperimentalTime::class)
private fun wallClockSeconds(): Long = Clock.System.now().epochSeconds
