package io.myotis.ui

// Verified head older than this reads as "warming up" (amber) — wallet calls would -32000 until a
// fresh servable head exists. Matches the old Android ReadinessStrip threshold.
internal const val READY_HEAD_WARM_MS = 45_000L

/**
 * An ACTIVE upgrade advisory that the node's OWN verified state corroborates: the beacon
 * feed is not SYNCED, or its verified head has gone stale. The advisory is unverified peer
 * data, so on its own it never turns readiness red or claims the node stopped verifying —
 * a SYNCED, fresh node is verifying, whatever peers say.
 */
internal fun upgradeCutOff(s: NodeSnapshot): Boolean =
    s.upgrade?.active == true && (s.beaconState != "SYNCED" || s.verifiedHeadAgeMs > READY_HEAD_WARM_MS)

/**
 * The readiness ladder, worst first. [readinessOf] walks it top-down and stops at the
 * first rung that applies, so the order here IS the precedence: a red node state
 * explains the index's lag too, and fixing it comes first.
 */
internal enum class ReadinessLevel {
    /** The host reports no connectivity — nothing below can make progress. */
    OFFLINE,
    /** Idle-paused: networking off, a request wakes it. */
    SLEEPING,
    /** No stack registered for this network. */
    STOPPED,
    /** Peers report a network upgrade this build can't follow, and the node agrees it stopped verifying. */
    UPDATE_REQUIRED,
    /** Parked in STALE_ANCHOR, waiting for the user's consent. */
    NEEDS_DECISION,
    /** Beacon light client not SYNCED yet (bootstrapping or catching up). */
    SYNCING,
    /** SYNCED, but no fresh verified head to serve reads from. */
    WARMING,
    /** Ready for reads, but the log index trails the head so head-reaching `eth_getLogs` is refused. */
    INDEX_CATCHING_UP,
    /** Ready for simple reads; the peer pool is still filling. */
    READY,
    /** Deep peer pool — heavy confirm screens will load too. */
    FULLY_READY,
}

/**
 * One network's readiness as the screens show it: a [level] for color and
 * precedence, a [headline] and [detail] for the status card, the formal
 * [a11yLabel] the strip has always announced, and a bar value while something
 * measurable is in progress ([progress], or [indeterminate] when it isn't).
 */
internal data class Readiness(
    val level: ReadinessLevel,
    val headline: String,
    val detail: String?,
    val a11yLabel: String,
    val progress: Float? = null,
    val indeterminate: Boolean = false,
)

/**
 * The wallet's "safe to transact" signal for one chain, evaluated in exactly the
 * strip's order (see [ReadinessLevel]). [online] is the host's connectivity; the
 * strip has never had it, so it defaults to true and callers without a
 * [NetworkStatus] see no change.
 */
internal fun readinessOf(
    s: NodeSnapshot?,
    deepPoolThreshold: Int,
    catchUp: CatchUpProgress? = null,
    online: Boolean = true,
): Readiness = when {
    !online -> Readiness(
        ReadinessLevel.OFFLINE,
        "No internet connection",
        "The node needs internet access to discover and connect to peers.",
        "Node readiness: offline — no internet connection",
    )
    s != null && s.lifecycle == "PAUSED" -> Readiness(
        ReadinessLevel.SLEEPING,
        "Sleeping",
        if (s.upgrade == null) "Networking is off to save battery. A wallet request wakes it."
        else "Networking is off to save battery. Peers report a network upgrade this version " +
            "doesn't support — update the app.",
        if (s.upgrade == null) "Node readiness: sleeping — a request wakes it"
        else "Node readiness: sleeping — peers report a network upgrade this version doesn't support",
    )
    s == null || !s.running -> Readiness(
        ReadinessLevel.STOPPED,
        "Not running",
        "Start the node to verify balances and answer wallet requests.",
        "Node readiness: not running",
    )
    // An unsupported upgrade the node's own state corroborates outranks a stale-anchor
    // park: updating the app fixes both (a new build ships a fresh checkpoint too),
    // while consenting to the old anchor cannot make this build follow the fork.
    upgradeCutOff(s) -> Readiness(
        ReadinessLevel.UPDATE_REQUIRED,
        "Update required",
        "Peers report a network upgrade this version can't follow, and the node has stopped " +
            "verifying. Update the app.",
        "Node readiness: not verifying — peers report a network upgrade this version doesn't support; update the app",
    )
    s.beaconState == "STALE_ANCHOR" -> Readiness(
        ReadinessLevel.NEEDS_DECISION,
        "Needs your decision",
        "The sync anchor is ${(s.syncTargetPeriod - s.syncCurrentPeriod).coerceAtLeast(0)} periods " +
            "old, past the ${s.wsBoundPeriods}-period safety bound. Syncing is paused until you decide.",
        "Node readiness: sync anchor too old — paused awaiting your consent",
    )
    s.beaconState != "SYNCED" -> syncing(s)
    s.verifiedHeadAgeMs > READY_HEAD_WARM_MS -> Readiness(
        ReadinessLevel.WARMING,
        "Almost ready",
        buildString {
            if (s.verifiedHeadAgeMs == Long.MAX_VALUE) {
                append("Synced. Waiting for the first verified head — reads are held until then.")
            } else {
                append("Synced, but the verified head is ${formatAge(s.verifiedHeadAgeMs)} old. ")
                append("Waiting for a fresh one.")
            }
            if (s.elHunting) append(" Looking for snap peers…")
        },
        "Node readiness: warming up, not ready to transact",
    )
    catchUp != null -> Readiness(
        ReadinessLevel.INDEX_CATCHING_UP,
        "Ready — log index catching up",
        LogIndexStatus.catchUpLine(catchUp),
        "Node readiness: ${LogIndexStatus.catchUpLine(catchUp)}; eth_getLogs near the head is refused" +
            if (catchUp.stalled) "" else " until it has caught up",
        // Nothing is closing a stalled gap: a bar would promise motion.
        progress = if (catchUp.stalled) null else catchUp.fraction,
    )
    s.snapServingPeers >= deepPoolThreshold -> Readiness(
        ReadinessLevel.FULLY_READY,
        "Ready",
        "Verified head ${formatAge(s.verifiedHeadAgeMs)} old · deep peer pool, heavy wallet " +
            "screens will load too.",
        "Node readiness: fully ready — deep peer pool, heavy confirm screens will load",
    )
    else -> Readiness(
        ReadinessLevel.READY,
        "Ready",
        "Verified head ${formatAge(s.verifiedHeadAgeMs)} old · peer pool still filling for heavier " +
            "wallet screens (${s.snapServingPeers} of $deepPoolThreshold).",
        "Node readiness: ready for simple reads; peer pool still filling for heavy confirm screens",
    )
}

/** The not-yet-SYNCED rung: label and bar follow the beacon STATE, as the sync bar's do. */
private fun syncing(s: NodeSnapshot): Readiness {
    val start = s.syncStartPeriod
    val current = s.syncCurrentPeriod
    val target = s.syncTargetPeriod
    val determinate = s.beaconState == "CATCHING_UP" && start >= 0 && target > start
    val hunt = if (s.lcHunting) " Looking for light-client servers…" else ""
    val detail = when {
        // Android reports STARTING as STOPPED while the stack is already running.
        s.beaconState == "STARTING" || s.beaconState == "STOPPED" -> "Starting the light client…"
        s.beaconState != "CATCHING_UP" -> "Bootstrapping the light client…"
        determinate && current >= target -> "Finishing sync…"
        determinate -> "Catching up sync committees — period $current of $target."
        else -> "Catching up sync committees…"
    } + hunt
    return Readiness(
        ReadinessLevel.SYNCING,
        "Syncing",
        detail,
        "Node readiness: not synced",
        progress = if (determinate) ((current - start).toFloat() / (target - start).toFloat()).coerceIn(0f, 1f) else null,
        indeterminate = !determinate,
    )
}

/** A head age for people: "4 s", "3 min", "2 h". Pure Kotlin — compiles for iOS too. */
internal fun formatAge(ms: Long): String {
    val sec = ms / 1000
    return when {
        sec < 60 -> "$sec s"
        sec < 3600 -> "${sec / 60} min"
        else -> "${sec / 3600} h"
    }
}

/** How a vitals tile reads: none (not applicable), bad, wait, ok, great. */
internal enum class Tone { NONE, BAD, WAIT, OK, GREAT }

/** One tile on the status screen: a label, the headline value, a one-line detail, and a color tone. */
internal data class Vital(val label: String, val value: String, val detail: String?, val tone: Tone)

/** The four vitals the normal-mode status screen shows. [index] is null unless the log index is enabled. */
internal data class Vitals(val el: Vital, val cl: Vital, val head: Vital, val index: Vital?)

/**
 * The vitals for one network: usable execution peers, consensus state and servers,
 * verified-head freshness, and — when the engine reports an enabled index — the log
 * index. The index tile's tone follows the HEAD side only (head-reaching queries are
 * refused while it trails); an incomplete backfill is said in the detail and never
 * changes the tone, because it does not affect what the node can answer at the head.
 */
internal fun vitalsOf(s: NodeSnapshot?, deepPoolThreshold: Int): Vitals {
    if (s == null || !s.running) {
        return Vitals(
            Vital(EL_LABEL, "—", null, Tone.NONE),
            Vital(CL_LABEL, "—", null, Tone.NONE),
            Vital(HEAD_LABEL, "—", null, Tone.NONE),
            index = null,
        )
    }
    if (s.lifecycle == "PAUSED") {
        return Vitals(
            Vital(EL_LABEL, "—", "sleeping", Tone.NONE),
            Vital(CL_LABEL, "—", "sleeping", Tone.NONE),
            Vital(HEAD_LABEL, "—", "sleeping", Tone.NONE),
            index = indexVital(s),
        )
    }
    val el = Vital(
        EL_LABEL,
        "${s.snapServingPeers} usable",
        "of ${s.readyPeers} connected" + if (s.elHunting) " · looking for more" else "",
        when {
            s.snapServingPeers == 0 -> Tone.BAD
            s.snapServingPeers < deepPoolThreshold -> Tone.OK
            else -> Tone.GREAT
        },
    )
    val servers = s.clServedPeersLastMin
    val cl = Vital(
        CL_LABEL,
        when (s.beaconState) {
            "SYNCED" -> "Synced"
            "CATCHING_UP" -> "Catching up"
            "SYNCING", "STARTING", "STOPPED" -> "Starting"
            "STALE_ANCHOR" -> "Paused"
            else -> s.beaconState
        },
        "$servers ${if (servers == 1) "server" else "servers"} answering" +
            if (s.lcHunting) " · looking for more" else "",
        when (s.beaconState) {
            "SYNCED" -> Tone.OK
            "STALE_ANCHOR" -> Tone.BAD
            else -> Tone.WAIT
        },
    )
    val head = when {
        s.beaconState != "SYNCED" -> Vital(HEAD_LABEL, "—", "waiting for sync", Tone.NONE)
        s.verifiedHeadAgeMs == Long.MAX_VALUE ->
            Vital(HEAD_LABEL, "None yet", "waiting for a peer that can answer", Tone.WAIT)
        s.verifiedHeadAgeMs > READY_HEAD_WARM_MS ->
            Vital(HEAD_LABEL, formatAge(s.verifiedHeadAgeMs), "stale — waiting for a fresh head", Tone.WAIT)
        else -> Vital(HEAD_LABEL, formatAge(s.verifiedHeadAgeMs), "fresh", Tone.OK)
    }
    return Vitals(el, cl, head, indexVital(s))
}

/** The log-index tile, or null when the engine reports no enabled index. */
private fun indexVital(s: NodeSnapshot): Vital? {
    val json = s.logIndexJson ?: return null
    val p = LogIndexStatus.parseOrNull(json)?.takeIf { it.enabled } ?: return null
    val gap = LogIndexStatus.headGap(json)
    val (value, headDetail, tone) = when {
        gap == null -> Triple("Starting", null, Tone.WAIT)
        !LogIndexStatus.refusesHeadQueries(gap) -> Triple("Up to date", null, Tone.OK)
        gap > LogIndexStatus.BRIDGE_MAX_GAP ->
            Triple("Too far behind", "${LogIndexStatus.grouped(gap)} blocks behind the head, not catching up", Tone.WAIT)
        else -> Triple("Behind head", "${LogIndexStatus.grouped(gap)} blocks behind the head", Tone.WAIT)
    }
    val remaining = p.blocksRemaining
    val backfill = when {
        p.entries.isEmpty() -> "no contracts watched"
        remaining == null -> null
        remaining == 0L -> "history complete"
        p.backfillPaused -> "history paused · ${LogIndexStatus.grouped(remaining)} blocks unindexed"
        else -> "history incomplete · " + (LogIndexStatus.progressLine(p) ?: "${LogIndexStatus.grouped(remaining)} blocks left")
    }
    val detail = listOfNotNull(headDetail, backfill).joinToString(" · ").ifEmpty { null }
    return Vital(INDEX_LABEL, value, detail, tone)
}

internal const val EL_LABEL = "Execution peers"
internal const val CL_LABEL = "Consensus"
internal const val HEAD_LABEL = "Verified head"
internal const val INDEX_LABEL = "Log index"
