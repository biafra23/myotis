package com.jaeckel.ethp2p.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.jaeckel.ethp2p.android.cmp.AndroidSettings
import com.jaeckel.ethp2p.android.log.LogBuffer
import io.myotis.api.ChainHandle
import io.myotis.ui.AccountResult
import io.myotis.ui.BalanceWatch
import io.myotis.ui.BalanceWatcher
import io.myotis.ui.WatchChange
import io.myotis.ui.WatchReader
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.runInterruptible

/**
 * The Android host's balance watch (the Watch tab; `io.myotis.ui.BalanceWatch`): the ONE
 * [BalanceWatcher] of the process, the reads it runs over a network's [ChainHandle], and the
 * notification a change posts. [NodeService] decides when to check ([WatchPolicy]); the
 * Watch tab's Check now comes through [check] too, so every trigger shares the watcher's
 * one-check-per-network guard and the same notifications.
 */
object BalanceWatchRunner {

    private const val TAG = "ethp2p.watch"

    /** Its own channel at default importance: a balance change is news, not an alarm —
     *  it lands in the shade with a sound, without peeking over the app in front. */
    private const val CHANNEL_ID = "myotis_balance_watch"

    /** Notification ids: one per watched (network, address), so a later change of the same
     *  address replaces its notification — the Watch tab keeps the history. Above the web
     *  refusals' range (1000 + one per refused site). */
    private const val NOTIFICATION_BASE = 100_000

    @Volatile
    private var watcher: BalanceWatcher? = null

    /** Where Check now and list edits run: off the main thread (a cause scan parses up to
     *  64 full blocks), and outliving the Watch tab's composition, so leaving the tab
     *  mid-check stops the tab's wait, not the check. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private fun watcher(c: Context): BalanceWatcher =
        watcher ?: synchronized(this) {
            watcher ?: BalanceWatcher(AndroidSettings(c.applicationContext)).also { watcher = it }
        }

    /** Whether [network] watches any address — the cheap gate before every trigger. */
    @JvmStatic
    fun hasEntries(c: Context, network: String): Boolean =
        BalanceWatch.parseList(NodeService.watchListJson(c, network)).isNotEmpty()

    /** Whether [network] watches anything and its stored state says a check is due. */
    @JvmStatic
    fun isDue(c: Context, network: String, intervalMs: Long, retryMs: Long): Boolean =
        hasEntries(c, network) && BalanceWatch.isDue(
            BalanceWatch.parseState(NodeService.watchStateJson(c, network)),
            System.currentTimeMillis(), intervalMs, retryMs,
        )

    /**
     * Check [network] over [handle] now and notify each change; blocking, for the service's
     * threads and the catch-up workers. Returns the number of changes, or -1 when nothing
     * was checked (nothing watched, or a check of [network] already running — [isBusy] tells
     * which). Never throws: a failed check is logged and the next trigger tries again. An
     * interrupt is kept on the thread for its owner to see.
     */
    @JvmStatic
    fun checkBlocking(c: Context, network: String, handle: ChainHandle, scanBlocks: Int, budgetMs: Long, why: String): Int =
        try {
            runBlocking { run(c, network, handle, scanBlocks, budgetMs.milliseconds, why) }?.size ?: -1
        } catch (t: Throwable) {
            if (t is InterruptedException) Thread.currentThread().interrupt()
            LogBuffer.w(TAG, "[$network] balance watch ($why) failed: $t")
            -1
        }

    /** Whether a check of [network] is running right now (any trigger's). */
    @JvmStatic
    fun isBusy(c: Context, network: String): Boolean = runBlocking { watcher(c).isChecking(network) }

    /** The Watch tab's Check now: [run] in this object's scope; throws what the reads throw. */
    suspend fun check(c: Context, network: String, handle: ChainHandle, scanBlocks: Int): List<WatchChange>? =
        scope.async { run(c, network, handle, scanBlocks, Duration.INFINITE, "check now") }.await()

    /** The Watch tab edited [network]'s list: drop what was removed (BalanceWatcher.prune). */
    @JvmStatic
    fun listChanged(c: Context, network: String) {
        scope.launch {
            runCatching { watcher(c).prune(network) }
                .onFailure { LogBuffer.w(TAG, "[$network] balance watch prune failed: $it") }
        }
    }

    private suspend fun run(
        c: Context,
        network: String,
        handle: ChainHandle,
        scanBlocks: Int,
        budget: Duration,
        why: String,
    ): List<WatchChange>? {
        val changes = watcher(c).check(network, HandleReader(handle), scanBlocks, budget) ?: return null
        LogBuffer.i(TAG, "[$network] balance watch ($why): " +
            if (changes.isEmpty()) "no change" else "${changes.size} change(s)")
        if (changes.isNotEmpty()) notify(c, network, changes)
        return changes
    }

    /** The engine reads behind a check. Off the caller's thread, and interruptible so a
     *  cancelled check does not leave its coroutine waiting on an engine call. */
    private class HandleReader(private val h: ChainHandle) : WatchReader {
        override suspend fun account(address: String): AccountResult =
            runInterruptible(Dispatchers.IO) { h.requestAccount(address) }.let { r ->
                AccountResult(
                    r.address(), r.exists(), r.nonce(), r.balanceWei(),
                    r.storageRootHex(), r.codeHashHex(), r.blockNumber(), r.peerStateRootHex(),
                    r.peerProofValid(), r.beaconChainVerified(), r.blsVerified(), r.matchedBeaconSlot(),
                    r.verifyMethod(), r.failReason(), r.blockTimestamp(),
                )
            }

        override suspend fun block(number: Long): String? =
            runInterruptible(Dispatchers.IO) { h.reads()?.getBlockByNumber("0x" + number.toString(16), true) }
    }

    private fun notify(c: Context, network: String, changes: List<WatchChange>) {
        val nm = c.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Balance changes", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "A watched address's verified balance changed. The Watch tab lists every change."
            },
        )
        val currency = BalanceWatch.currency(network)
        for (ch in changes) {
            val id = NOTIFICATION_BASE + Math.floorMod("$network/${ch.address}/${ch.asset}".hashCode(), 1_000_000)
            // The tap opens the app on the Watch tab: NEW_TASK from a service context,
            // SINGLE_TOP + CLEAR_TOP so a running Activity gets onNewIntent instead of a copy.
            val open = PendingIntent.getActivity(
                c, id,
                Intent(c, MainActivity::class.java)
                    .putExtra(MainActivity.EXTRA_OPEN_TAB, "Watch")
                    .putExtra(MainActivity.EXTRA_NETWORK, network)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val text = BalanceWatch.notificationText(ch, currency)
            val n = Notification.Builder(c, CHANNEL_ID)
                .setContentTitle(BalanceWatch.notificationTitle(ch, currency))
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setSubText(NodeService.displayName(network))
                .setSmallIcon(R.drawable.ic_stat_myotis)
                .setContentIntent(open)
                .setAutoCancel(true)
                // Balances are private: the lock screen shows that something changed, not how much.
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setPublicVersion(
                    Notification.Builder(c, CHANNEL_ID)
                        .setContentTitle("A watched balance changed")
                        .setSmallIcon(R.drawable.ic_stat_myotis)
                        .build(),
                )
                .build()
            nm.notify(id, n)
        }
        // nm.notify is a silent no-op when Myotis may not post notifications (an auto-started
        // app never asked for the permission on Android 13+): say so, or "notified" would be
        // undiagnosable. The Watch tab shows the change either way.
        if (!nm.areNotificationsEnabled()) {
            LogBuffer.w(TAG, "[$network] balance changed but notifications are off for Myotis; the Watch tab shows it")
        }
    }
}
