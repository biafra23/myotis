package com.jaeckel.ethp2p.android

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import com.jaeckel.ethp2p.android.log.LogBuffer
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/**
 * On-device boot smoke test, aimed at the minSdk emulator (the `api29` Gradle managed
 * device — see the managedDevices block in build.gradle.kts): launch the real
 * [MainActivity], let its fresh-launch path auto-start [NodeService], and wait for the
 * primary network's boot verdict.
 *
 * The point is runtime linkage, not sync: `ChainStack.start()` synchronously walks the
 * whole networking + consensus init sequence — EIP-1459 DNS discovery, the RLPx
 * connector and initial dials, discv4, discv5 + the beacon light client (libp2p, BLS,
 * SSZ), the Ktor JSON-RPC server, the snap-peer maintainer — so a recorded
 * [NodeService.BOOT_STARTED] proves that code actually EXECUTED on this API level.
 * That is coverage a static bytecode scan cannot give: `android.*` framework APIs
 * above minSdk (`SDK_INT` guards are invisible to a dex scan — only running on real
 * API-29 ART checks they work), `java.*` members the SDK's api-versions.xml has no
 * entry for, and anything that only breaks when class init actually runs (provider
 * lookups, reflective access, native-lib fallbacks). It is the runtime complement to
 * the static minSdk dex gate (scripts/check_apk_min_api.py, run by the same
 * workflow's build job).
 *
 * How a startup `NoClassDefFoundError` / `NoSuchMethodError` surfaces here:
 *  - thrown in host/service code or `ENGINE.create()`: the boot worker catches only
 *    `Exception`, so the `Error` crashes the app process and the instrumentation
 *    report carries the crash stack;
 *  - thrown inside `ChainStack.start()`: its internal `catch (Throwable)` converts it
 *    to a `false` return (no crash, stack trace in the log), which [NodeService]
 *    records as a failed boot outcome — this test then FAILS FAST with the app log's
 *    error lines instead of burning the whole deadline.
 *
 * Success additionally requires [NodeService.Snapshot.rpcServing]: ChainStack treats
 * the JSON-RPC bring-up as best-effort (an init failure there is swallowed with
 * "continuing without JSON-RPC" and the stack still reports started), so without this
 * condition a linkage error inside the Ktor/RPC stack would pass silently. On a fresh
 * emulator nothing else holds the RPC port, so the extra condition adds no flake in
 * practice.
 *
 * Deliberate scope choices:
 *  - The boot is triggered by MainActivity's fresh-launch auto-start — the real
 *    cold-launch path. If that auto-start is ever gated (onboarding, a setting), this
 *    test must start the service itself instead of timing out.
 *  - Engine-agnostic, but under `-PskipRustEngine` (how CI runs it) the selector
 *    serves the Java engine — exactly the fallback an APK without the Rust jniLibs
 *    uses at runtime. The Rust engine's own load path is NOT covered here.
 *  - Needs no peers and no internet: "started" means local binds and threads are up.
 */
@RunWith(AndroidJUnit4::class)
class NodeBootSmokeTest {

    // 60 s, not the rule's 5 s default: the bind callback queues on the main looper
    // behind NodeService.onCreate/onStartCommand (startForeground, notification
    // channel, engine class init) on a cold, software-rendered emulator — 5 s there
    // is a flake that would fail the run before the boot path is exercised at all.
    @get:Rule
    val serviceRule: ServiceTestRule = ServiceTestRule.withTimeout(60, TimeUnit.SECONDS)

    @Test
    fun mainActivityLaunches_andNodeServiceBootsTheEngineStack() {
        // launch() throws if the activity fails to reach RESUMED — that alone covers
        // "the app's UI comes up" (Application.onCreate, Compose first render).
        ActivityScenario.launch(MainActivity::class.java).use {
            // MainActivity.onCreate has already called startForegroundService (fresh
            // launch, service not running). Binding does NOT boot anything by itself
            // (see the BIND_AUTO_CREATE note in MainActivity.onStart) — it only gets
            // us the instance whose per-network snapshot we can poll.
            val binder = serviceRule.bindService(
                Intent(ApplicationProvider.getApplicationContext(), NodeService::class.java)
            )
            val service = (binder as NodeService.LocalBinder).service()

            val deadline = System.currentTimeMillis() + BOOT_DEADLINE_MS
            while (true) {
                if (startedCompletely(service)) return
                if (System.currentTimeMillis() >= deadline) break
                // The loop shape guarantees one more check after the final sleep, so
                // a boot landing right at the deadline can't be misreported.
                Thread.sleep(POLL_INTERVAL_MS)
            }
            failTimedOut(service)
        }
    }

    /** One poll: fail the test immediately on a recorded boot failure; true when the
     *  boot verdict is in AND the (best-effort) RPC listener is live. */
    private fun startedCompletely(service: NodeService): Boolean {
        val outcome = NodeService.bootOutcome(NETWORK)
        // Polling the snapshot is itself part of the smoke: it drives the engine's
        // status surfaces (status(), beaconStatus(), cache-file stats) on this ART.
        val snapshot = service.snapshot()
        if (outcome != null && outcome != NodeService.BOOT_STARTED) {
            fail("NodeService boot FAILED: $outcome\n${diagnostics(snapshot)}")
        }
        return outcome == NodeService.BOOT_STARTED && snapshot?.rpcServing() == true
    }

    private fun failTimedOut(service: NodeService) {
        val outcome = NodeService.bootOutcome(NETWORK)
        val snapshot = service.snapshot()
        val hint = when {
            outcome == null ->
                "no boot verdict was recorded — the boot worker never finished " +
                    "(service running=${NodeService.isRunning()})"
            // A failure verdict recorded between the last poll and this re-read:
            // without this arm it would be misreported as an RPC problem below.
            outcome != NodeService.BOOT_STARTED ->
                "boot FAILED between the last poll and this re-read: $outcome"
            snapshot?.rpcServing() != true ->
                "the stack started but the RPC listener never came up — ChainStack " +
                    "treats that bind as best-effort; look for \"continuing without " +
                    "JSON-RPC\" in the log"
            // Fully started between the final poll and this diagnostic re-read: a pass.
            else -> return
        }
        fail(
            "Not fully started after ${BOOT_DEADLINE_MS / 1000}s: $hint\n" +
                diagnostics(snapshot)
        )
    }

    /** Error lines are collected separately from the tail: on the timeout path the
     *  buffer keeps filling after an early failure (idle ticker, heartbeat), and a
     *  plain tail would have scrolled the one interesting stack trace away. */
    private fun diagnostics(snapshot: NodeService.Snapshot?): String {
        val all = LogBuffer.snapshot()
        fun fmt(e: LogBuffer.Entry) = "${e.level()}/${e.tag()}: ${e.message()}"
        val errors = all.filter { it.level() == 'E' }.takeLast(ERROR_LINES)
        val tail = all.takeLast(TAIL_LINES)
        return "last snapshot=$snapshot\n" +
            "--- error log lines (up to $ERROR_LINES) ---\n" +
            errors.joinToString("\n", transform = ::fmt) +
            "\n--- log tail (last $TAIL_LINES) ---\n" +
            tail.joinToString("\n", transform = ::fmt)
    }

    private companion object {
        /** The default-enabled network on a fresh install (NodeService.enabledNetworks). */
        const val NETWORK = "mainnet"
        /** The boot normally lands well under a minute; 240 s absorbs a slow CI runner
         *  (each DNS probe may eat its 10 s deadline offline) while staying under the
         *  job's outer timeout. Boot FAILURES don't wait for this — they fail fast via
         *  the recorded boot outcome. */
        const val BOOT_DEADLINE_MS = 240_000L
        const val POLL_INTERVAL_MS = 2_000L
        const val ERROR_LINES = 40
        const val TAIL_LINES = 100
    }
}
