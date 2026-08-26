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

/**
 * On-device boot smoke test, aimed at the minSdk emulator (the `api29` Gradle managed
 * device — see the managedDevices block in build.gradle.kts): launch the real
 * [MainActivity], let its fresh-launch path auto-start [NodeService], and wait until
 * the primary network's engine stack reports a COMPLETED start.
 *
 * The point is runtime linkage, not sync: `ChainStack.start()` synchronously walks the
 * whole networking + consensus init sequence — EIP-1459 DNS discovery, the RLPx
 * connector and initial dials, discv4, discv5 + the beacon light client (libp2p, BLS,
 * SSZ), the Ktor JSON-RPC server, the snap-peer maintainer — so reaching "started"
 * proves that code actually EXECUTES on this API level. That covers what the static
 * APK scan (scripts/check_apk_min_api.py) deliberately cannot:
 *
 *  - `android.*` framework APIs above minSdk in startup code — out of the dex gate's
 *    scope, because `SDK_INT` guards are invisible to a bytecode scan (lint's NewApi
 *    owns the source side; only running on real API-29 ART checks the guards work);
 *  - `java.*` members the SDK's api-versions.xml has no entry for (the gate must skip
 *    what it cannot resolve);
 *  - anything that only breaks when class init actually runs (provider lookups,
 *    reflective access, native-lib fallbacks).
 *
 * A [NoClassDefFoundError] / [NoSuchMethodError] anywhere on the boot path crashes the
 * app process — NodeService's boot workers catch `Exception`, not `Error` — which
 * fails this test with the crash stack in the instrumentation report. A boot that dies
 * with a plain Exception is also caught: the stack never reports started and the
 * timeout failure below prints the in-app log tail, which includes the boot error.
 *
 * The test needs no peers and no internet: "started" means local binds and threads are
 * up, before any peer answers. It is engine-agnostic — under `-PskipRustEngine` (how
 * CI runs it) the selector serves the Java engine, exactly the fallback an APK without
 * the Rust jniLibs uses at runtime.
 */
@RunWith(AndroidJUnit4::class)
class NodeBootSmokeTest {

    @get:Rule
    val serviceRule = ServiceTestRule()

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
            var last: NodeService.Snapshot? = null
            while (System.currentTimeMillis() < deadline) {
                // Polling snapshot() is itself part of the smoke: it runs the engine's
                // status surfaces (status(), beaconStatus(), the cache-file stats).
                last = service.snapshot()
                // "RUNNING + RPC serving" is the start-completed signal: ChainStack
                // flips its lifecycle to RUNNING on ENTRY to start(), but binds the
                // RPC listener as the last-but-one init step — so a live listener
                // means the whole init sequence above it has already executed.
                if (last != null && last.lifecycle() == "RUNNING" && last.rpcServing()) {
                    return
                }
                Thread.sleep(POLL_INTERVAL_MS)
            }

            val logTail = LogBuffer.snapshot()
                .takeLast(LOG_TAIL_LINES)
                .joinToString("\n") { e -> "${e.level()}/${e.tag()}: ${e.message()}" }
            fail(
                "NodeService did not report a fully started stack within " +
                    "${BOOT_DEADLINE_MS / 1000}s (service running=${NodeService.isRunning()}, " +
                    "last snapshot=$last).\nRecent app log:\n$logTail"
            )
        }
    }

    private companion object {
        /** Generous: cold ART + a software-GPU emulator boot the stack in well under a
         *  minute, but CI runners are slow and the DNS probes may each eat their 10 s
         *  deadline offline. Well below any outer per-run timeout, so the timeout path
         *  fails with our diagnostics instead of a bare hang. */
        const val BOOT_DEADLINE_MS = 300_000L
        const val POLL_INTERVAL_MS = 500L
        /** Enough to include the boot banner and any boot failure with its cause chain. */
        const val LOG_TAIL_LINES = 150
    }
}
