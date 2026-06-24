package io.myotis.desktop

import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.system.exitProcess

/**
 * Headless verification that the Desktop `NodeController` actually drives the Java backend
 * in-process (no GUI / display needed): start the primary network, poll snapshots, exit 0 on
 * SYNCED. Run: `./gradlew :app-desktop:syncSmoke`. Proves the desktop↔node-core wiring on a
 * headless host; the GUI render itself is verified on macOS.
 */
fun main() = runBlocking {
    val dataDir = Files.createTempDirectory("myotis-smoke")
    val controller = DesktopNodeController(dataDir)
    val settings = DesktopSettings()
    val net = settings.primaryNetwork()
    println("[smoke] enabling $net (dataDir=$dataDir)")
    controller.enableNetwork(net)

    // nanoTime deadline — immune to wall-clock / NTP steps that could prematurely fire or
    // never fire a currentTimeMillis() deadline.
    val deadline = System.nanoTime() + 180_000_000_000L
    controller.snapshots().collect { snaps ->
        snaps[net]?.let { s ->
            println("[smoke] ${s.network} state=${s.beaconState} blk=${s.executionBlockNumber} " +
                "peers=${s.connectedPeers} snap=${s.snapPeers} period=${s.syncCurrentPeriod}/${s.syncTargetPeriod}")
            if (s.beaconState == "SYNCED") {
                println("[smoke] SYNCED — Desktop controller drives node-core in-process OK")
                controller.shutdown()
                exitProcess(0)
            }
        }
        if (System.nanoTime() - deadline >= 0) {  // overflow-safe nanoTime comparison
            println("[smoke] timeout (no SYNCED in 180s)")
            controller.shutdown()
            exitProcess(1)
        }
    }
}
