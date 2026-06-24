// :app-desktop — the Compose-Multiplatform DESKTOP app. Hosts the shared `:ui` NodeScreen
// and drives the Java backend (`node-core`) in-process via DesktopNodeController — the same
// backend the daemon and Android use, so there's no duplication. (JVM target; not iOS.)

import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":ui"))

    // The shared backend + the daemon's file-backed cache adapters / CCIP gateway, reused.
    implementation(project(":node-core"))
    implementation(project(":app"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))
    implementation(project(":rpc-backend"))
    implementation(project(":core"))

    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.core)

    runtimeOnly(libs.logback.classic)
}

// Headless check that the Desktop controller drives node-core (no display needed).
tasks.register<JavaExec>("syncSmoke") {
    group = "verification"
    description = "Start the primary network in-process and exit 0 on SYNCED (no GUI)."
    mainClass.set("io.myotis.desktop.SyncSmokeKt")
    classpath = sourceSets["main"].runtimeClasspath
    javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) })
    systemProperty("myotis.logfile", rootProject.file("devp2p.log").absolutePath)
}

compose.desktop {
    application {
        mainClass = "io.myotis.desktop.MainKt"
        nativeDistributions {
            // macOS first (Apple Silicon). The .dmg can only be PRODUCED on macOS (jpackage
            // is host-OS-bound) — build/run on Linux for dev; package the dmg on a macOS CI
            // runner. Add Deb/Msi when those hosts exist.
            targetFormats(TargetFormat.Dmg)
            packageName = "Myotis"
            packageVersion = "1.0.0"  // jpackage/dmg requires MAJOR > 0
            macOS {
                bundleID = "io.myotis.desktop"
            }
        }
    }
}
