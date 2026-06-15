import org.jetbrains.compose.desktop.application.dsl.TargetFormat

// Installable desktop GUI for Linux / Windows / macOS. Embeds the real :app daemon
// (DaemonRuntime) in-process — the same node stack the CLI and Android app run — and
// packages it with jpackage via the Compose Desktop Gradle plugin.
//
// JVM 21: this module is NOT on the Android consumption path (CLAUDE.md's JVM-17
// rule is about staying Android-consumable). It depends on :networking and
// :myotis-evm, which ship JVM-21 class files, and the bundled jpackage runtime is
// a full JDK 21 — so 21 is both required and free of Android cost here.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.jetbrains.compose)
}

// Same netty story as :app and :android-app: jvm-libp2p (via :consensus) and Besu's
// netty-bom (via :myotis-evm) drag upstream io.netty onto the classpath, which clashes
// with the JitPack netty-kotlin fork (republished under the same io.netty.* package
// names). Strip upstream group-wide so only the fork — pulled in transitively from
// :networking / :consensus, and pinned explicitly below — assembles into the runtime image.
configurations.all {
    exclude(group = "io.netty")
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    // The embedded daemon (DaemonRuntime, AppPaths, CommandHandler) plus the node
    // stack types the controller observes (NetworkConfig, BeaconSyncState, RLPxConnector).
    // :app exposes its module deps only as `implementation`, so :networking and
    // :consensus are declared here too for compile-time visibility of those types.
    implementation(project(":app"))
    implementation(project(":networking"))
    implementation(project(":consensus"))

    // Netty fork — same artifacts :app pins. Present transitively at runtime, declared
    // explicitly so the jpackage runtime image is satisfied regardless of resolution order.
    implementation(libs.netty.transport)
    implementation(libs.netty.codec)
    implementation(libs.netty.handler)

    // Compose Desktop UI.
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.swing)

    implementation(libs.slf4j.api)
    runtimeOnly(libs.logback.classic)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
}

tasks.test {
    useJUnitPlatform()
}

// jpackage rejects Maven-style versions: no "-SNAPSHOT", strictly MAJOR.MINOR.PATCH.
// Releases pass the git tag via -PappVersion=vX.Y.Z; local builds fall back to a
// sanitized project version. macOS additionally rejects a leading-zero major, so the
// app-bundle version coerces 0.x -> 1.x (real releases tag >= 1.0.0, where it's a no-op).
val rawVersion = (findProperty("appVersion") as String? ?: project.version.toString())
val cleanVersion = rawVersion.removePrefix("v").substringBefore("-").ifBlank { "1.0.0" }
val macVersion = cleanVersion.split(".").toMutableList()
    .also { if (it.isNotEmpty() && it[0] == "0") it[0] = "1" }
    .joinToString(".")

// Optional per-OS icons. Wired only when present so the module builds before art exists
// (jpackage falls back to a default icon otherwise). Generate with tools/make-icons.sh.
val linuxIcon = layout.projectDirectory.file("icons/myotis.png")
val windowsIcon = layout.projectDirectory.file("icons/myotis.ico")
val macIcon = layout.projectDirectory.file("icons/myotis.icns")

compose.desktop {
    application {
        mainClass = "com.jaeckel.ethp2p.desktop.MainKt"

        // Force our logback config over any that dependency jars (trueblocks-kotlin, etc.)
        // bundle under the same resource name.
        jvmArgs += listOf("-Dlogback.configurationFile=logback-desktop.xml")

        nativeDistributions {
            targetFormats(
                TargetFormat.Deb, TargetFormat.Rpm,   // Linux
                TargetFormat.Msi, TargetFormat.Exe,   // Windows
                TargetFormat.Dmg, TargetFormat.Pkg,   // macOS
            )
            packageName = "Myotis"
            packageVersion = cleanVersion
            description = "Myotis — trustless Ethereum light-client wallet"
            vendor = "Myotis"
            copyright = "© 2026 Myotis"

            // Bundle a full JDK runtime image. includeAllModules is the safe default for
            // the Besu / jvm-libp2p / Netty(Unsafe) / BouncyCastle classpath — trim to an
            // explicit modules(...) set later to shrink the installer.
            includeAllModules = true

            linux {
                packageName = "myotis"
                menuGroup = "Network"
                if (linuxIcon.asFile.exists()) iconFile.set(linuxIcon)
            }
            windows {
                menuGroup = "Myotis"
                // Stable so installers upgrade in place instead of stacking side-by-side.
                upgradeUuid = "7E3B2C10-9A4D-4F2B-8C1E-2D6F5A9B3C40"
                perUserInstall = true
                if (windowsIcon.asFile.exists()) iconFile.set(windowsIcon)
            }
            macOS {
                bundleID = "com.jaeckel.myotis"
                packageVersion = macVersion
                if (macIcon.asFile.exists()) iconFile.set(macIcon)
            }
        }

        // Keep ProGuard/minification off for now: the reflective Besu/BouncyCastle/libp2p
        // surface needs a keep-rule audit before shrinking is safe.
        buildTypes.release.proguard {
            isEnabled.set(false)
        }
    }
}
