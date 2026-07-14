// :app-ios — the iOS host: a Kotlin/Native framework (MyotisKit) bundling the shared
// Compose UI (:ui) with the iOS actuals of its seams, driving the RUST engine
// in-process over the plain C ABI (rust/include/myotis_engine.h). The cinterop
// absorbs libmyotis_engine.a into the framework, so the Xcode side needs no extra
// link flags. The JVM engine never runs on iOS — this host has no :myotis-engines /
// :node-core dependency at all. Consumed by ios-app/ (the Xcode project) via the
// standard embedAndSignAppleFrameworkForXcode build phase.

import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    // Cargo triple + root cargo task per Kotlin/Native target. x86_64 simulators are
    // deliberately absent (Apple-Silicon-only dev fleet); add iosX64 + a cargo task
    // if an Intel simulator is ever needed.
    val rustTargets = mapOf(
        "ios_arm64" to ("aarch64-apple-ios" to "cargoBuildIosDevice"),
        "ios_simulator_arm64" to ("aarch64-apple-ios-sim" to "cargoBuildIosSim"),
    )

    listOf(iosArm64(), iosSimulatorArm64()).forEach { target: KotlinNativeTarget ->
        val (triple, cargoTask) = rustTargets.getValue(target.konanTarget.name)
        target.compilations.getByName("main").cinterops.create("myotisEngine") {
            defFile(project.file("src/nativeInterop/cinterop/myotis_engine.def"))
            includeDirs(rootProject.file("rust/include"))
            // The def file names the static library; the search path is per-target
            // (device and simulator builds live in different cargo target dirs).
            extraOpts("-libraryPath", rootProject.file("rust/target/$triple/release").absolutePath)
        }
        target.binaries.framework {
            baseName = "MyotisKit"
            // Static framework: the Rust .a and the Kotlin objects end up in one
            // archive the app links directly — no embed step, no dyld at launch.
            isStatic = true
        }
    }

    sourceSets {
        // This whole module is the FFI host — cinterop symbols and platform.*
        // (Foundation/UIKit) APIs are its bread and butter.
        all {
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
        }
        iosMain.dependencies {
            implementation(project(":ui"))
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.ui)
            implementation(libs.kotlinx.coroutines.core)
            // Parses the engine's JSON (status/account/ENS/catalog) — the Kotlin
            // twin of :myotis-engines' minimal-json marshalling layer.
            implementation(libs.kotlinx.serialization.json)
        }
    }
}

// The cinterop step absorbs libmyotis_engine.a — cargo must have produced it first.
mapOf(
    "cinteropMyotisEngineIosArm64" to "cargoBuildIosDevice",
    "cinteropMyotisEngineIosSimulatorArm64" to "cargoBuildIosSim",
).forEach { (cinteropTask, cargoTask) ->
    tasks.matching { it.name == cinteropTask }.configureEach {
        dependsOn(rootProject.tasks.named(cargoTask))
    }
}
